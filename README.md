# Attested Capability Broker

An independent reference experiment exploring how released
[AgenTrust](https://github.com/agentrust-io) components can turn TPM-appraised
platform state and authenticated agent identity into a short-lived, minimal-scope
MCP capability.

This repository is a verification harness, not an interactive or production
broker. Upstream project names identify dependencies, not affiliation or
endorsement, and no upstream issue is claimed closed.

| Start here | Command or result |
|---|---|
| Clean verification | `docker compose build --pull --no-cache` followed by `docker compose up --abort-on-container-exit --exit-code-from verify verify` |
| Expected smoke result | The full suite under branch-enabled combined coverage, real-`swtpm` integration, lint, format, type, security, and installed-package checks pass; the verifier prints `container smoke: PASS` and exits `0`. |
| Reviewer map | [Audit guide](docs/audit-guide.md) and [threat model](docs/threat-model.md) |
| Report a vulnerability | Follow the repository's [security policy](SECURITY.md). |

## What the experiment establishes

This is the assurance ceiling for a passing clean-container run, not an assertion
that an unreported run passed. For the tested configuration, the experiment may
establish only that:

- the broker accepted a fresh TPM appraisal against its configured trust root,
  narrow synthetic-AK certificate policy, and approved PCR state;
- the broker accepted a signed Agent Manifest and an issuance request endorsed by
  the one agent identity authorized for that manifest digest;
- a resource-specific issuer produced a short-lived cA2A credential whose exact
  scope is `mcp://inventoryd/tool/inventory.lookup`; and
- the intended MCP server accepted and redeemed that credential at most once.

It does **not** establish holder-key residency, holder/TPM/agent co-location,
execution of the agent or manifest, runtime integrity, or safe behavior. An
authenticated requester can use an accepted TPM as a remote signing oracle. The
synthetic certificate profile is not production AK enrollment or evidence of
manufacturer-backed hardware provenance.

## Security path

```text
authorized identity + ephemeral holder key + complete issuance request
                              |
                              v
 signed Agent Manifest -> broker <- fresh, policy-matching TPM quote
                              |     + narrow AK certificate-policy precheck
                              v
                 resource-specific cA2A credential
                              |
                              v
 inventoryd MCP call -> native authorization middleware -> internal tool handler
       exact scope          challenge + proof + atomic spend       invocation
```

There is no authorization gateway in front of an otherwise callable MCP tool.
`inventoryd` owns the only registered lookup route and performs verification and
redemption before reaching its unregistered handler.

The resource challenge commits to the credential ID, server-selected method,
canonical argument digest, record ID, audience, and challenge expiry. The server
stores and consumes the SHA-256 digest of the issued challenge token. In cA2A
Runtime `0.2.0`, `DelegationCredential` has no audience field. Resource
restriction therefore relies on both a resource-specific broker issuer key and
the fully qualified scope; this experiment does not claim that the credential
itself is audience-bound.

On normal decision paths, the deciding service emits a compact JWS decision receipt. Its RFC 8785 canonical
JSON payload is protected with standards-based Ed25519 JWS using protected `alg`,
`kid`, and `typ` fields and is verified against a configured receipt key. Signed
types are not coerced, unknown fields are rejected, and cross-field decision
semantics are checked. Hash-linked cA2A provenance, when present, remains
unauthenticated diagnostic data.

If receipt signing fails only after the credential has been spent and the handler
has run, the MCP boundary returns a closed, explicitly `UNSIGNED`
post-invocation error containing the invocation ID and whether the handler
completed. It is never labeled a denial and is not an authenticated receipt; a
caller must treat it as an uncertain post-spend outcome and must not retry the
credential as though authorization had failed before invocation.

The broker completes certificate-policy, manifest, identity, and TPM appraisal
before consuming its one-time challenge. Both broker-challenge consumption and
resource redemption re-read the clock after acquiring the SQLite write lock. The
resource also requires both signed credential validity bounds and rejects
lifetimes exceeding its configured maximum. The exact invariants and tests are
indexed in the [audit guide](docs/audit-guide.md).

## Certificate-policy and dependency boundary

Released dependencies are used for their documented behavior:

- [Agent Manifest `0.11.2`](https://github.com/agentrust-io/agent-manifest/releases/tag/python-v0.11.2)
  verifies the signed manifest and supplies the configured-root, AK-chain
  signature, qualifying-data, PCR-digest, and TPM-quote checks;
- [cA2A Runtime `0.2.0`](https://github.com/agentrust-io/ca2a/releases/tag/v0.2.0)
  supplies credential, challenge, and holder-proof behavior; and
- the [`mcp` Python SDK `2.1.1`](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.1.1)
  supplies the server protocol boundary.

This experiment independently performs a narrow, fail-closed X.509 precheck for
its synthetic AK profile before invoking released quote verification. At an
injected evaluation time, it requires parseable policy inputs and current
validity for the AK leaf and every non-anchor intermediate. It also enforces CA
BasicConstraints on issuers and configured roots, intermediate path-length
compliance, `keyCertSign` on CAs, and a non-CA AK leaf with `digitalSignature` and
without `keyCertSign`.

The repository profile deliberately does not evaluate the validity window of the
terminal chain certificate or configured trust-anchor certificates. It still
requires their CA BasicConstraints and `keyCertSign`. The released Agent Manifest
path remains responsible for certificate-chain signatures, configured-root
fingerprint trust, and TPM quote verification.

That division does not create a general PKIX engine. The guard does not claim
revocation checking, certificate-policy or name-constraints processing,
algorithm-policy enforcement, trust-anchor expiry policy, discovery or reordering
of arbitrary chains, manufacturer endorsement, hardware provenance, or production
certificate lifecycle management. Its scope is only the caller-supplied,
leaf-first synthetic chain and policy profile exercised here.

## At-most-once boundary

`inventoryd` starts an SQLite write transaction, consumes the resource challenge,
and records the credential ID as spent before invoking the handler. A second
redemption therefore returns `CREDENTIAL_SPENT`, even with a different fresh,
valid holder proof. Two concurrent fresh proofs racing on one credential result
in at most one handler invocation.

This is at-most-once credential redemption, not exactly-once business execution.
A process crash after the spend commit and before or during handler execution can
consume the credential without returning a result. The experiment deliberately
accepts that availability tradeoff.

## Reproduce with Docker

Requirements: Docker Engine with Compose v2. No TPM hardware or cloud account is
required.

From a clean checkout:

```sh
docker compose config --quiet
docker compose build --pull --no-cache
docker compose up --abort-on-container-exit --exit-code-from verify verify
docker compose down --volumes --remove-orphans
```

Compose starts one disposable `swtpm` profile on an internal network. The
verifier checks TPM reachability, installs the `uv.lock`-resolved Python
environment, runs the complete suite with branch measurement enabled,
lint/format/type checks, and Bandit. It then builds the wheel and sdist, verifies
their metadata and exact file inventories, rejects forbidden generated/private
files, validates expected sdist modes and Unix wheel modes when present, checks
every wheel `RECORD` hash and size, and installs the wheel with the frozen
dependencies into a fresh offline environment for an isolated import smoke.
Simulator ports are not published to the host, and TPM state lives in a temporary
in-container filesystem.

Coverage measures both statements and branch opportunities over `atcap`; the
configured `fail_under` applies to coverage.py's combined percentage. The
enforced `85.00%` combined floor is below the measured `85.66%` `origin/main`
combined baseline that preceded this hardening pass. Baseline branch-only
coverage was `71.51%` and is informational: there is no independent branch-only
threshold and no claim that every branch is covered.

The integration fixture creates an AK inside `swtpm`, then uses an ephemeral test
CA to issue a synthetic AK leaf around that public key. It exercises a real quote,
the actual signed PCR-selection parser, qualifying-data binding, configured-root
and chain-signature verification, the narrow certificate-policy guard, PCR policy,
and broker issuance. It also exercises real-quote negatives for leaf and
intermediate certificate time, constraints, leaf and CA key usage, and tampered
certificate-chain and quote signatures. It does not model manufacturer
enrollment, EK/AK certification, a hardware trust chain, or an operational AK
issuance ceremony.

The Dockerfile pins `python:3.12.11-slim-bookworm` to a Docker Hub multi-platform
index digest. Python dependencies are exact-pinned in `pyproject.toml` and
resolved by the committed `uv.lock`. This is not a bit-reproducible image claim:
Debian package names resolve through floating Bookworm repositories, and the
version-pinned `uv==0.12.5` bootstrap is downloaded without an independently
pinned artifact hash.

## Host-side checks

Python 3.12 and `uv==0.12.5` are the supported host path. The host test command
excludes the Linux-only `swtpm` profile; Compose is authoritative for that path.

```sh
uv sync --frozen --python 3.12 --extra dev
TZ=UTC ./scripts/verify-coverage.sh -m 'not swtpm'
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy
uv run --frozen bandit -q -r src
uv run --frozen bandit -q scripts/verify-package.py
package_dist_dir="$(mktemp -d)"
uv run --frozen python -m build --no-isolation --outdir "${package_dist_dir}"
uv run --frozen python scripts/verify-package.py --dist-dir "${package_dist_dir}"
find "${package_dist_dir}" -depth -delete
uv run --frozen pip-audit
uv run --frozen detect-secrets scan --all-files \
  --exclude-files '(^|/)(\.git|\.venv|\.mypy_cache|\.pytest_cache|\.ruff_cache|build|dist)/' .
```

Vulnerability scanning consults a current advisory database and is an explicit
verification step rather than a frozen behavioral result.

## Deliberately deferred

Live TPM hardware, production AK enrollment, cloud evidence, elaborate provenance
DAGs, fuzzing, Sigstore, published SBOMs, external workloads, broad CLI work,
availability engineering, and external services are outside this experiment.

## License

[MIT](LICENSE)

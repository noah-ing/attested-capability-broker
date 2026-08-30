# Runpod as an untrusted disposable holder

This optional lab places only a disposable cA2A holder on Runpod CPU
Serverless. Runpod is wholly outside the trusted computing base. It is not a
TPM, TEE, attestation service, trusted execution environment, or source of
authorization truth. The lab is a store-and-forward adversarial transport for
the local verification harness, not a production deployment guide.

The core experiment does not need Runpod. Nothing in this directory strengthens
the assurance statement in the repository root, and a successful live run adds
no claim about Runpod, its host, or the image that actually executed.

## Trust boundary

```text
trusted local host                                wholly untrusted Runpod

identity/issuer/receipt keys ─┐
TPM root, quote, manifest     ├─ never sent ──────X
policy, SQLite, HMAC secret   ┘

local prepare ── store/forward payload ─────────> disposable holder worker
               (one short-lived credential         builds real cA2A proofs
                per adversarial case,
                disposable holder key, public              │
                challenges/call context only)               │ raw result
                                                            v
local finalize <──────────────────────────────────────── store/forward
  verifies holder-signed bindings
  submits calls to local inventoryd middleware
  verifies local decision receipts
```

The remote payload necessarily contains the short-lived, resource-qualified
cA2A credential, its disposable Ed25519 holder private key, resource challenges,
and public call contexts. Together, the credential and key are usable authority:
a malicious provider can disclose them and can alter, suppress, or fabricate
holder-authorized output. This store-and-forward harness gives Runpod no direct
network route to `inventoryd`; the trusted local finalizer presents the returned
proof. If the same authority were exposed where the provider could reach the
resource, it could attempt redemption first or replay a proof until the credential
was spent. The local resource's atomic spend limits a credential to at-most-once
redemption; it does not provide exactly-once business execution.

The following experiment secrets and state remain on the local host. The lab
does not place them in the worker image, job payload, provider-facing request, or
evidence bundle:

- agent identity, resource-broker issuer, receipt, and experiment-record private
  keys;
- broker/resource challenge secrets, broker policy, TPM trust roots, manifest,
  quote, PCR policy, and SQLite state.

The Runpod API key is not embedded in the worker image, job payload, command-line
arguments, or evidence bundle. The runner does not intentionally read, copy, or
print it. `runpodctl` may obtain it from an inherited environment variable or its
local configuration and necessarily transmits it to Runpod's control plane for
authentication; provider-side handling is outside this experiment's assurance
claim.

Successful holder-signature verification proves that some signer with the
deliberately exposed disposable holder key signed those response bytes; it does
not attribute them to the intended worker. The claimed worker digest and all
Runpod endpoint/job metadata remain untrusted observations. Neither proves image
execution, holder-key residency, TPM/worker co-location, platform integrity,
agent execution, runtime integrity, or safe behavior. The local TPM can still be
a remote signing oracle for an authenticated requester.

## What the worker does

The shared strict wire contract is `lab/worker_wire.py`; the local controller and
deployed handler import that exact module. For each closed test case the worker
calls cA2A 0.2.0's real `build_holder_proof(...)` implementation. Cases cover a
valid proof, exact replay, argument or record substitution, a wrong holder,
malformed proof, and concurrent fresh proofs. Replay and concurrency scheduling
remain local-controller decisions; provider job IDs are never confused with
local request IDs.

`handler.py` is the Runpod entrypoint. `self_test.py` is a non-networked fake
worker smoke test over the same proof generator and wire models. Fake results are
test evidence only: they are never presented as live Runpod or software-TPM
evidence.

## Worker image contract

The worker image:

- is built for `linux/amd64` from a digest-pinned Python 3.12.11 Bookworm base;
- installs the example-local, fully versioned and hash-locked
  `requirements.lock` with `pip --require-hashes`;
- runs as fixed non-root UID/GID `10001`; and
- contains only the handler, fake smoke, shared worker modules, and runtime
  dependencies. It contains no local controller, evidence, policy, TPM state, or
  credentials.

The worker lock is independent of the root project's `uv.lock`. Its direct
inputs are recorded in `requirements.in`; Runpod 1.12.0 is used because Runpod
1.9.1 requires `cryptography<47`, which is incompatible with this experiment's
`cryptography==50.0.1`. Regenerate the lock deliberately and review its diff:

```bash
uv pip compile examples/runpod-untrusted-caller/requirements.in \
  --python-version 3.12 \
  --python-platform x86_64-unknown-linux-gnu \
  --generate-hashes --no-annotate --no-header \
  --output-file examples/runpod-untrusted-caller/requirements.lock
```

Run the exact deployed-code smoke locally without contacting Runpod:

```bash
worker_ref='registry.example/portfolio/atcap-holder@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
./examples/runpod-untrusted-caller/scripts/run-live.sh \
  --validate-only \
  --worker-image "$worker_ref" \
  --max-duration-minutes 10

docker build --platform linux/amd64 \
  --tag atcap-runpod-holder:local \
  examples/runpod-untrusted-caller
docker run --rm --platform linux/amd64 --network none --read-only \
  --env TMPDIR=/run/worker-tmp \
  --tmpfs /run/worker-tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges \
  atcap-runpod-holder:local sh -c \
    'python /opt/worker/self_test.py && python /opt/worker/handler_self_test.py'
```

Before a live run, publish the reviewed `linux/amd64` image to a registry using
that registry's authenticated workflow, then resolve its immutable OCI digest.
The image must be anonymously pullable by Runpod: this narrow runner does not
accept or provision container-registry credentials. Supply only
`registry/repository@sha256:<64 lowercase hex>`; never use `latest` or a tag
alone. The live runner inspects the registry manifest and refuses an image index
without an exact `linux/amd64` member. It then anonymously pulls that exact
digest and, before any Runpod resource mutation, runs both deployed worker
self-tests with no network, a read-only root filesystem, a non-root user, no
Linux capabilities, and `no-new-privileges`. The image build itself rejects an
empty dependency lock, runs `pip check`, and imports the copied handler. These
checks prevent publishing or selecting a locally non-starting worker; they bind
local configuration to registry bytes but still do not attest what Runpod
executes.

## Live run: cost and cleanup boundary

Prerequisites are Docker with Buildx, uv, the exact reviewed `runpodctl` 2.12.0
release, a funded Runpod account, the publicly pullable immutable worker image, and
a mounted writable evidence drive. Authenticate using Runpod's documented `runpodctl`
environment or local-configuration mechanism, as applicable, then verify without
printing or pasting a key:

```bash
runpodctl user >/dev/null
```

The runner makes exactly one provider submission attempt and never resubmits it.
The provider may internally queue, retry, or schedule work; this harness cannot
prove that exactly one worker execution occurred. It fetches current official
Serverless pricing and CPU-type pages before creating resources; no price is
hardcoded. Review [Runpod Serverless pricing](https://docs.runpod.io/serverless/pricing)
and your account limits immediately before use. Cold start, execution, the idle
window, container disk, and provider rounding can all affect cost.

Before creating any provider resource, the shell starts a uniquely named local
Compose project, creates a fresh real `swtpm` AK, and obtains a fresh quote over
the exact identity-endorsed request for every issued case capability. The
released quote-verification adapter and this experiment's narrow synthetic AK
certificate policy verify those quotes locally. The shell records
`tpm_mode=real-swtpm` and tears down that local Compose project before making
the one provider submission attempt. This still does not place the TPM with the
remote worker or turn Runpod into an attestation root.

```bash
worker_ref='registry.example/portfolio/atcap-holder@sha256:<64-lowercase-hex>'
./examples/runpod-untrusted-caller/scripts/run-live.sh \
  --worker-image "$worker_ref" \
  --max-duration-minutes 10 \
  --evidence-root /absolute/path/to/dedicated-evidence-root \
  --confirm-cost 'I ACCEPT RUNPOD CHARGES'
```

The cost controls are intentionally narrow:

- CPU Serverless flavor `cpu3g-4-16`; no GPU, model, or network volume;
- flex workers with minimum `0`, maximum `1`, and scale-to-zero;
- one provider submission attempt with no resubmission, a 120-second
  provider-side request execution timeout, a
  5-second idle timeout, and a `runpodctl` wait limit selected from 5–30 minutes;
- a local best-effort deadline supervisor for the live execution body. At the
  selected duration it sends `TERM` to the local process group and allows up to
  120 seconds for its cleanup trap before sending `KILL`. It is neither a hard
  cost cap nor proof that the provider job stopped; and
- a composed, pre-submission validation across three `runpodctl` 2.12.0
  responses. The GraphQL endpoint-create response must carry the exact
  `computeType: CPU` and `instanceIds: [cpu3g-4-16]` binding; the subsequent REST
  endpoint read-back must carry the exact endpoint/template identities, worker
  bounds, scaler, timeouts, FlashBoot-off state, no GPU pool, and no network
  volume; and the earlier standalone template read-back must bind the template
  to the immutable worker-image digest. The REST endpoint read-back omits
  `computeType` and `instanceIds` and reports the provider's generic
  `gpuCount: 1`; the validator checks that value only as part of the reviewed
  response shape and never interprets it as GPU-allocation evidence. The
  standard-library validator bounds JSON size/shape, rejects duplicate members,
  and revalidates the nested included template. Any omission, type/value change,
  or list-shape change in these reviewed bindings, or the appearance of a
  specifically forbidden compute, GPU, volume, model, location, or template
  alias, stops the run before the one provider job submission.

The exact-digest runtime preflight is intentionally stronger than manifest
inspection. A syntactically valid image can still contain an empty dependency
lock or a handler that cannot import. The runner records bounded self-test logs
in the diagnostic evidence bundle and refuses to create a template or endpoint
unless the pulled image starts and passes both deployed contracts locally.

[`runpodctl` 2.12.0](https://github.com/runpod/runpodctl/blob/v2.12.0/cmd/template/create.go#L95-L97)
omits an empty ports slice from its template-create REST body; the current
provider then reports the ordered defaults `8888/http` and `22/tcp`. The
read-back validator accepts exactly that typed list and rejects omissions,
reordering, duplicates, or additions. The evidence projection records
`ports_requested: false`, those provider defaults, and
`port_reachability_assurance: none`. The REST endpoint's included-template view
also reports `startSsh: true` and `startJupyter: true`; the validator accepts
exactly those provider-default flags as response-shape observations, not as
evidence that either service is running, reachable, authenticated, isolated, or
implemented by the reviewed image. The worker image runs as a non-root user and
contains neither Jupyter nor an SSH daemon, but Runpod, its networking, and its
actual worker runtime remain wholly untrusted. The composed read-backs do not
prove that Runpod executed the intended image or any particular bytes. The
worker receives only disposable holder material, and all of its output remains
adversarial input to the local controller; the port and start-flag metadata do
not create a path to local `inventoryd` or establish any network/runtime
assurance.

The runner creates uniquely named template and endpoint resources. On handled
exit, interrupt, deadline, and error paths it attempts endpoint deletion followed
by template deletion, each with bounded retries and absence read-backs. After an
attempted create whose identifier was never verified, cleanup requires eight
empty exact-name/identifier listings separated by two seconds (at least 14
seconds from the first through the last observation, plus bounded query time)
before declaring the resource absent. Once a resource was observed or its ID was
verified, cleanup requires three consecutive absence listings after deletion. An
uncatchable process or host failure can prevent that trap from running, and the
supervisor's final `KILL` can end cleanup if the grace period is exhausted. A
timeout from `runpodctl serverless run` does not mean the provider job stopped;
the runner therefore deletes the endpoint instead of resubmitting. If cleanup
completes far enough to record an incomplete result, the evidence directory
retains `RECOVERY.txt` with the exact unique names and generic list-and-confirm
workflow. If local private-state deletion failed, it also records that exact
guarded local path. Provider resource IDs and raw provider output are not copied
there. Treat missing or incomplete cleanup evidence as requiring manual Runpod
inspection before doing anything else.

## Evidence handling

The required `--evidence-root` must name an existing writable absolute directory.
Each live run creates exactly one new child named
`attested-capability-broker-runpod-live-<timestamp>.<random>` under that root.
The script does not inspect, move, overwrite, or delete any other contents.
Source, tests, and the core clean-container path do not depend on the evidence
drive.

After successful finalization, the dedicated directory contains current
pricing/type snapshots, the image manifest, closed template/endpoint validation
projections, local-controller output, the canonical `experiment-record.json`,
compact `experiment-record.jws`, public-only `experiment-verifier.json`, a
bounded billing observation, cleanup logs/status, `SHA256SUMS`, and
`verification-manifest.json`. A failed, interrupted, or timed-out run may leave
only a checksummed subset of diagnostic and cleanup evidence; it does not
contain the experiment record, its JWS, or the verifier unless finalization
actually completed. Resource IDs in the provider projections are SHA-256
digests. The projections contain the local expected configuration plus closed,
explicit provider observations such as the composed read-back sources, generic
GPU count, omitted REST compute fields, default ports, and start flags; they do
not authenticate those observations. Raw provider template/endpoint read-backs
remain in the mode-`0700` temporary state directory, are never copied into
evidence, and are removed with a path guard. The evidence bundle is untracked
and excluded from the worker build context; do not commit it. Treat it as
private operational evidence: it contains proof material and billing
observations, and an incomplete-cleanup recovery file may contain exact unique
names or a local private-state path, so inspect and deliberately redact it
before sharing.

Verify a completed record from the repository root:

```bash
PYTHONPATH=examples/runpod-untrusted-caller:src \
  uv run --frozen python -m lab.live_cli verify-record \
  --evidence-dir /absolute/path/to/the/dedicated-run-directory
```

This rechecks canonical framing and projection equality, the experiment-record
JWS, every embedded broker and resource receipt JWS, their public-only JWKs, and
the closed case/count semantics. The bundled experiment verifier establishes
self-consistency only; controller origin requires independently pinning its
public key through an independent trusted channel. This command trusts the
bundled key and does not enforce such a pin. The record commits SHA-256 digests
of worker requests, responses, and holder proofs, but intentionally omits those
operational preimages, so a third party cannot replay the worker-proof appraisal
from the public bundle alone.

Only the experiment-record JWS, its exact JSON projection, and the embedded
broker/resource receipt JWS values are cryptographically checked by that
command. `SHA256SUMS` and `verification-manifest.json` are unsigned and can be
rewritten together; pricing, billing, provider projections, cleanup status, and
logs are diagnostic observations rather than authenticated evidence. Preserve
their hashes externally if their later integrity matters.

After confirming `cleanup_complete: true` and copying anything you intend to
retain, remove only the exact directory printed by the runner. Substitute the
same dedicated root passed to the runner; this guard refuses sibling contents:

```bash
evidence_root='/absolute/path/to/dedicated-evidence-root'
evidence_dir="${evidence_root}/attested-capability-broker-runpod-live-<exact-printed-name>"
evidence_root_real="$(cd -- "$evidence_root" && pwd -P)"
evidence_parent_real="$(cd -- "$(dirname -- "$evidence_dir")" && pwd -P)"
evidence_name="$(basename -- "$evidence_dir")"
if [[ "$evidence_parent_real" != "$evidence_root_real" \
  || "$evidence_name" != attested-capability-broker-runpod-live-* \
  || ! -d "$evidence_dir" \
  || -L "$evidence_dir" ]]; then
  printf 'refusing unexpected evidence path: %s\n' "$evidence_dir" >&2
  exit 1
fi
find "$evidence_dir" -depth -delete
```

## Software-TPM and fake boundaries

Runpod supplies no tenant-verifiable attestation chain used by this experiment,
so `swtpm` stays local. The live runner composes the same real local appraisal
path during capability preparation, while the repository's core Compose smoke
remains its independently repeatable integration check:

```bash
docker compose config --quiet
docker compose build --pull --no-cache
docker compose up --abort-on-container-exit --exit-code-from verify verify
docker compose down --volumes --remove-orphans
```

The no-Runpod-infrastructure unit/fake-transport path uses an explicit
`TestTpmAppraiser` and
records `tpm_mode=test-double` with TPM assurance excluded. A live record can say
`real-swtpm` only because the local controller has verified fresh local quotes
before issuance. Neither mode proves TPM/worker co-location, holder-key
residency, Runpod image execution, or any Runpod/TEE/network/runtime integrity.

## Manual GitHub workflow

`.github/workflows/runpod-live-lab.yml` is manual and creates no Runpod
resources or Runpod charges. It has only
`contents: read`, persists no checkout credential, pins action commits, installs
the root locked environment, validates immutable-reference syntax and the
5–30-minute bound, and runs the shared fake worker smoke. It has no Runpod secret,
does not inspect or pull the supplied image, does not build or publish an image,
does not call the Runpod control plane, and cannot execute the live lab. A green
workflow is contract-test evidence only.

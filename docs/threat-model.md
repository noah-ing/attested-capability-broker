# Threat model

## Scope and assurance statement

This document covers the reference harness: one broker, one configured software-TPM
profile, one signed Agent Manifest, one policy-authorized agent identity, one
ephemeral holder key, one resource-specific broker issuer, and one MCP resource
server (`inventoryd`). It is not an interactive or production deployment.

The experiment may establish only that the configured broker accepted a fresh TPM
appraisal, approved measurements, a verified manifest, and an issuance request
endorsed by an authorized identity, and that the intended MCP server accepted and
redeemed the resource-specific capability at most once.

It must not be cited as evidence of holder-key residency, TPM/holder/agent
co-location, agent execution, manifest execution, runtime integrity, safe agent
behavior, workload confidentiality, or exactly-once business execution. The TPM
may be a remote signing oracle for the authenticated requester.

## Assets and security objectives

The protected asset is the ability to invoke the private
`inventory.lookup` handler. The objectives are:

1. only the configured manifest/identity pairing can obtain a capability after a
   fresh, accepted TPM appraisal;
2. the capability is valid only under the resource-specific broker root and exact
   `mcp://inventoryd/tool/inventory.lookup` scope;
3. possession of the credential alone is insufficient without the ephemeral
   holder private key and a server-issued challenge;
4. the credential ID can be redeemed at most once, including under concurrent
   requests; and
5. every denial occurs before the private handler and leaves its invocation
   counter unchanged.

Decision-receipt authenticity is a separate objective. A verifier with the
configured receipt public key can authenticate the deciding service's canonical
receipt payload and protected JWS metadata. A receipt describes that service's
decision; it is not proof that downstream business effects completed.

## Trusted computing base

The harness trusts:

- the broker and `inventoryd` processes and their loaded code;
- the configured manifest signer, agent-identity, resource-issuer, TPM root, and
  receipt-verification public keys;
- the secrecy of their corresponding private keys;
- SQLite's transaction and uniqueness behavior, plus the integrity and
  availability of each service's database and host filesystem;
- the canonical JSON, Ed25519/JWS, Agent Manifest, cA2A, MCP, TPM parsing, and TPM
  quote-verification libraries pinned by the project;
- the narrow synthetic-AK X.509 policy implemented by the project, including its
  injected evaluation time and leaf-first input convention; and
- the policy configuration, wall clocks, randomness source, and deployment
  topology that prevents an alternate route to the private handler.

The unsigned, hash-linked cA2A provenance records are outside the authenticated
audit boundary. They can be useful diagnostic context but can be rewritten along
with their index.

## Trust boundaries and decisions

### Broker boundary

The broker issues a one-time challenge and persists the SHA-256 digest of the
token. At issuance it requires all of the following:

- the cA2A challenge is authentic, unexpired, stored, and not previously consumed;
- the caller-supplied, leaf-first synthetic AK chain is parseable, its leaf and
  non-anchor intermediates are current at the injected evaluation time, and it
  satisfies the configured CA/non-CA role, path-length, and key-usage profile;
- `verify_tpm_quote(...)` returns the boolean value `True` for the expected quote
  transcript, trusted AK root, expected PCR digest, and expected qualifying data;
- the signed PCR selection exactly matches policy;
- Agent Manifest verification returns `OverallResult.VALID` under the configured
  signer policy;
- the digest of that signed manifest maps to exactly one configured agent identity
  key; and
- that identity key signs the ephemeral holder public key and the complete,
  canonical issuance request, including protocol version, broker, challenge,
  manifest digest, identity key, resource issuer key and key ID, and scope. The
  quote's qualifying data separately commits to that complete endorsed request,
  linking the TPM transcript to it.

Only after these checks may the broker atomically consume its challenge and issue
a credential. A stale or replayed challenge, untrusted quote/root, wrong PCR
state, unauthorized manifest/identity pair, or substituted holder key is denied.
Appraisal happens before challenge consumption so rejected evidence does not burn
the challenge. Challenge time is checked again only after the SQLite write lock
is held, closing the precheck-to-lock race. The complete issuance request also
names both the resource issuer public key and its key ID; both must match policy
and are covered by the identity signature and quote qualifying-data digest.

The certificate-profile precheck runs before released quote verification. It is
not a general PKIX engine and does not independently establish signature validity
or configured-root trust; those checks remain in the released Agent Manifest
path. The quote transcript binds statements together, but it does not demonstrate
that the holder key lives in the TPM or on the same machine. Network proximity
and physical co-location are not inferred.

### Resource-server boundary

`inventoryd` is the enforcement point. There is no separate gateway that can be
bypassed to reach an ordinary unauthenticated MCP lookup method. The only
registered lookup path enters resource-native middleware; the business handler
remains private and unregistered.

The resource server accepts only a cA2A credential that:

- verifies to the configured resource-specific broker issuer;
- contains exactly the qualified lookup scope;
- is within its signed validity interval; and
- is accompanied by a valid holder proof over a live server challenge.

Both signed validity bounds are mandatory, and their difference may not exceed
the resource's configured maximum lifetime. Credential and challenge time are
rechecked after the SQLite write lock is acquired, before any spend is committed.

Because cA2A Runtime `0.2.0`'s `DelegationCredential` has no audience field, the
project does not claim that the credential itself is audience-bound. A distinct
issuer key for `inventoryd`, plus its fully qualified scope, supplies the resource
restriction.

The server chooses the method identifier; it does not trust a caller-supplied
method for authorization. Its challenge record binds the credential ID, that
method, canonical business-argument digest, record ID, audience, expiry, and the
stored challenge-token hash. Any mismatch is denied before spending or invoking.

### Atomic redemption and crash behavior

Inside one SQLite write transaction, `inventoryd` validates and consumes the
challenge and inserts the credential ID into a unique spent-credential table. The
transaction commits before handler invocation. Unique insertion and SQLite's
write serialization ensure that two valid, fresh proofs racing on one credential
cannot both reach the handler.

This ordering favors safety over availability. A crash after commit can permanently
spend the credential before the handler runs or before a result is returned. No
exactly-once claim is made. Recovery means obtaining a new credential, not
unspending the old one.

A handler exception after that boundary is reported as an authorized but failed
execution, not as an authorization denial. Raw successful output must pass the
strict, extra-forbidden `InventoryLookupResult` boundary, which emits only `sku`,
`quantity`, and the server-assigned `invocation_number`. A malformed, extra-field,
or non-JSON-safe handler result becomes a signed `allow` / `HANDLER_FAILED`
execution state without exposing raw output. If receipt signing fails after the
handler runs, including after malformed output, the MCP boundary returns a closed,
explicitly unsigned post-invocation error carrying the invocation ID and
completion state. It is not an authenticated receipt and does not manufacture a
denial that could mislead a caller into retrying as if authorization had never
been consumed.

### Receipt policy commitments

On normal runtime-shape-validated input paths, the signed broker receipt hashes
raw TPM evidence, the complete issuance request, and a canonical public policy
projection. That projection covers broker ID, scope, resource issuer key and key
ID, time-to-live values, manifest identity and artifact bindings, PCR
selection/digest, and a hash of the trusted-root PEM. Runtime-malformed denials
include only safely derived hashes: an unavailable or not runtime-shape-validated
input artifact hash is omitted rather than fabricated, while policy and
already-validated bindings may remain. The resource receipt hashes a projection
covering its audience, method, scope, trusted broker key, challenge TTL, and
maximum credential lifetime.

Receipt verification is strict and extra-forbidden after JWS authentication, so
signed JSON types are not coerced and decision/reason/execution combinations must
be consistent. A broker allow receipt conditionally requires its manifest,
challenge, scope, and broker-policy bindings; an inventory allow conditionally
requires its challenge, record, and resource-policy bindings. A denial may not
omit any core claims: unavailable role bindings are explicitly `null`, and the
receipt cannot claim a handler invocation.

These are authenticated decision inputs, not an append-only log. The current
broker projection includes both the manifest signing key ID and its configured
base64url public key. Tests require mutations to the TPM root, resource issuer
key, manifest signing public key, and TTL to change the broker hash, and mutations
to every modeled resource-policy input to change the resource hash.

## Adversaries and covered attacks

The tests model a network caller who can copy, modify, replay, delay, and race
requests; obtain public manifests and credentials; choose business arguments and
record IDs; and possess an authorized identity or holder key only in the scenarios
where the test grants it. Covered denials include:

- untrusted or invalid TPM quote/root;
- expired or not-yet-valid synthetic AK leaves or non-anchor intermediates,
  CA-role/path-length/key-usage violations, malformed certificate inputs, and
  tampered certificate-chain or quote signatures;
- stale and consumed broker challenges;
- disallowed PCR state or selection;
- unauthorized identity/manifest pairing;
- holder-key substitution after identity endorsement;
- wrong resource scope or issuer root;
- expired credentials;
- repeat redemption with a new valid holder proof;
- an unauthenticated direct MCP lookup attempt; and
- concurrent redemption of one credential.

For every denial, the observable handler invocation count must remain unchanged.

## Residual risks and non-goals

- **Compromised trusted services or keys.** A compromised broker, resource server,
  trusted signer, receipt key, database, or policy host can authorize or fabricate
  decisions. Key provisioning, rotation, revocation, and HSM custody are not solved.
- **Remote TPM oracle.** An accepted TPM can quote a transcript supplied by a
  remote authorized requester. The protocol does not locate the holder key or
  prove that an approved agent is running beside the TPM.
- **Post-appraisal change.** A quote is a point-in-time appraisal of configured
  measurements, not continuous runtime-integrity monitoring.
- **Manifest semantics.** A valid signature authenticates the manifest and its
  signer; it does not prove execution, correctness, safety, or correspondence to a
  running process.
- **Local rollback and denial of service.** Restoring an old SQLite database can
  roll back spend state. Attackers can exhaust challenges, force credential loss
  in the commit-to-handler crash window, or deny service. Durable anti-rollback,
  replication, rate limits, and availability engineering are deferred.
- **Side channels and host isolation.** Timing leakage, memory disclosure,
  container-escape resistance, kernel compromise, and confidential computing are
  outside this experiment.
- **Receipt scope.** Signed receipts authenticate canonical decision claims from
  one configured service. They are not a transparency log, timestamp authority,
  non-repudiation system, or proof of completed side effects.
- **Supply chain.** Exact dependency and base-image pins improve reproducibility
  but do not eliminate dependency compromise. The Docker base-image index and
  Python resolution are pinned, but apt repositories float and the
  version-pinned `uv` bootstrap is not hash-verified; this is not a
  bit-reproducible build. Sigstore and published SBOMs are deferred.
- **Synthetic AK enrollment.** The `swtpm` integration creates an ephemeral test
  CA and signs a leaf certificate for the generated software-TPM AK. It
  verifies the configured quote and X.509 processing path, not a manufacturer
  endorsement chain, hardware provenance, or production enrollment ceremony.

## Dependency and certificate-policy boundary

Released Agent Manifest `0.11.2` supplies its documented manifest and TPM quote
behavior, including certificate-signature and configured-root checks. This
experiment does not attribute production PKIX policy validation to that release.
Instead, `enforce_synthetic_ak_certificate_policy` independently and fail-closed
checks the supplied leaf-first synthetic chain for:

- leaf and non-anchor-intermediate validity at an injected evaluation time;
- a non-CA leaf with `digitalSignature` and without `keyCertSign`;
- CA BasicConstraints and `keyCertSign` for each issuer and configured root; and
- intermediate path-length limits.

Missing, malformed, or incompatible policy inputs are rejected before the
released quote verifier runs. Signature verification, root trust, and TPM quote
verification remain in that released path.

The repository policy deliberately does not evaluate the validity window of the
terminal chain certificate or configured trust-anchor certificates. Their CA
BasicConstraints and `keyCertSign` remain mandatory, and released verification
still performs certificate-chain signature and configured-root fingerprint
checks.

This composition is deliberately narrower than production PKIX validation. It
does not claim revocation checking, complete RFC 5280 policy or name-constraints
processing, certificate algorithm or trust-anchor-expiry policy, arbitrary path
discovery/reordering, manufacturer enrollment, hardware provenance, or
certificate lifecycle operations. A production design would need an
enrollment-specific policy and a maintained path-validation strategy appropriate
to its trust domain.

## Deployment boundary

The reference Compose topology is a verification environment, publishes no
simulator port, and uses one disposable `swtpm` instance. It is not a production
network or deployment model and provisions no external service.

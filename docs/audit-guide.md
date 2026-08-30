# Audit guide

This guide maps the security claims to the implementation and named tests. It is
written for source review, not as a substitute for running the verification
commands. No pass count is asserted here: a checkout earns only the result of the
commands actually run against that checkout.

## Architecture and trust boundaries

```text
 UNTRUSTED / CLAIMED INPUTS                         CONFIGURED TRUST
 ┌──────────────────────────────┐                  ┌──────────────────────────┐
 │ signed manifest              │                  │ manifest signer + digest │
 │ identity-endorsed request    │                  │ authorized identity key  │
 │ TPM quote + synthetic chain  │                  │ TPM/AK root + cert/PCR   │
 └──────────────┬───────────────┘                  │ policy; issuer key/kid   │
                │                                  └─────────────┬────────────┘
                v                                                │
 ┌──────────────────── BROKER TRUST BOUNDARY ────────────────────v────────────┐
 │ verify cA2A challenge -> manifest -> identity -> AK policy -> TPM appraisal│
 │                                  |                                         │
 │              SQLite BEGIN IMMEDIATE: recheck time, consume challenge       │
 │                                  |                                         │
 │ issue signed, bounded cA2A credential under inventoryd-specific issuer     │
 │ sign canonical broker decision receipt                                     │
 └──────────────────────────────────┬─────────────────────────────────────────┘
                                    │ credential
                                    v
 UNTRUSTED MCP CALLER             CONFIGURED RESOURCE TRUST
 ┌──────────────────────────┐     ┌───────────────────────────────────────────┐
 │ credential + proof       │     │ broker public key; exact scope/audience   │
 │ sku + record ID          │     │ receipt verification key; clocks/policy   │
 └─────────────┬────────────┘     └───────────────────┬───────────────────────┘
               v                                      v
 ┌────────────────── INVENTORYD TRUST BOUNDARY ───────────────────────────────┐
 │ one low-level MCP call dispatcher                                          │
 │  challenge: persist token hash + exact call context                        │
 │  lookup: verify root, scope, bounds, lifetime, stored context, holder proof│
 │                     |                                                      │
 │  SQLite BEGIN IMMEDIATE: recheck time, consume challenge, insert spend     │
 │                     | commit before invocation                             │
 │                     v                                                      │
 │              private `_inventory_lookup` handler                           │
 │                     |                                                      │
 │              signed canonical decision receipt                             │
 └────────────────────────────────────────────────────────────────────────────┘
```

The deployment and its policy/key material, clocks, process integrity, SQLite
files, and routing topology are trusted. The caller, manifest document, quote,
credential, proof, tool arguments, and record ID are inputs to be verified.
Receipt consumers form a further boundary: they must use the configured receipt
public key and expected key ID, not a key delivered alongside a receipt.

## Released APIs and exact semantics

The relevant dependencies are exact-pinned in `pyproject.toml` and resolved in
`uv.lock`.

- **Agent Manifest `0.11.2`.** The repository's `verify_signed_manifest` wrapper
  first normalizes through released `Manifest`, checks the configured issuer and
  digest, constructs a strict `VerificationContext`, calls released
  `verify_manifest`, then requires both
  `result.result is OverallResult.VALID` and
  `result.signature_verified is True`. Merely receiving a truthy result is not
  enough.
- **cryptography `50.0.1` synthetic AK policy.** Before released quote
  verification, `enforce_synthetic_ak_certificate_policy` parses the supplied
  leaf-first chain and configured roots with
  `x509.load_pem_x509_certificates`, reads the UTC validity properties and
  `BasicConstraints` / `KeyUsage` extensions, and applies this experiment's
  limited, fail-closed profile at an injected evaluation time. It requires
  current validity for the leaf and every non-anchor intermediate, a non-CA leaf
  with `digitalSignature` and without `keyCertSign`, CA BasicConstraints and
  `keyCertSign` for every issuer and configured root, and intermediate path-length
  limits. Missing, malformed, or policy-incompatible inputs fail closed.

  The profile deliberately does not evaluate the validity window of the terminal
  chain certificate or configured trust anchors; it still enforces their CA role
  and `keyCertSign`. This is not a general PKIX engine: it does not establish
  trust-anchor equality, verify signatures, build arbitrary paths, check
  revocation, apply a trust-anchor expiry policy, or process the full RFC 5280
  policy surface. Certificate signatures and configured-root fingerprint trust
  remain checks in the released Agent Manifest path.
- **Agent Manifest TPM API.** `ReleasedTpmAppraiser.appraise` parses the signed
  PCR selection with `tpm2-pytss`, requires its exact equality to policy, runs
  the narrow certificate-policy guard, then calls `verify_tpm_quote(...)` with
  the configured roots, qualifying data, and PCR digest. It accepts only the
  singleton boolean result `is True`; a truthy non-boolean fails closed. The
  released API does not surface the signed PCR selection, hence the separate
  standards-backed parse.
- **cA2A Runtime `0.2.0`.** Broker and resource tokens use the documented
  `v1.<expiry>.<random>.<HMAC-SHA256>` challenge wire shape. The small
  `issue_ca2a_challenge_at` adapter exists only to inject the same testable clock
  into issuance and persistence; it self-checks each token with the released
  `verify_challenge`. SQLite stores `SHA-256(token)`, not the bearer token.
  A holder proof's wire object is `{challenge, signature}`; `inventoryd`
  reconstructs the signed body with credential ID/subject, audience, exact
  qualified capability, record ID, canonical sealed arguments, and the explicit
  null channel/parent bindings before calling `verify_holder_proof`.
- **No credential audience in cA2A Runtime `0.2.0`.** `DelegationCredential`
  signs issuer, subject,
  scope, credential ID, depth/parent, and validity bounds, but has no audience
  field. Resource restriction is therefore the combination of a distinct
  inventoryd issuer key and exact
  `mcp://inventoryd/tool/inventory.lookup` scope. Audience is instead bound in
  the resource challenge and holder proof. The credential itself is not claimed
  to be audience-bound.
- **`mcp` Python SDK `2.1.1`.** `InventoryApplication` constructs the low-level
  `mcp.server.Server` with one `on_call_tool` dispatcher. That dispatcher exposes
  only `inventory.challenge` and the protected `inventory.lookup`; the private
  handler is not registered. The server-selected `params.name` and configured
  method drive authorization, not a caller-provided method field.
- **JWS.** `joserfc==1.7.5` performs compact JWS signing and verification with
  the allowlisted `Ed25519` algorithm. The entire protected header must equal
  `{"alg":"Ed25519","kid":<configured>,"typ":"atcap-decision+jws"}`.
  Payloads must be RFC 8785 canonical JSON and validate against the closed
  receipt schema. This is library JWS serialization, not bespoke signature
  framing.

Implementation anchors:

- [`src/atcap/manifest_verifier.py`](../src/atcap/manifest_verifier.py)
- [`src/atcap/tpm.py`](../src/atcap/tpm.py)
- [`src/atcap/challenge.py`](../src/atcap/challenge.py)
- [`src/atcap/inventory.py`](../src/atcap/inventory.py)
- [`src/atcap/receipt.py`](../src/atcap/receipt.py)

## Readable allow trace

1. `CapabilityBroker.new_challenge` issues a cA2A-format token and stores its
   SHA-256 digest plus issuance and expiry times.
2. The requester constructs `IssuanceRequest`. Its identity signature covers the
   canonical version, broker ID, challenge, signed-manifest digest, identity key,
   ephemeral holder key, resource issuer key ID, resource issuer public key, and
   exact requested scope. `issuance_qualifying_data` additionally hashes the
   complete endorsed request, including that signature, into TPM `extraData`.
3. `CapabilityBroker.issue` verifies token MAC/expiry, the signed manifest, the
   exact manifest-to-identity mapping, the issuer key and key-ID request bindings,
   the identity signature, PCR selection, the synthetic AK certificate profile,
   quote signature/AK chain, qualifying data, and expected composite PCR digest.
   The repository profile check runs before the released quote verifier; the latter
   remains responsible for signatures, configured-root trust, and the quote.
4. Only after appraisal completes, `SQLiteStore.consume_broker_challenge` obtains
   a write lock, re-reads time, and atomically consumes the still-live challenge.
   Failed appraisal therefore does not burn the challenge. A post-appraisal race
   still yields at most one credential.
5. The broker uses 32 random bytes rendered as a 64-hex-character credential ID,
   sets both `not_before` and `not_after`, sets only the qualified scope, and signs
   with the policy-matched resource-specific issuer private key.
6. `InventoryApplication.issue_resource_challenge` fixes the method and audience
   from resource policy, canonicalizes the business arguments, and stores only
   the token hash plus credential ID, method, argument digest, record ID,
   audience, and expiry.
7. The holder calls the protected lookup with the signed credential and the cA2A
   `{challenge, signature}` proof. `InventoryApplication.redeem` parses both,
   requires a 256-bit ID, both validity bounds, an allowed maximum lifetime, the
   configured root at current time, exact singleton scope, stored context, a live
   challenge, and a valid reconstructed holder proof.
8. `SQLiteStore.consume_challenge_and_spend_credential` acquires a write lock and
   rechecks challenge time, credential time, and the full stored context inside
   the transaction. It consumes that challenge and performs an
   `INSERT OR IGNORE` into the credential-ID primary-key table, then commits. A
   non-first insertion is `CREDENTIAL_SPENT`; its fresh challenge is consumed.
9. Only the first spender reaches `_record_invocation` and the private handler.
   The commit deliberately precedes invocation, so a crash can spend a credential
   without returning a result. That is at-most-once redemption, not exactly-once
   execution.
10. The deciding service signs a canonical receipt. If the handler itself fails,
    the outcome remains an authorized invocation (`allow` / `HANDLER_FAILED`),
    never a fabricated authorization denial; the MCP result can still set
    `is_error` to report the business failure. If signing fails after handler
    completion, `PostInvocationError` preserves that the handler ran rather than
    returning a false denial.

## Invariant-to-evidence map

| Invariant | Enforcing implementation | Direct tests |
|---|---|---|
| Manifest is authorized and cryptographically valid | `verify_signed_manifest`; `ManifestPolicy` | `test_allow_uses_real_manifest_verification_and_signed_receipt`; `test_substituted_manifest_is_not_authorized`; `test_manifest_with_policy_matching_digest_but_invalid_signature_is_denied` |
| One manifest digest maps to one requester identity | `verify_identity_endorsement`; `ManifestPolicy.identity_public_hex` | `test_identity_not_bound_to_manifest_is_denied` |
| Identity endorses the holder and the complete issuance request | `IssuanceRequest.body/signing_bytes`; `endorse_request`; `verify_identity_endorsement` | `test_holder_substitution_breaks_complete_request_endorsement`; `test_quote_qualifying_data_commits_to_every_issuance_field` |
| Resource issuer public key and `kid` are request- and policy-bound | `verify_identity_endorsement`; `BrokerPolicy.resource_issuer_*`; broker constructor key match | `test_substituted_resource_issuer_is_denied_even_when_identity_endorses_it`; `test_quote_qualifying_data_commits_to_every_issuance_field` |
| Protocol version and holder public-key shape are explicit | `verify_identity_endorsement`; `_ISSUANCE_VERSION`; `_ED25519_PUBLIC_HEX_RE` | `test_unsupported_issuance_request_version_is_denied`; `test_identity_endorsed_malformed_holder_key_is_denied` |
| Synthetic AK certificate policy is checked before released quote verification | `enforce_synthetic_ak_certificate_policy`; `ReleasedTpmAppraiser.appraise` ordering | `test_local_ak_policy_rejects_before_released_quote_verification`; `test_local_ak_policy_fails_closed_on_missing_or_malformed_pem`; `test_local_ak_policy_requires_role_extensions`; `test_local_ak_policy_rejects_naive_evaluation_time`; `test_real_swtpm_ak_certificate_and_signature_denials` |
| Validity applies to the leaf and non-anchor intermediates, not terminal/configured trust anchors | `_require_current`; terminal-index exclusion; configured-root policy loop | `test_local_ak_policy_does_not_apply_validity_to_trust_anchors`; `test_local_ak_policy_rejects_before_released_quote_verification[expired-intermediate]`; `test_local_ak_policy_rejects_before_released_quote_verification[not-yet-valid-intermediate]` |
| Quote selection and values are exact and verifier result is literally `True` | `tpm2_pytss_selection_reader`; `ReleasedTpmAppraiser.appraise` | `test_released_adapter_passes_all_policy_bindings_and_requires_true`; `test_truthy_non_boolean_tpm_result_fails_closed`; `test_wrong_signed_pcr_selection_fails_before_quote_acceptance`; `test_real_swtpm_quote_drives_broker_allow_and_rejects_bad_policy` |
| Appraisal precedes broker challenge spend | `CapabilityBroker.issue` ordering; `SQLiteStore.consume_broker_challenge` | `test_failed_appraisal_does_not_burn_broker_challenge` |
| Clock-injected challenges retain the released cA2A wire and expiry semantics | `issue_ca2a_challenge_at`; released `verify_challenge` self-check | `test_clock_injected_challenge_has_exact_ca2a_shape_and_expiry` |
| Broker challenge is one-time and time is rechecked under lock | `SQLiteStore.consume_broker_challenge` (`BEGIN IMMEDIATE`) | `test_consumed_broker_challenge_cannot_be_reused`; `test_two_issuances_racing_one_broker_challenge_mint_exactly_one_credential`; `test_broker_challenge_expiring_while_waiting_for_sqlite_lock_is_not_used` |
| Credential IDs contain 256 random bits before hex encoding | `CapabilityBroker.issue` (`secrets.token_hex(32)`); resource ID syntax check | `test_credential_ids_have_256_bits_of_randomness_and_do_not_repeat` |
| Credential root and exact scope are resource-specific | `InventoryApplication.redeem`; `verify_chain`; exact `frozenset` comparison | `test_untrusted_resource_specific_broker_root_is_denied`; `test_wrong_resource_scope_is_denied` |
| Both signed validity bounds and maximum lifetime are required | `InventoryApplication.redeem`; `ResourcePolicy.max_credential_lifetime_seconds` | `test_expired_credential_is_denied`; `test_credential_with_missing_validity_bound_is_denied`; `test_overlong_credential_lifetime_is_denied` |
| Resource challenge and proof bind the exact call | `issue_resource_challenge`; `verify_holder_proof`; `consume_challenge_and_spend_credential` | `test_resource_challenge_hash_and_full_context_are_persisted`; `test_holder_key_substitution_is_denied`; `test_resource_challenge_cannot_be_moved_to_another_credential`; `test_holder_proof_is_bound_to_audience_and_qualified_capability`; `test_resource_challenge_rejects_argument_or_record_substitution` |
| Challenge and credential validity are rechecked under the redemption lock | `SQLiteStore.consume_challenge_and_spend_credential` | `test_challenge_expiring_while_waiting_for_sqlite_lock_is_not_spent`; `test_credential_expiring_while_waiting_for_sqlite_lock_is_not_spent` |
| A credential reaches the handler at most once, including concurrent fresh proofs | credential-ID primary key; `consume_challenge_and_spend_credential`; commit-before-handler ordering | `test_spent_credential_is_denied_with_a_fresh_valid_holder_proof`; `test_two_fresh_proofs_racing_one_credential_invoke_exactly_once` |
| No unauthenticated MCP route reaches the private handler | low-level `_list_tools` / `_call_tool`; private `_inventory_lookup` | `test_only_challenge_and_protected_lookup_are_registered`; `test_unauthenticated_direct_and_mcp_bypass_attempts_never_invoke_handler`; `test_mcp_allow_path_passes_through_resource_native_middleware` |
| Receipts require trusted key, exact protected metadata, signature, canonical payload, non-coercing types, closed fields, consistent semantics, and role-specific allow bindings | `DecisionReceiptPayload`; `ReceiptSigner`; `ReceiptVerifier` | all tests in `tests/test_receipts.py`; allow-receipt assertions in broker/resource tests |
| Failures after invocation are never relabeled as authorization denial | post-spend branch in `InventoryApplication.redeem`; `PostInvocationError` | `test_handler_failure_after_spend_is_an_authorized_failed_execution`; `test_receipt_failure_after_successful_handler_is_never_reclassified_as_denial` |
| Broker receipt policy hash changes with every modeled broker trust root and TTL | `ManifestPolicy.public_dict`; `TpmPolicy.public_dict`; `BrokerPolicy.public_dict` | `test_broker_policy_hash_commits_every_security_root_and_ttl`; broker allow-receipt artifact-hash assertion |
| Resource receipt policy hash changes with every modeled resource-policy input | `ResourcePolicy.public_dict`; `InventoryApplication._receipt` | `test_resource_receipt_policy_hash_commits_every_security_input` |
| Parallel successful calls retain their own receipt identity | `_record_invocation`; `DecisionReceiptPayload.invocation_id`; `handler_count_snapshot` | `test_parallel_valid_calls_sign_their_own_invocation_ids` |

## Denial matrix

All listed resource denials assert that the handler counter remains unchanged,
or are paired with an assertion that only the already-authorized first call was
counted.

The unit and real-`swtpm` certificate matrices use the exact new profile IDs
`expired-intermediate`, `not-yet-valid-intermediate`,
`intermediate-key-usage`, and `leaf-key-cert-sign`. They run under
`test_local_ak_policy_rejects_before_released_quote_verification` and
`test_real_swtpm_ak_certificate_and_signature_denials`, respectively. The latter
uses a genuine software-TPM AK and quote for every profile.
`intermediate-key-usage` removes `keyCertSign` from an intermediate CA;
`leaf-key-cert-sign` keeps `digitalSignature=true` while adding the forbidden
`keyCertSign=true` to the AK leaf.

| Attack or failure | Expected result | Exact pytest evidence |
|---|---|---|
| Untrusted/modified TPM evidence | `TPM_UNTRUSTED` or fail-closed TPM error | `test_untrusted_tpm_evidence_is_denied_and_receipted`; production adapter coverage in `test_real_swtpm_quote_drives_broker_allow_and_rejects_bad_policy` |
| Expired/not-yet-valid AK leaf or non-anchor intermediate, CA-role/path-length violations, incompatible leaf/CA KeyUsage, or malformed certificate input | `TPM_UNTRUSTED` before released verification | `test_local_ak_policy_rejects_before_released_quote_verification`; `test_local_ak_policy_fails_closed_on_missing_or_malformed_pem`; `test_real_swtpm_ak_certificate_and_signature_denials` |
| Tampered certificate-chain or quote signature | `TPM_UNTRUSTED` / `TPM_INVALID` from released verification before issuance | `test_parseable_tampered_chain_signature_reaches_released_verifier`; `test_real_swtpm_ak_certificate_and_signature_denials` |
| Wrong PCR selection or digest | `PCR_POLICY` / `TPM_INVALID` | `test_wrong_pcr_state_is_denied`; `test_wrong_signed_pcr_selection_fails_before_quote_acceptance`; `test_real_swtpm_quote_drives_broker_allow_and_rejects_bad_policy` |
| Stale broker challenge | `CHALLENGE_STALE` | `test_stale_broker_challenge_is_denied`; `test_broker_challenge_expiring_while_waiting_for_sqlite_lock_is_not_used` |
| Consumed/raced broker challenge | `CHALLENGE_CONSUMED`; only one credential | `test_consumed_broker_challenge_cannot_be_reused`; `test_two_issuances_racing_one_broker_challenge_mint_exactly_one_credential` |
| Unauthorized manifest/identity pairing | `IDENTITY_UNAUTHORIZED` | `test_identity_not_bound_to_manifest_is_denied` |
| Substituted or invalid manifest | `MANIFEST_POLICY` / `MANIFEST_INVALID` | `test_substituted_manifest_is_not_authorized`; `test_manifest_with_policy_matching_digest_but_invalid_signature_is_denied` |
| Substituted holder in issuance request | `IDENTITY_SIGNATURE` | `test_holder_substitution_breaks_complete_request_endorsement` |
| Substituted resource issuer key or key ID | `REQUEST_BINDING` | `test_substituted_resource_issuer_is_denied_even_when_identity_endorses_it`; `test_substituted_resource_issuer_kid_is_denied_even_when_identity_endorses_it` |
| Unsupported issuance protocol or malformed endorsed holder key | `REQUEST_BINDING` | `test_unsupported_issuance_request_version_is_denied`; `test_identity_endorsed_malformed_holder_key_is_denied` |
| Resource credential from another root | `CREDENTIAL_INVALID` | `test_untrusted_resource_specific_broker_root_is_denied` |
| Wrong resource scope | `SCOPE_DENIED` | `test_wrong_resource_scope_is_denied` |
| Expired, unbounded, or overlong credential | `CREDENTIAL_EXPIRED` / `CREDENTIAL_INVALID` | `test_expired_credential_is_denied`; `test_credential_with_missing_validity_bound_is_denied`; `test_overlong_credential_lifetime_is_denied` |
| Holder key substitution | `HOLDER_PROOF_INVALID` | `test_holder_key_substitution_is_denied` |
| Challenge moved to another credential | `HOLDER_PROOF_INVALID` | `test_resource_challenge_cannot_be_moved_to_another_credential` |
| Wrong audience or capability in proof | `HOLDER_PROOF_INVALID` | `test_holder_proof_is_bound_to_audience_and_qualified_capability` |
| Argument or record substitution | `HOLDER_PROOF_INVALID` | `test_resource_challenge_rejects_argument_or_record_substitution` |
| Stale or replayed resource challenge | `CHALLENGE_STALE` / `CHALLENGE_CONSUMED` | `test_stale_resource_challenge_is_denied`; `test_consumed_resource_challenge_cannot_be_replayed`; `test_challenge_expiring_while_waiting_for_sqlite_lock_is_not_spent` |
| Credential expires while blocked on the spend lock | `CREDENTIAL_EXPIRED`, no spend | `test_credential_expiring_while_waiting_for_sqlite_lock_is_not_spent` |
| Spent credential with a new valid proof | `CREDENTIAL_SPENT` | `test_spent_credential_is_denied_with_a_fresh_valid_holder_proof` |
| Two fresh proofs race one credential | one `ALLOW`, one `CREDENTIAL_SPENT`, one invocation | `test_two_fresh_proofs_racing_one_credential_invoke_exactly_once` |
| Missing auth or private-name MCP bypass | `UNAUTHENTICATED`, zero invocations | `test_unauthenticated_direct_and_mcp_bypass_attempts_never_invoke_handler` |
| Receipt tampering, wrong key/header, noncanonical JSON, wrong types, unknown fields, inconsistent semantics, or missing allow bindings | `RECEIPT_INVALID` | tests named `test_*receipt*rejected` in `tests/test_receipts.py` |

## Signed receipt and policy-hash inputs

Broker receipts contain hashes, not raw evidence, for the TPM attestation,
signature, and AK chain. They also carry:

- `issuance_request_sha256` over the complete request including the identity
  signature; and
- `broker_policy_sha256` over the RFC 8785 canonical `BrokerPolicy.public_dict()`.

The broker policy projection includes broker ID, exact scope, resource issuer
`kid`, resource issuer public key and its SHA-256 digest, challenge and credential
TTLs, the authorized manifest digest/issuer/signing key ID/signing public key,
identity key and three artifact hashes, plus the TPM selection, expected PCR
digest, and SHA-256 of the trusted-root PEM bytes.

Inventory receipts carry `resource_policy_sha256` over audience, method, exact
scope, trusted broker public key, challenge TTL, and maximum credential lifetime.
The receipt also directly records the decision, reason, credential ID, challenge
token hash, method, audience, argument digest, record ID, per-call
`invocation_id`, `handler_count_snapshot`, handler-invoked flag, and
business-result state.

The verifier uses strict, extra-forbidden Pydantic validation after authenticating
canonical bytes, so it does not reinterpret signed string values as integers or
booleans. It also enforces role-specific conditions. A broker allow requires a
manifest digest, challenge hash, exact scope, and `broker_policy_sha256`; an
inventory allow requires a challenge hash, record ID, and
`resource_policy_sha256` in addition to its call and invocation fields. Denial
receipts explicitly encode unavailable bindings as `null`; they may not omit the
schema or core execution-state claims and must state that the handler was not
invoked.

These hashes make a signed decision self-describing with respect to the listed
inputs; they are not a transparency log. Broker tests mutate the TPM root,
resource issuer key, manifest signer public key, and TTL independently. Resource
tests mutate audience, method, scope, broker key, challenge TTL, and maximum
credential lifetime. Every mutation must change the corresponding policy hash.

For handler execution, the schema records the specific `invocation_id` allocated
to that call and a `handler_count_snapshot` taken when its receipt is constructed.
The snapshot may exceed the call's own ID when other successful calls run in
parallel; it is not the identity of the invocation.

## Synthetic `swtpm` profile

The marked integration test performs a real TPM 2.0 command flow against the
single Compose `swtpm`: reset and extend PCR 16, create EK/AK objects, produce a
quote whose `extraData` is the issuance transcript digest, independently check
the quote with `tpm2_checkquote`, parse its signed selection, and feed the bytes
through `ReleasedTpmAppraiser` and broker issuance. It also rejects an incorrect
PCR digest, a previously valid quote replayed against a fresh issuance request,
an untrusted configured root, leaf/intermediate time violations,
constraint/key-usage violations, and tampered certificate-chain and quote
signatures. These cases use a real software-TPM quote and the actual policy and
released-verification paths; they are not mocks presented as integration
evidence.

For this fixture, the test creates an ephemeral test CA and issues a synthetic
AK certificate for the `swtpm` AK public key. That construction exercises the
narrow certificate profile plus the configured signature/root verification path.
It is not manufacturer enrollment, proof of a hardware endorsement credential,
or an operational AK issuance ceremony.

`test_local_ak_policy_does_not_apply_validity_to_trust_anchors` separately fixes
the policy boundary: an expired terminal chain anchor and an additional expired
configured anchor are accepted by this narrow precheck when their required CA
constraints and key usage remain valid. That unit test is not evidence that the
complete released path would select or trust either anchor.

## Repeatable verification commands

Host checks use the committed lock and exclude only the Linux `swtpm` marker:

```sh
uv sync --frozen --python 3.12 --extra dev
TZ=UTC uv run --frozen pytest -m 'not swtpm'
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy
uv run --frozen bandit -q -r src
uv run --frozen python -m build --no-isolation
uv run --frozen pip-audit
uv run --frozen detect-secrets scan --all-files \
  --exclude-files '(^|/)(\.git|\.venv|\.mypy_cache|\.pytest_cache|\.ruff_cache|build|dist)/' .
```

The clean Linux/TPM path starts exactly one internal-only simulator and makes the
marked test mandatory by supplying `ATCAP_SWTPM_TCTI`:

```sh
docker compose config --quiet
docker compose build --pull --no-cache
docker compose up --abort-on-container-exit --exit-code-from verify verify
docker compose down --volumes --remove-orphans
```

`container-smoke.sh` checks simulator usability first and then runs the complete
pytest suite, Ruff lint and formatting, strict mypy, Bandit, and package build.
`pip-audit` and `detect-secrets` remain explicit host checks because the former's
advisory result changes with its online database and neither is part of the TPM
behavioral smoke.

The Docker path has a digest-pinned base-image index and a committed Python lock.
It is not bit reproducible:
apt package versions come from floating Debian repositories, and the
version-pinned `uv` bootstrap is not artifact-hash-verified. These commands are a
repeatable verification procedure, not a promise of byte-identical images.

## What a pass would and would not show

A passing full suite supports only this configured experiment: the broker
accepted a fresh, synthetically enrolled `swtpm` quote with approved PCR state, a
verified manifest, and a completely endorsed issuance request; then the intended
MCP resource verified and spent the resulting exact-scope capability at most
once.

It does not prove TPM/holder/agent co-location, holder-key residency, agent or
manifest execution, continuous runtime integrity, safe behavior, real-hardware
provenance, rollback-resistant storage, or exactly-once handler execution. The
TPM may be a remote signing oracle for the authenticated requester. See the
[threat model](threat-model.md) for the full nonclaim and dependency boundaries.

# ADR-0010: Account identity is the (issuer, subject) pair

- **Status**: Accepted
- **Date**: 2026-08-22
- Refines [ADR-0003](0003-google-attestation-as-trust-root.md), which stands.

## Context

[ADR-0003](0003-google-attestation-as-trust-root.md) made an OIDC-nonce Attestation the root of trust. Nothing in that mechanism is specific to Google: any provider that reflects the `nonce` claim into a signed ID token and publishes a JWKS can serve as a root.

The design nevertheless identified an account by the bare `sub` claim, and that value does not stay inside the verifier. It is the input to values that are **derived, persisted, and visible on the wire**:

| Derived value | Where it lives |
|---|---|
| `account_tag = BLAKE3(sub \|\| salt)` | Sent to a Brokr, stored in its database, indexed |
| The bootstrap EID secret, `HKDF(sub, "tradr-bootstrap-v1")` | Broadcast over BLE |
| `peer_sub` in a link record | Persisted on every device of both accounts |

**A `sub` is unique only within its issuer.** OIDC says so explicitly: the pair is the identifier, and a bare subject is meaningless across providers. Two providers may legitimately issue the same string.

## Decision

**An account is identified by the pair `(iss, sub)`, and every value derived from account identity takes the pair as input.**

```
account_id      = iss || "\x00" || sub          <- never the bare sub
account_tag     = BLAKE3(account_id || salt)
bootstrap_secret = HKDF(account_id, "tradr-bootstrap-v1")
```

Provider-specific knowledge is confined to one value, the **Provider Profile**:

```
issuer            the exact iss string to compare against
jwks_uri          where the signing keys are published
authorization_uri, token_uri
client_ids        the accepted aud set for this provider
nonce_binding     how the nonce appears in the token: verbatim, or a hash of it
renewal           how a fresh ID token is obtained without user interaction
```

A verifier selects the profile by the token's `iss`, then runs the same eight steps for every provider. Verification logic is provider-independent; only the profile changes.

## Reasoning

1. **The correction is free now and a flag day later.** `account_tag` and the bootstrap EID are how devices find each other. Changing their input after devices exist means every device's tag and broadcast identifier change at once, and old and new builds stop discovering one another until every device has updated. There is no migration that avoids this, because the old value cannot be recomputed from a token minted under the new rule without keeping both.

2. **Same-account trust must never cross issuers.** Comparing bare subjects would grant `TRUST_TIER_SAME_ACCOUNT` to an account at a different provider that happened to share a subject string. Requiring the pair to match makes that impossible by construction rather than by care.

3. **A second provider is not a URL swap.** Providers differ in ways the profile has to carry. `nonce_binding` exists because at least one major provider is documented to place a **hash** of the supplied nonce in the token rather than the value itself, which would fail step 5 outright. `renewal` exists because the 24-hour silent renewal in [docs/05](../05-security.md#handling-expiry) assumes refresh tokens with a `prompt=none` path, and not every provider offers one on the same terms. Discovering these through a profile field is cheaper than discovering them through a rewrite.

4. **It costs nothing to the single-provider case.** Google remains the only profile shipped. The pair simply makes the assumption explicit instead of implicit.

## Consequences

- **The `aud` set becomes per-profile**, not global. The reasoning in [docs/05](../05-security.md#why-step-4-compares-against-a-set) applies within a provider.
- **A linked account records its issuer.** A link is to `(iss, sub)`, so the same person at two providers is two links, which is correct — they are two identities and the device cannot know they are the same person.
- **The Change Drill's D2 keeps its budget of two files**: one profile registration, one place that enumerates profiles. Nothing else may learn a provider's name.
- **`iss` must be compared exactly, never inferred from the JWKS host.** A provider with per-tenant issuer strings therefore needs one profile per tenant, or an issuer pattern in the profile. This is recorded rather than solved, since no such provider is planned.
- **Adding a provider is a trust decision, not a feature.** Any shipped profile is a root of trust for every user. Profiles are not user-configurable.

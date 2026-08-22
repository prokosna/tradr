# ADR-0003: An OIDC-nonce Attestation is the root of trust

- **Status**: Accepted. Refined by [ADR-0010](0010-identity-is-the-issuer-subject-pair.md), which generalizes the mechanism to any OIDC provider and makes identity the `(iss, sub)` pair
- **Date**: 2026-08-22

## Context

Two requirements meet here: signing in with Google grants free access among your own devices, and the product works without a backend.

The problem is **how device B verifies that device A belongs to the same Google account**.

The conventional design has an authentication server verify the ID token, issue its own session, and maintain a device roster. That makes the server mandatory, colliding with the optional-backend requirement.

Options considered:

1. **Require an authentication server** — straightforward, but contradicts the requirement
2. **Pass Google ID tokens between devices, naively** — an intercepted token can be reused
3. **Put the device public key in the OIDC `nonce`** — this decision
4. **Skip Google, pair devices by QR** — the Syncthing model; every new device needs an in-person meeting

## Decision

**Set the OIDC authorization request's `nonce` to `BLAKE3(ed25519_pub || x25519_pub)`.** The ID token Google returns carries that nonce, signed with Google's private key.

The token thereby becomes a Google-signed assertion that:

> the holder of `(iss, sub)` controls this public key pair

Devices hold this as an **Attestation** and present it on connection. The peer verifies it against Google's JWKS alone. No Tradr backend appears anywhere in the sequence.

## Reasoning

1. **It is the only practical way serverless works.** Option 4 is also serverless, but cannot deliver "sign in with Google and your devices work" — every new device would need an in-person pairing with an existing one.

2. **It closes option 2's hole.** Passing the raw ID token lets an interceptor reuse it on their own device. Binding the nonce to the public keys means an attacker cannot obtain a token whose nonce matches their own keys, since Google's signature is required.

3. **`nonce` is core OIDC**, not a Google extension, so the mechanism extends to Microsoft, Apple, and others later.

4. **The pattern has precedent.** Proving possession of a public key through an OIDC token is used in several end-to-end encrypted systems.

## Handling expiry

An ID token's `exp` is typically an hour out, but what an Attestation asserts is a **binding** between key and account, not that someone is signed in right now.

- **Ignore `exp`; judge the age of `iat`.** Accepted within 30 days by default
- Devices re-mint a token with the same nonce every 24 hours using the refresh token and `prompt=none`
- Revoking access at Google stops renewal, and every peer rejects the device 30 days later

## Costs

- **Google becomes the root of trust.** Google can forge an Attestation for any `sub`. Unavoidable once Google sign-in is a requirement. Mitigated by out-of-band Fingerprint verification.
- **Revocation is slow.** Stopping a stolen device means revoking at Google and waiting up to 30 days. Manual revocation, gossip between devices, and a Brokr's revocation list supplement it, but Tier 0 has no immediate revocation.
- **Devices that have never met cannot be discovered**, since no central roster exists. Either deploy a Brokr or meet once on a LAN or in proximity.
- **A compromised Google account is immediate access to everything.** The attacker enrols a device and obtains a valid Attestation. Detectable only for peers whose Fingerprints were verified.

## Conditions for withdrawal

- Google restricting silent renewal through `prompt=none`. The design would survive, but re-login frequency would rise; if that is intolerable, reconsider
- Needing several identity providers whose handling of `nonce` does not agree

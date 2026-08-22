# ADR-0005: The Brokr is an optional component

- **Status**: Accepted
- **Date**: 2026-08-22

## Context

The design initially assumed a mandatory backend handling authentication, the device roster, account linking, presence, signalling, and relay.

The requirement then arrived: the server is optional, the client alone covers the basic functionality, and someone running Tailscale, for example, can deploy a server and register clients to gain cross-network reach.

That is not "defer the server". **It changes what the design is built around.**

## Decision

**Make the backend — the Brokr — an optional component, with its absence as the default.** Operation splits into three tiers.

| Tier | Requires | Provides |
|---|---|---|
| 0 Standalone | Nothing | Discovery, transfer, and share browsing on the LAN and in proximity |
| 1 Pinned | A reachable address for the peer | Direct connections across overlay networks or fixed IPs |
| 2 Brokered | A deployed and registered Brokr | Discovery from anywhere, NAT traversal, relay, wake-up |

A Brokr takes no part in Attestation verification. It sits outside the circle of trust.

## Reasoning

1. **Serverless cannot be added later.** Building on server-dependent authentication and then removing it means rewriting the architecture. It has to be settled first.

2. **The requirement centres on people already running Tailscale.** An overlay network has solved reachability; adding a Brokr on top is pure wasted operational load. Tier 1 exists as its own tier for that reason. **All that is missing is the peer's address, and the user can supply it once.**

3. **Self-hosting effort can be zero in the common case.** "You have to deploy something before you can try it" is a large adoption barrier for this class of tool. Install, sign in with Google, and it works on the LAN.

4. **It lets the Brokr sit outside the circle of trust.** Carrying no authentication duty, a compromised Brokr cannot impersonate anyone. Given that it is the only internet-exposed component, that separation matters.

## Consequences

Making this work forces a chain of further decisions.

- **Authentication becomes the Attestation of [ADR-0003](0003-google-attestation-as-trust-root.md)**, since no server can verify anything; devices verify against Google's JWKS directly
- **No central roster exists.** There is no global truth about which devices an account owns; each device holds the set it has met and verified
- **A device never met cannot be discovered at Tier 0.** The first meeting must be on a LAN or in proximity
- **Immediate revocation is unavailable.** Tier 0 offers manual revocation and gossip
- **A Brokr learns no `sub`, no email, and no Share definition.** Identifiers stop at `account_tag = BLAKE3(sub || salt)`
- **Losing a Brokr's database is not fatal.** The truth lives on devices

## Costs

- **Android background arrival works only at Tier 2.** At Tier 0 and 1, peers are found on screen-on and at intervals. That is a battery constraint with no way around it, and the UI says so honestly.
- **Experience differs by tier**, raising the documentation and support burden.
- **The test matrix grows**, since Tier 0 and Tier 2 both need verifying.
- **The premise is fragile.** Every feature addition invites an implicit dependency on a Brokr.

Against that last point, **CI runs the Tier 0 and Tier 1 integration tests with no Brokr as a required job**, introduced at M1 rather than waiting for M8. Without that discipline this ADR becomes a fiction within months.

# ADR-0020: `ble-gatt` uses `Noise_XX`, and the handshake payload carries the identity join

- **Status**: Accepted
- **Date**: 2026-09-07
- **Supersedes**: the `Noise_IK` bullets of [docs/05](../05-security.md#why-there-are-two-encryption-layers), for `ble-gatt` only. No earlier ADR decided the pattern, so none is rewritten. [ADR-0002](0002-ble-for-discovery-and-small-payloads.md) is untouched: BLE still carries discovery, authentication and small payloads only

## Context

`WI-M7-007a` landed `Noise_IK` over a byte stream. Cutting `WI-M7-007b`, the `SecureChannel` around it, found that `SecureChannel::peer` cannot be answered on the listening side, and answering that question found a second and larger one underneath it.

**`SecureChannel::peer` returns a `DeviceId` and a Noise handshake does not authenticate one.** A `DeviceId` is `BLAKE3(identity_pub)[0..16]`; Noise authenticates the *agreement* key. The two are bound by the `KeyBinding` signature that [docs/04](../04-protocol.md#the-hello-exchange) carries inside `Hello`, which travels over the channel after the channel exists. `peer` cannot fail, by a doc comment saying mutual authentication has already happened, so a listener finishing a handshake holds 65 bytes it cannot turn into the value it must return.

**QUIC has the same shape and no problem, which is what hid this.** The certificate's `SubjectPublicKeyInfo` *is* the identity key, so the listening side learns the `DeviceId` from it. Noise's static key is the agreement key, and the one step that makes the QUIC listener work has no counterpart.

**`IK`'s premise is that the initiator already knows the responder's static public key, and no source in this design supplies one.** docs/05 said discovery had supplied it along with the Device ID. It has not, in any of the four:

- **mDNS carries an 8-byte fingerprint of the agreement key**, which is what decision 18 already recorded as the reason `PeerExpectation` could not live on a `Candidate`
- **BLE carries no per-device identifier at all.** Ten service-data bytes: a version, an EID, and a flags byte. [docs/03](../03-discovery-and-transport.md#what-a-scanner-reports-and-what-blesource-does-with-it) says a BLE `PeerObservation` carries no Device ID and no display name, so a `ble-gatt` dial is `PeerExpectation::Unpinned` -- **every time, for every peer**
- **A Static Peer carries a hostname**, and its first connection is the one docs/05 already names as holding nothing to pin against
- **Nothing persists a peer's `PublicIdentity`.** `LinkRecord` stores a `link_id`, an `(iss, sub)`, a label and two timestamps. The keys that arrived in an `Invite` are used and dropped

So the exit that keeps `IK` -- construct the transport with a lookup from agreement key to `PublicIdentity` -- is a lookup over an empty table, and would stay empty until something built the store. **The alternative exit is a GATT characteristic serving the static key before the handshake, and it is worse than it looks.**

## Decision

**`ble-gatt` uses `Noise_XX_P256_ChaChaPoly_BLAKE2s`, and each side's identity join rides in the handshake payload.**

```
-> e                       65 bytes
<- e, ee, s, es           299 bytes    payload: the responder's identity join
-> s, se                  234 bytes    payload: the initiator's identity join
```

The identity join is 137 bytes, fixed and unprefixed: `identity_pub` at 65, the `KeyBinding` signature at 64, and `not_after` as a big-endian `i64` at 8. **A payload of any other length is a malformed message rather than a bad binding**, because nothing in it is variable and so nothing needs a length to be read. Each side verifies the binding against the static key Noise has just authenticated, and `peer` returns `BLAKE3(identity_pub)[0..16]`. That is [docs/04](../04-protocol.md#what-each-side-checks-and-in-what-order)'s check 3 run one layer lower, against the same field, and it has one home in `tradr-identity`.

**The verification arrives as a Layer 1 port.** `ci/layer-deps.sh` rule 4 forbids `tradr-transport` from naming `tradr-identity`, and the rule is right: a P-256 signature check belongs where the other five live. `tradr-core` declares the port, `tradr-identity` implements it over the function `on_peer_hello` already calls, and the transport is constructed with it. Nothing points outward.

**The three `PeerExpectation` variants all work, which under `IK` two of them could not.** `Unpinned` reports the `DeviceId` the join produced; `Device` refuses unless it matches; `Identity` refuses unless both it and the authenticated agreement key match.

## Why not read the key from a GATT characteristic and keep `IK`

**Because a key learned from the peer is not a pin, and calling it one is the defect.** `IK`'s guarantee is that the responder proves possession of the key *the initiator already expected*, and the value of that guarantee is entirely in where the expectation came from. Read the expectation off the peer moments earlier and the guarantee collapses to "the responder holds the key it just told me about" -- which is exactly `XX`'s guarantee, reached by a longer route under a name that claims more.

**It is also slower.** A GATT read is a round trip. Read plus a two-message `IK` is two round trips; `XX` is one and a half, over the link this design describes as slow enough to rule out TLS.

**And it leaks the same value.** `XX` reveals the responder's static key to an active prober in message 2, encrypted under an `ee` any prober can compute. A readable characteristic reveals it to the same prober one step sooner. Neither is worse than the other, and the section below bounds both.

## Consequences

- **`WI-M7-007a` keeps its hard half.** The `KeyStore`-backed `Dh`, the injected `Rng`, the error slot and `NoiseSession` are unchanged; the pattern string and the two-message typestate are what `XX` replaces, with a third step on each side
- **Measured, not assumed.** 65, 299 and 234 bytes with a 137-byte payload in messages 2 and 3, all inside the 512-byte `max_frame_size` [docs/04](../04-protocol.md#framing) negotiates for BLE, driven through the existing resolver on 2026-09-07. The resolver's first-call-is-static rule holds unchanged, because `XX` transmits a static key rather than asking a `Dh` for anything new
- **An active prober learns a peripheral's permanent keys, and the EID's promise survives that.** [docs/03](../03-discovery-and-transport.md#2-ble--proximity-no-network-required-tier-0) says why no permanent identifier goes on the air, and the threat it names is a receiver: shop receivers and passing phones, listening. A prober that connects and speaks a handshake is not listening, and this design has no pattern in which a dialler who holds nothing learns nothing. **Refusing message 1 unless it proves possession of an ABK or a Link Secret would close it**, and it is recorded as deferred rather than built, because it is a new wire concept and `peer` is the question this ADR was cut to answer
- **`relay` is not decided here.** docs/05 gives it `Noise_IK` on the same premise, and a Brokr rendezvous may genuinely supply the key. M8 answers it against facts rather than now against none
- **`not_after` is checked here as well as in `Hello`.** It is the same field against the same `Clock`, so there is one date and not two -- which is what docs/05 refuses for the certificate, and a different thing

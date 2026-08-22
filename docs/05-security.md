# 05. Security and identity

## The question at the centre

**Without a backend, how does a device prove it belongs to the same Google account?**

The usual answer is an authentication server. A device signs in with Google, hands the ID token to the server, the server verifies it, issues its own session, and maintains a device roster. That makes the server mandatory.

Tradr answers with the **OIDC `nonce` claim** instead.

## Attestation — making Google the root of trust

### The mechanism

An OIDC authorization request may carry a `nonce`. Google **copies that value into the ID token and signs it**. That is the whole trick.

```
1. The device generates key pairs
     ed25519_priv/pub   for signing and identity
     x25519_priv/pub    for Noise key agreement

2. It computes a nonce
     nonce = base64url(BLAKE3(ed25519_pub || x25519_pub))

3. It runs Google's authorization flow carrying that nonce
     https://accounts.google.com/o/oauth2/v2/auth
       ?client_id=...&scope=openid%20email%20profile
       &nonce=<the value above>&code_challenge=...&access_type=offline

4. Google returns an ID token containing
     {
       "iss": "https://accounts.google.com",
       "aud": "<Tradr's OAuth client ID>",
       "sub": "104839...",              <- account identity
       "nonce": "<BLAKE3(public keys)>", <- the binding to the keys
       "iat": ..., "exp": ...
     }
     signed with Google's private key.
```

That token is a Google-signed assertion that:

> the holder of Google account `sub=104839...` just presented the value `BLAKE3(public keys)`

Since the nonce is a hash of the device's public keys, it functions as:

> the holder of `sub=104839...` controls this key pair

That is an **Attestation**.

### What a verifier does

When device B receives an Attestation from device A:

```
1. Fetch Google's JWKS from https://www.googleapis.com/oauth2/v3/certs
     Cacheable. Verification works offline against an existing cache
2. Verify the id_token signature against the JWKS
3. Check iss == "https://accounts.google.com"
4. Check aud == Tradr's OAuth client ID
5. Check nonce == base64url(BLAKE3(A's ed25519_pub || A's x25519_pub))
6. Check iat falls within the staleness limit, 30 days by default
7. Compare sub against
     our own sub          -> TRUST_TIER_SAME_ACCOUNT
     a linked sub         -> TRUST_TIER_LINKED
     neither              -> NEARBY_EPHEMERAL only in ephemeral receive mode,
                             otherwise REJECTED
8. Verify the Ed25519 signature over Hello.nonce
     <- proves A holds the private key right now, defeating replay
```

**No Tradr backend appears anywhere in that sequence.** All it requires is Google's public keys, which anyone can fetch.

### Handling expiry

An ID token's `exp` is typically one hour out. But what an Attestation asserts is not "signed in right now" — it is **a binding** between a key and an account.

- **`exp` is ignored; the age of `iat` is what matters.** Accepted within 30 days by default
- Devices hold a Google refresh token and **re-mint an ID token with the same nonce every 24 hours** via a `prompt=none` silent refresh, requiring no user interaction
- A healthy device therefore always presents an Attestation less than a day old

### That is also the revocation mechanism

Revoking Tradr's access in Google account settings means:

1. The refresh token stops working
2. The device can no longer renew its Attestation
3. After 30 days, every peer rejects it on staleness

**Having "wait 30 days" as the only way to stop a stolen device is slow.** That is the price of Tier 0's serverless property, offset by:

| Mechanism | Speed | Tier |
|---|---|---|
| Revoke access in Google settings | Up to 30 days | 0 |
| Manual per-device revocation by fingerprint | Immediate on that device; does not propagate | 0 |
| Gossip of revocations between devices that meet | Whenever they meet | 0 |
| A Brokr's revocation list | Immediate, pushed to online devices | 2 |
| ABK rotation | Immediate for remaining devices; the revoked one falls off BLE discovery | 0 |

The staleness limit is configurable down to one day. Shorter means faster revocation but breaks long-offline devices. 30 days is the compromise.

### Why `sub` and not email

Google's `email` claim can change through an account email change or a Workspace domain migration. `sub` is permanent and unique. Display email freely, but **always decide identity on `sub`**.

### What this defends, and what it does not

| Attack | Defended? |
|---|---|
| Forging an Attestation | Yes — Google's signature is required |
| Replaying someone else's stolen Attestation | Yes — the nonce will not match the attacker's keys |
| Presenting the attacker's own Attestation | Yes — the `sub` will not match |
| Replaying an old Attestation | Yes — the signature over `Hello.nonce` proves current key possession |
| **Google itself acting maliciously** | **No.** Google can forge an Attestation for any `sub` |
| **The user's Google account being taken over** | **No.** The attacker can enroll new devices |

The last two follow necessarily from choosing Google as the root of trust. **Fingerprint verification** exists to mitigate them.

## Fingerprint — the option not to trust Google

A Device Key rendered human-readable, equivalent to a Signal safety number.

```
Take the first 15 bytes of BLAKE3("tradr-fp-v1" || ed25519_pub || x25519_pub),
split into three groups of 5, and encode each as 4 words from a
BIP-39-style list of 2048.

  example:  harbor  lantern  copper  drift
            silent  meadow   quartz  ember
            violet  anchor   pebble  frost
```

- Settings shows your own fingerprint
- Each peer's fingerprint can be shown and marked verified
- Once verified, a changed fingerprint **refuses the connection with a warning**
- Verification is never mandatory. The default is trust on first use

This catches the case where Google forged an Attestation for an unknown device, for peers that were verified. The UI presses for verification during account linking.

## Key storage

Private keys never leave the device after generation. There is no export function; migration means enrolling with new keys.

| OS | Storage | Hardware backing |
|---|---|---|
| Android | Android Keystore, attempting `setIsStrongBoxBacked(true)`, falling back to the TEE | Yes — StrongBox or TEE |
| macOS | Keychain, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | Partial — the Secure Enclave handles P-256 only, so the key itself lives in the Keychain |
| Windows | CNG with DPAPI; the Platform Crypto Provider where a TPM exists | Yes, with a TPM |
| Linux | Secret Service via `libsecret`, then the kernel keyring, then a `0600` file | No — the last resort is software only |

**Falling short of hardware backing on Linux is stated plainly.** Settings displays the storage method in use and says so explicitly when it has fallen back to a file. Headless environments without a running Secret Service get a warning.

Ed25519 signing keys cannot use the Secure Enclave because Apple restricts it to P-256 ECDSA and ECDH. Switching to P-256 is possible, but Ed25519 wins on Noise compatibility and implementation simplicity, so it stands for now.

## Why there are two encryption layers

| Transport | Secure channel |
|---|---|
| `direct-quic`, `holepunch-quic`, `wifi-direct` | QUIC's TLS 1.3 |
| `ble-gatt`, `relay` | Noise_IK |

QUIC already contains TLS 1.3, so stacking another encryption layer on top would be pure duplication. On QUIC paths TLS is used directly, with **a self-signed certificate whose public key is the Device Key, matched against the pinned value**. No certificate chain and no CA.

- The certificate's `SubjectPublicKeyInfo` is the device's Ed25519 public key
- Certificates are requested in both directions, giving mutual TLS
- Verification asks not whether a chain validates but whether this public key equals the expected Device ID

BLE and `relay` are raw byte streams where TLS does not fit — its handshake overhead is prohibitive over BLE, and on relay the WebSocket's TLS terminates at the Brokr. Those use **Noise_IK**.

- The `IK` pattern assumes the initiator **already knows** the responder's static public key, which discovery has supplied along with the Device ID. One round trip completes mutual authentication and key agreement
- A two-message handshake stays usable over BLE's slow round trips
- On relay the Brokr sits between the endpoints and sees only Noise ciphertext

**Both give the layer above identical guarantees**: mutually authenticated, forward secret, ordered, bidirectional. That invariant is expressed as a `SecureChannel` trait, and `tradr-core` never learns which one it is using.

## Trust Tiers and their powers

| | `SAME_ACCOUNT` | `LINKED` | `NEARBY_EPHEMERAL` |
|---|---|---|---|
| Receiving files | Auto-accepted by default | Confirmation by default | Always confirmed, plus a PIN check |
| Browsing Shares | Those with `audience=account` | Those whose audience includes the link | No |
| Writing to Shares | Where `mode=rw` | Where `mode=rw` and explicitly permitted | No |
| Size limit per transfer | None | Configurable, unlimited by default | 100 MB |
| Duration | Permanent | Until the link is removed | 10 minutes |

`NEARBY_EPHEMERAL` corresponds to Quick Share's "everyone" mode. It is **off by default**; the user turns it on for ten minutes at a time. Even then, the sender displays four digits the receiver must confirm, which surfaces a man-in-the-middle.

## Threat model

### Adversaries considered

| # | Adversary | Capability |
|---|---|---|
| T1 | Another party on the same LAN | Observe packets, spoof mDNS, attempt connections to any device |
| T2 | A passive observer on the path | Record all packets |
| T3 | An active attacker on the path | Modify, inject, attempt man-in-the-middle |
| T4 | A malicious or compromised Brokr | Every relayed byte, presence data, registered Device IDs |
| T5 | A BLE receiver in proximity | Every advertisement |
| T6 | A malicious linked peer | Holds a valid Attestation and acts as `LINKED` |
| T7 | Someone holding the device physically | Disk contents, and the whole app once unlocked |

### Responses

**T1 — another party on the LAN**
- Spoofing mDNS TXT records to claim a false identity is possible, but Attestation verification after connection always rejects it
- Incoming connections receive no resources until `Hello` arrives. Per-connection memory limits and rate limits apply before the handshake
- **Leaked**: Device ID, display name, platform, capability flags. Who is present on a LAN is not concealed — see [03](03-discovery-and-transport.md)

**T2 — passive observer**
- All payload is encrypted. Part of the QUIC handshake is visible, but SNI is not used
- **Leaked**: peer IP addresses, transfer timing, approximate sizes. Traffic analysis is not defended against; padding and cover traffic are out of scope

**T3 — active attacker and man-in-the-middle**
- Public-key pinning on QUIC and Noise_IK on BLE and relay both prevent an intermediary without the key from completing a handshake
- The first connection is trust on first use, so **a man-in-the-middle is possible on that first contact only**. Out-of-band fingerprint verification is what detects it
- The Attestation nonce prevents stealing a legitimate device's Attestation and presenting it with attacker-controlled keys

**T4 — malicious Brokr** — the case this design paid the most attention to
- Only Noise ciphertext traverses a relay. A Brokr never sees plaintext
- **A Brokr is designed to be unable to verify Attestations.** Verification always happens on a device against Google's JWKS. Compromising a Brokr therefore grants no impersonation. It can insert fake devices into presence listings, but those devices hold no Attestation and get rejected at connection time
- The identifier a Brokr receives is `account_tag = BLAKE3(google_sub || salt)`. The `sub` itself is never sent
- **A Brokr can**: collect metadata about who communicated with whom and when, observe presence, deny service, and retain relayed ciphertext it cannot decrypt
- **A Brokr cannot**: read content, impersonate anyone, or reach another party's Shares
- Self-hosting means the Brokr's operator is usually the user. The separation still holds because a Brokr is the only component exposed to the internet, making it the most likely thing to be compromised

**T5 — BLE receivers**
- Broadcast EIDs rotate every 15 minutes and are untrackable without the matching secret
- The bootstrap secret, `HKDF(google_sub)`, falls to anyone who learns the `sub`. Routes to obtaining one are limited but not nonexistent. Exchanging an ABK closes the window by ending bootstrap advertising
- BLE addresses themselves use resolvable private addresses. This depends partly on OS settings; on Linux, BlueZ `Privacy` must be enabled

**T6 — malicious linked peer**
- Sees only Shares whose audience includes them. Path boundary enforcement is covered in [06](06-shares-and-linking.md)
- Writable Shares carry limits on write volume and rate, against disk-filling
- A link can be removed unilaterally at any time, taking effect locally at once
- **Not mitigated**: a file once handed over cannot be recalled, and nothing stops the entire contents of a read-only Share being taken. That is what sharing means, so the response is a UI that makes the exposure obvious

**T7 — physical possession**
- Private keys sit in the OS key store and require device unlock, the Linux file fallback excepted
- Biometric or PIN gating at app launch is available optionally
- After a loss: revoke access at Google, revoke manually from another device, rotate the ABK. Speeds are in the table above

### Explicitly not defended

- **Traffic analysis.** Who communicated with whom, when, and roughly how much is not concealed
- **Device presence on a LAN.** Visible over mDNS
- **The receiving filesystem against a trusted peer.** Anyone given a writable Share can write anything within it. There is no ransomware-shaped countermeasure
- **Side channels.** Timing and power analysis are out of scope
- **A device already running malware.** No defence against an attacker who can execute code on the device

## Algorithms

| Purpose | Algorithm | Notes |
|---|---|---|
| Device identity and signing | Ed25519 | |
| Key agreement | X25519 | |
| Noise pattern | `Noise_IK_25519_ChaChaPoly_BLAKE2s` | via `snow` |
| QUIC encryption | TLS 1.3, `TLS_AES_128_GCM_SHA256` | via `rustls` |
| Hashing for integrity and identifiers | BLAKE3 | |
| KDF | HKDF-SHA256 | EID derivation and similar |
| Randomness | The OS CSPRNG via `getrandom` | |

Post-quantum migration is deferred. Noise offers hybrid patterns such as `Noise_IKhfs`, and `rustls` is gaining X25519MLKEM768; once both are stable, an ADR will record the switch. Priority is low on the judgement that most transferred files do not need secrecy over the horizon that harvest-now-decrypt-later implies.

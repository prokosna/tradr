# 05. Security and identity

## The question at the centre

**Without a backend, how does a device prove it belongs to the same Google account?**

The usual answer is an authentication server. A device signs in with Google, hands the ID token to the server, the server verifies it, issues its own session, and maintains a device roster. That makes the server mandatory.

Tradr answers with the **OIDC `nonce` claim** instead.

## Attestation — making the identity provider the root of trust

### The mechanism

An OIDC authorization request may carry a `nonce`. The provider **copies that value into the ID token and signs it**. That is the whole trick.

Nothing below is specific to Google. Any provider that reflects the nonce and publishes a JWKS can serve as a root of trust; Google is simply the only **Provider Profile** shipped. See [ADR-0010](adr/0010-identity-is-the-issuer-subject-pair.md) and [profiles](#provider-profiles) below.

```
1. The device generates key pairs
     identity key pair    P-256, for signing and identity
     agreement key pair   P-256, for Noise key agreement

2. It computes a nonce
     nonce = base64url(BLAKE3(identity_pub || agreement_pub))

3. It runs the provider's authorization flow carrying that nonce
     https://accounts.google.com/o/oauth2/v2/auth
       ?client_id=...&scope=openid%20email%20profile
       &nonce=<the value above>&code_challenge=...&access_type=offline

4. The provider returns an ID token containing
     {
       "iss": "https://accounts.google.com", <- which provider
       "aud": "<the OAuth client ID that ran the flow>",
       "sub": "104839...",              <- subject, unique within that iss
       "nonce": "<BLAKE3(public keys)>", <- the binding to the keys
       "iat": ..., "exp": ...
     }
     signed with the provider's private key.
```

That token is a provider-signed assertion that:

> the holder of account `(iss, sub)` just presented the value `BLAKE3(public keys)`

Since the nonce is a hash of the device's public keys, it functions as:

> the holder of `(iss, sub)` controls this key pair

That is an **Attestation**.

### What a verifier does

When device B receives an Attestation from device A:

```
1. Read iss from the token and select the Provider Profile matching it
     exactly. No profile -> REJECTED. Nothing else is read first
2. Fetch that profile's JWKS and verify the id_token signature
     Cacheable. Verification works offline against an existing cache
3. Check aud is one of that profile's client IDs
4. Check the nonce binds A's keys, per the profile's nonce_binding
     verbatim: nonce == base64url(BLAKE3(identity_pub || agreement_pub))
     hashed:   nonce == SHA-256 of that value
5. Check iat falls within the staleness limit, 30 days by default
6. Compare the pair (iss, sub) against
     our own pair         -> TRUST_TIER_SAME_ACCOUNT
     a linked pair        -> TRUST_TIER_LINKED
     neither              -> NEARBY_EPHEMERAL only in ephemeral receive mode,
                             otherwise REJECTED
7. Verify the signature over "tradr-hello-v1" || Hello.nonce
     <- proves A holds the private key right now, defeating replay
```

**No Tradr backend appears anywhere in that sequence.** All it requires is the provider's public keys, which anyone can fetch.

**Step 1 comes first for a reason.** Every later step depends on which profile is in force — which JWKS, which `aud` set, which nonce encoding. Selecting the profile from anything other than an exact `iss` match, the JWKS host for instance, would let a token nominate its own verification rules.

#### Why step 3 compares against a set

Google issues one OAuth client ID per platform: one for desktop, one for Android, and one more if iOS is added. **The `aud` in an Attestation is the client ID of whichever platform ran the flow**, so a desktop device verifying an Android peer sees the Android client ID.

Comparing against a single value would therefore fail every cross-platform verification while same-platform pairs kept working — a failure mode that presents as "only Android will not connect" and hides its cause well.

Every device carries the full set of Tradr client IDs, compiled in, and step 3 accepts membership in the set belonging to the selected profile. The values are public and belong in the repository.

Adding a platform means adding its client ID to that set, which older builds will not have. Since an unknown `aud` is rejected, **a new platform cannot be verified by devices that predate it**. Client IDs are therefore added to the set one release ahead of the platform that uses them.

### OAuth client configuration

The client IDs are public values and live in the repository. The desktop client also carries a secret, which Google's token endpoint requires for Desktop-type clients even under PKCE. Google states that an installed application's secret is not treated as confidential, and it is extractable from any shipped binary regardless of how it is delivered. **PKCE is what actually protects the flow.** Android-type clients have no secret at all.

That secret is therefore committed alongside the client IDs, so that anyone who clones and builds gets a working application. Both values can be overridden at runtime:

```
TRADR_OAUTH_CLIENT_ID
TRADR_OAUTH_CLIENT_SECRET
```

An override extends the accepted `aud` set with the supplied client ID rather than replacing it, so an overridden device still verifies peers on the default client.

**But the reverse does not hold, and that is the consequence worth stating.** A device using an overridden client produces Attestations whose `aud` is that client, which a device on defaults does not recognize and rejects. **Overriding therefore has to be done across every device of an account, never on some of them** — a partial override splits the account into two sets that cannot see each other. The settings UI says so at the point of override.

Read positively, this means an organization can point every device at its own Google project and obtain a self-contained trust domain, unable to authenticate against anyone else's deployment.

Should the published client be abused — a third party using it to present a consent screen bearing Tradr's name — the response is to rotate it in Google Cloud Console and ship the new value. Devices that fail to renew their Attestation against a retired client fall back on the 30-day staleness window, which leaves ample room for the release to reach them.

### Provider profiles

Everything a provider brings to verification lives in one value. Nothing else in the codebase names a provider.

| Field | Why it cannot be assumed |
|---|---|
| `issuer` | Compared exactly against `iss`. Selecting the profile is step 1 |
| `jwks_uri` | Moves independently of the issuer string. D1 of the Change Drill is this field |
| `authorization_uri`, `token_uri` | Discovered once from `/.well-known/openid-configuration`, then pinned |
| `client_ids` | One per platform, per provider. See [above](#why-step-3-compares-against-a-set) |
| `nonce_binding` | Verbatim or hashed. A provider that stores a digest of the nonce fails step 4 outright under the wrong assumption |
| `renewal` | Whether a fresh ID token can be minted without user interaction, and on what terms |

The last two are why **adding a provider is not a URL swap**, and why they are fields rather than an assumption discovered during a rewrite. `renewal` in particular carries the design's weight: the 24-hour silent renewal below assumes a refresh token and a `prompt=none` path. A provider offering neither shifts that account's whole revocation story, and the profile is where that becomes visible.

**Profiles are compiled in and are not user-configurable.** A shipped profile is a root of trust for every user of that build, so adding one is a trust decision taken in an ADR, not a setting.

Google is the only profile shipped. **The pair `(iss, sub)` is nevertheless what identity means everywhere**, not a bare `sub` — see the next section but one, and [ADR-0010](adr/0010-identity-is-the-issuer-subject-pair.md).

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

### Why `(iss, sub)` and not email, and not `sub` alone

The `email` claim can change through an account email change or a Workspace domain migration. Display email freely, but **never decide identity on it**.

`sub` is permanent, but it is **unique only within its issuer**. Two providers may issue the same string to different people, and nothing prevents it — OIDC defines the identifier as the pair. So the account identifier is

```
account_id = iss || 0x00 || sub
```

and every value derived from account identity takes `account_id`, never the bare subject:

| Derived value | Definition |
|---|---|
| `account_tag` | `BLAKE3(account_id \|\| salt)`, the only identifier a Brokr receives |
| Bootstrap EID secret | `HKDF(account_id, "tradr-bootstrap-v1")`, broadcast over BLE |
| A link record's peer identity | The peer's `(iss, sub)` pair |

**These are persisted and visible on the wire, which is why the pair has to be settled before any of them exists.** Changing the input afterwards changes every device's `account_tag` and bootstrap broadcast at once, and devices on either side of the change stop finding each other until all of them have updated. There is no migration; the old value cannot be recomputed from a token minted under the new rule.

Requiring the pair to match also makes cross-issuer confusion impossible by construction: an account at another provider that happens to share a subject string cannot reach `TRUST_TIER_SAME_ACCOUNT`.

### What this defends, and what it does not

| Attack | Defended? |
|---|---|
| Forging an Attestation | Yes — Google's signature is required |
| Minting a token against our public client ID | Yes — a client ID is not a secret, but the resulting token carries the attacker's own `sub`, which fails step 7 |
| Replaying someone else's stolen Attestation | Yes — the nonce will not match the attacker's keys |
| Presenting the attacker's own Attestation | Yes — the `sub` will not match |
| Replaying an old Attestation | Yes — the signature over `Hello.nonce` proves current key possession |
| **Google itself acting maliciously** | **No.** Google can forge an Attestation for any `sub` |
| **The user's Google account being taken over** | **No.** The attacker can enroll new devices |

The last two follow necessarily from choosing Google as the root of trust. **Fingerprint verification** exists to mitigate them.

## Fingerprint — the option not to trust Google

A Device Key rendered human-readable, equivalent to a Signal safety number.

```
Take the first 15 bytes of BLAKE3("tradr-fp-v1" || identity_pub || agreement_pub),
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
| macOS | Keychain, with Secure Enclave key generation where available | Yes — the Enclave handles P-256, which is what Device Keys use |
| Windows | CNG with DPAPI; the Platform Crypto Provider where a TPM exists | Yes, with a TPM |
| Linux | Secret Service via `libsecret`, then the kernel keyring, then a `0600` file | No — the last resort is software only |

**Falling short of hardware backing on Linux is stated plainly.** Settings displays the storage method in use and says so explicitly when it has fallen back to a file. Headless environments without a running Secret Service get a warning.

### The KeyStore boundary

A key inside StrongBox, a TPM, or the Secure Enclave **cannot be read out** — that is the entire point of those elements. So the shape of the `KeyStore` trait, not the choice of curve, is what first decides whether hardware backing is reachable at all. A trait that hands Layer 1 a private key can only ever be implemented in software, on every platform, and it fails silently because the code still works.

`KeyStore` therefore exposes `sign`, `agree`, and `backing`, and no method returns key material. [ADR-0011](adr/0011-keystore-exposes-operations.md) has the trait and the consequences, of which two bind other choices: the Noise implementation must accept an external DH, and the TLS stack must accept an external signer.

`backing()` returns whether the key is in hardware or software and why, and **Settings renders it**. Falling short of hardware backing on Linux is stated plainly rather than assumed; the same display covers a missing TPM, an old Keymint, and a headless box with no Secret Service.

### Hardware backing and the curve

Given that boundary, the curve decides how much of the promise each platform can keep — and only one curve keeps it. **Device Keys are P-256**, ECDSA for signing and ECDH for agreement, decided in [ADR-0012](adr/0012-p256-for-device-keys.md).

| | Ed25519 + X25519 | P-256 |
|---|---|---|
| macOS Secure Enclave | No | Yes |
| Windows TPM via CNG | Not generally | Yes |
| Android StrongBox | Recent Keymint only | Yes |
| Linux | Software either way | Software either way |

The design previously specified Ed25519 and X25519, which forfeited hardware backing on three platforms out of four. **Both keys were affected, not only the signing key** — the Secure Enclave performs ECDH on P-256, so an X25519 static key for Noise was as unprotected there as an Ed25519 one.

Two things had to hold before this could be decided, and both were measured rather than assumed:

- `snow` supports P-256, through its `p256` feature and `DHChoice::P256`. A probe completed a full `Noise_IK_P256_ChaChaPoly_BLAKE2s` handshake
- **A key `snow` never sees can still drive the handshake.** `Dh::privkey()`, the one method a hardware key cannot answer, is reached only from `Builder::generate_keypair`, which Tradr does not call. The static and ephemeral keys resolve to separate `Dh` instances, so the static key delegates to `KeyStore::agree` while the ephemeral key stays in software, where it belongs

**Per-device curve agility is rejected.** Noise's pattern name fixes the DH for both parties, so mixed curves would force a negotiation round trip onto the BLE path and open a downgrade. One curve is in force per protocol version, which `Hello.min_version` and `Hello.max_version` already carry.

Wire fields are therefore named for their role — `identity_pub` and `agreement_pub` — never for the algorithm behind them.

**Both are 65-byte uncompressed SEC-1 points.** `snow` puts the agreement key on the wire in that form and offers no choice, and using the compressed 33-byte encoding for the identity key alone would put two encodings of the same curve in one message — 32 bytes saved against a standing invitation to pass one where the other belongs.

Pinning the encoding is not cosmetic. The Attestation nonce is `BLAKE3(identity_pub || agreement_pub)`, so two implementations that disagree about how a point is encoded compute different nonces and **fail every verification against each other**, with nothing in the error to say why.

## Every signature carries a domain tag

The identity key signs in five places, and until this was written down only one of them said what it was signing for.

| What is signed | Where |
|---|---|
| `"tradr-keybind-v1" \|\| agreement_pub` | `KeyBinding.signature` |
| The peer's `Hello.nonce` | `HelloAck.nonce_signature` |
| The Brokr's challenge nonce | `BrokrRegister.challenge_signature` |
| A revocation record | [docs/07](07-brokr.md#data-model) |
| The self-signed certificate's TBS structure | The QUIC handshake |

**Two of those are "sign these opaque bytes somebody handed me", and a Brokr chooses one of them.** That is a cross-protocol signature reuse attack, and it needs no cryptographic weakness:

```
1. A malicious Brokr opens a Tradr handshake with peer P, claiming to be device D
2. P sends its Hello.nonce
3. D registers with that Brokr, which is the Brokr's normal job
4. The Brokr sends P's Hello.nonce back to D as the registration challenge
5. D signs it, because a challenge is opaque bytes and this one looks like any other
6. The Brokr replays that signature to P and completes the handshake as D
```

[ADR-0005](adr/0005-brokr-is-optional.md) states that a compromised Brokr cannot impersonate anyone. Without domain separation that is false, and the Brokr does not even have to be compromised to try it.

**So every signature the identity key produces is over `tag || message`, where `tag` comes from a closed set:**

```
tradr-keybind-v1     binding the agreement key to the identity key
tradr-hello-v1       proving key possession during a handshake
tradr-brokr-v1       answering a Brokr's registration challenge
tradr-revoke-v1      declaring a device revoked
```

The set is closed rather than a free string so that adding a context is a visible edit in one place, not something any call site can invent.

**The certificate is the exception, and it is safe by structure rather than by tag.** X.509 fixes what gets signed, so no prefix can be added. It does not need one: a `TBSCertificate` is DER and begins with `0x30`, while every tagged message begins with `tradr-`, so no byte string is a valid instance of both. That reasoning is worth keeping written down, because it is the only thing standing between the certificate key and the same attack.

### The token never chooses how it is verified

Step 2 verifies the `id_token` against the profile's JWKS. Three things about that are decisions rather than details, and none was written down until now.

**The accepted algorithms are a field of the Provider Profile, and the token's `alg` header is checked against that set, never used to select anything.** Google's profile lists `RS256` and nothing else.

This is step 1's rule applied a second time. A verifier that reads `alg` and dispatches on it lets the token nominate its own verification method, and the two classic outcomes are well known:

- **`alg: none`.** A token declaring it has no signature, verified by a verifier that believes it.
- **Algorithm confusion.** A token declaring `HS256`, verified by passing the provider's RSA *public* key as an HMAC secret. The public key is public, so anyone can mint a token that passes.

Both are unreachable when the algorithm comes from the profile and the header is only ever compared to it. **`none` is not a value any profile may contain.**

**`kid` selects among the profile's keys and nothing else.** A provider publishes several and rotates them, so the header has to pick one; what it must not do is reach outside the set the profile's `jwks_uri` returned. An unknown `kid` is a rejection, not a lookup.

**A cache miss may trigger at most one refetch, and refetches are rate limited.** Key rotation means an unknown `kid` is sometimes legitimate, so the cache is refreshed and the token retried once. Without a limit that is a denial-of-service primitive: a peer sending tokens with random `kid` values would drive one outbound fetch each, from every device it contacts. **Verification works offline against an existing cache**, which is what makes Tier 0 serverless, so a failed refetch degrades to rejecting that one token rather than to failing every verification.

### How a signature is encoded, and where its nonce comes from

**64 bytes, `r || s`, each a 32-byte big-endian scalar. Never DER.**

`bytes signature` in `proto/` said only "P-256 signature", and DER and raw `r || s` are both exactly that while being incompatible. The deciding reason is not taste:

- **A Brokr verifies `BrokrRegister.challenge_signature`**, and a Brokr is TypeScript. `crypto.subtle.verify` with `ECDSA` takes raw `r || s` and nothing else, so DER would oblige every Brokr to carry an ASN.1 parser to undo an encoding the client chose for no reason.
- **Fixed length makes a length check a real check.** A 64-byte field either is the right size or is rejected before any parsing happens. DER is variable-length, and its parsers are a well-supplied source of vulnerabilities.

`s` is normalized to the lower half of the curve order. `(r, s)` and `(r, n - s)` both verify, so leaving it unnormalized means one signature has two valid spellings; nothing here treats a signature as an identifier today, and permitting that is still free to avoid.

**The ECDSA nonce is derived per RFC 6979, from the private key and the message. It must not come from the `Rng` the KeyStore was given.**

This is the sharpest edge in the whole design. Injecting randomness is what rule B7 asks for everywhere else, and doing it here is fatal: **two ECDSA signatures made under one nonce expose the private key** by elementary algebra, and a test `Rng` is deterministic by construction. An implementation that draws its nonce from the injected source is correct-looking, passes every functional test, and hands its Device Key to anyone who collects two signatures.

RFC 6979 removes the failure mode rather than defending against it: there is no nonce source to get wrong, and signing needs no randomness at all.

## Why there are two encryption layers

| Transport | Secure channel |
|---|---|
| `direct-quic`, `holepunch-quic`, `wifi-direct` | QUIC's TLS 1.3 |
| `ble-gatt`, `relay` | Noise_IK |

QUIC already contains TLS 1.3, so stacking another encryption layer on top would be pure duplication. On QUIC paths TLS is used directly, with **a self-signed certificate whose public key is the Device Key, matched against the pinned value**. No certificate chain and no CA.

- The certificate's `SubjectPublicKeyInfo` is the device's P-256 identity public key
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
- The identifier a Brokr receives is `account_tag = BLAKE3(account_id || salt)`. Neither the issuer nor the `sub` is ever sent
- **A Brokr can**: collect metadata about who communicated with whom and when, observe presence, deny service, and retain relayed ciphertext it cannot decrypt
- **A Brokr cannot**: read content, impersonate anyone, or reach another party's Shares
- Self-hosting means the Brokr's operator is usually the user. The separation still holds because a Brokr is the only component exposed to the internet, making it the most likely thing to be compromised

**T5 — BLE receivers**
- Broadcast EIDs rotate every 15 minutes and are untrackable without the matching secret
- The bootstrap secret, `HKDF(account_id)`, falls to anyone who learns the pair. Routes to obtaining one are limited but not nonexistent. Exchanging an ABK closes the window by ending bootstrap advertising
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
| Device identity and signing | ECDSA P-256 | [ADR-0012](adr/0012-p256-for-device-keys.md) |
| Key agreement | ECDH P-256 | |
| Noise pattern | `Noise_IK_P256_ChaChaPoly_BLAKE2s` | via `snow`, `use-p256` |
| QUIC encryption | TLS 1.3, `TLS_AES_128_GCM_SHA256` | via `rustls` |
| Hashing for integrity and identifiers | BLAKE3 | |
| KDF | HKDF-SHA256 | EID derivation and similar |
| ID token signature | RS256, pinned by the Provider Profile | The token's `alg` header is compared against the profile, never used to select. See [above](#the-token-never-chooses-how-it-is-verified) |
| Randomness | The OS CSPRNG via `getrandom` | |

Post-quantum migration is deferred. Noise offers hybrid patterns such as `Noise_IKhfs`, and `rustls` is gaining X25519MLKEM768; once both are stable, an ADR will record the switch. Priority is low on the judgement that most transferred files do not need secrecy over the horizon that harvest-now-decrypt-later implies.

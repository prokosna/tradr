# 05. Security and identity

## Attestation: the IdP is the root of trust ([ADR-0003](adr/0003-google-attestation-as-trust-root.md))

There is no auth server. A device binds its keys to an account through the OIDC `nonce`, which the provider signs into the ID token:

```
identity key   P-256 ECDSA     agreement key   P-256 ECDH        (ADR-0012)
nonce = base64url(BLAKE3(identity_pub || agreement_pub))         65-byte uncompressed SEC-1 points
id_token = { iss, aud, sub, nonce, iat, exp }  signed by Google
```

### Verification (the seven steps; Critical Module, in `tradr-identity`)

1. Select the Provider Profile by exact `iss` match, and by nothing else. No match → reject.
2. Verify the signature against that profile's JWKS. `alg` must be in the profile's set (Google: RS256 only); the header never selects an algorithm. `kid` selects only among the profile's keys.
3. `aud` must be a single string, and a member of the profile's client-ID set (every platform's ID).
4. The nonce binds the peer's keys (the profile's `nonce_binding`: verbatim or hashed).
5. `iat` is ≤ 30 days old and ≤ 300 s in the future. The two directions give distinct errors (old binding vs. clock skew). `exp` is ignored.
6. `(iss, sub)` equals ours → `SAME_ACCOUNT`; is a linked pair → `LINKED`; otherwise `REJECTED`, or `NEARBY_EPHEMERAL` in ephemeral mode (not built).
7. Signature over `tradr-hello-v1 || our Hello.nonce` (proves current key possession).

- The profile is selected **once** and used for every step.
- Verification is pure and returns `JwksNeeded` instead of fetching. The composition root fetches through `tradr-oidc` and retries.
- **Link entry point**: a separate function runs steps 1-5 plus the key join and returns the **account**. Its policy type has no account fields, so step 6 cannot be expressed there.
- **Key join** (separate from the Attestation): `BLAKE3(Hello.identity_pub)[0..16]` must equal the channel-authenticated DeviceId. This catches a replayed, unaltered Attestation before any tier is computed.

### JWKS cache (`tradr-identity`) and fetch (`tradr-oidc`: Critical Module)

- The cache is bound to one `jwks_uri` at construction. Installing a document from a different URI is refused.
- On an unknown `kid`: at most one refetch, with a **5 min floor** between refetches (the cache decides). A failed fetch leaves the existing keys untouched. The cache never expires and is not persisted.
- The cache is warmed by this device's own sign-in fetch, so an offline device can verify its first peer.
- The fetch must use HTTPS, follow no redirects, and enforce a status check and a size cap. TLS to the provider's host is the only thing that makes a JWKS Google's.

### Expiry, the kept Attestation, revocation

- The kept `attestation` file (0600, atomic write) is re-verified at every start through `finish_sign_in` against the current keys, and reused while `iat` ≤ 21 days old. It carries `sub` and email but grants nothing without the Device Key.
- 24 h silent renewal through a refresh token is **not built**. Android renewal is unmeasured.
- Revocation: revoke the app in Google settings. The device can no longer renew, and peers reject it after 30 days. There is no faster global mechanism at Tier 0.

### OAuth client configuration

No client ID or secret ships. Each deployment registers its own Google Cloud project, which makes each deployment its own trust domain.

```
TRADR_OAUTH_CLIENT_IDS     desktop:<id>,android:<id>,web:<id>   same on every device; every id forms the aud set
TRADR_OAUTH_CLIENT_SECRET  this platform's secret (Desktop has one; Android none)
```

- A build looks up its own label: desktop → `desktop`, **Android → `web`**, because Credential Manager needs the Web client as the server client ID and Google then sets `aud` to the Web ID. An unknown label still joins the `aud` set.
- The GUI bakes the values in at build time (`build.rs`, `option_env!`). The CLI reads them from the environment at run time. A half-set pair is refused at startup.
- The desktop flow is a loopback redirect to `http://127.0.0.1:<port>/callback` with PKCE. Google's Desktop client **requires** its secret for the code exchange (measured).
- **Android uses Credential Manager** (Google ID). It returns an ID token directly; there is no redirect or code. **Google Play Services is required**. Custom schemes and loopback are blocked for Android clients, and shipping the Desktop secret in an APK is refused.
- Each Android package/certificate pair (debug, release) needs its own Android client registration.
- Profiles (issuer, JWKS URI, algorithms, nonce binding) are compiled in. Only the client is configuration. `tradr-oidc` never sees a profile type, and takes plain arguments.

### Identity = `(iss, sub)` ([ADR-0010](adr/0010-identity-is-the-issuer-subject-pair.md))

`account_id = iss || 0x00 || sub`. Email is display-only. Everything derived from account identity uses `account_id`: the Brokr `account_tag`, the bootstrap EID secret, and link records.

### What this defends

Defended: forged tokens, tokens minted with our public client ID (wrong `sub`), stolen Attestations (nonce mismatch), replay (`Hello.nonce` signature).
**Not defended**: Google itself acting maliciously; a takeover of the user's Google account. The Fingerprint mitigates both when a Link is made.

## Fingerprint

`BLAKE3("tradr-fp-v1" || identity_pub || agreement_pub)`. Take the first 132 bits, big-endian, as 12 × 11-bit indices into the BIP-39 English list (vendored, SHA-256 `2f5eed53…4dbda`, MIT; any 4-letter prefix is unique). Shown in 3 rows of 4. It is compared when a Link is made. Nothing records that it was compared, and a later key change is not refused.

## Key storage

`KeyStore` exposes `sign(DomainTag, msg)`, `agree` and `backing()`, and **never key bytes** ([ADR-0011](adr/0011-keystore-exposes-operations.md)). It is `Send + Sync` because rustls signs from many threads.

| OS | Today | Intended (unscheduled) |
|---|---|---|
| Android, macOS, Windows | 0600 file in app data, **software** | Keystore/StrongBox, Secure Enclave, CNG/TPM |
| Linux | Secret Service, else a 0600 file | — |

- `backing()` must never overstate itself (Critical Module). Settings shows it.
- **Linux ladder** (`tradr-secrets` for I/O, `tradr-identity` for policy): it is searched on load. An absent rung is skipped. A failed rung, such as a locked collection, stops the search **only if no lower rung holds the key**: never generate a key over a rung that failed. A key is never moved between rungs. Never unlock a collection (the D-Bus prompt blocks forever when headless). The kernel keyring is not a rung, because it does not survive a reboot.
- The ladder guarantees availability, not at-rest security. The file rung is plaintext, and full-disk encryption is the OS's job.
- Link Secrets and the ABK are stored on the rung the Device Key selected. The rung is chosen once, at open.
- Key generation is a Critical Module: a predictable key is a derivable key.

### Signatures

- Raw 64-byte `r || s` with low-`s` normalization, never DER (the Brokr verifies with WebCrypto).
- **ECDSA nonces follow RFC 6979, never the injected `Rng`**: a reused nonce leaks the key.
- Every identity-key signature is domain-separated by a closed `DomainTag` set:

| Tag | Use |
|---|---|
| `tradr-keybind-v1` | agreement key binding |
| `tradr-hello-v1` | handshake possession proof |
| `tradr-brokr-v1` | Brokr challenge |
| `tradr-revoke-v1` | revocation record |
| `tradr-deferred-v1` | Deferred Delivery manifest |
| `CertificateTbs` | requires prefix `0x30` (DER) |
| `TlsCertificateVerify` | requires 64 × `0x20` + `TLS 1.3, ` |

The last two do not prepend anything. Instead they **require** the message to start with those bytes, so no caller can obtain an untagged signature over bytes it chose.

## Secure channels

| Transport | Channel |
|---|---|
| QUIC paths | TLS 1.3 (`TLS_AES_128_GCM_SHA256`, rustls), mutual, self-signed |
| `ble-gatt` | `Noise_XX_P256_ChaChaPoly_BLAKE2s` ([ADR-0020](adr/0020-noise-xx-for-ble-gatt.md)) |
| `relay` | `Noise_IK` (provisional, not built) |

**QUIC certificate**: the SPKI is the identity key. Subject, issuer and serial are constants; validity never expires; there are no extensions. Identity lives only in the SPKI.
- The **dialler** pins: with `Device(id)` it closes on a mismatch; with `Unpinned` it learns the id. These must never collapse into one code path, and a missing expectation is never replaced by a default.
- The **listener** only checks that the certificate is a well-formed P-256 certificate. Whether the peer is welcome is decided by `Hello`.

**Noise**:
- `snow` with `use-p256`. `use-curve25519` is enabled only to compile. `use-getrandom` is **off**, so the injected `Rng` is the only RNG.
- The resolver gives the KeyStore-backed `Dh` on the **first** `resolve_dh` call (static) and software on the second (ephemeral).
- Message sizes 65 / 299 / 234 B. Messages 2 and 3 carry the 137-byte identity join (`identity_pub`, KeyBinding signature, `not_after`). The covered agreement key is not sent; it is rebuilt from the Noise-authenticated static key.
- A record's position in the stream is its nonce. A transmit lock spans encrypt+send; the session lock is never held across I/O. An authentication failure closes the channel as `AuthenticationFailed`.
- Keep local errors (KeyStore, Rng) distinct from a peer's bad message.
- XX reveals the responder's static key to an active prober. Gating message 1 on an ABK or Link Secret is deferred.

## Trust Tiers

| | SAME_ACCOUNT | LINKED | NEARBY_EPHEMERAL (not built) |
|---|---|---|---|
| Receive | auto-accept | auto-accept | confirm + PIN |
| Browse / write folder | yes | only if the link has `full_access` ([ADR-0024](adr/0024-one-folder-per-device-full-access.md)) | no |

## Threat model (summary)

| Adversary | Gets | Cannot |
|---|---|---|
| LAN party | Device ID, name (hostname), platform, caps; can spoof mDNS | pass Attestation |
| Passive path | IPs, timing, sizes | content |
| Active path | MITM on a TOFU first contact only (Static Peer) | complete a handshake without the key or KeyBinding |
| Brokr | metadata, presence, ciphertext, DoS | read content, impersonate (never verifies Attestations; sees only `account_tag`) |
| BLE listener | EIDs (rotate every 15 min); bootstrap presence if it knows `account_id` | track across windows |
| Linked peer | everything in the folder it is allowed to access | other devices' folders |
| Physical | keys in the file rung | — |

Not defended: traffic analysis, LAN presence, a trusted peer writing junk, side channels, malware on the device.

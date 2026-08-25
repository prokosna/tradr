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

Every device carries the full set of its deployment's client IDs and step 3 accepts membership in it. Those IDs are configuration rather than shipped values -- see [below](#oauth-client-configuration) -- and one string carries them to every device.

Adding a platform means adding its client ID to that one string. **Devices that predate the new platform accept it as soon as they are restarted with the updated configuration**, since an ID whose platform label they do not recognise still joins the `aud` set. When the set was compiled in, the same change required a rebuild and older builds rejected the new platform outright.

### OAuth client configuration

**No client ID and no client secret ship with this software.** Both are configuration, supplied at runtime, and every deployment registers its own Google Cloud project. Tradr is set up by the person running it, not distributed with credentials of its own.

```
TRADR_OAUTH_CLIENT_IDS      desktop:<id>,android:<id>   the same string on every device
TRADR_OAUTH_CLIENT_SECRET   this platform's secret; a Desktop client has one, an Android client none
```

**The first is one value, identical across the deployment, and every device derives the rest from it.** A build knows which platform it is, so it looks itself up in the list to find the client it authenticates as, and takes every ID in the list as the `aud` set it accepts. Nothing is written twice and nothing differs per device but the secret.

**That is what makes the incomplete list detectable.** An earlier draft had each device configured separately with its own ID and its own audience set, which put the same value in two places and made a forgotten entry surface only at the first connection between two devices, as a rejected peer. Now a deployment that lists `desktop:` and forgets `android:` starts its desktop devices correctly -- as a desktop-only deployment, which is what it is -- and **an Android device refuses to start at all**, saying that this build is Android and the list names no Android client. The mistake is reported where it was made.

**An entry naming a platform this build does not know contributes its ID to the `aud` set and nothing else.** Adding iOS later means adding `ios:<id>` to the one string, and existing desktop and Android devices then accept iOS peers without being rebuilt. Rejecting the whole list instead would make adding a platform break every device that predates it, which is the cost the compiled-in design used to carry.

**The secret stays out of that list.** Putting each platform's secret beside its ID would be the tidier string, and would place the Desktop client's secret in the environment of every Android device, which never uses it. A value not present cannot leak.

**Each deployment is therefore its own trust domain**, unable to authenticate against anyone else's. That was previously a consequence of overriding a shipped default; it is now the only mode, and it is the point rather than a side effect.

**Why nothing ships.** Committing a working client so that a clone builds and runs is the obvious convenience, and it was the earlier decision here. Three things cost more than it is worth:

- **A shared client ID is a shared rate limit.** rclone ships one for Google Drive and is retiring it during 2026 for exactly this reason, telling every user to register their own instead. That is this design's risk arriving on someone else's schedule.
- **A published secret is a single revocation point.** `google_oauth_client_id, google_oauth_client_secret` is a GitHub secret-scanning pattern in the partner programme, so pushing one to a public repository is reported to Google. If Google revokes, every deployment's sign-in stops at once.
- **A published client is a brandable consent screen.** The measurements below show the secret gates the exchange step, so publishing it lets a third party complete an OAuth flow under this application's name.

Setting up a project is a few minutes in Google Cloud Console, and it is a step the person running an OSS tool takes once.

**A Desktop client still needs its secret, and that is worth knowing before registering one.**

**Google requires it, and this was settled by running the flow.** An earlier probe posting a *fabricated* code proved nothing: `client_secret is missing` arrives as `invalid_request`, which is parameter validation reached before any code is looked up, so it measured the endpoint's handling of a code Google had never issued. The real flow, on 2026-08-24, with a genuine code obtained under `code_challenge_method=S256`:

| Attempt | Result |
|---|---|
| Exchange with **no** `client_secret` | `invalid_request` -- *client_secret is missing.* |
| Exchange **with** it, reusing the same code | a valid `id_token` |

The same request shape, with `code_verifier` present and a code Google never issued, gives that description verbatim -- so the name of the cause comes from Google rather than from inference.

**The second row is what makes the first conclusive, and it did more than it was designed to.** It was included expecting failure -- an authorization code is single use -- so that a refusal could not be mistaken for a spent code. It succeeded instead, which means **the secretless attempt never consumed the code**: Google rejected it before reaching the grant at all. So the refusal is about the secret and nothing else.

RFC 8252 section 8.5 and RFC 7636 make a native app a public client whose PKCE exchange needs no client authentication, and RFC 8252 also permits an authorization server to issue credentials to native apps. Google's Desktop client type does, and requires them.

**The value is checked, not merely required to be present.** Three states, three answers:

| `client_secret` sent | Response |
|---|---|
| omitted | `invalid_request` -- *client_secret is missing.* |
| any wrong value, including the real one with one character changed | `invalid_client` -- *The provided client secret is invalid.* |
| the real value | `invalid_grant` -- *Malformed auth code*, so client authentication passed |

**So it is not true that this value guards nothing.** What it gates is the exchange step: a third party holding only the client id can raise a consent screen bearing this application's name, because the authorization request needs no secret, but cannot turn the resulting code into tokens. Publishing the secret removes that last step. **PKCE protects something different** -- a code stolen on the user's own machine, by a local process racing the loopback port -- and it goes on doing so whether or not the secret is public.

The reason to publish it anyway is Google's own: an installed application's secret is extractable from any shipped binary, so withholding it from the repository buys a delay rather than a defence, while costing every person who clones the repository a working sign-in. `TRADR_OAUTH_CLIENT_ID` and `TRADR_OAUTH_CLIENT_SECRET` exist so that anyone preferring their own Google project can use one. **That is a judgement about cost, not a claim that nothing is being given away**, and the earlier wording here said otherwise.

**The redirect uri is the loopback IP literal, and that too was measured.** Three authorization requests on 2026-08-24, differing only in `redirect_uri`:

| `redirect_uri` | Response |
|---|---|
| `http://127.0.0.1:8731/callback` | accepted |
| `http://localhost:8731/callback` | accepted |
| `http://evil.example/callback` | `redirect_uri_mismatch` |

The third row is what makes the first two mean anything: the check is real, and loopback is what it exempts. An installed client's registered `redirect_uris` are not an exhaustive list -- RFC 8252 section 7.3's loopback rule is, and any port is accepted. **The literal is chosen over the name because a name resolves through the host's own resolver**, and what it resolves to is not this process's decision.

**Both variables are set together or neither is.** An ID without its secret, or a secret without its ID, is a pair Google's token endpoint rejects, and the failure surfaces as a refused exchange. Refusing the half-set configuration at startup puts the message where the mistake was made. An Android client is the exception: it has no secret, and none is expected.

**Profiles remain compiled in; only the client is configured.** The issuer, the JWKS URI, the nonce binding and the permitted algorithms are a trust decision and are not settings. What a deployer supplies is which OAuth client speaks for them, never how a peer's token is verified.

### Provider profiles

Everything a provider brings lives in one value -- what a peer's token is verified against, and what this device needs to obtain a token of its own. Nothing else in the codebase names a provider.

| Field | Why it cannot be assumed |
|---|---|
| `issuer` | Compared exactly against `iss`. Selecting the profile is step 1 |
| `jwks_uri` | Moves independently of the issuer string. D1 of the Change Drill is this field |
| `authorization_uri`, `token_uri` | Discovered once from `/.well-known/openid-configuration`, then pinned |
| `client_ids` | One per platform, per provider. See [above](#why-step-3-compares-against-a-set) |
| `client_id`, `client_secret` | **Configuration, not shipped.** Which OAuth client speaks for this deployment. See [below](#oauth-client-configuration) |
| `nonce_binding` | Verbatim or hashed. A provider that stores a digest of the nonce fails step 4 outright under the wrong assumption |
| `algorithms` | The signature algorithms this provider's tokens may use. The token's `alg` header is compared against this and never used to select. See [above](#the-token-never-chooses-how-it-is-verified) |
| `renewal` | Whether a fresh ID token can be minted without user interaction, and on what terms |

The last two are why **adding a provider is not a URL swap**, and why they are fields rather than an assumption discovered during a rewrite. `renewal` in particular carries the design's weight: the 24-hour silent renewal below assumes a refresh token and a `prompt=none` path. A provider offering neither shifts that account's whole revocation story, and the profile is where that becomes visible.

**A credential sits in this value at runtime, and that is deliberate.** Splitting it into a verification half and an authentication half would put a provider's name in two places, and Change Drill D2 budgets two files for adding a provider -- one definition and one registration. What keeps that budget is that **`tradr-oidc` never sees this type**: it may not depend on `tradr-identity` at all (`ci/layer-deps.sh`), so the flow takes a uri, a client id and a secret as plain arguments and names no provider. A driver that cannot name a provider cannot acquire a second place to name one.

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
| Linux | Secret Service over D-Bus, then a `0600` file | No — the last resort is software only |

**Falling short of hardware backing on Linux is stated plainly.** Settings displays the storage method in use and says so explicitly when it has fallen back to a file. Headless environments without a running Secret Service get a warning.

### A locked Secret Service is a rung that fails, not a rung that is absent

Never unlock a collection to reach a key. An unlock is an interactive prompt, and a prompt with nobody to answer it — a headless box, an ssh session, a login whose desktop has gone — **does not fail, it waits**, measured here as a process that never returns from its own startup. A key store opened during startup must not be able to do that: the window never appears and there is nothing on screen to read.

So the rung is built without unlocking anything, and the distinction [descending the ladder](#descending-the-linux-ladder) already draws decides the rest. **A Secret Service that answers on the bus is present**, so the rung joins the ladder. **A collection that is locked has not said whether it holds this device's key**, so reading it is an error and the search stops, exactly as any other failed read does.

Descending past it instead would be the worse answer, and it is the tempting one, because it keeps a headless machine working. It also mints a second Device Key over one that may be sitting in the locked collection, and that failure is silent while this one is a sentence the user can act on.

### Why the kernel keyring is not a rung

The ladder listed the kernel keyring between the Secret Service and the file until it was measured. **A kernel keyring has no backing store**: it is kernel memory, there is no file behind it anywhere, and `persistent_keyring_expiry` bounds even the persistent keyring at three days without surviving a reboot at all.

That makes it **less durable than the rung below it**, which inverts the whole point of an ordered ladder. And the machine where it would be chosen is precisely the one that cannot afford it: the keyring is reached only when no Secret Service answers, which is a headless box, where a reboot would find the keyring empty, the file never written, and the ladder concluding that this device has no key. It would mint a second Device Key on every reboot, losing every link, and nothing would fail.

What it would have bought does not pay for that. Against another process running as the same user — the only attacker a `0600` file in a `0700` directory does not already stop — a keyring is no defence either, since that process can read this one's memory.

Linux therefore has two rungs, and a device with no Secret Service says plainly that its key is in a file.

### Descending the Linux ladder

That ladder is a **search on load, not only a preference on write**. A device that stored its key in a `0600` file because no Secret Service was running must find that same key the day one is running. Reading only the highest available rung would find it empty, and the device would generate a second Device Key and present to its own peers as a device none of them has ever seen.

**A key found on a lower rung is not moved to a higher one.** Moving it means deleting it from the rung being vacated, and a move whose delete fails leaves the key readable from the weaker of the two while `backing()` names the stronger. That is the overstatement [the KeyStore boundary](#the-keystore-boundary) exists to prevent, arriving by a different route. `backing()` names the rung the key is actually on, and a device that once fell back says so for as long as that remains true.

**A rung that is absent is skipped; a rung that is present and then fails stops the search.** The two are separated when a rung is constructed rather than when it is read: a Secret Service that cannot be reached at all is never on the ladder, and one that is on it and then errors is not treated as an empty slot, because a read that failed and a slot that is empty are indistinguishable in the answer while only one of them may lead to generating a key. A headless box with no D-Bus session descends to the keyring and says so; a D-Bus session that is running and refuses is an error the user is shown, not a new identity.

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

The identity key signs in six places, and until this was written down only one of them said what it was signing for.

| What is signed | Where |
|---|---|
| `"tradr-keybind-v1" \|\| agreement_pub` | `KeyBinding.signature` |
| The peer's `Hello.nonce` | `HelloAck.nonce_signature` |
| The Brokr's challenge nonce | `BrokrRegister.challenge_signature` |
| A revocation record | [docs/07](07-brokr.md#data-model) |
| The self-signed certificate's TBS structure | The QUIC handshake |
| TLS 1.3's `CertificateVerify` content | The QUIC handshake |

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

### Two contexts admit no prefix, and the structure is checked rather than argued

The QUIC handshake signs bytes whose shape somebody else fixed, so no tag can go in front of them. There are two such contexts, not one.

- **The self-signed certificate's `TBSCertificate`.** X.509 fixes the signed structure, and a prefix would make the certificate unparseable.
- **TLS 1.3's `CertificateVerify`.** RFC 8446 fixes the content: sixty-four `0x20` bytes, then `TLS 1.3, server CertificateVerify` or `TLS 1.3, client CertificateVerify`, then a `0x00`, then the transcript hash. `rustls` assembles that buffer itself and hands it to the signer unhashed, so what the identity key signs there is not this design's to choose. **This row was missing until now and it is the unavoidable one**: mutual TLS on the QUIC paths does not happen without it.

Neither needs a tag, because each already begins with a byte no other context can produce:

| What is signed | First byte |
|---|---|
| Any of the four tagged messages | `0x74`, the `t` of `tradr-` |
| `TBSCertificate` | `0x30`, DER's SEQUENCE |
| `CertificateVerify` | `0x20`, the first of sixty-four spaces |

**That was prose, and prose is not an instrument.** `KeyStore::sign` takes a `DomainTag` from a closed set, and the set could not say "these bytes carry their own separation", so an implementation reaching the QUIC handshake had two ways out and both are worse than the attack: an escape hatch on the closed set, which hands any caller an untagged signature over bytes the caller chose, or signing outside `KeyStore` altogether, which forfeits hardware backing and with it [ADR-0011](adr/0011-keystore-exposes-operations.md).

**So a `DomainTag` names a separation, and a separation is one of two things**: bytes prepended to the message before signing, or bytes the message must *already* begin with, where signing is refused when it does not. `CertificateTbs` and `TlsCertificateVerify` join the closed set as the second kind, requiring `0x30` and the sixty-four spaces followed by `TLS 1.3, ` respectively. The disjointness above stops being an argument and becomes a refusal: a caller handing `CertificateTbs` a message that begins with `tradr-` gets an error rather than a signature.

**One tag covers both spellings of `CertificateVerify`.** The client and server context strings differ, but RFC 8446 already separates them from each other, and both are the same act — a device proving possession of the key in the certificate it just sent.

**TLS chooses its own signature encoding, and that is not a contradiction of the next section.** `r || s` is what Tradr's own wire fields carry, for the reasons given there; a `CertificateVerify` and an X.509 signature field are DER by their own specifications. The conversion belongs to the Layer 3 adapter that implements `rustls`'s signer against `KeyStore`, which is the same place [ADR-0011](adr/0011-keystore-exposes-operations.md) already puts the external signer.

### The token never chooses how it is verified

Step 2 verifies the `id_token` against the profile's JWKS. Three things about that are decisions rather than details, and none was written down until now.

**The accepted algorithms are a field of the Provider Profile, and the token's `alg` header is checked against that set, never used to select anything.** Google's profile lists `RS256` and nothing else.

This is step 1's rule applied a second time. A verifier that reads `alg` and dispatches on it lets the token nominate its own verification method, and the two classic outcomes are well known:

- **`alg: none`.** A token declaring it has no signature, verified by a verifier that believes it.
- **Algorithm confusion.** A token declaring `HS256`, verified by passing the provider's RSA *public* key as an HMAC secret. The public key is public, so anyone can mint a token that passes.

Both are unreachable when the algorithm comes from the profile and the header is only ever compared to it. **`none` is not a value any profile may contain.**

**`aud` is a single string, and a token carrying an array is rejected.** RFC 7519 permits either, and the providers this design serves send one client id. Accepting an array would require a policy for which member counts, and every such policy is a place for a token to slip a value past a check that was written for the other shape. One accepted spelling means the comparison in step 3 has one meaning.

**`kid` selects among the profile's keys and nothing else.** A provider publishes several and rotates them, so the header has to pick one; what it must not do is reach outside the set the profile's `jwks_uri` returned. An unknown `kid` is a rejection, not a lookup.

**A cache miss may trigger at most one refetch, and refetches are rate limited.** Key rotation means an unknown `kid` is sometimes legitimate, so the cache is refreshed and the token retried once. Without a limit that is a denial-of-service primitive: a peer sending tokens with random `kid` values would drive one outbound fetch each, from every device it contacts. **Verification works offline against an existing cache**, which is what makes Tier 0 serverless, so a failed refetch degrades to rejecting that one token rather than to failing every verification.

**The cache decides; the composition root fetches.** The limit is a property of the cache's own state rather than of the code calling it: asking the cache whether a refetch is warranted *is* the act of spending that budget, so a caller that asks twice is refused the second time however its loop happens to be written. Putting the rule anywhere else makes it a rule about callers, and there will be more than one caller. This also keeps verification synchronous and free of any HTTP client, and leaves the single `await` where the process already holds its I/O.

**The floor between refetches is five minutes.** That bounds a peer sending random `kid` values to twelve outbound requests an hour from each device it reaches, while still picking up a legitimate rotation within one -- and providers publish a new key well before signing with it, so five minutes costs nothing against the rotation this exists to tolerate. A device whose first fetch fails is then unable to verify anything for five minutes, which is the same limit doing its job: the tokens it would have verified came from peers, and rejecting them is the safe direction.

**The cache does not expire.** An old cache is a working cache, since offline verification is the property that keeps Tier 0 serverless, and a key does not become dangerous by ageing. A fetch that fails, or returns a document that does not parse, therefore leaves the existing keys exactly as they were: a refetch can only ever add to what a device can verify, never take it away.

**A cache is bound to a `jwks_uri` when it is built.** A JWKS document names no issuer, so nothing in the bytes could catch a document from one provider being installed into another provider's cache. Binding the two at construction removes the chance to pair them wrongly rather than detecting it afterwards.

### Who runs the seven steps

**The sequence lives in `tradr-identity`, not in whatever crate binds the app to its shell.** Every piece of it -- profile selection, signature verification, the audience set, the nonce binding, staleness, the tier -- is code in that crate, and until now nothing joined them, so the join would have landed in the composition root by default. [ADR-0001](adr/0001-tauri-2-as-app-shell.md) records conditions under which the shell is dropped and Change Drill D9 budgets for swapping the crate that names it. **The order of these steps is security design and not wiring**, and leaving it in the crate D9 discards means whoever writes the next binding re-derives it from this document, correctly, under time pressure.

**The fetch still stays outside, by the same device [DCR-022](../STATE.md) used for the cache.** Verification returns "this token names a `kid` I do not hold and the budget allows one fetch of *this* uri" instead of fetching; the caller fetches, installs, and calls again. So the sequence is synchronous and pure, `tradr-identity` names no HTTP client, and the single `await` remains in the composition root where the process already holds its I/O.

**The profile is selected once and used for every step that depends on one.** Step 2 needs the profile to know which algorithms are permitted and which keys to trust; steps 3, 4 and 5 need it for the client id set and the nonce binding. Two independent selections is the failure this rules out: a signature checked under one provider's rules while another provider's `nonce_binding` and `client_ids` decide what the claims mean. Step 1's rule is that a token may not nominate its own verification rules, and **a token that gets the rules applied to it chosen twice has done exactly that**, whichever way each selection went.

**Selecting the profile reads `iss` before any signature has been checked, and that is not a contradiction.** Verification does not alter the payload, so the `iss` read in step 1 is the `iss` the signature covers; if it were forged, the profile it selects carries keys that will not verify the token, and step 2 rejects it. What step 1 must never do is read anything *other* than `iss` -- a JWKS host, a `kid`, an `alg` -- to decide which rules apply.

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
- **Only the dialling side pins, and the sentence above is written from its point of view.** A listener cannot pin: it is handed the peer's certificate and nothing else, because it does not know who is dialling it until they arrive. So the two directions do different work. **The dialling side** compares the certificate's public key against the Device ID it meant to reach, and closes on a mismatch. **The listening side** checks only that the certificate is a well-formed P-256 certificate, learns the Device ID from it, and defers every question of whether that device is welcome to the Attestation exchange in `Hello` — which is where it already was: [step 6](#what-a-verifier-does) compares `(iss, sub)` and assigns a Trust Tier, and that happens after a channel exists. Mutual TLS still proves current key possession in both directions, which is what it is for. What it does not do, and never did, is decide whether a peer is welcome
- **The subject and issuer are a constant, identical on every device.** Putting the Device ID in the common name is the obvious move and it is wrong: it gives a device's identity a second place to live, and a verifier reading the wrong one is a defect that the most likely test — a device verifying itself, where both fields agree — cannot expose. The `SubjectPublicKeyInfo` is the only place identity appears, and a constant name is what keeps that literally true
- **The validity window is fixed and never expires.** Nothing validates this certificate as a chain, so a window is a field nothing reads — and a narrow one is a field nothing reads until it silently begins refusing connections. A Device Key's lifetime is already governed by the staleness rule in [step 5](#what-a-verifier-does), against a different clock and a different mechanism. Two expiry dates that can disagree is worse than one that is never consulted, and it keeps certificate construction free of a `Clock`
- **The serial number is a constant, for the reason the name is.** A serial derived from the Device ID hands identity the second home the constant subject was just chosen to deny, and a random one puts an `Rng` into a construction that decision otherwise keeps free of one. RFC 5280 requires serial numbers to be unique per issuer so that a chain validator can name one certificate among many; nothing here validates a chain, so nothing here reads it.
- **The certificate carries no extensions.** It is a v3 certificate, because that is the version a TLS peer expects to parse, but every extension a CA would add — `basicConstraints`, `keyUsage`, a subject alternative name — is there to tell a chain validator something, and there is no chain validator. A subject alternative name would do worse than sit unread: it is the second place identity could live, which is what the constant subject exists to prevent.

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

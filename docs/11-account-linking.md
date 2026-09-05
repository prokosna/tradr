# 11. Account linking



Enabling communication with another Google account. **Both sides must approve explicitly**; a one-sided invitation establishes nothing.

### Tier 0 — linking in person, no Brokr

```
   Alice's device                        Bob's device
        |                                     |
   [start linking]                            |
        |                                     |
   show a QR code ----------------------> [scan the QR]
     {                                        |
       v: 1,                                  |
       invite_id: ...,      <- 16 bytes       |
       sub: "1048...",     <- Alice's sub     |
       identity_pub: ...,  <- Alice's key     |
       agreement_pub: ...,                    |
       attestation: ...,   <- Google-signed   |
       half_secret: ...,   <- 16 random bytes |
       expires: ...        <- 5 minutes       |
     }                                        |
        |                                     |
        |                         verify the Attestation
        |                         display the Fingerprint
        |                                     |
        |<---- reply over BLE or LAN ---------|
        |        {                            |
        |          invite_id: ...,            |
        |          identity_pub: ...,         |
        |          agreement_pub: ...,        |
        |          attestation: ...,          |
        |          half_secret: ...           |
        |        }                            |
        |                                     |
  verify the Attestation                      |
  display the Fingerprint                     |
        |                                     |
  [both compare Fingerprints and approve]     |
        |                                     |
  Link Secret = BLAKE3::derive_key("tradr-link-v1", half_A || half_B)
  link_id     = BLAKE3(Link Secret)[0..16]
        |                                     |
  both store the Link locally                 |
```

Where a QR will not work — a screen out of view, or distance — the same JSON travels as a base64 **invite blob** pasted into a chat. That channel cannot be trusted, so **Fingerprint verification becomes mandatory**, with the UI prompting both parties to read it aloud.

Contributing half the randomness each stops either side deciding the secret alone. Photographing the QR does not yield the Link Secret.

### What the Invite carries, and how it travels

**The block the diagram draws is a sketch of a payload and not a definition of one**, the fourth in this document read as a specification, after the `link_id` that rendered as a ULID, the reply that omitted `agreement_pub`, and the Link record whose three fields nothing could write. DCR-071 settles it, and one of its lines is the defect DCR-068 had already removed from the reply.

| Field | Wire | Native | On disagreement |
|---|---|---|---|
| `invite_id` | `bytes`, 16 | `InviteId` | **Refuse.** The reply names it, so an invite whose id cannot be read is one no reply could answer |
| `identity_pub`, `agreement_pub` | `bytes`, 65 each | `PublicKeyPoint` | **Refuse.** The first of the two is the pin -- Bob dials `BLAKE3(identity_pub)[0..16]` -- and step 3's nonce binding reads both |
| `attestation.id_token` | `string` | `String`, unverified | **Refuse when absent.** It is what Bob verifies before he answers, and the same empty-string rule a `LinkReply` carries: proto3 cannot tell an absent string from an empty one |
| `attestation.issuer`, `attestation.issued_at` | `string`, `int64` | **absent** | **Dropped**, as in a `Hello` and a `LinkReply`: the token's own `iss` and `iat` are the authoritative values |
| `half_secret` | `bytes`, 16 | `HalfSecret` | **Refuse.** It is half of the Link Secret |
| `expires_at` | `int64` | `UnixTime` | **Refuse when zero.** The diagram's `expires` named no shape; it is seconds since the Unix epoch, for DCR-069's reason for `created_at` -- `UnixTime` is the only time this workspace has, and a second representation is a second thing that can disagree |
| `display_name` | `string` | `DisplayName`, dropped when invalid | **Drop it and carry on**, exactly as in a `LinkReply`. **The sketch omitted it and the reply carries one**, so without it Bob decides whether to answer a stranger from a Fingerprint alone. It decorates and decides nothing |
| `sub` | -- | -- | **Not carried at all.** DCR-068's argument, unchanged: it is a wire copy of a claim already inside the token, and two answers to "which account is this" is the defect the key join exists to prevent |
| `device_id`, `platform`, `capabilities` | `DeviceInfo` fields | **absent** | **Dropped.** The Device ID is recomputed from `identity_pub` and never read off the payload, and nothing here negotiates a capability or reads a platform |

#### The Invite is the only linking payload that is never framed, and that decides its encoding

**It carries a version byte, and the three framed messages do not need one.** A type byte says what a framed message is; an invite has no frame, so it has no type byte and no place in [docs/04](04-protocol.md#the-type-byte)'s registry. **A version field inside the payload could only be read after deciding the bytes are protobuf**, which is the decision the version exists to make -- so it is one byte in front of the body, `0x01`, and a blob opening with anything else is refused as an invite this build cannot read. That is a different sentence from a malformed one, and it is the one a user can act on.

**The body is protobuf and not the JSON the diagram draws.** protobuf is what this workspace encodes with, [Change Drill D5](../CLAUDE.md#c-flexibility-against-external-change--the-change-drill) confines it to one crate, and the field-refusal discipline `hello.rs` established applies here unchanged rather than being invented a second time in a second format. It is also about a third smaller, which matters for the reason immediately below and nowhere else in this design.

**The blob is unpadded base64url**, the encoding `attestation.rs`, `jwks.rs`, `id_token.rs` and the mDNS TXT records already use. **The QR encodes exactly that string and nothing else**: one payload and one parser, because the channel a person happened to choose is not a second format.

#### Why an invite's size is a design constraint here and nowhere else

**A blob is roughly 1.7 KB and almost all of it is one field.** A Google `id_token` runs to about 1 KB; everything else the invite carries is under 200 bytes. **QR byte mode holds 2953 bytes at its lowest error-correction level**, so a real invite fits, and it fits at around 137x137 modules -- a QR a phone camera reads off a bright screen, and not much margin beyond that.

- **Generating an invite never fails on size.** The field that decides the size is a token an identity provider issued, which this design does not control, and refusing to link because Google issued a long token is a failure the user cannot act on.
- **The paste channel is therefore not only a convenience.** The diagram introduces it for a screen out of view or a distance; it is also what an invite too large for a QR must use, and the interface says which of the two it is faced with rather than rendering a QR that will not scan.
- **Parsing refuses a blob longer than 4096 characters, before decoding it.** It is an untrusted paste, so it needs a bound; the cap sits well above any invite this design produces and well below anything a parser should spend time on.

#### What an invite's expiry decides, and what it does not

**The five minutes are enforced by the inviter and merely advised to the reader.** Alice's device closes its window five minutes after showing the QR and refuses a reply arriving after that -- the single-use window above, on the side that has the authority to enforce it. `expires_at` lets Bob decline to answer an invite that is certainly dead, and it decides nothing else.

**So the reader's check takes its clock-skew allowance from the caller rather than baking one in**, the shape `AttestationPolicy` already gives every limit it applies. Nothing else in this design catches a device whose clock runs fast: [docs/05](05-security.md) step 5's forward allowance is applied by a verifier to a token's `iat`, so a reader ten minutes ahead finds every Attestation fine and every fresh invite expired. **A too-generous allowance costs nothing here**, because the most it can do is let Bob answer an invite that Alice will refuse.


#### The same expiry bounds the wait on a person, and there is no second number

**Nothing else in this exchange has a deadline, and without one both sides wait forever** (DCR-075). The inviter's approval reaches a person who may put the phone down mid-comparison; the replier is then blocked reading an answer that will never be written, holding a connection open behind it. **The bound is the invite's own `expires_at` and not a timeout invented beside it**, because a second number is a second thing that can disagree with the first, and this one is already on the wire — both sides hold it, so both arrive at the same instant with nothing negotiated to get there.

**A wait that reaches it declines with `InviteExpired`, which is true rather than merely convenient.** What ended the exchange is the window closing: the user did not decline, verification did not fail, and the invite is exactly what expired. So no fourth decline reason is invented. **The contrast with a failed store is what makes the choice a decision rather than a default**: a store that fails is none of the three reasons and declines with none, while a window that closes is one of them exactly.

**The replier stops after the inviter, by the allowance it already grants.** Its read is bounded at `expires_at` plus the same caller-supplied clock-skew allowance its expiry check above takes, so an approval the inviter writes just inside its own window is still read rather than raced against a deadline that fired first. The asymmetry is the point: **the side that decides must be the side whose deadline comes first**, or the exchange can end with one side linked and the other not for no reason but a tie.

**The cost is that a reply arriving late in the window leaves little time to approve**, and that is the honest consequence of one deadline rather than two. It is also the recoverable one: what the interface says is that the invite expired, and showing a fresh one takes a moment. A separate approval timeout would buy that time and pay for it with a second clock nothing displays.

### Deriving the Link Secret

**This line read `HKDF(half_A || half_B, "tradr-link-v1")` and named no hash, no salt and no output length**, which is three decisions left to whoever implemented it first. DCR-066 settles them as BLAKE3's own key derivation:

```
Link Secret = BLAKE3::derive_key(context = "tradr-link-v1",
                                 key_material = half_A || half_B)   32 bytes
link_id     = BLAKE3(Link Secret)[0..16]
```

**`derive_key` is a KDF with a context string, which is the role HKDF's `info` was playing here**, so nothing about the construction changes — only the primitive that performs it. Every other derived value in this design is BLAKE3: the Device ID, the Content Hash, the Attestation nonce, the Agreement Key Tag, the EIDs. Adding HMAC-SHA256 for one value would put a second hash family in the trust path to save nothing.

**"The EIDs" was not true when this sentence was written, and [ADR-0018](adr/0018-blake3-derive-key-for-eids.md) is what made it so.** [docs/05](05-security.md#algorithms)'s Algorithms table said `HKDF-SHA256` for EID derivation at the time, so the list this paragraph reasons from contained one item that contradicted it -- found in M7, by the first reading that had to compute an EID. The reasoning survives the correction because it is what settled the contradiction, but **it was an argument from a premise nobody had checked**, which is worth more as a record than the conclusion it reached.

**The salt the original line omitted has no source, which is why it could not be named.** HKDF's salt wants a value both sides share and neither controls alone, and at this point in the exchange the only such value is the key material itself. `derive_key`'s context string carries the domain separation a salt would have carried here, and it is a compile-time constant rather than a negotiated one, which is what the specification of that function asks for.

**`half_A` is the invite's creator's 16 bytes and `half_B` the replier's**, and the order is by role rather than by value. Both sides know which they are — Alice showed the QR, Bob scanned it — so no comparison is needed to agree, and sorting the two halves instead would let one side try both orders against a target.

**`link_id` is a plain hash and not a second `derive_key`.** It is an identifier that both sides must compute alike and neither must be able to invert into the secret; a truncated hash of the secret is exactly that. It is 16 bytes rendered as lowercase hex, the same shape as a `DeviceId`.

### How Bob's reply reaches Alice, and what authorises the connection

**The diagram says "reply over BLE or LAN" and that sentence was written before there was a handshake to say it about.** BLE is M7, so M6's reply is a LAN connection — and since `WI-M6-001` every live connection classifies the peer's Attestation, whose step 6 refuses an account that is neither this device's own nor already linked. Bob's account is exactly that account, by definition, at the moment he replies. **The check that makes linking worth having is the one that refuses the connection establishing it**, and DCR-067 settles how.

**Finding Alice needs no address in the QR, because the QR carries her identity key.** Bob computes `BLAKE3(identity_pub)[0..16]`, which is Alice's Device ID, and looks for it in his own Peer List — mDNS publishes it as TXT `id`, and a Static Peer entry carries it once pinned. **Tier 0 linking therefore requires that Bob has already discovered Alice**: a shared LAN, or an entry he added by hand. When that Device ID is in no observation, the interface says the peer cannot be found, which is a different sentence from a dial that failed.

**The QR is the pin.** Bob dials under `PeerExpectation::Device`, so the channel authenticates Alice's Device Key against the key he read off her screen. A device on the same LAN claiming her Device ID cannot complete the handshake, because it does not hold the key that ID is a hash of.

**The invite authorises one connection, for one purpose, and it does so outside the Trust Tier entirely.** While an invite is open — from the moment its QR is shown until it expires five minutes later — this device accepts an inbound Control stream **whose first frame is a `LinkReply` rather than a `Hello`**. Such a stream carries no session: no Trust Tier is computed for it, no `HelloAck` is exchanged, and the only frames that may travel on it are the three linking messages [docs/04](04-protocol.md#the-type-byte) assigns. No transfer and no browse is reachable from it.

**Bob's Attestation is verified in full on that stream, minus the single step that cannot apply.** Steps 1 to 5 all run — the provider's signature, the audience, the nonce binding Bob's two keys, the freshness — and so does the key join, `BLAKE3(LinkReply.identity_pub)[0..16]` against the Device ID the channel authenticated. **Step 6 is the only one left out, and it is the one the link exists to change.** What Alice ends up holding is therefore the same assertion an ordinary connection would have given her: this `(iss, sub)` controls these keys.

**What performs that check is a second entry point in `tradr-identity`, not a widened first one** (DCR-072). It takes a policy carrying the provider profiles and the two freshness limits and nothing else -- no `own_account`, no `linked_accounts`, no `ephemeral_receive` -- so step 6 is inexpressible on it rather than skipped, and it returns the peer's `(iss, sub)` rather than a Trust Tier, because the account is what the Link record stores. **The key join is inside it**, against the `DeviceId` the channel authenticated and passed as an argument: the Hello path performs that join inside its own state machine, a link stream has none, and this is the one place left that can hold it. Steps 1 to 5 are the same implementation the ordinary path runs, so the profile is still selected once. [docs/05](05-security.md#what-runs-on-a-stream-that-has-no-session) carries the reasoning.

**Nothing in the tier machinery moves.** `classify` is untouched, `TrustTier` gains no fourth variant, and no widening flag is added to the policy: `ephemeral_receive` is the precedent for widening step 6 and it is the wrong instrument here, because it grants receiving files and an invite must grant nothing of the sort. Once both sides store the Link, the ordinary handshake returns `TrustTier::Linked` on its own, with no further special case anywhere.

**The window is single-use.** It closes at the first completed exchange — an approval and a decline close it alike — or at expiry, whichever comes first. A second reply arriving after that is refused the way any unexpected first frame is.

#### What the window survives, and where the wait on a person is parked

**"Single-use" says what closes the window and not what may close it, and the difference is reachable from the network** (DCR-076). A `LinkReply` is the first frame on a stream that carries no session, so any device that can reach this one can send any bytes it likes into that branch. **If a reply naming an unknown invite closed the window, closing someone else's would cost one connection and no credential at all** — and the person watching the QR would see nothing, because a window that closes looks exactly like one that expired.

**So the window closes on the exchange it is holding and on nothing else.** The invite the reply names decides which exchange that is, before anything is verified: a reply naming the open invite takes it, and a reply naming any other leaves it exactly where it was. That is the same sentence as "an unknown invite is not among the decline reasons" read from the other side — such a reply is not this exchange, so it neither answers it nor ends it.

**The wait on a person is a value parked in the window, because the answer arrives from somewhere else.** The exchange awaits a decision; the person makes it in the interface, one act later and on its own path. So the window holds the proposal and the single place an answer may be delivered, and **the first answer takes that place with it**. A second finds nothing to answer and is refused — never held for the next exchange, which is a different peer being approved by a press meant for this one.

**A new invite is refused while a decision is pending, and replaces the window whenever one is not.** Showing a fresh QR is this design's own recovery from an invite that expired, so a person will reach for it; what it must never do is discard a proposal they are in the middle of reading. **The rule is one sentence: the QR on the screen is the invite this device will answer.** A window replaced while nothing waits keeps that true, and one replaced while something waits breaks it in the direction nobody can see.

**A parked decision that can never be answered is a decline.** Nothing in the exchange discards one — the deadline above already ends the wait, and an answer ends it sooner — so the only thing that can is this device going away, where no wire is left to write to. It is named rather than left to fall out, because a decision channel that simply vanishes is the shape that hangs.

#### What each side verifies, and the order the inviter's two acts go in

**Both sides verify over the channel and neither off the payload the Attestation arrived in.** The replier holds the inviter's Attestation from the invite and the inviter holds the replier's from the `LinkReply`, and each runs it through the same steps-1-to-5 entry point against the `DeviceId` its own channel authenticated. **The key join is what makes the channel the authority rather than the payload**: the invite's `identity_pub` is already the pin the replier dialled under, so checking it against the authenticated `DeviceId` is checking that the QR and the connection name one device. Verifying a token against a key nobody proved possession of would be the whole exchange resting on a photograph.

**The inviter stores the Link before it writes `LinkApprove`.** That message carries the `link_id` and asserts the link exists on the inviter's side; writing it first would make it a claim about state not yet written, and a store that then failed would leave the replier holding a link to an account that holds none back -- refusing its next connection with nothing on the inviter's side naming why. Storing first turns that failure into a `LinkDecline`, which is a state both sides agree on. **It is DCR-070's rule one layer up**, and the same sentence settles it: what names the thing must not precede the thing.

**A store that fails carries no reason.** None of the three is true of it -- the user did not decline, the invite did not expire, and verification succeeded -- and an absent reason is already a value this message defines, since what the reason decides is nothing. A fourth reason invented for a failure the peer can do nothing about would be a wire field carrying an apology.

**A reply naming an invite that is not the open one is refused rather than declined**, and the stream closes with nothing written. That is the same sentence as "an unknown invite is not among the reasons": a decline answers an exchange this device is in, and a stream naming an invite it is not holding is not that exchange. The check runs before anything is verified, so an unknown `invite_id` never spends a signature verification either.

**So what a photographed QR buys is one thing: the chance to be shown to Alice as a stranger asking to link.** The approval and the Fingerprint comparison are still in the way, `half_B` was never on the screen, and no Link Secret of the real link is derivable from what the camera saw.

#### Where the replier's consent goes, and why it is before the dial

**The diagram has Bob verify and read the Fingerprint before he replies, and the exchange as built does both after** (DCR-077). `send_link_reply` verifies the inviter and writes the `LinkReply` in one uninterrupted call, because the replier was given no decision closure and only the inviter a `decide`. Nothing is disclosed to a stranger by that -- verification runs before the reply is written, so a device that is not the inviter never receives Bob's token -- **and the moment is still wrong**: a person reads the Fingerprint after the exchange rather than before it, and this document makes that comparison mandatory on the paste channel, where a blob can come from anyone.

**The pause is before the dial and not inside the exchange.** At that point nothing has been sent, no channel exists, and the invite alone carries everything the comparison needs -- so the consent costs one local read and the exchange keeps the single uninterrupted shape [DCR-073](#how-bobs-reply-reaches-alice-and-what-authorises-the-connection) gave it. A pause inside would mean holding a QUIC channel open across a wait on a person, which is the cost the inviter's side pays because its own decision cannot be made any earlier. **The replier's can**, and that asymmetry is the reason the two sides park their waits in different places.

**What the pause shows is the inviter's Fingerprint and nothing about the inviter's account.** The Fingerprint is `device_fingerprint(identity_pub, agreement_pub)` over the invite's own two keys, which is the same twelve words the inviter's screen displays beside its QR, so the comparison this document calls mandatory is a person reading one screen against another. **Naming the account would need the Attestation verified, and it cannot be verified here**: the entry point that runs steps 1 to 5 takes the `DeviceId` the channel authenticated, and before the dial there is no channel, so the only argument available would be one recomputed from the invite -- the exact shape the exchange's own tests forbid. The account arrives from the exchange, once the channel has proved which device holds the key.

**The expiry is the second thing the pause shows, and it takes the allowance the reply itself takes.** An invite already dead by this device's clock is one the inviter will refuse, and saying so before the dial spends no connection; the allowance is the same clock-skew number `send_link_reply` applies, because a second one is a second thing that can disagree.

**A person who does not consent has sent nothing and stored nothing.** That is the whole of what the pause buys, and it is what the diagram always said.

#### The consent is to one blob, and the expiry it reports refuses nothing

**The pause reads a blob and the reply sends one, and nothing so far says they are the same blob** (DCR-078). A paste field holds whatever it holds at the moment of the press, so a reply carrying the field's current value lets a person read one device's Fingerprint and reply to another's -- and the twelve words on the screen would be describing a device this exchange never touches. **So the reply carries the previewed blob**, captured at the pause, and text that changes afterwards discards the preview rather than standing beside it. It is the inviter's own rule one side over: "the QR on the screen is the invite this device will answer" becomes **the Fingerprint on the screen is the invite this device will reply to**.

**The expiry the pause reports is shown and does not refuse the reply.** The five minutes are the inviter's to enforce and the reader's to be advised of, as the expiry section above already says, and a reader whose clock runs fast finds every fresh invite expired. A device declining to send on its own reading would therefore refuse live invites with nothing on the screen naming which of the two clocks was wrong, while sending against a genuinely dead one costs a connection and a `LinkDecline`. **The cheaper failure is the one the person can see**, so the reading is displayed and the decision stays theirs.

#### The approval has to arrive, and recording before sending is what makes that strict

**Step 7 sends `LinkApprove` and the exchange is not over when the write returns.** The order this document fixes -- record, then approve -- exists so that an approval never asserts a link the inviter does not hold, and it has a consequence the sketch never drew: **the inviter is the only side holding the Link until its last frame is delivered.** A frame lost there is not a failed link, it is a half link, and the replier cannot repair it alone because the two half secrets are gone.

**So the inviter does not release the connection until the replier has seen the stream end**, which [docs/04](04-protocol.md#what-ends-a-link-stream-and-why-when-serve-returns-was-wrong) states as a protocol rule. Recovering from the half state is the user's: the inviter removes the stale Link, which discards its Link Secret, and the pair links again from a fresh invite. DCR-081.

### What the three linking messages carry

**The diagram above is a sketch of a payload and not a definition of one**, and two of its lines could not be implemented as drawn. DCR-068 settles the three messages; `proto/tradr/v1/link.proto` is where they live, and the same rule the Offer and the Hello follow applies here: **a field that decides something refuses the message; a field that only decorates it never does.**

**`LinkReply` (`0x0c`), the replier to the inviter.**

| Field | Wire | Native | On disagreement |
|---|---|---|---|
| `invite_id` | `bytes`, 16 | `InviteId` | **Refuse.** It names which invite this answers, which is the reason that type exists at all, and a reply naming an invite that is not the open one is a reply to something else |
| `identity_pub`, `agreement_pub` | `bytes`, 65 each | `PublicKeyPoint` | **Refuse.** The key join reads the first and step 3's nonce binding reads both. **The diagram carried only `identity_pub` and the verification it describes cannot run on that**: the Attestation's nonce is `BLAKE3(identity_pub \|\| agreement_pub)`, so a reply omitting the agreement key omits half of what step 3 recomputes |
| `attestation.id_token` | `string` | `String`, unverified | **Refuse when absent.** It is the whole of what the exchange is for |
| `attestation.issuer`, `attestation.issued_at` | `string`, `int64` | **absent** | **Dropped**, exactly as in a `Hello`: the authoritative values are the token's own `iss` and `iat` claims, and a second copy is a second answer |
| `half_secret` | `bytes`, 16 | `HalfSecret` | **Refuse.** It is half of the Link Secret |
| `display_name` | `string` | `DisplayName`, dropped when invalid | **Drop it and carry on**, exactly as in a `Hello`. It is shown to a person and decides nothing |
| `sub` | — | — | **Not carried at all.** The diagram showed it and it is a wire copy of a claim already inside the token. Two answers to "which account is this" is the defect the key join exists to prevent, and it is why `Attestation.issuer` is a hint rather than a value |
| `device_id`, `platform`, `capabilities` | `DeviceInfo` fields | **absent** | **Dropped.** The Device ID is recomputed from `identity_pub` and never read off the wire, and nothing in this exchange negotiates a capability or reads a platform |
| a `KeyBinding` | — | — | **Not carried.** It is the redundant proof, and what makes it redundant is exactly the Attestation nonce this stream verifies in full. A `Hello` carries it so the agreement key can rotate on its own later; nothing here rotates a key |

**A `LinkReply` carries no nonce and no signature over one**, which a `Hello` does. It does not need one: the channel is already mutually authenticated before the first frame, so the inviter knows the replier's Device Key from the channel rather than from the message, and the key join is what ties the message to it.

**`LinkApprove` (`0x0d`), the inviter to the replier**: the `invite_id` and the `link_id` the inviter derived. **Both sides derive that identifier independently and a mismatch refuses the exchange** — it is the one cheap check that the two halves joined into the same secret in the same order. `link_id` is safe to send: a Share's Audience already names it, and it is a truncated hash nobody can invert into the Link Secret.

**`LinkDecline` (`0x0e`), the inviter to the replier**: the `invite_id`, and a reason that decorates. Three reasons are reachable and no more — the user declined, the invite expired while the user was reading the Fingerprint, or verification of the reply failed. **An unknown invite is not among them**, because a stream naming one is refused before any message is read. The reason follows `TransferReject.reason`: an unspecified or unrecognised value is dropped and the decline still stands, since what it decides is nothing.

### Tier 2 — linking through a Brokr

For linking at a distance.

```
1. Alice creates an invitation. The Brokr issues a six-character code, valid 10 minutes
2. Alice passes the code to Bob by any means
3. Bob enters it. The Brokr records a pending link
4. Alice's device receives an approval request   <- the second consent
5. Alice approves. The Brokr delivers each side the other's DeviceInfo and Attestation
6. Both sides verify the Attestation themselves  <- the Brokr never verifies
7. half_secrets are exchanged through the Brokr and the Link Secret derived
8. Both sides display Fingerprints and press for verification, strongly but not mandatorily
```

The Brokr only mediates and takes no part in verification. A compromised Brokr introducing a fake peer fails on both sides, since its Attestation lacks Google's signature.

A Brokr can obstruct a link and can learn who linked with whom. Nothing more.

### State after linking

**This block was a sketch of a record and not a definition of one**, the same way the reply payload four sections above was, and DCR-069 settles it against what the code can actually write. The registry is `links.json` in the application data directory, beside `static-peers.json`, written whole through a temporary file renamed over the target.

```jsonc
{
  "links": [
    {
      "link_id": "3f1c9a04e7b25d68...",  // 16 bytes of hex, never a ULID
      "peer_iss": "https://accounts.google.com",  // the peer's issuer
      "peer_sub": "9273...",          // subject, unique only within that issuer
      "peer_label": "Bob",            // display only, dropped when absent
      "created_at": 1756684800,       // seconds since the Unix epoch
      "fingerprint_verified": true
    }
  ]
}
```

**`created_at` is an integer of seconds and not an ISO-8601 string.** `UnixTime` is the only time this workspace has, nothing anywhere formats a date, and a second time representation is a second thing that can disagree with the one the Attestation staleness rule already compares against. The same argument settled the certificate validity window in decision 20: a field written in a shape nothing reads is a field that goes wrong unobserved.

**The Link Secret is in the OS key store and never in this file**, on the same rung of the storage ladder the Device Key is on and never on one chosen for it separately ([docs/05](05-security.md#one-rung-per-device-and-what-else-goes-on-it)). The slot holding it is `link-` followed by the same lowercase hex the `link_id` field carries, so **the record is the only thing that names the slot** — which is what decides the order the two are written and discarded in, below. The record itself stays what a reader of `links.json` may see.

#### What this record deliberately does not carry yet

**`peer_email` has no source.** `VerifiedClaims` carries no `email` claim and no linking message carries one, so it is a field nothing could write. It is left out rather than landed empty, following `ProviderProfile::renewal` — DF-16 — for the same reason.

**`policy` and `known_devices` are left out on the same grounds**: nothing reads either one, and a per-Link transfer policy is a decision open decision 9 has not settled. Both return when something consults them.

**What is here is what the milestone's own criterion needs**: the account, so `AttestationPolicy::linked_accounts` stops being `&[]`; the `link_id`, so removal names one Link; and `fingerprint_verified`, which the exchange writes and docs/05's changed-fingerprint refusal will read.

#### What the registry refuses

**A malformed `links.json` is an error and never an empty registry**, the same rule DCR-063 gives `static-peers.json` and for a sharper reason. An emptied Link registry silently withdraws `TrustTier::Linked` from every peer at once, and what the user sees is every one of their links appearing to have been removed from the other side.

**A second Link to an account already linked is refused.** Linking is per account, as "When the peer adds a device" below says, so two records naming one `(iss, sub)` are two answers to a question that has one. **A duplicate `link_id` is refused too**: it is the key removal and Fingerprint verification address a Link by, and a registry holding two would act on whichever it found first.

#### Where the registry is read from, and when

**`linked_accounts` is read off the registry at each classification and never captured once.** [docs/05](05-security.md#what-a-verifier-does)'s step 6 runs on every connection, and "removal takes effect locally at once" below is true in code only if the list that step reads is the list the registry holds at that moment. A copy taken when the application started goes on granting `TrustTier::Linked` to an account the user has just removed, and nothing anywhere fails.

**A registry that cannot be read is reported at every use and never at startup**, which is the opposite of what DCR-063 gives `static-peers.json`, and the difference is what is left to say it in. An unreadable list must never be read as an empty one, so a device whose `links.json` is malformed classifies no peer at all -- that is already every connection refused, and refusing them from a running window that names the file is strictly more than refusing them from no window. **`PeerTrustState` is the precedent**: it holds its own build failure and reports it through every classification rather than aborting the setup hook, for the same reason.

### Removing a link

- Either side removing it ends it. The other's consent is irrelevant
- Removal discards the Link Secret, so the peer's EIDs no longer resolve and they fall off BLE discovery
- The peer is notified when online, but **removal takes effect locally at once regardless**. Their connections are then rejected because the Attestation's `(iss, sub)` matches no known link
- Files already handed over cannot be recalled. The UI says so

**Discarding the Link Secret needed an operation `SecretStore` did not have, and DCR-070 adds it.** The trait declared `store` and `load` and nothing that empties a slot, so removal as first built dropped the Link record and left the secret behind it — orphaned, since nothing knows the slot name once the record naming it is gone, but still on disk or in the keyring. **The account half of removal was complete throughout and is what the milestone is judged on**: the `(iss, sub)` leaves `linked_accounts` at once and the peer's next connection is refused.

#### `remove`, and the order the two halves move in

**`remove(slot)` empties a slot, and a slot that was already empty is a success.** That mirrors `load`'s `Ok(None)` rather than inventing a second convention for the same absence: what a caller asks for is a slot that is empty afterwards, and a removal that refused because there was nothing there would make the retry after a half-finished removal fail forever. **The rule `load` already carries is unchanged** — a backend that cannot be reached is an error and never a success, because the two must not be confused by a caller deciding whether anything is still there.

**The secret moves first and the record second, in both directions.** One rule, and one reason: the record is the only thing that names the slot.

- **Removing.** A record deleted before its secret leaves a slot nothing can address again, which is the orphan above. Secret first means a discard that fails changes nothing at all, and a record write that fails afterwards leaves the record still naming the slot — so the repair is to run the same removal again, which an idempotent `remove` and a whole-file write both accept.
- **Adding.** The two half secrets are ephemeral, so a record written before its secret can never acquire one and re-linking is the only repair. **That is why this cannot wait for M7's EIDs to be the first thing that reads a Link Secret.** Secret first, and a record that then fails to write **takes its secret back down with it**, so a refused `add` leaves nothing behind.

**A rollback that itself fails is reported beside the failure that caused it, never instead of it.** A second error discarded to report the first is rule F6's shape exactly, and the file rung already carries this pattern for the temporary file it cleans up.

**The registry performs both halves, and no caller can ask for one without the other.** `add` and `remove` take the secret store as an argument, so removing a Link and leaving its secret behind is not a thing a caller can express. **That is the difference between a sentence and an instrument**, and it is the finding this repository has recorded against a rule with no check five times over: "removal discards the Link Secret" was true as design and false as code for exactly as long as it rested on a caller remembering.

**`add` refuses a secret that does not derive the Link's own id.** `link_id` is `BLAKE3(Link Secret)[0..16]` and the slot is addressed by it, so a record and a secret that do not derive from each other would put the secret under a name nothing could find it by. It costs one comparison, and it is the check `LinkApprove` already makes across the wire, made again where the two are stored.

**What reads a Link Secret back, and what a wrong length means.** M7's EIDs are the first thing that will derive from one, and the registry exposes the read now anyway, because **a store nothing can read is a store nothing can check**: the slot a record names either holds that record's secret or it does not, and only a reader can say which. Two absences must not collapse into one answer. **A record whose slot is empty reads as empty rather than as an error** -- that is the intermediate state a removal whose record write failed leaves behind, and it is precisely the state a repair expects to find. **A stored value that is not a Link Secret's length is malformed, never read as absent**: an empty slot says the secret was discarded, and a wrong-length one says the key store returned something nothing here ever wrote, which is the same distinction `load` draws between `Ok(None)` and `Err` one layer down.

**On the Secret Service rung an item is labelled from its slot rather than `Tradr Device Key`.** The label is what a person reads in their keyring, lookup goes by attributes and never by it, and a Link Secret is not a Device Key.

### When the peer adds a device

Bob buying a new phone leaves Alice's device unaware of it. Even so:

1. Bob's new device holds an Attestation for Bob's `(iss, sub)`
2. Alice's device matches it against `link.peer_sub` and grants `TRUST_TIER_LINKED`
3. The Link Secret is shared across Bob's devices — handed over when Bob's devices meet — so BLE discovery works too

**Linking is therefore per account, not per device.** Nobody has to re-link every time the other person buys something. The cost is that a compromised account automatically extends trust to the attacker's new devices. That trade reflects how unusable per-device linking becomes when every new device demands an in-person meeting. Fingerprint verification remains per device for anyone who wants it stricter.

## Distributing the Account Broadcast Key

The shared secret letting same-account devices recognize each other over BLE.

```
1. The first device generates 32 random bytes
2. A second device advertises with the bootstrap secret, HKDF(account_id),
   and is discovered by the first, or they meet over mDNS on a shared LAN
3. Attestations are verified, confirming the same (iss, sub)
4. The first device passes the ABK over the Noise channel
5. Both now advertise EIDs derived from the ABK and stop bootstrap advertising
```

**Rotation**: revoking a device regenerates the ABK, handed to remaining devices as they meet. The revoked device never receives the new one, so it disappears from BLE discovery.

**Collision**: two devices may each independently generate an ABK, having each been "the first" somewhere. On meeting, the earlier creation time wins; on a tie, the smaller value. Every device applies the same rule, so it converges.

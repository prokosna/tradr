# ADR-0019: A 128-bit service UUID for the BLE advertisement, and what the 31 bytes actually hold

- **Status**: Accepted
- **Date**: 2026-09-05
- **Supersedes**: the advertisement payload block of [docs/03](../03-discovery-and-transport.md#2-ble--proximity-no-network-required-tier-0). No earlier ADR decided it, so none is rewritten

## Context

`WI-M7-002` is the advertisement codec, and its Definition of Done says the 31-byte budget is **enforced rather than assumed**. Enforcing a budget means knowing what is inside it, and reading the block that specifies it found that the arithmetic had never been done.

```
Service UUID, 16-bit, one allocated value    2 bytes
Service Data:
  +- version                                 1 byte
  +- EID (ephemeral identifier)              8 bytes
  +- platform and capability flags           1 byte
  \- reserved                                2 bytes
```

**Three things in fourteen lines are undecided, and each of them is decided by whoever writes the encoder first.**

**There is no allocated 16-bit value and there will not be one.** A 16-bit UUID is an entry in the Bluetooth SIG's registry, assigned to a member. Tradr is not one, and "one allocated value" describes a thing that does not exist and cannot be obtained by writing it down. **This is DCR-082's shape**: a line that reads as settled, in a document that has shipped, naming something nothing can satisfy.

**The block counts payload and not the wire.** An advertisement is a sequence of AD structures, each carrying a length byte and a type byte before its data, and a discoverable advertisement carries a Flags structure as well. The block's own numbers sum to 14; what those 14 bytes cost on the air is between 19 and 33 depending on the container, and 33 does not fit in 31. **The budget it claims to fit inside was never compared with the encoding it describes.**

**Neither field named in the flags byte fits the type this repository already has.** `Capabilities` is a `u16` with seven named bits and bits 7-15 reserved for a later transport ([docs/03](../03-discovery-and-transport.md#capability-flags), Change Drill D10). `Platform` is a validated open string, deliberately not a closed set, so that Change Drill D7's iOS does not become invisible to a build that predates it. **One byte holds neither, let alone both**, and the narrowing is a decision about what a scanner is entitled to know before it has connected to anything.

## Decision

**One 128-bit UUID is generated here, once, and every Tradr UUID is a 16-bit slot within it.**

```
Tradr base UUID    0000xxxx-6eed-40d6-85d3-3794eaa7b21c

  slot 0x0001      the advertisement service, this ADR
  slot 0x0002      the ble-gatt service, WI-M7-007
  slots 0x0003+    unallocated; a characteristic takes one
```

The advertised value is therefore `00000001-6eed-40d6-85d3-3794eaa7b21c`.

**The advertisement is one AD structure Tradr writes, beside one the controller writes.**

```
Flags,  AD type 0x01                              3 bytes   written by the platform
Service Data - 128-bit UUID, AD type 0x21        28 bytes   written by Tradr
  +- length                                       1 byte
  +- type, 0x21                                   1 byte
  +- service UUID, little-endian                 16 bytes
  \- service data                                10 bytes
       +- version, 0x01                           1 byte
       +- EID                                     8 bytes
       \- platform and capability flags           1 byte
                                                 --------
                                                 31 bytes
```

**Tradr's own budget is 28 bytes and the encoding is exactly 28.** There is no slack and no reserved field.

**The UUID goes on the air least-significant byte first**, which is the reverse of how it is written above and is what the Core Specification requires of a 128-bit UUID in an AD structure. The encoder writes `1c b2 a7 ea 94 37 d3 85 d6 40 ed 6e 01 00 00 00`.

**The flags byte is a platform code in the high nibble and `Capabilities` bits 0-3 in the low nibble.**

| Bits | Meaning |
|---|---|
| 7-4 | Platform code: `0` unknown, `1` linux, `2` win, `3` mac, `4` android. `5`-`15` unassigned |
| 3-0 | `Capabilities` bits 0-3, in their own positions: `direct-quic`, `wifi-direct`, `ble-gatt`, `relay` |

**A version byte the parser does not know means the advertisement is ignored, not that the scanner fails.** Everything after it is version-defined, so there is nothing to interpret and nothing to report.

## Reasoning

1. **A 128-bit UUID needs nobody's permission, and that is the whole of why it wins.** The alternative on offer was to pick an unallocated 16-bit value and ship it, which is squatting on a registry whose entries are handed out by someone else. It buys 14 bytes and it can be revoked from under the product by an allocation Tradr is not party to.

2. **The collision it avoids is cheaper than it looks, and saying so is what makes the choice honest rather than reflexive.** Two products sharing a 16-bit UUID would not confuse each other's peers: the service data begins with a version byte, and the EID after it has to match a secret the scanner holds, which a foreign payload does not. **What a squatted value actually costs is wasted `derive_key` calls and a claim in this repository that is not true.** The second is the one that decides it, in a file whose recurring lesson is to probe for the artifact instead of for a document's opinion of it.

3. **A base UUID with 16-bit slots means this decision is taken once.** `WI-M7-007` needs a GATT service UUID and characteristics; without a base, each is a second random value and a second decision. With one, they are names. This is the convention the SIG's own base UUID follows, applied to a value Tradr owns outright.

4. **The low nibble carries transports because a transport is what a scanner acts on.** Path selection consumes exactly `direct-quic`, `wifi-direct`, `ble-gatt` and `relay`; browsing, a writable Share and a metered link are facts about what a peer will *do*, and they arrive in `Hello` where the peer has already been authenticated. **Keeping the four bits in their `Capabilities` positions makes the narrowing a mask rather than a mapping**, so nothing has to be kept in step with the bit table in docs/03.

5. **The platform is a closed 4-bit code where the TXT record is an open string, and the disagreement is deliberate.** `Platform`'s openness exists so that an unknown token does not make a device invisible; a 4-bit field with `0` meaning unknown keeps that property exactly, since an unrecognised code parses as unknown and the advertisement is still matched on its EID. **What an open string cannot do is fit in four bits**, and the eleven unassigned codes are where Change Drill D7's iOS goes.

## The reserved bytes, and where the room went instead

**Two reserved bytes do not fit and are dropped.** With a 128-bit UUID the service data may be 10 bytes, and version, EID and flags are exactly 10.

**The extension room is real and is in three places, none of them a reserved field.** The version byte admits 255 further layouts, one of which can be an extended advertisement with 254 bytes to spend. Eleven platform codes are unassigned. And the **scan response is a second 31 bytes that this design does not use at all**, available to any value a passive scanner does not need.

**A reserved field inside a budget with zero slack is a field that can never be used**, which is worse than an absent one for the reason DF-16 records about `ProviderProfile::renewal`: it looks like room that is being kept.

## Costs

- **The budget is exactly full, and the first thing that wants a byte will find out at runtime.** Android answers an over-long advertisement with `ADVERTISE_FAILED_DATA_TOO_LARGE` at the moment advertising starts, not at build time. The codec asserts the size at compile time so that this repository finds it first; nothing can make a platform's own limit forgiving.
- **Three bytes are spent on a Flags structure Tradr never writes**, and it cannot be reclaimed: a connectable, discoverable advertisement carries it, and `WI-M7-007` makes the device connectable by making `ble-gatt` a transport.
- **A 16-byte UUID on every advertisement is 16 bytes of radio on every interval, forever.** At a 31-byte payload the packet is the same size either way, so the cost is the room, not the airtime — which is precisely the room the reserved bytes were occupying.

## Conditions for revisiting

- **Tradr becoming a Bluetooth SIG member with an allocated 16-bit UUID.** That would return 14 bytes, and it is the only thing that would.
- **Extended advertising becoming the floor rather than the ceiling.** Both platforms in M7's completion criterion support it; the 31-byte legacy limit is what a scanner on an older controller can see, and when that stops mattering the version byte is how the layout moves.
- **A field the scanner genuinely needs before connecting.** The scan response is the first place to put it, and a version bump is the second. Neither is this ADR being wrong.

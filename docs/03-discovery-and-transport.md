# 03. Discovery and transport

## Starting premise: Bluetooth cannot carry bulk

This has to be stated first, because the rest of the design follows from it.

| Method | Effective throughput | Time for 1 GB |
|---|---|---|
| BLE GATT, 20-byte MTU | ~5 KB/s | about 55 hours |
| BLE GATT, 247-byte MTU on 2M PHY | ~100 KB/s | about 2.8 hours |
| Bluetooth Classic, RFCOMM | ~1.5 MB/s | about 11 minutes |
| Wi-Fi Direct, 802.11n | ~20 MB/s | about 50 seconds |
| Wired or Wi-Fi 6 LAN | 50-110 MB/s | 10-20 seconds |

Neither Quick Share nor AirDrop puts payload on BLE. **BLE carries discovery and key exchange only**, after which both switch to Wi-Fi Direct or AWDL. Tradr takes the same shape.

The decision, recorded in [ADR-0002](adr/0002-ble-for-discovery-and-small-payloads.md):

- **BLE serves three purposes: discovery, mutual authentication, and small payloads**
- BLE alone may carry **512 KiB at most** — text, URLs, contacts, small images
- Anything larger drops BLE from the candidate list. With no other path available the transfer queues as waiting for a network and starts by itself once Wi-Fi returns

512 KiB comes from roughly 5 seconds at the 100 KB/s that a 247-byte MTU on 2M PHY achieves in practice. The implementation adjusts the ceiling from measured throughput.

## Discovery

Four `DiscoverySource` implementations run concurrently, merging into one peer list. A Device ID arriving from several sources collapses into a single peer holding several candidates.

### 1. mDNS / DNS-SD — the same LAN, Tier 0

- Service type `_tradr._udp.local`, since QUIC rides UDP
- Instance name: eight random hex characters. The Device ID never appears in the name
- TXT record:

  | Key | Value |
  |---|---|
  | `v` | Protocol major version |
  | `id` | Device ID, 16 bytes, base64url **without padding** — 22 characters |
  | `pk` | Agreement Key Tag: the first 8 bytes of `BLAKE3(agreement_pub)`, base64url without padding — 11 characters |
  | `n` | Display name, UTF-8, 32 bytes maximum |
  | `p` | Platform: `linux`, `win`, `mac`, `android` |
  | `c` | Capability flags, a bitmask |

- Implemented with `mdns-sd`. On Android, multicast arrives only while a `WifiManager.MulticastLock` is held, acquired on the Kotlin side

**Both encoded values are base64url with no padding**, matching the Attestation nonce in [docs/05](05-security.md#the-attestation) and every base64 already in this codebase. Padding would buy nothing here and costs bytes in a record with a budget.

**The Agreement Key Tag is not the Fingerprint, and this table called it one until DCR-047.** [CONTEXT.md](../CONTEXT.md) defines a Fingerprint as a Device Key rendered as human-readable words, the Signal-safety-number idea, meant for a person to read aloud. The `pk` value is eight raw bytes meant for a machine to compare. Two unrelated things under one word in the vocabulary file that exists to stop exactly that, and the collision is not harmless: an implementer sent to `CONTEXT.md` for "fingerprint" would find a word encoding.

**What the tag is for, and what it is not sufficient for.** It lets a device that already holds a peer's full agreement key confirm cheaply that the key has not changed, without a connection. It cannot carry `PeerExpectation::Identity`, which `Noise_IK` needs, because that needs the whole key and this is eight bytes of a hash of it — the point made under "What a transport is told about the peer it is dialling" below. **Nothing in M1 reads it**; it is advertised so that a peer which does read it is not talking to a device that never emitted it.

**A browsing device must not drop an instance whose `v` it does not recognise.** [docs/04](04-protocol.md#versioning) carries each side's supported range in `Hello` and takes the highest common version, so a version this build cannot speak is a negotiation that has not happened yet, not a peer to hide. Filtering here would make that peer silently invisible, and a peer that never appears is the hardest failure this design has to diagnose.

**A malformed record is skipped, and the source keeps running.** Anyone on the LAN can advertise anything, so a record with a missing key, an `id` that is not 22 base64url characters, or a value carrying a control character is one the source ignores while continuing to browse. That is a filter and not a swallowed error: nothing failed that a caller could act on, and a source that died on the first hostile advertisement would be trivially deniable.

Putting the Device ID in the TXT record exposes device identity to anyone on the LAN. That is accepted: a LAN is already a somewhat trusted space, and concealing identity there would badly hurt how quickly discovery works. **Proximity, where anonymity does matter, is handled differently** — see EIDs below.

### 2. BLE — proximity, no network required, Tier 0

Advertise on an interval while scanning at the same time. Both roles run.

**Advertisement payload** ([ADR-0019](adr/0019-a-128-bit-service-uuid-for-the-ble-advertisement.md)), counted as it goes on the air rather than as a field list:

```
Flags,  AD type 0x01                              3 bytes   written by the platform
Service Data - 128-bit UUID, AD type 0x21        28 bytes   written by Tradr
  +- length                                       1 byte
  +- type, 0x21                                   1 byte
  +- service UUID, little-endian                 16 bytes
  \- service data                                10 bytes
       +- version, 0x01                           1 byte
       +- EID (ephemeral identifier)              8 bytes
       \- platform and capability flags           1 byte
                                                 --------
                                                 31 bytes
```

The service UUID is `00000001-6eed-40d6-85d3-3794eaa7b21c`, slot `0x0001` of the Tradr base UUID `0000xxxx-6eed-40d6-85d3-3794eaa7b21c`; `ble-gatt` takes slot `0x0002`. **It goes on the air least-significant byte first**, which the Core Specification requires of a 128-bit UUID in an AD structure and which is the reverse of how it is written here.

The flags byte is a platform code in bits 7-4 -- `0` unknown, `1` linux, `2` win, `3` mac, `4` android, `5`-`15` unassigned -- and `Capabilities` bits 0-3 in bits 3-0, in their own positions. Those four are the transports; the rest of the bitmask arrives in `Hello`, where the peer has been authenticated. A version byte the parser does not know means the advertisement is ignored.

**This read `Service UUID, 16-bit, one allocated value` and had two reserved bytes until [ADR-0019](adr/0019-a-128-bit-service-uuid-for-the-ble-advertisement.md), and the arithmetic had never been done.** There is no allocated 16-bit value and there will not be one -- the registry belongs to the Bluetooth SIG and Tradr is not a member -- and the block counted a field list summing to 14 rather than an encoding, which with a 128-bit UUID costs 28 of the 31. **Tradr's budget is 28 bytes and the encoding is exactly 28**, so the reserved bytes are gone; the room is the version byte, the eleven unassigned platform codes, and the scan response's second 31 bytes, which this design does not use.

**Deriving an EID** ([ADR-0018](adr/0018-blake3-derive-key-for-eids.md)):

```
window = unix_time.div_euclid(900)                        i64
EID    = BLAKE3::derive_key(context = "tradr-eid-v1",
             key_material = secret || window_be)[0..8]
```

`window_be` is that window number as **8 bytes, big-endian**. `secret` is one of the following, 32 bytes in every case. A device computes an EID from every secret it holds and **advertises them in rotation**. A scanner computes candidate EIDs from every secret it holds and matches against what it received.

| secret | Purpose |
|---|---|
| ABK (Account Broadcast Key) | Devices of the same account |
| Link Secret | Devices of a linked account |
| `BLAKE3::derive_key("tradr-bootstrap-v1", account_id)` | First discovery, before any ABK exists |

**This read `HKDF-Expand` until [ADR-0018](adr/0018-blake3-derive-key-for-eids.md), and the primitive was the smaller half of what it left open.** It named no hash, which [docs/05](05-security.md#algorithms) and [docs/11](11-account-linking.md#deriving-the-link-secret) then answered differently; and it fed HKDF-**Expand**, which takes a pseudorandom key, a bootstrap secret derived from `account_id` -- a structured, low-entropy, public string, which is exactly what HKDF-Extract exists to condition. `derive_key` takes arbitrary key material, so **one construction now covers all three secrets** instead of two written as one.

**The window goes into the key material rather than the context, and the order and width are what make that safe.** `derive_key`'s context must be a compile-time constant by its own specification, so it cannot carry a per-window value the way HKDF's `info` did. Appending a fixed-width window to a 32-byte secret makes every input exactly 40 bytes, so no `secret || window` pair can collide with another -- **unambiguous by construction rather than by luck**, which a decimal rendering would not be.

**`div_euclid` and not `/`**, because Rust's `/` truncates toward zero while `floor` does not: `-1 / 900` is `0`, so a device whose clock is set before 1970 would otherwise share the epoch's own window with every other such device, and both sides would agree with each other while doing it.

Rotation period is 15 minutes. To absorb clock skew, scanners try the `t-1`, `t`, and `t+1` windows. **Two windows away is refused**, and that is the direction that matters: a wider allowance goes on recognising a device by an identifier it has already rotated away from, which is the tracking window this design bounds at 15 minutes.

Holding N secrets costs 3N `derive_key` calls per advertisement. N stays in the low tens in practice and BLAKE3 takes microseconds, so this does not matter.

**Why no permanent identifier goes on the air**: anyone can receive BLE advertisements. Broadcasting a fixed value would let shop receivers and passing phones track a device's movements. An EID looks like a random string that changes every 15 minutes to anyone without the matching secret.

**On the weakness of the bootstrap secret**: `account_id` is `iss || 0x00 || sub` and is not a secret, merely an opaque provider identifier with the issuer prepended. Anyone who obtains one can detect when that person's device is nearby. This is accepted — a `sub` does not normally leave the app, and **detection grants no ability to connect**, which still requires mutual Attestation. Once two same-account devices meet they exchange an ABK and stop advertising the bootstrap EID.

**Per-platform implementation**: no Rust crate covers the BLE peripheral role across platforms, so this part is written four times. It is the least predictable work in the design — see [09](09-roadmap-and-risks.md).

| OS | Advertising (peripheral) | Scanning (central) |
|---|---|---|
| Linux | `bluer`, BlueZ over D-Bus | `bluer` |
| Windows | `windows` crate, `BluetoothLEAdvertisementPublisher` | `btleplug` |
| macOS | `objc2`, `CBPeripheralManager` | `btleplug` |
| Android | Kotlin, `BluetoothLeAdvertiser` | Kotlin, `BluetoothLeScanner` |

`tradr-discovery` declares `BleAdvertiser` and `BleScanner` traits with those four implementations behind them.

#### Where a platform implementation lives, and what the two traits promise across all four

**DCR-084 settled what the traits are for; what it did not settle is what four separate implementations have to agree about.** A trait with one implementation is defined by that implementation. A trait with four is defined by what is written down, and whatever is left unwritten gets decided four times.

**Each implementation lives in `tradr-discovery` beside the traits, behind a `cfg` on its own target**, and `ci/layer-deps.sh` rule 4 decides that rather than taste: an implementation crate may depend internally only on `tradr-core` and `tradr-proto`, so a `tradr-ble-linux` crate could not name the crate its traits are declared in. The platform dependency is target-gated in the manifest, so a Windows or macOS build never resolves `bluer` at all — and Rust's `target_os` is `android` rather than `linux`, so the same gate correctly excludes the Android build, whose radio code is Kotlin behind `tauri-plugin-tradr`. **Android is this paragraph's one exception and the subsection below is what it costs**: the Kotlin side is not a Rust `BleAdvertiser`, so a Rust half inside `tauri-plugin-tradr` is what implements the two traits.

**`start` replaces, and that is what makes rotation expressible.** The EID rotates every 15 minutes and a device holding several secrets advertises them in turn, so the advertiser is told to advertise ten new bytes far more often than it is told to stop. `start` while already advertising therefore replaces the payload rather than failing; `stop` while not advertising succeeds; and dropping the advertiser stops the radio. **No second method is added for rotation**, because a replace and a start differ in nothing the caller knows.

**Only the Service Data goes on the air.** ADR-0019's budget is exactly full: three bytes of Flags the controller writes and 28 that are Tradr's. A local name, a TX power level, an appearance, or the same UUID repeated in a Service UUID list is each another AD structure, and none of them fits. **A platform answers an over-long advertisement when advertising starts, not when the code is built**, so this is a constraint each of the four implementations holds on its own.

**A scanner yields one report per advertisement received, not one per payload that changed.** `BleSource` decides `Lost` from 30 seconds of silence about a handle, so a scanner that suppressed a repeat would age out a stationary peer whose EID has not rotated — and that peer would return, under the same handle, as a new observation. **Where a platform's default is to suppress duplicates, turning that off is part of the implementation**, and `bluer`'s `DiscoveryFilter` is one such default.

**The platform's own UUID filter cannot do that selecting, at least not on BlueZ, and the two rules above are what collide.** A discovery filter naming the service UUID is the obvious way to make the radio do the work, and it would find nothing at all: BlueZ's own `eir.c` puts a Service Data UUID into a service-data list of its own and only a Service UUID AD list into the `services` set a discovery filter matches — and an advertisement carrying that list does not fit in 31 bytes, which is why the paragraph above forbids it. **An advertisement carrying only Service Data is therefore invisible to a filter that matches only advertised Service UUIDs.** The failure is silence rather than an error, which this document already names as the hardest thing it has to diagnose.

**A scanner reports Tradr's service data and nothing else.** A `ScanReport` carries exactly the ten bytes held under the advertisement UUID, so selecting that UUID out of what the radio heard belongs to the scanner and not to `BleSource`: a device advertising other service data, or none under this UUID, produces no report at all, and a payload under this UUID that is not ten bytes is dropped the way a malformed mDNS record is. That leaves `BleSource` as the only thing deciding an EID does not match, which is the one filter it is meant to own.

**`Unsupported` is reported for a role the platform cannot perform, and for nothing else.** It is Change Drill D4's retreat expressed as a value, so a device reporting it once runs scan-only from then on. Mapping a busy adapter, a refused permission, or a daemon that is not running onto it would retreat a device permanently on a transient condition, and each of those has a variant of its own.

**No test can hold a radio, so a platform implementation is judged in two parts.** Everything that is a mapping — a platform error onto `BleError`, a platform's advertising payload onto a `ScanReport` — is a pure function, is kept apart from the code that talks to the radio, and is tested. **The radio itself is verified by a run against real hardware whose result is recorded**, which is the standard M0's and M5's completion criteria already met. A platform implementation that has never been run against an adapter is not done, and nothing in this repository can say so on its own.

#### The Android implementation is two files in two languages, and the seam is drawn where the tests are

**The radio is Kotlin's and the match is Rust's, so this one implementation is split, and DCR-086 is where.** `BluetoothLeAdvertiser` and `BluetoothLeScanner` have no Rust binding, while `BleSource` owns the EID match and cannot move: Kotlin holds no secret and no `derive_key`. So a Rust half implements `BleAdvertiser` and `BleScanner` by forwarding to Kotlin, and it cannot live in `tradr-discovery` -- reaching Kotlin is `PluginHandle::run_mobile_plugin`, and `ci/layer-deps.sh` check 3 lets only `tauri-plugin-tradr` name `tauri`. **It lives in `tauri-plugin-tradr`, and Change Drill D9's budget is unchanged**, because the binding crate is the one D9 already spends.

**Kotlin maps nothing, and that is the whole of the seam.** The rule above puts every mapping in a tested pure function, and there is no Kotlin test infrastructure here at all: the plugin's `build.gradle.kts` declares no test source set, and `ci/run-all.sh` compiles no Kotlin. **A mapping written on that side is a mapping nothing can check.** Kotlin therefore returns the platform's own failure codes and the advertisement bytes verbatim, and every mapping onto `BleError` and `ScanReport` happens in Rust. Anything expressible on either side goes on the Rust side.

**The Rust half then splits again, on the same test.** `#[cfg(target_os = "android")]` is invisible to a host `cargo test`, which is what `WI-M5-005` measured for `clippy` and `android.rs`. So the mappings and the report queue carry no `cfg` and are compiled and tested on every target, and only the type holding a `PluginHandle` is gated -- checked with `cargo check --target aarch64-linux-android`. **A test that runs only on a target nothing builds is not a test.**

**A command resolves with an outcome rather than rejecting with a sentence.** `run_mobile_plugin`'s error channel carries a string, so a rejection would put Android's numeric failure code inside prose for Rust to parse back out, which is a decision in the one place no test reaches. The commands resolve with a tagged value instead: `ok`, `unsupported`, `permissionDenied`, `adapterUnavailable`, or `advertiseFailed` and `scanFailed` carrying the `AdvertiseCallback` or `ScanCallback` code unchanged. **An `Err` from the bridge itself is `Io` and never `Unsupported`**, because nothing about the radio is known when the call did not reach it.

**`Unsupported` is `ADVERTISE_FAILED_FEATURE_UNSUPPORTED`, `SCAN_FAILED_FEATURE_UNSUPPORTED`, and an adapter that hands out no advertiser, and nothing else.** The two callbacks number their codes from 1 independently and 1 means a different thing in each, so they are two mapping functions rather than one taking a role argument. A busy advertiser, a scan started too often and a payload the platform calls too large are all `Io`, by the rule above: D4's retreat is permanent and none of those conditions is.

**Android's scan filter does what BlueZ's could not, and using it is not optional.** `ScanFilter` matches Service Data as well as an advertised Service UUID list, so the selecting rule is satisfiable on the radio here; and a scan carrying no filter at all **returns nothing while the screen is off**, which reproduces DCR-085's silence by a different route. The filter names the advertisement UUID under an all-zero mask, so the UUID selects and no byte of the payload does -- the version byte is parsed in Rust, where every other platform parses it. `CALLBACK_TYPE_ALL_MATCHES` and a report delay of zero are how "one report per advertisement received" is spelled on Android.

**Advertising is the legacy `startAdvertising`**, because `AdvertisingSetParameters` is API 26 against a `minSdk` of 24, and because legacy is the 31 bytes ADR-0019 counted. The device name and the TX power level are excluded explicitly rather than left to a default, since the budget has room for neither, and the advertisement is connectable because `ble-gatt` dials this same one. **Android has no replace, so `start` stops the current advertisement and starts the new one against the same callback object**, which makes `ADVERTISE_FAILED_ALREADY_STARTED` unreachable by construction rather than handled.

**The queue between the two threads is bounded and drops its oldest.** A `ScanCallback` fires on a binder thread while `next_report` is awaited on Rust's, so the two meet in a queue, and an unbounded one is a radio writing into memory nothing has to read. Every entry is a refresh of one kind of fact, so a full queue drops the oldest: the newest report is the one whose EID window is current, and keeping stale ones instead could age out a peer that is still there. A dropped report costs one refresh against a 30-second age-out.

**Both legacy Bluetooth permissions are absent from the manifest, and the API levels below 31 need them.** `BLUETOOTH_SCAN` and `BLUETOOTH_ADVERTISE` exist from API 31; below it the same calls need `BLUETOOTH` and `BLUETOOTH_ADMIN`, and scanning needs `ACCESS_FINE_LOCATION`, which is already declared with `maxSdkVersion="30"`. They are install-time permissions, so the repair is two manifest lines -- plus a Kotlin side that answers `permissionDenied` for the level it is running on rather than letting a `SecurityException` escape.

#### The one part of this seam nothing can check is Kotlin's own JSON, and a self-test push is the instrument

**A `serviceData` key that Rust read as `service_data` made every scan report on Android fail to deserialize, silently, through a passing review and every green gate.** `if let Ok(push)` was false for every report, the report was dropped, and a `BleSource` on Android saw an empty world with no error anywhere. **The defect sat exactly between the two parts DCR-085 judges a platform implementation by**: it is not a mapping, because the mapping was correct on both sides of it, and a run against real hardware cannot tell it from a radio hearing nothing.

**The instrument is a self-test push, and what makes it an instrument rather than a second place the same bug can hide is that Kotlin builds it with the function that builds a real one.** One private builder takes a handle and ten bytes and returns the `JSObject` that goes on the channel; `onScanResult` calls it and so does the self-test. A self-test assembling its own object would be checking a copy of the shape rather than the shape, which is the failure this repository has recorded three times as tests standing where the bug cannot exist.

**It is a flag on `startBleScan` rather than a command of its own**, because the push has to travel the channel the scan is actually running on, reaching the closure `AndroidBleScanner` installed and the queue it owns. A second command would need a second channel and therefore a second Rust receiver, which is the copy again. **And it is a flag rather than something unconditional**, because a synthetic report entering a live `BleSource` is a probe that has quietly become the application's behaviour -- the thing a sixty-second bound was put on the Android probe to prevent. Whatever wires BLE for real passes false.

**The flag's name is one lowercase word in both languages, and that is the decision rather than an accident.** `#[serde(rename_all = "camelCase")]` leaves a single-word field alone, so `selftest` has no second form the two sides can disagree about -- **the failure this whole subsection exists to answer, removed by construction rather than by a test**, in the way ADR-0019's budget is held by a compile-time assertion instead of by an encoder.

**The push carries a payload that could not have come off a radio and is legible in a log**: version `0x01`, the eight ASCII bytes of `SELFTEST` where the EID belongs, and a zero flags byte, under the handle `self-test`. Well-formed to the parser, matching no secret any device can hold, and recognisable in a hex dump beside the real thing. **Rust states the same two values independently rather than sharing them**, because nothing can share a constant across the two languages and the comparison of the two statements is the whole of what the probe reports.

**What it proves is every part of the receive path this repository wrote, and nothing else**: Kotlin's key names, Tauri's channel, `ScanPush`'s deserialization, `scan_push_entry`, the bounded queue, and `next_report` -- with no second device, no advertisement and no radio traffic at all. **What it does not prove is Android's own `ScanFilter`**, which needs a Tradr peer transmitting Service Data, and that stays where DCR-085 put it: a recorded run against real hardware.

#### The two BLE traits belong to `tradr-discovery`, and Change Drill D4 is why

Rule B3 puts a trait in Layer 1 and its implementation in Layer 3, so `tradr-core` is where a trait goes by default. **These two are the exception, and the drill decides it rather than taste.** D4 retreats BLE to scan-only and budgets "one discovery implementation plus a capability flag"; if `BleAdvertiser` were declared in `tradr-core`, dropping the peripheral role would delete a trait from `tradr-core`, which is the one thing D10 forbids outright. `tradr-core` also has no reason to name either: nothing above `BleSource` knows that BLE has two roles, and `DiscoverySource` is the trait Layer 1 does declare and does consume.

**A trait declared beside its only consumer is not an inverted dependency.** `BleSource` is the adapter, `BleAdvertiser` and `BleScanner` are its own ports, and the four platform implementations are the drivers behind them. Nothing points outward at any step.

#### What a scanner reports, and what `BleSource` does with it

**A scanner reports the ten service-data bytes and a handle, never a raw 31-byte advertisement.** That is the same finding [ADR-0019](adr/0019-a-128-bit-service-uuid-for-the-ble-advertisement.md) recorded on the advertising side: no platform API deals in AD bytes, and `bluer`, `addServiceData` and `ScanRecord.getServiceData` all hand over the service data for one UUID. The eighteen bytes of AD structure around it are constants, so a scanner that reported them would be reporting what the parser already knows.

**The handle is whatever the platform calls the peripheral, and it is the observation key and the `ble-gatt` candidate address at the same time.** `bluer` gives a Bluetooth address, `btleplug` on macOS gives an opaque per-host UUID, and Android gives `BluetoothDevice.getAddress()`; the design does not care which, because the only two things done with it are reconnecting to it and telling two observations apart. **An EID is not something `ble-gatt` can dial**, so an observation keyed on one would carry no candidate at all. Phase 1's `handle:0x0042` is this string. The subsection below is why the handle keeps that job after a measurement showed it rotating.

**An advertisement whose EID matches no secret the device holds produces no observation.** Matching is what the EID is for: a payload nobody can match is a stranger's, and putting it in the peer list would be listing devices this account has no relationship with. A payload that is malformed, or that carries a version byte the parser does not know, is skipped the same way a malformed mDNS record is, and the source keeps scanning.

**A `PeerObservation` from BLE therefore carries no Device ID and no display name.** The advertisement has room for neither — 28 bytes, and the section above accounts for all of them — so both stay absent until a connection produces them, exactly as a Static Peer's `expect_device_id` does. The platform code is parsed and then dropped rather than stored, because `PeerObservation` has no field for it and a field nothing reads is worse than an absent one.


#### The handle rotates, and every other key is worse

**Measured on 2026-09-06, not reasoned about.** One Android phone advertising, one `BluerScanner` receiving, ninety seconds: the identical ten bytes arrived under `44:8C:FE:E9:F2:A4` for seven reports and then under `6F:AE:BF:92:2A:78` for thirty-seven, a clean handover with no interleaving. Both are Resolvable Private Addresses, which the top two bits of each say. **The address rotated at least once inside a window in which the EID did not rotate at all**, and Tradr cannot resolve either address to the other, because resolving one needs the peer's Identity Resolving Key and that is exchanged by BLE bonding, which this design never performs.

**That falsifies the reason this document gave, and not the decision it gave it for.** The paragraph above used to reject keying on the EID partly because "an EID rotates every 15 minutes, so a stationary device would become a new peer four times an hour" -- an argument that prefers the handle for its stability, over a handle that turns out to be the less stable of the two. The decision survives on an argument the measurement does not touch.

**The advertisement carries no per-device identifier at all, and that is what decides it.** Ten bytes: a version, an EID, and a platform-and-capability byte. Two devices of one account derive their EID from the same ABK in the same window, so their advertisements are byte-identical; two devices of a linked account are byte-identical the same way through a Link Secret. **The handle is the only thing in a scan report that can tell two devices apart.** Keying on the EID -- or on the secret that matched it, which is the repair the measurement invites -- collapses two devices into one observation whose candidate set holds both their addresses, and Path Selection races a candidate set, so the peer the user chose would connect to whichever answered first. On an ABK that is one of the user's own devices; on a Link Secret it is one of somebody else's. **The duplicate the handle produces is a listing error lasting thirty seconds; the merge is a delivery error with no bound.**

**And the two cases cannot be told apart from the air.** "The same payload under a new handle" and "a second device holding the same secret" produce exactly the same ten bytes from an unrelated address at the same moment. No rule inside `BleSource` separates them, because the separating fact is not broadcast. A merge is therefore not a repair that could be written more carefully; it is a guess, and it is wrong in the direction that costs a file.

**So the handle stays the key, and both consequences are accepted with their bounds written down.** A device that rotates its address is listed twice until the old handle ages out, which is thirty seconds after its last report and the same latency this design already accepts for a peer that walked away. A `ble-gatt` candidate carrying a rotated-away address is dead, and the age-out is what removes it.

**What a dead candidate costs `ble-gatt` is a slow failure, and rotation being a handover is most of what pays for it.** A central given an address that is no longer advertised does not fail fast; it scans for that address until its own timeout. But the fresh address is in the peer list at the same moment the stale one is, so **racing every candidate in parallel is what absorbs it** -- the live one connects while the dead one is still waiting. What the duplicate costs is that the two addresses sit under two `ObservationId`s and therefore under two peers, so the race has one candidate rather than two and the user picks which. **A `ble-gatt` dial is therefore bounded by its own timeout**, so that choosing the dead entry costs a wait rather than a hang. That is a constraint on the transport, not on this source.

**The exit exists, it merges by knowing rather than by guessing, and it belongs to `ble-gatt`.** A connection produces the peer's Device ID — from the identity join in the Noise handshake payload, [ADR-0020](adr/0020-noise-xx-for-ble-gatt.md), since the handshake itself authenticates only the agreement key — and the Trust-on-first-use rule below already says what a source does with one: it re-reports the same `ObservationId` with the Device ID now present, and the peer list folds every observation carrying that Device ID into one peer. It cannot run before a connection, so it does not tidy the list; it does mean the duplicate resolves the moment either entry is used.

#### The secret set is read per advertisement, not captured when scanning starts

The secrets a scanner matches against are the ABKs and Link Secrets the device currently holds, and that set changes while scanning runs — a link is made, a link is removed. **DCR-074 settled the identical question for Trust Tier classification and the answer is the same here**: the set is read at the moment of the match, so removing a link stops that account's devices matching on the very next advertisement rather than at the next restart. A set captured when scanning started would keep recognising a removed peer for as long as the scan runs, and would pass a test that restarts the process.

#### `Lost` is an age-out, and it is evaluated when a report arrives

BLE has no counterpart to mDNS's `ServiceRemoved`: a peer that walks away simply stops advertising, so something has to decide when it is gone. **`BleSource` decides, on the monotonic clock, after 30 seconds without a report for that handle.** Thirty is several advertisement intervals, so a couple of lost packets do not drop a peer, and it is far below the 15-minute EID rotation, so a peer whose EID has just rotated is never aged out for that reason. **A handle that rotates is the other case and the age-out is not confused by it but is the mechanism for it**: that address really is gone, and thirty seconds after its last report it stops being listed and stops being dialled.

**The age-out is evaluated when a scan report arrives and at no other time, which leaves one gap and it is named rather than hidden.** Doing it on a timer would need an asynchronous sleep, and Layer 1's `Clock` reads time without being able to wait for it — adding a timer port is a larger decision than this one and would not change the answer while any Tradr device is in range, because every advertisement from any of them drives the check. What it does not cover is a radio that goes completely quiet: the last peer seen stays listed until something else is heard. That is a bounded staleness in a list the user is looking at, not a path anything dials, and it is recorded as a Deferred entry with the timer port as its exit.

**This is where `Clock`'s two methods earn the split.** The EID window is wall-clock, because both devices must land in the same 15-minute bucket; the age-out is monotonic, because a wall clock that steps backwards mid-scan would otherwise revive an expired peer or expire a live one.

#### A BLE error says why, and one variant is the retreat

`DiscoveryError` has `Closed` and `Io`, which is all Layer 1 needs to know about any source. **BLE has failures that are neither, and the interface has to be able to say so**: the adapter is off or absent, the user refused the runtime permission, or the radio cannot do the peripheral role at all. So the two traits return a `BleError` of their own, and `BleSource` narrows it to a `DiscoveryError` at the `DiscoverySource` boundary rather than widening a Layer 1 type that four sources share.

**`Unsupported` is the variant D4 reads.** A platform that cannot advertise reports it once, the device runs scan-only from then on, and the capability flag is what tells peers. That is the whole retreat, expressed as a value rather than as a build configuration.

### 3. Static Peer — overlay networks and fixed IPs, Tier 1

A reachable address the user registered by hand.

```jsonc
{
  "label": "Home desktop",
  "endpoints": ["desktop.tail9f3c.ts.net:21820", "192.168.10.5:21820"],
  "expect_device_id": "3f9a..."   // filled in on the first connection
}
```

- Several endpoints are allowed, tried in order — in practice, in parallel
- **This is what Tailscale, WireGuard, and ZeroTier use.** On those networks the peer is simply reachable, so Tradr needs no reachability trickery. It only needs the address, which the user supplies once
- MagicDNS names such as `*.ts.net` work directly; resolution is left to the system resolver
- Recording `expect_device_id` detects DNS hijacking and address reassignment. The first connection pins it, and later mismatches refuse the connection with a warning

**A convenience**: where Tailscale is installed, read `tailscale status --json` and offer tailnet devices as candidates. This only saves typing addresses and creates no dependency — with no such command present, it silently does nothing.

#### What a Static Peer entry is keyed by, and what the first connection writes back

**An entry carries an id of its own**: 16 random bytes rendered as 32 lowercase hex characters, generated when the entry is created, and it is the `ObservationKey` this source reports under. The two obvious alternatives are both wrong in the same way. **The label is user-editable**, so a rename would report a new `ObservationId`, and the peer list's replacement rule would leave the old observation standing beside the new one -- one device shown twice, with the pin attached to whichever copy the user did not act on. **The endpoint list is editable too**, and an entry naming two endpoints has no single one to be keyed by.

**A missing port is filled in with the default before the endpoint becomes a candidate**, so what reaches the transport always carries one. In order: an endpoint that parses as a socket address is kept as it is; one that parses as a bare IP address gets the default port appended, bracketed first where it is IPv6; anything else that already ends in `:` followed by digits is kept; everything else gets `:21820` appended.

#### The default port, and why it is not 51820

A Static Peer's address has to name a port, and **nothing on an overlay network can tell the dialling side which one the listener chose**. mDNS carries the bound port in its SRV record and that is why the LAN case never needed a default; a tailnet has no mDNS, so the port is either a constant both sides know or a number the user has to read off the other device.

**Tradr listens on UDP 21820 by default**, and the examples above are written with it. **51820 is the one number that must not be chosen**, and this document used it until 2026-08-31: it is WireGuard's default, and an overlay network is precisely the deployment this section exists for, so the collision would land on exactly the users this feature is for. 21820 sits below Linux's default ephemeral range, 32768 to 60999, so the kernel never hands it to another process on the same machine, and no `/etc/services` entry names it.

**The bind falls back to an ephemeral port when the default is taken**, which is what happens whenever two instances run on one machine -- how this is developed and tested. mDNS advertises the port actually bound, so LAN discovery is unaffected by the fallback. A Static Peer cannot be told, and that asymmetry is the whole reason a default has to exist.

#### The pin: what fills it in, and what may never overwrite it

**The registry is the only thing that decides what a Static Peer connection expects.** An entry holding `expect_device_id` yields `PeerExpectation::Device(that id)`; an entry without one yields `Unpinned`. **Handing back `Unpinned` for a pinned entry is the failure this section exists to prevent**: a hijacked DNS name or a reassigned address is then authenticated to whatever key answers, and nothing downstream catches it, because every signature the impostor makes is valid under its own key. That makes the choice a Critical Module by [CLAUDE.md](../CLAUDE.md#6-critical-modules--tests-come-first)'s own test -- a named, severe failure that nothing else notices -- so its tests are written before its implementation.

**The pin is written by whoever completed the connection**, from the `DeviceId` the channel authenticated, and **only into an entry that holds none**. Once an entry is pinned a differing Device ID cannot arrive, because the expectation would have refused the connection before a channel existed; so a second pin is a bug in the caller rather than a peer that moved, and it is refused rather than applied. **There is deliberately no re-pin operation.** Re-pinning and accepting an impostor are the same act performed for different reasons, and the interface cannot tell them apart; a user who really did rebuild the far device deletes the entry and adds it again, which is a decision they take rather than one the code takes for them.

**The source never probes.** It reports every entry the moment it starts and again whenever the set changes, reachable or not -- "an entry the user registered by hand is a real, reachable, listable peer with no Device ID at all" is this document's own rule -- and it opens no socket and holds no timer. When a pin is written it re-reports the same `ObservationId` with the Device ID now present, which is the trust-on-first-use path described above and needs no operation of its own.

#### Where the set is kept

`static-peers.json` in the application data directory, rewritten whole on every change. **Nothing in it is secret** -- a label, some addresses, and a public device identifier -- so the `SecretStore` ladder [docs/05](05-security.md#key-storage) defines for key material is the wrong home for it. **A missing file is an empty registry rather than an error**, which is what a first run looks like. **A malformed file is an error and must not be replaced with an empty one**: silently starting over deletes every pin the user holds, and the next connection to each of those peers accepts whatever answers.

### 4. Brokr presence registry — from anywhere, Tier 2

Active only when a Brokr is registered.

- Devices hold a WebSocket open to the Brokr: always on desktop, only while running on Android
- The Brokr tracks each device's Device ID, last-seen time, and observed reflexive address
- Peer presence and address candidates can be queried
- Offline peers can be woken through FCM or APNs

Details in [07](07-brokr.md).

### What a Discovery Source reports

**A `DiscoverySource` does not return a list of peers. It reports events.** All four sources are continuous rather than one-shot: mDNS records arrive and expire, a BLE advertisement is seen and stops being seen, a Brokr's WebSocket pushes presence changes, and the Static Peer set changes when the user edits it. A method returning a snapshot would make every source keep one internally anyway, and would lose the one thing a snapshot cannot express — the moment a peer went away.

| Event | Meaning |
|---|---|
| `Observed(PeerObservation)` | This source can currently see this peer, and here is everything it knows. **It replaces any earlier observation carrying the same `ObservationId`**, rather than adding a second one |
| `Lost(ObservationId)` | This source can no longer see that observation. It says nothing about the other three, which may still see the same device |

**An observation is keyed by what its source calls it, not by the Device ID**, and a Static Peer forces that. Its `expect_device_id` is empty until the first connection fills it in, so an entry the user registered by hand is a real, reachable, listable peer with no Device ID at all. A key that a source cannot always supply is not a key.

| `PeerObservation` field | Contents |
|---|---|
| `id` | An `ObservationId`: the `SourceId` that produced it, plus a key that is meaningful only to that source. Two sources may use the same key and mean different devices |
| `device_id` | The Device ID, once this source knows it, and absent until then |
| `candidates` | Every address this source currently offers for the peer. One observation carries several, because a Static Peer registers several endpoints |
| `display_name` | The name the peer publishes — the mDNS TXT `n`, at most 32 bytes. Validated the way a candidate address is, never parsed |
| `capabilities` | The bitmask under Capability flags below |

**Trust on first use needs no operation of its own.** When a Static Peer's first connection fills in `expect_device_id`, its source re-reports the same `ObservationId` with the Device ID now present, and the replacement rule above folds it into whichever peer already holds that Device ID. A separate `identify` call on the peer list would be a second way to change an observation, and therefore a second thing for the two to disagree about.

### The peer list

Every observation from every source, merged. Four rules, and the interesting ones are the last two.

- **Observations sharing a Device ID are one peer.** Every observation whose `device_id` is present joins the peer for that Device ID; every observation without one is a peer by itself, since nothing yet says it is the same device as anything else
- **A peer's candidate set is the union of its observations' candidates, deduplicated and in a fixed order** — by transport, then by address. `Candidate` derives `Eq` and `Hash` exactly so that this is a set union. The order is not a preference: Phase 3 races all of them at once, and a fixed order is here so that the same inputs produce the same list twice
- **A peer reports no merged name and no merged capability set.** Two sources can disagree about both, and every rule for reconciling them is a policy — take the newest, take the union, take the most conservative bit by bit — that belongs to whatever is about to act on the answer. So each observation keeps its own, the peer exposes the observations it was built from, and a caller that needs one name picks it and owns that choice
- **An event is refused if its `ObservationId` names a source other than the one that produced it.** [docs/05](05-security.md#threat-model) does not trust a Brokr, and a Brokr source able to emit an observation labelled `mdns` could replace a LAN peer's candidate set with addresses of its own choosing — the peer list would merge them under a Device ID the Brokr also chose, and path selection would dial them. The list is told which source each event came from and compares it against the event's own claim

**The peer list runs no sources.** Merging touches no clock, no socket and no executor, so it sits with the domain types in `tradr-core` and its tests need none of the three. Driving four sources at once is a `select` over four futures, needs an executor, and belongs with the implementations in `tradr-discovery`.

**It lives in `tradr-core` for a second reason, and that one is not a preference.** Phase 1 of path selection reads a peer's candidates, path selection lives in `tradr-transport`, and `ci/layer-deps.sh` permits an implementation crate only `tradr-core` and `tradr-proto`. A `Peer` declared in `tradr-discovery` is a `Peer` that `tradr-transport` cannot name.

## Transports

| ID | What it is | Tier | Typical throughput | Where it applies |
|---|---|---|---|---|
| `direct-quic` | QUIC over UDP straight to the peer's address | 0 / 1 | 50-110 MB/s on LAN; network-bound on a tailnet | The default. Peers found via mDNS or a Static Peer |
| `wifi-direct` | A Wi-Fi P2P group carrying QUIC | 0 | 15-25 MB/s | Android to Android with no shared LAN |
| `holepunch-quic` | QUIC through a NAT hole opened via Brokr rendezvous | 2 | Network-bound | Direct connection across networks |
| `relay` | A Brokr forwarding ciphertext | 2 | Bound by the Brokr's uplink | When hole punching fails |
| `ble-gatt` | A BLE GATT write characteristic | 0 | 20-100 KB/s | 512 KiB or less with no Wi-Fi |

### Why QUIC

Chosen over TCP with TLS — see [ADR-0004](adr/0004-quic-as-the-bulk-transport.md):

1. **Multiplexed streams.** Control messages and several file bodies ride independent streams of one connection. On TCP, control queues behind payload — head-of-line blocking.
2. **Connection migration.** Switching from Wi-Fi to cellular, or changing IP, does not end the connection. That matters for the real behaviour of carrying a laptop mid-transfer.
3. **Fits hole punching.** Being UDP, the socket used to punch the hole is the socket used to transfer.
4. **0-RTT resumption.** A previously contacted peer connects one round trip sooner, which shows up in the feel of frequent short transfers.

Implemented with `quinn`.

### Why Wi-Fi Direct is Android-only

Desktop Wi-Fi Direct APIs do not line up — Linux goes through `wpa_supplicant` P2P, Windows through WinRT, and macOS exposes nothing public — and most implementations tear down the existing Wi-Fi connection. What it breaks outweighs what it delivers. Restricted to Android pairs; anything involving a desktop relies on a shared LAN or a Brokr.

### The `ble-gatt` link is two characteristics, and the ATT operation boundary means nothing

The service is slot `0x0002` of the base UUID [ADR-0019](adr/0019-a-128-bit-service-uuid-for-the-ble-advertisement.md) reserved, `00000002-6eed-40d6-85d3-3794eaa7b21c`, and it holds two characteristics rather than one:

```
service 00000002-...      the ble-gatt service
  +- 00000003-...         central -> peripheral, written by the central
  \- 00000004-...         peripheral -> central, notified by the peripheral
```

**Two, because a characteristic has one value and two directions cannot share one.** A single characteristic that the central writes and the peripheral notifies would have each side overwriting what the other had just put there, and no ordering between the two uses.

**The service UUID is not advertised.** ADR-0019 spends all 28 of Tradr's bytes on the advertisement service and its Service Data, so a central dials the handle its scan reported and discovers this service after connecting. Which end holds the server is not a preference: R1 is that this machine's Linux controller refuses every advertisement, so the peripheral is whichever side can advertise.

#### The central writes without response and the peripheral notifies, and neither is a preference

| Characteristic | Properties | Descriptor |
|---|---|---|
| `00000003-...` | `write-without-response` | none |
| `00000004-...` | `notify` | Client Characteristic Configuration, `0x2902` |

**An acknowledged write cannot reach the throughput this document's own opening table gives the link.** An ATT Write Request occupies the bearer until its Write Response arrives, so the next one leaves no earlier than the following connection event -- one operation every 30 ms at a typical interval, whatever the MTU is, which is an order of magnitude under the 5-100 KB/s the rows above assume. An unacknowledged write is several operations per event, and what makes it reliable is the Link Layer retransmitting until acknowledged, which is the same sentence as the subsection below: loss and ordering arrive from under ATT and are not this framing's to add. **A response at the ATT layer would confirm a delivery the layer beneath has already guaranteed**, at the cost of the only throughput this transport has.

**The flow control this design specified is the local one, and the unacknowledged pair is the pair that has it.** The subsection below says a send is complete once the platform has accepted the operation, and that a stack whose buffers are full reports that rather than dropping it. That report is exactly what a host writing Write Commands into a full controller buffer is given, and it is the whole of what BLE offers a sender. **What it is not is end-to-end**: nothing here tells a sender that the peer's application read the bytes, and nothing needs to, because a record that fails to arrive fails authentication and closes the channel ([docs/05](05-security.md#a-records-place-in-the-sequence-is-its-nonce-so-encrypting-and-transmitting-are-one-critical-section)).

**And the acknowledged forms do not tell the sender the MTU, which the framing above requires it to know.** The sender chops its byte stream to whatever the current MTU carries; BlueZ reports that number only through `AcquireWrite` and `AcquireNotify`, and grants those only to a characteristic carrying `write-without-response` and `notify` respectively. `WriteValue` neither reports the MTU nor leaves the segmentation to its caller -- it performs a long write of its own devising underneath a framing that has already decided how a record crosses an operation boundary. **So the properties are what makes the framing above implementable rather than a preference between two workable shapes.**

**Only the peripheral's direction takes a descriptor.** A notification goes to a client that has subscribed and subscribing is a write to the Client Characteristic Configuration, so `00000004-...` carries one and `00000003-...` carries none: nothing subscribes to the central, which writes when it has bytes.

#### No record fits one ATT operation, so each direction is a byte stream

An ATT operation carries `ATT_MTU - 3` bytes and never more than 512, which is the longest an attribute value may be, and the MTU is negotiated once per connection. **The largest MTU that negotiation can reach is 517, so the largest operation is 512 bytes and the largest record this link has to move is 528** -- the 512-byte mux record [docs/04](04-protocol.md#the-in-band-multiplexing-frame) bounds, plus Poly1305's 16-byte tag. **So a record does not fit an operation even at the maximum MTU**, and at the 247 ADR-0002's throughput row assumed it carries 244, which is short of `Noise_XX`'s 299-byte second message ([ADR-0020](adr/0020-noise-xx-for-ble-gatt.md)).

**A minimum MTU is therefore not the answer, and requiring one would be worse than the problem.** It would make the transport's availability depend on a negotiation neither end controls, in exactly the case -- proximity, no Wi-Fi -- where `ble-gatt` is the only path there is.

**So the operation boundary carries no meaning at all and each direction is a byte stream.** A record goes on it length-prefixed:

```
[u16 len][record]        len is big-endian and counts the record alone
```

The sender chops that stream to whatever the current MTU carries; one operation may hold the tail of one record and the head of the next, and a record may span as many as the MTU requires. **The MTU is never a parameter of the framing** -- it is a platform fact that a re-negotiation may change mid-connection, and it belongs to the side that owns the radio.

#### What the reassembler refuses, and why every refusal is permanent

| Refused | Why |
|---|---|
| A length of `0` | A Noise record is never empty: the tag alone is 16 bytes |
| A length above 528 | The bound above, and the only thing keeping the reassembly buffer bounded |
| The link ending mid-record | A byte stream that stops between the prefix and its record ended in error, which is a different sentence from a link that ended |
| One delivery larger than 530 | An ATT operation cannot carry more, so a larger one is not this link speaking |

**Each is permanent**, the poisoning [docs/04](04-protocol.md#the-in-band-multiplexing-frame) already makes `FrameDecoder` and the multiplexer do, and for the same reason one layer down: after a refusal nothing in the byte sequence has a known position, so a reassembler that carried on would hand records above that are correctly framed and wrong.

**The bound on peer-controlled memory is one pending record and one delivery**, which is the DCR-095 quantity counted at this layer. An incomplete record is at most 529 bytes, its prefix and one byte short of the longest record it may announce, and a delivery is at most 530, so the buffer never holds more than 1059.

#### Loss and ordering are the Link Layer's, and flow control is not

A Noise record's place in its direction's sequence is its nonce ([docs/05](05-security.md#a-records-place-in-the-sequence-is-its-nonce-so-encrypting-and-transmitting-are-one-critical-section)), so a record that arrives out of order fails authentication and closes the channel. **BLE supplies both properties below ATT**: the Link Layer retransmits until acknowledged and delivers in order, so neither is this framing's to add, and a sequence number here would detect one layer earlier something the layer above already treats as fatal.

**What BLE does not supply is host-side flow control.** A stack whose buffers are full reports that it could not accept the operation rather than dropping it, and a send is complete only once the platform has accepted it. That is what `LinkSink::send_record` returning `Result` already says, and a stack that reports it could not is a link error rather than something to retry.

#### The responder's handshake driver measures one round trip, and not the wait for a peer

**The initiator's driver landed alone, and the two ends are not symmetric in what each can honestly report.** `handshake_as_initiator` runs where the dial is, and `dial` above times itself: from before it connects to after it has written the third message, which is a connect plus one round trip and every millisecond of it work this side asked for. The responder's first act is to wait, and that wait has no bound at all -- a GATT server holds a byte stream that begins whenever a central decides to write into it, which may be hours after the server started.

**Timing the responder's call would therefore report how long a peer took to arrive.** That is not a property of the link, it is a property of the person holding the other phone, and the section above spends `SecureChannel::rtt` on scoring one candidate against another of the same class. A responder that reported its wait would score `ble-gatt` behind every transport that measures honestly, on a number that says nothing about the path.

**So the responder measures from message 1 having been read to message 3 having been read.** That is exactly one round trip -- its own reply, and the confirmation that answered it -- and nothing that happened before the peer spoke. **The driver takes the `Clock` and returns the duration beside the session** rather than leaving the caller to time a call whose start it cannot see: the boundary being measured is inside the driver, and a caller timing the whole call would measure the wrong thing by construction.

**A link that ends before message 1 or message 3 arrives is `Closed` and never an authentication failure.** Nothing was refused: the byte stream ended between records, which is what the reassembler above already distinguishes from a stream that stopped mid-record. Only a message that arrived and did not verify is `AuthenticationFailed`, and that is the same rule the initiator's driver holds.

## Path selection

The mechanism behind picking the right path automatically. **It does not pick — it races and keeps the winner.** The same idea as ICE and Happy Eyeballs.

```
+- Phase 1: gather candidates (~200 ms) --------------------+
|  Collect every way discovery says the peer is reachable   |
|    mDNS      -> 192.168.1.42:51820        (direct-quic)   |
|    Static    -> desktop.tailnet.ts.net    (direct-quic)   |
|    Brokr     -> 203.0.113.7:44821         (holepunch-quic)|
|    Brokr     -> relay://brokr.example/x   (relay)         |
|    BLE       -> handle:0x0042             (ble-gatt)      |
+-------------------+---------------------------------------+
                    v
+- Phase 2: prefilter --------------------------------------+
|  total bytes > 512 KiB          -> drop ble-gatt          |
|  metered link, not user-approved -> drop relay            |
|  no candidates left              -> queue as              |
|                                     "waiting for network" |
+-------------------+---------------------------------------+
                    v
+- Phase 3: race (3 seconds maximum) -----------------------+
|  t=0 ms     handshake every direct-quic candidate at once |
|  t=0 ms     begin hole punching                           |
|  t=1500 ms  start relay if nothing has established yet    |
|             (a head start for direct paths, so relay      |
|              bandwidth is not spent needlessly)           |
|  t=3000 ms  time out                                      |
+-------------------+---------------------------------------+
                    v
+- Phase 4: adopt ------------------------------------------+
|  Among those established, take the highest score:         |
|    score = class_weight(transport) - rtt_ms / 10          |
|    class_weight: direct-quic 1000 / wifi-direct 800       |
|                  holepunch-quic 700 / relay 300 / ble 50  |
|  Abandon the remaining handshakes immediately             |
+-------------------+---------------------------------------+
                    v
+- Phase 5: re-evaluate mid-transfer -----------------------+
|  Path drops        -> back to Phase 1, resume from the    |
|                       last acknowledged chunk             |
|  Running on relay  -> switch at the next chunk boundary   |
|  and direct opens     to the direct path                  |
+-----------------------------------------------------------+
```

### A transport delivers an already-secure channel

`Transport::connect` returns a `SecureChannel`, never a raw byte stream. [docs/05](05-security.md#two-encryption-layers) gives two families for the five transports — QUIC paths use QUIC's own TLS 1.3, while `relay` and `ble-gatt` use Noise_IK — and says the layer above is never told which.

**That promise is only keepable if each implementation owns its own encryption.** `direct-quic` gets it from the protocol; the `relay` and `ble-gatt` implementations wrap their raw stream in Noise before returning, and **`ble-gatt` is where the identity join lives**, because a Noise handshake authenticates an agreement key and `SecureChannel::peer` answers with a Device ID ([ADR-0020](adr/0020-noise-xx-for-ble-gatt.md)). Putting the Noise handshake in Layer 1 instead would mean the core branching on which transport it is holding, which is the coupling the trait exists to prevent, and it would put a second encryption layer on the QUIC paths or a conditional that skips it.

A `SecureChannel` therefore offers the same thing on every path: mutually authenticated, forward secret, ordered, bidirectional, and multiplexed into the streams [docs/04](04-protocol.md#the-three-planes) describes. Where the underlying transport has no native multiplexing, the implementation provides it in-band, which is what the `stream_id` frame variant in docs/04 is for. **Layer 1 asks for a stream and gets one**; whether that cost a QUIC stream or a frame header is not its concern.

### What the core knows about a transport

**No trait that changes when a transport is added.** Change Drill D10 budgets one implementation, one registration, one weight-table entry and one capability bit for a new transport, and forbids any change to a trait in `tradr-core`. **The bit is in the budget rather than outside it**: the flags below enumerate transports deliberately, and naming a reserved value rewrites nothing. Two things follow, and both are constraints on the `Transport` trait rather than observations about it.

- **A transport's identity is an opaque token, not a closed set.** The core carries a `TransportId` it can compare, order and display, and cannot enumerate. An `enum { DirectQuic, WifiDirect, ... }` in the core would make every new transport a core change, which is the one outcome the drill forbids
- **A candidate address is opaque too.** `192.168.1.42:51820`, `relay://brokr.example/x` and `handle:0x0042` share no structure, and the core has no reason to parse any of them. It collects candidates from discovery and hands each to the transport that produced it
- **Opaque is not unchecked.** A candidate can arrive from a Brokr, which [docs/05](05-security.md#threat-model) does not trust, and it reaches logs and the UI on its way to a transport. So the core rejects an empty address and one carrying control characters: the same two rules, and the same reasoning, as the `item_id` token in [docs/04](04-protocol.md#partial-files). It checks nothing else, because everything else is syntax only a transport knows. **The transport that receives a candidate validates it before use**, and that is a contract on each implementation rather than something the core can do for them
- **The class weights above belong to path selection, not to the transports.** A weight is a comparison between transports, so it is a policy of the component doing the comparing. `tradr-transport` holds the table; a transport does not report its own rank
- **A frame-size limit is the opposite case, and the channel reports it.** [docs/04](04-protocol.md#framing) negotiates `max_frame_size` in `Hello` — 1 MiB by default, 512 bytes over BLE — and that negotiation happens in Layer 1. Either the core carries a per-transport table of limits, which is the table this whole section exists to keep out of it, or the established channel says what it can carry. It says. Unlike a weight, a limit is a property of one path rather than a comparison between several
- **A round-trip estimate is reported and never invented.** `SecureChannel::rtt` is a method rather than a value so that Phase 5 can score a path it is already running on, and a transport that measures continuously -- QUIC does -- answers with what it currently observes. **A transport that measures nothing answers with what establishing the link cost**, which is a number it holds, rather than manufacturing a moving one out of a constant. `ble-gatt` is that case: BLE offers no continuous estimate and this protocol has no ping below the planes, so the channel is constructed with the round trip its own handshake took. The scoring above is what makes that affordable -- the rtt term subtracts one point per ten milliseconds against a class weight of 50, so the comparison it decides is between candidates of the same class

### A discovery source must emit an address its transport can parse

"Opaque to the core" above says the core does not parse a candidate address. It does not say a source may write whatever it likes: **a candidate no transport can parse is a peer that silently never connects**, and the failure surfaces inside the transport at dial time, far from the source that built the string.

`direct-quic` parses a candidate with `str::parse::<SocketAddr>()`, and resolves it as a name only when that parse fails (see "How `direct-quic` turns a candidate into an address" below). Measured against rustc 1.98.0 on 2026-08-27, that parser accepts `192.168.1.42:51820`, `[2001:db8::1]:51820` and `[fe80::1%2]:51820`, and **rejects `[fe80::1%eth0]:51820` and RFC 6874's `[fe80::1%25eth0]:51820`**. So a link-local IPv6 candidate carries the **numeric** interface index, never the interface name.

**This is a trap rather than a detail, because the obvious implementation gets it wrong on one platform only.** `mdns-sd`'s `ScopedIp` has a `Display` that renders the scope as the interface *name* off Windows and as the *index* on Windows, so `format!("[{scoped}]:{port}")` produces an address `direct-quic` refuses on Linux and accepts on Windows — a platform-dependent failure that testing on either one alone would miss. A source reads the index field and formats the address itself.

**The general rule is the part worth keeping.** A library's own `Display` is written for a human reading a log, not for the parser at the other end of this design; where a source converts a library type into a candidate, what it owes is a string the receiving transport accepts, checked against that parser rather than against how the value prints.

### How `direct-quic` turns a candidate into an address

A Static Peer's endpoint is a name as often as it is an address — `desktop.tail9f3c.ts.net:21820` is the example this design has carried since the design phase — so the transport parses first and resolves second. `str::parse::<SocketAddr>()` runs on every candidate; only where it fails does the address reach the system resolver, through `tokio::net::lookup_host`. A literal therefore costs no resolver query and no thread hop, and every rule the section above states about scoped IPv6 is unchanged, because the same parser still decides it.

Four rules govern what happens after that, and three of them were established by running the resolver rather than by reading its documentation.

- **Resolution happens per dial and the transport caches nothing.** An overlay network reassigns addresses, and a cache inside a transport is a second place a stale address lives with nothing to invalidate it. The system resolver has a cache and it is the one that gets to be wrong.
- **The resolver's answer is filtered to what this endpoint can dial, and the first survivor is dialled.** Measured on 2026-08-31, `example.com:51820` answers **AAAA first**, and a `quinn::Endpoint` bound to `0.0.0.0` refuses every IPv6 remote with `InvalidRemoteAddress` before a packet leaves. So an unfiltered "take the first" makes every dual-stack name unreachable on the socket this application actually binds, and it fails for a reason that names neither DNS nor the socket. An endpoint bound to `[::]` accepts both families and is the exit, but not on every platform for free — see [DF-24](../STATE.md).
- **The transport dials one address and does not race them.** Phase 3 above already races every candidate at once and owns the three-second deadline; a second race inside one transport competes with it and makes the timing of a single candidate irreproducible. A name that answers with an address that does not respond is a candidate that fails, exactly as a literal one would.
- **Every resolution failure is `Unreachable`.** An unknown name, an answer with no usable address, and a string carrying no port at all are all decided before a packet reaches the peer, which is what that variant means. The query to the resolver is not a packet to the peer, so the "local verdict" reading below is unchanged. **A missing port is a resolution failure rather than a parse failure**, and worth naming because it does not look like one: `lookup_host("192.168.1.42")` fails with `InvalidInput`, and so does `lookup_host("desktop")`.

### What a transport is told about the peer it is dialling

`Transport::connect` takes a second argument beside the candidate: a `PeerExpectation`, which is what the dialling side already knows about the device it is reaching for. Three variants, and they are the three states of identity knowledge this design has rather than a guess at what a transport might want.

| Variant | Where it comes from | What the transport must do with it |
|---|---|---|
| `Unpinned` | A Static Peer's **first** connection, whose `expect_device_id` is empty until that connection fills it | Authenticate the peer to whatever key it presents, and report the `DeviceId` that key derives. Refuse a peer that presents no key at all |
| `Device(DeviceId)` | mDNS, a Brokr, and every Static Peer connection after the first | Refuse unless the key the peer proves possession of derives exactly that `DeviceId` |
| `Identity(PublicIdentity)` | A peer already known in full, both public keys | As `Device`, and additionally refuse unless the agreement key the channel authenticated is the one named here |

**`Unpinned` is not "unauthenticated", and the distinction is the whole reason the variant can exist.** The peer still proves possession of the key its certificate names, so the channel is mutually authenticated and `SecureChannel::peer` still cannot fail; what is absent is only a *prior* expectation to compare that key against. Trust-on-first-use pinning is then the caller's, above the transport, which is exactly where docs/03's Static Peer already puts it — "the first connection pins it". The account-level question is answered later still, by the Attestation exchange in `Hello` ([docs/04](04-protocol.md#the-three-planes)), which does not consult this argument at all.

**It is an argument to `connect` and not a field on `Candidate`, and three separate facts forced that.**

- **A Static Peer's first connection has no `DeviceId` to put there.** A field would have to be optional on a type where every other reader treats it as known
- **`Candidate` derives `PartialEq`, `Eq` and `Hash`, and collapsing one `DeviceId` arriving from several sources into one peer is what those derives are for.** A per-attempt field on it would silently make one address two candidates
- **mDNS carries an 8-byte fingerprint of the agreement key, and `Noise_IK` needs the whole key.** So a candidate could not carry the expectation `ble-gatt` needs even if the first two objections were answered

**That third objection was right about mDNS and wrong about what followed from it, and [ADR-0020](adr/0020-noise-xx-for-ble-gatt.md) is the correction.** No source supplies a whole agreement key — a BLE advertisement carries no per-device identifier at all, and nothing persists a peer's `PublicIdentity` — so `Noise_IK` on `ble-gatt` was waiting on a value that was never going to arrive. **`ble-gatt` is `Noise_XX`**, which needs no prior key, and the three variants above are therefore three degrees of comparison rather than three degrees of capability: **every `ble-gatt` dial is `Unpinned`** today, because that is what BLE discovery produces, and the channel is mutually authenticated all the same.

**The type is `#[non_exhaustive]` and that keeps it inside Change Drill D10.** A fourth state of identity knowledge would be a variant nobody was matching exhaustively on, which rewrites no existing line -- the same reasoning as the reserved capability bit below. **What D10 forbids is changing the trait**, and this argument is added once, before the first transport exists, rather than by a transport paying for itself.

**A transport needing something that is not identity knowledge takes it at construction, not per connect.** A pairing code, a relay token, a Brokr's address: those are configuration of one transport instance, and putting them here would turn a closed domain vocabulary into a bag every transport adds to.

### What a transport can know about a refusal, and what it must not invent

A `Transport` reports `TransportError`, a closed set of six. Mapping a real transport's failures onto it turned out to decide two things the design had not settled, and both were established by running a QUIC handshake rather than by reading a crate's documentation.

**A QUIC peer cannot tell a pin mismatch from a forged signature, and must not pretend it can.** Both arrive as one opaque CRYPTO_ERROR code -- RFC 9000's `0x0100` to `0x01ff` range, carrying a TLS alert number in its low byte -- and the dialling side sees it as a transport error while the listening side sees the same code inside a connection-close frame. **So every code in that range is `AuthenticationFailed`, whichever side reports it.** That is wider than "the peer's key did not match the expected Device ID", and the type says so: the finer distinction is not on the wire, and a transport that invented one would be handing a caller a fact it does not have. What the variant guarantees is the part that matters to a caller — **the peer failed to authenticate, and retrying will not change that**, which is precisely what separates it from `Rejected`.

**`Unreachable` is a local verdict, not the absence of a reply.** Dialling an address where nothing listens does not produce an error: QUIC retries its Initial packets and the future simply stays pending. So `Unreachable` means the dial could not be attempted — an address this transport cannot parse, an endpoint that is shutting down, no common QUIC version — and it is decided before a packet leaves. **The deadline on waiting belongs to Phase 3 above, which already owns a three-second race**, and a transport that invented a second one would compete with it. A dial into nothing does resolve eventually, at the QUIC idle timeout -- `quinn`'s own default of 30 seconds, which this design accepts rather than chooses. **Choosing a value belongs with Phase 5 and not here**: the same timeout governs an established connection, so a number picked to make a failed dial fail sooner is a number that also decides when a paused transfer is abandoned.

**This is also why `Rejected` and `Closed` are separate.** A peer that closes during the handshake with a non-crypto code refused the connection; a peer that closes an established one is `Closed`. A caller retries the first and does not retry the second, and neither is a security event.

### Phase 5 is the point

**Refusing to make path selection a one-time decision is the most important thing in this design.**

Because transfers resume at chunk granularity (see [04](04-protocol.md)), any choice of path is always revocable. That property buys:

- A short Phase 3 timeout, since guessing wrong is correctable
- Safe optimization such as starting on relay and moving to direct
- Transfers that survive carrying a laptop into another room and onto another access point
- No special handling for the "waiting for network" queue — it is simply the state of having zero candidates, inside the same state machine

Read the other way: **if chunk-level resumption breaks, the entire path-selection design stops working.** It gets tested first and hardest.

### Worked example: sending to a home PC over Tailscale

1. A Static Peer already holds `desktop.tail9f3c.ts.net:21820`
2. Phase 1: mDNS returns nothing, being another network. The Static Peer yields one candidate. No Brokr is configured, so there are no others
3. Phase 3: QUIC handshake over the tailnet establishes at 25 ms RTT
4. Phase 4: one candidate, so it is adopted. Transfer runs at full speed as `direct-quic`
5. No Brokr appears anywhere in the sequence

WireGuard and ZeroTier behave identically. The overlay network solved reachability, so Tradr does nothing.

## Android listening and wake-up

| Tier | Mechanism | Experience |
|---|---|---|
| 0 / 1 | BLE scan and mDNS query on screen-on and at an interval, 15 minutes by default. Foreground service only during a transfer | Peers appear when you pick up the device. Fully backgrounded arrival is not possible |
| 2 | The above plus wake-up from a Brokr's FCM data message, sent at `high` priority, connecting within 10 seconds | Arrivals land with the screen off |

Continuous BLE scanning and a permanently held connection are avoided because of Doze and battery drain. The UI presents this gap as the reason to consider Tier 2.

## Capability flags

Carried in advertisements and in `Hello`, so each side knows what the other can do. A bitmask.

| Bit | Meaning |
|---|---|
| 0 | Supports `direct-quic` |
| 1 | Supports `wifi-direct` |
| 2 | Supports `ble-gatt` payloads |
| 3 | Supports `relay`, meaning a Brokr is registered |
| 4 | Accepts Share browsing |
| 5 | Has a writable Share |
| 6 | Currently on a metered link |
| 7-15 | Reserved |

**Bits 7 to 15 are where a new transport's bit comes from, and that is why they are reserved.** Enumerating transports on the wire is deliberate: a peer declares membership of a closed set rather than naming a transport in a string, so a peer cannot claim a transport that does not exist and a receiver never parses an open-ended value. The cost is that adding a transport touches `proto/`, and [Change Drill D10](../CLAUDE.md#c-flexibility-against-external-change--the-change-drill) counts that in its budget instead of pretending it does not happen.

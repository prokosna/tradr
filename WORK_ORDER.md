# Work Order WI-M7-007m — REVISE round 1

## Role

You are the **Implementer**. `CLAUDE.md` §3 and §4 bind you exactly. **Never edit** `docs/`, `STATE.md`, `RECORD.md`, `CLAUDE.md`, `AGENTS.md`, or this file. **Never commit, push, branch, stash, checkout or reset.** Leave the work in the working tree.

**Your delivered tree stands and is not being discarded.** Fifteen mutations were run against it: five against `LocalCapabilities` and all five killed by exactly the tests that name them, and the rest are the three findings below. The implementation is right; two findings are the tests, and one is the Supervisor's own instruction being withdrawn.

## Finding 1 — the rule this whole Work Item exists for can be reverted with the entire suite green

`crates/tauri-plugin-tradr/src/listener.rs`, in `handle_incoming_channel`, reads `our_capabilities: params.our_capabilities.get()`. **Replacing that with the literal `tradr_core::Capabilities::DIRECT_QUIC` leaves `cargo test -p tauri-plugin-tradr` entirely green — measured, not assumed.** So does every weaker mutation of it.

That line is the whole of DCR-105: the declared set is read where the `Hello` is composed rather than captured once, and the doc comment you wrote on `ListenerParams::our_capabilities` asserts exactly that — "fresh for each connection rather than captured once at startup". **Nothing checks the sentence.** Nineteen test sites now build an `Arc<LocalCapabilities>` and not one of them ever reads what reached the wire.

### What to add

One test in `crates/tauri-plugin-tradr/tests/listener.rs`, named for what it pins. It drives `listen_for_transfers` over `MockIncoming` with **two** channels and **one** `Arc<LocalCapabilities>` shared between them, declaring `Capabilities::BLE_GATT` between the first connection and the second.

The peer side does not complete a handshake and does not need to. For each channel it:

1. opens a bi stream,
2. builds its own `PeerHello` through `tradr_identity::hello::open` and writes it with `tradr_proto::hello::encode_hello_frame` — the identity fixtures, `SeededRng`, `FakeClock` and `read_frame_helper` in that file are what the existing tests already use,
3. reads the listener's reply with `read_frame_helper` and decodes it with `tradr_proto::hello::decode_hello_frame`,
4. asserts on `capabilities().bits()`, then drops its handle.

**Assert against literals, not against the constants the test exists to pin**: `1` for the first connection and `0b101` for the second. An assertion computing its expectation out of `Capabilities::DIRECT_QUIC.bits()` is the finding this milestone has now recorded four times.

`listen_for_transfers` awaits each channel inline, so the two connections are strictly ordered and the test needs no `sleep` and no wall-clock wait (E3). A peer that drops mid-handshake makes `handle_incoming_channel` return an error, which that loop prints and carries on from — that is the existing behaviour and is what lets one test hold two connections.

**Verify by breaking it** (E1): put the `Capabilities::DIRECT_QUIC` literal back in `handle_incoming_channel`, confirm this test and no other fails, quote the assertion failure with its left and right values, and restore the line.

## Finding 2 — `TransferListener::public_identity()` has no caller

`crates/tauri-plugin-tradr/src/lifecycle.rs`. `capabilities()`, `key_store()` and `key_binding()` are all called from `spawn_ble_gatt_listener`; `public_identity()` is called from nowhere in the workspace. It is public API on a public type, so no lint reports it. **Delete it** (rule F3).

## Finding 3 — `app.manage(listener.clone())` is state nothing reads, and that instruction was mine

`crates/tauri-plugin-tradr/src/lifecycle.rs` manages the `Arc<TransferListener>` as Tauri state. Nothing extracts it: `spawn_ble_gatt_listener` receives the listener as an argument, and no command takes it. The round-1 Work Order asked for that `manage` call and was wrong to — a managed value nobody reads is a field that looks like state being kept, which is DF-16's shape.

**Delete the `app.manage(listener.clone())` line**, and with it the now-unneeded `.clone()`. `app.manage(capabilities)` **stays**: the three command wrappers read it through `State<'_, Arc<LocalCapabilities>>`.

## Change nothing else

`crates/tauri-plugin-tradr/src/capabilities.rs`, `commands.rs`, `ble_gatt_android.rs`, `lib.rs`, `tests/capabilities.rs` and the nineteen mechanical test-site edits are all accepted as delivered. Do not touch them. Do not touch `spawn_ble_gatt_listener`'s body, its six-step order, or the `declare`/`withdraw` placement.

## Gates — all five pass, and you report the output

Bounded single target first, then the workspace:

```
cargo test -p tauri-plugin-tradr --test listener --test capabilities
cargo fmt --all -- --check
sh ci/run-all.sh
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Format files you edited with `rustfmt --edition 2024 <path>` per file.

**Report the commands' actual output, never an assertion about it.** A gate you did not run is reported as NOT RUN.

## Report back

The files you changed; each of the three findings and whether it is addressed; **the verbatim assertion failure from Finding 1's break-and-restore**, with its left and right values; the verbatim tail of each of the five gate commands; and any Design Change Request you are raising.

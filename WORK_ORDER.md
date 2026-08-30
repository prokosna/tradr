# Work Order WI-M3-003: Share browsing — File download

## Target
Implement file downloading over the Browse plane.

## Design
- See `docs/04-protocol.md` and `docs/06-shares-and-browsing.md`.
- `ReadFile` and `ReadFileBegin` protobuf definitions in `proto/tradr/v1/browse.proto`.
- A file read begins by opening a new, dedicated bidirectional QUIC stream.
- The requester sends a `ReadFile` message on this stream.
- The provider validates the request (trust tier, path limits), responds with `ReadFileBegin` on the same stream, and then immediately transmits the raw file bytes on that same stream until EOF.

## Definition of Done
1. Add `ReadFileBegin` encoding/decoding in `crates/tradr-proto/src/browse.rs`.
2. Implement `handle_browse_stream` in `crates/tradr-core/src/browse.rs` to handle `ReadFile` by:
   - Verifying the file exists and is a file.
   - Returning `ReadFileBegin` on the same stream.
   - Streaming the bytes from the file to the stream until EOF.
3. Add a new `tauri::command` called `download_file` in `crates/tauri-plugin-tradr/src/commands.rs` that takes `(app, peer_id, share_id, path, dest_path)`. It should:
   - Dial the peer and authenticate.
   - Open a bidirectional stream.
   - Send a `Hello` message on the stream and receive `HelloAck`.
   - Send `ReadFile` and receive `ReadFileBegin`.
   - Write the incoming raw bytes to `dest_path`.
4. Add basic test coverage for `download_file` in `crates/tauri-plugin-tradr/tests/browse.rs` if tests exist for browse.
5. All workspace tests, `cargo fmt`, and `cargo clippy` pass without warnings.

## Constraints
- Do not add any new crates or change `Cargo.toml` dependencies.
- `tradr-core` must not depend on `tauri` or read files outside the VFS.
- Follow the rules in `AGENTS.md` and `CLAUDE.md`.

## Notes for Implementer
- You are the Implementer. DO NOT EDIT `STATE.md` or `docs/`.
- Do not commit or push. Just leave the code in the working tree.
- Report back when done.

# Work Order: WI-M1-029 (Fix QUIC transport initialization outside tokio runtime)

## The Goal
Fix a runtime panic/error on Linux (and other platforms) where `quinn::Endpoint::server` fails with `Io(Other)` representing "no async runtime found". This happens because `QuicTransport::new` is called synchronously in `tauri-plugin-tradr/src/lifecycle.rs` inside the `tauri::Builder::setup` hook, which lacks a Tokio runtime context.

## Tasks
1. **`crates/tradr-transport/src/quic/transport.rs`**:
   - Change `QuicTransportError::Io(std::io::ErrorKind)` to `QuicTransportError::Io(std::io::Error)`.
   - Update `Display` implementation for `QuicTransportError` to format the `std::io::Error`.
   - In `QuicTransport::new`, map the `rustls` to `quinn` crypto conversion error to a meaningful `std::io::Error` (e.g. `std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid TLS config")`).
   - Pass the full `std::io::Error` from `quinn::Endpoint::server` into `QuicTransportError::Io`.
2. **`crates/tauri-plugin-tradr/src/lifecycle.rs`**:
   - In `init_lifecycle`, wrap the `QuicTransport::new` invocation in `tauri::async_runtime::block_on`. For example:
     ```rust
     let transport = Arc::new(
         tauri::async_runtime::block_on(async {
             QuicTransport::new(key_store.clone(), bind_addr)
         }).map_err(|e| format!("failed to start quic transport: {e}"))?,
     );
     ```

## Constraints & Rules
- Do NOT edit `STATE.md`, `CLAUDE.md`, `AGENTS.md`, or `docs/`.
- Do NOT commit or push your changes. Leave them in the working tree.
- Ensure the project builds cleanly with `cargo check --workspace` and passes all local tests with `cargo test --workspace`.

## Definition of Done
1. `QuicTransportError::Io` holds an `std::io::Error`.
2. `QuicTransport::new` retains and propagates the original `std::io::Error` message (e.g., "no async runtime found").
3. `QuicTransport::new` is wrapped in `tauri::async_runtime::block_on` inside `lifecycle.rs`.
4. `cargo fmt --check` and `cargo clippy --workspace --all-targets -- -D warnings` pass.

# 0017. NativeVfs for Windows

Date: 2026-08-30

## Context
`PosixVfs` relies heavily on `rustix` and `openat` to provide secure, race-free boundary enforcement. However, Windows lacks `openat` and `rustix` does not support these APIs on Windows, causing the Windows CI build to fail. The desktop shell (`tauri-plugin-tradr`) hardcodes `PosixVfs`, breaking the build on Windows.

## Decision
1. `PosixVfs` remains Unix-only, gated by `#[cfg(unix)]`.
2. A new `WindowsVfs` is introduced for Windows, gated by `#[cfg(windows)]`, implemented using `std::fs` and path canonicalization for boundary enforcement.
3. `tradr_vfs::NativeVfs` is exported as a type alias: `PosixVfs` on Unix, `WindowsVfs` on Windows.
4. All usages of `PosixVfs` in `tauri-plugin-tradr` and `tradr-core` tests are updated to `NativeVfs`.

## Consequences
Windows gains a working VFS backend. Boundary enforcement on Windows relies on string/path prefix checks rather than OS-level `openat` isolation, which is a known trade-off until a more robust Windows-specific isolated VFS can be built.

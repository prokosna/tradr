# ADR-0023: One `unsafe` call adopts a file descriptor Android hands over

- **Status**: Accepted
- **Date**: 2026-09-27
- **Supersedes**: [docs/08](../08-platform-integration.md#receiving-from-the-share-sheet-uc-2)'s rule that a shared file under 50 MB is copied into the app cache, and the workspace-wide `#![forbid(unsafe_code)]` for exactly one file

## Context

A file a person picks or shares on Android arrives as a `content://` URI whose permission ends with the Activity. docs/08 had Kotlin copy anything under 50 MB into the app cache and hand Rust a detached descriptor for anything larger. **Nothing in Rust ever read that descriptor** (DF-113), so a file of 50 MB or more could not be sent from a phone, and the copies were never deleted (DF-118).

The person using it chose on 2026-09-27 to read the descriptor directly rather than copy every file, and approved the one exception this needs. **Adopting a raw descriptor as a Rust `File` is `unsafe` by construction**: `OwnedFd::from_raw_fd` has no safe equivalent, because nothing in the type system can know the number is open and owned by nobody else. Every crate in this workspace is `#![forbid(unsafe_code)]`.

The safe alternative, reopening `/proc/self/fd/N`, re-runs the path permission check against the underlying file, and a file reached through a document grant is exactly the one scoped storage refuses by path. It is expected to fail and was not adopted on a guess.

## Decision

**Exactly one function adopts a descriptor, and it is the only `unsafe` in the workspace.**

- It lives in `crates/tauri-plugin-tradr/src/android_fd.rs`, compiled on Android only, and is the file's only item carrying `#[allow(unsafe_code)]`. The plugin crate's root changes from `#![forbid(unsafe_code)]` to `#![deny(unsafe_code)]`, because `forbid` cannot be relaxed for one item; every other crate keeps `forbid`
- **The safety argument is ownership transfer**: Kotlin obtains the descriptor with `ParcelFileDescriptor.detachFd()`, which gives up its own ownership, and Rust adopts it **once, at the moment it arrives in Rust** -- in the response to `pick_files_to_send` and in the share-intent channel -- never from a number the front end sends back. From then on it is an ordinary `File`, closed when dropped
- The front end refers to an adopted file by an opaque id into a registry the plugin holds, not by the descriptor number
- `ci/` gains a check that `unsafe` appears in no other file of the workspace

**Every picked or shared file is handed over as a descriptor, whatever its size**, so there are no cache copies to delete. **The exception is a descriptor that cannot be read at an offset** -- a cloud provider may answer a pipe -- which Kotlin detects (`statSize < 0`) and copies into the cache as before; those copies are swept when the plugin next starts, since a staged file does not survive a restart.

**An adopted file becomes a single-file root in `tradr-vfs`**, registered under the name the platform gave it, so the send path, the Offer and [invariant I5](../../CLAUDE.md#8-invariants-that-must-not-break) are unchanged: the sender opens `(root, name)` as it opens any other file, and no path is assembled for it anywhere.

## Consequences

- **A file of any size can be sent from a phone without being copied**, once [DCR-164](../04-protocol.md#the-sender-streams-a-file-and-never-holds-it-dcr-164) has made the sender stream
- The workspace has one `unsafe` call, in the one crate D9 already expects to swap, and a check that keeps it one
- A descriptor held in the registry keeps its file open until the send it was staged for succeeds or the process ends

## Alternatives rejected

- **Copy every file into the cache**: offered to the user and declined; it costs the file's size in free space and a wait before every large send
- **Reopen `/proc/self/fd/N`**: safe, and expected to be refused under scoped storage for exactly the files that matter
- **Read through Kotlin over the plugin bridge**: every byte crosses JNI and JSON, which a multi-GB video cannot afford

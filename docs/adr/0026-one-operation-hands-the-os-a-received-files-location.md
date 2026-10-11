# ADR-0026: One operation hands the operating system a received file's location

- **Status**: Accepted
- **Date**: 2026-10-11
- **Narrows**: [ADR-0014](0014-vfs-exposes-operations-never-paths.md)'s last consequence, which said a feature wanting a file's real location "gets an explicit operation with its own review, not a general-purpose path escape hatch". This is that operation and that review

## Context

The person asked on 2026-10-11 that a row in Received can be opened and shared (DF-122). Opening a file in another application is done by the operating system, and every desktop takes one thing for it: a path. Android takes a `content://` URI, which its `FileProvider` builds from a path. So this feature cannot be built on handles, and [ADR-0014](0014-vfs-exposes-operations-never-paths.md) gives no method that answers a path.

ADR-0014's rule exists because a path returned to a caller is validated at one moment and opened at another, and the caller who opens it is code that must not know about symlinks. Both halves are different here. **The opener is not Tradr**: it is the person's own application, running as the person, opening a file in the person's own Downloads, which their file manager would open the same way. And the Layer 1 trait is not involved at all.

## Decision

**The native Vfs implementations in `tradr-vfs` (Layer 3) gain one inherent method, `host_file_path(root, relative)`, and the `Vfs` trait gains nothing.**

- It answers only for a **regular file** that the ordinary validated open reaches: it opens the target exactly as `open_read` does, so the deny list, the no-symlink descent and the boundary all apply, and it fails with the same errors. A directory, a symlink, a missing file and a root registered from an open descriptor (which has no location) are refused.
- The path it answers is the root's own path joined with the validated components. It is assembled in `tradr-vfs`, so [invariant I5](../../CLAUDE.md#8-invariants-that-must-not-break) holds as written.
- **It has exactly one caller: the plugin's commands that open, reveal or share a row of the Received list**, addressed by the row's number and never by a path the front end supplies. The path goes to the operating system and to nothing else. It is not returned to the front end, not logged, and never used by Tradr to open, read, write or delete anything.
- It is boundary enforcement, so it is a Critical Module: the Supervisor writes its tests first.

## Reasoning

1. **The interval ADR-0014 closes cannot be closed for this feature, by anyone.** "Open with" is a request to another process, and what that process opens is decided when it opens. What can be decided here is that the interval is harmless: whoever could swap the file for a symlink in that interval can already write to the person's Downloads as the person.
2. **A peer cannot plant the symlink.** The Browse plane writes files and directories and nothing else, and the transfer plane places regular files. The check at the time of the call refuses anything that is not a regular file reached without a symlink, so a planted link would have to appear in the interval, from the local account.
3. **Keeping it off the trait keeps every argument ADR-0014 made.** Layer 1 still cannot hold a path, `SafVfs` still has nothing to implement, and a test implementation is still an in-memory map.
4. **Addressing by row number keeps the front end out of it.** A command taking a path would let any script in the webview ask the operating system to open any file. A command taking a row number can only reach what this device recorded receiving.

## Consequences

- Change Drill D7 (a new platform) gains nothing to implement unless that platform wants Open; D8 is untouched, since SAF roots are refused rather than served.
- **A second caller is a new decision.** Desktop drag-out (DF-1) would want the same thing; it gets its own review against this ADR, not a quiet reuse.
- The `tradr-vfs` crate now has one public method whose result is a location. `ci/` has no check that would notice a second; review does.

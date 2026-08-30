# ADR-0014: The Vfs exposes operations, never paths

- **Status**: Accepted
- **Date**: 2026-08-22

## Context

[docs/06](../06-shares-and-browsing.md#enforcing-the-share-root-boundary) calls Share Root enforcement "the most security-critical code in Tradr" and gives it a seven-step resolution procedure. [Invariant I5](../../CLAUDE.md#8-invariants-that-must-not-break) states that file paths are assembled in exactly one place, `tradr-vfs`. And the TOCTOU section states the rule the procedure depends on:

> Between validating a path in steps 4 and 5 and opening it in step 6, an attacker who can insert a symlink defeats the check. So **validation and opening are never separated**.

The obvious signature for the trait breaks that rule by construction:

```rust
fn resolve(&self, share: &ShareId, relative: &RelPath) -> Result<PathBuf>;
```

Nothing about it is wrong to read. It validates, and it returns a validated path. But the value it returns is a path the caller must then open, so **validation and opening are now in different crates, with an arbitrary interval between them**. The window the TOCTOU section exists to close is reopened by the type signature, and no amount of care inside `tradr-vfs` can close it again — the race is in the caller, and the caller is Layer 1, which is not allowed to know about symlinks.

`openat2` with `RESOLVE_BENEATH`, which docs/06 names as the Linux mechanism, cannot be expressed through this signature at all. Its guarantee is a property of the open, not of a string.

There is a second, independent reason. On Android a Share Root is a tree URI, not a path:

```
content://com.android.externalstorage.documents/tree/primary%3ADocuments%2Fscan
```

`SafVfs` has no `PathBuf` to return. A trait shaped around paths has no Android implementation, in the same way that a `KeyStore` shaped around key bytes has no StrongBox implementation ([ADR-0011](0011-keystore-exposes-operations.md)). The two decisions are the same decision applied to a different resource.

## Decision

**`Vfs` is declared in Layer 1 as a set of operations. No method returns a path, and no method accepts an absolute one.**

Every operation names its target as a `(root, relative path)` pair and returns data or a handle:

```rust
trait Vfs: Send + Sync {
    fn list<'a>(&'a self, root: &'a RootId, relative: &'a RelPath)
        -> BoxFuture<'a, Result<Vec<DirEntry>, VfsError>>;

    fn stat<'a>(&'a self, root: &'a RootId, relative: &'a RelPath)
        -> BoxFuture<'a, Result<Metadata, VfsError>>;

    fn open_read<'a>(&'a self, root: &'a RootId, relative: &'a RelPath)
        -> BoxFuture<'a, Result<Box<dyn ReadAt>, VfsError>>;

    // ... the write and finalize half, fixed by WI-M0-006d
}
```

- **`RootId` covers both kinds of root** — a Share Root and a transfer's destination directory. Both are boundaries, and neither is a path as far as Layer 1 is concerned
- **`DirEntry` carries a name, never a location.** A caller can render a listing and can descend, and cannot reconstruct where anything lives on disk
- **The handle is what enforces the boundary.** `open_read` performs validation and opening as one operation, so `RESOLVE_BENEATH` and `O_NOFOLLOW` descent are expressible, and SAF's `DocumentFile` traversal fits the same signature
- The futures are `BoxFuture` per [ADR-0013](0013-layer-1-async-traits-return-boxed-futures.md)

## Reasoning

1. **It makes the TOCTOU rule structural instead of advisory.** docs/06 asks that validation and opening never be separated. With this shape a caller has no way to separate them, because it never holds the intermediate value. A rule the type system enforces does not depend on whoever writes the next caller having read docs/06.

2. **It is the only shape `SafVfs` can implement.** As with `KeyStore`, this constraint alone would settle the question.

3. **It is what invariant I5 actually means.** "Paths are assembled in one place" is not a statement about tidiness; it is a statement about no other code holding a path to assemble. Returning one from the trait would satisfy the letter and lose the point.

4. **The deny list and the audience check have somewhere to live.** Both are conditions on an operation, not on a string, and `open_read` is the point at which every one of them has been checked. A path returned to a caller has been checked against whatever `tradr-vfs` thought the caller intended.

## Consequences

- **Layer 1 cannot log an absolute path**, because it never has one. Diagnostics name a root and a relative path. This is a small loss in debugging and a direct contribution to F4, since a Share Root reveals a directory layout.
- **`tradr-core` gains no filesystem knowledge from the trait.** `RelPath` validation — rejecting `..`, absolute forms, NUL and control characters — is a Layer 0 concern about the *shape of a name* and belongs with `ItemId`. Everything about the real filesystem stays in `tradr-vfs`.
- **NFC normalization cannot happen in Layer 0**, and this splits step 2 of docs/06's procedure across two layers. The standard library ships no Unicode normalization, so it needs a crate, and `tradr-core` may have none. `tradr-vfs` normalizes and then **rebuilds a `RelPath` from the result**, which re-runs every Layer 0 check on the normalized form. That is what docs/06 asks for by "re-run the checks above", and routing the re-check through the same type is what keeps two copies of the rules from drifting apart.
- **The trait cannot express "give me the file's real location" and that is deliberate.** Desktop drag-out, already deferred as DF-1, is the one feature that would want it. When it arrives it gets an explicit operation with its own review, not a general-purpose path escape hatch.
- **Test implementations are in-memory maps**, satisfying B5 without a temporary directory.

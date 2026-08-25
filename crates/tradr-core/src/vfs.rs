//! Layer 1's filesystem abstraction (ADR-0014). No implementation lives
//! here: `PosixVfs`, `SafVfs`, and every other backend belong to Layer 3.
//! No method returns a path, and none accepts an absolute one, so
//! validation and opening can never be separated by a caller.

use std::fmt;

use crate::future::BoxFuture;
use crate::{RelPath, UnixTime};

/// A local handle naming one filesystem boundary: a Share Root, or a
/// transfer's destination directory. Assigned by the local device and
/// never carried on the wire: a peer names a `share_id`, and the local
/// side maps that to a `RootId`, so unlike `RelPath` it needs no
/// validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootId(u64);

impl RootId {
    /// Builds a `RootId` from a value the local device already assigned.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw value.
    pub fn value(self) -> u64 {
        self.0
    }
}

/// What a `DirEntry` or `Metadata` names. Exactly two variants: docs/06
/// step 6 rejects a symlink, device, FIFO or socket before it is ever
/// listed or opened, so no third case exists to represent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
}

/// One entry in a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// A name only, never a location: a caller can render or descend into
    /// it but cannot reconstruct where it lives on disk (ADR-0014).
    pub name: String,
    /// File or directory; never anything else, per `EntryKind`.
    pub kind: EntryKind,
    /// The entry's size in bytes; zero for a directory.
    pub size_bytes: u64,
    /// The entry's last modification time.
    pub modified: UnixTime,
}

/// What `stat` reports about one entry, without listing its siblings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// File or directory; never anything else, per `EntryKind`.
    pub kind: EntryKind,
    /// The entry's size in bytes; zero for a directory.
    pub size_bytes: u64,
    /// The entry's last modification time.
    pub modified: UnixTime,
}

/// An error from a `Vfs` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    /// No entry exists at the given root and relative path.
    NotFound,
    /// docs/06's boundary check rejected the resolved target.
    OutsideRoot,
    /// The path matches an entry on docs/06's default deny list.
    DenyListed,
    /// The target is a symlink, device, FIFO or socket (docs/06 step 6).
    UnsupportedEntry,
    /// The operation wanted a file where the target is a directory, or
    /// the reverse.
    WrongKind,
    /// The Share's mode is `"ro"`, so a write operation is rejected.
    ReadOnly,
    /// The underlying filesystem call failed.
    Io(std::io::ErrorKind),
}

impl fmt::Display for VfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "no entry at the given root and relative path"),
            Self::OutsideRoot => write!(f, "the resolved target falls outside its root"),
            Self::DenyListed => write!(f, "the path matches the default deny list"),
            Self::UnsupportedEntry => {
                write!(f, "the entry is a symlink, device, FIFO, or socket")
            }
            Self::WrongKind => write!(f, "the entry is not the kind the operation wanted"),
            Self::ReadOnly => write!(f, "the root is read-only"),
            Self::Io(kind) => write!(f, "filesystem error: {kind}"),
        }
    }
}

impl std::error::Error for VfsError {}

/// A handle open for reading, returned by `Vfs::open_read`. Validation and
/// opening already happened together in that call (ADR-0014), so nothing
/// here can reopen or re-resolve a path.
pub trait ReadAt: Send {
    /// Reads into `buf` starting at `offset`, returning the byte count
    /// actually read.
    fn read_at<'a>(
        &'a self,
        offset: u64,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<usize, VfsError>>;
}

/// A handle open for writing, returned by `Vfs::open_write`.
pub trait WriteAt: Send {
    /// Writes `buf` starting at `offset`.
    fn write_at<'a>(
        &'a mut self,
        offset: u64,
        buf: &'a [u8],
    ) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Flushes to durable storage. docs/04 requires the database update
    /// following a chunk write to happen only after this completes.
    fn sync<'a>(&'a mut self) -> BoxFuture<'a, Result<(), VfsError>>;
}

/// The Share Root boundary, exposed as operations rather than paths
/// (ADR-0014). Every method names its target as a `(root, relative path)`
/// pair; none returns or accepts an absolute path.
pub trait Vfs: Send + Sync {
    /// Lists the entries directly inside `at`, relative to `root`.
    fn list<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Vec<DirEntry>, VfsError>>;

    /// Reports what `at` is, without listing its siblings.
    fn stat<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Metadata, VfsError>>;

    /// Validates and opens `at` for reading in one operation, so a
    /// symlink swapped in after validation can never be followed.
    fn open_read<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn ReadAt>, VfsError>>;

    /// Creates the directory at `at`. Part of the partial-file lifecycle
    /// in docs/04: `.tradr-partial/<transfer_id>/` is created before the
    /// first chunk of a transfer is written.
    fn create_dir<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Validates and opens `at` for writing in one operation, for the same
    /// reason as `open_read`. Every implementation must create the file
    /// if absent and never truncate one that exists: a caller resuming a
    /// transfer reopens the partial file at `at` and writes into the gaps.
    fn open_write<'a>(
        &'a self,
        root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn WriteAt>, VfsError>>;

    /// Moves `from` to `to`, both relative to `root`. Used to move a
    /// verified partial file into place atomically (docs/04).
    fn rename<'a>(
        &'a self,
        root: RootId,
        from: &'a RelPath,
        to: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Removes a file, or a directory that is already empty. Never
    /// recurses: `at` is peer-influenced, and a caller here only needs to
    /// remove a file or an empty directory (docs/04's partial-file sweep).
    /// A non-empty directory is `WrongKind`.
    fn remove<'a>(&'a self, root: RootId, at: &'a RelPath) -> BoxFuture<'a, Result<(), VfsError>>;
}

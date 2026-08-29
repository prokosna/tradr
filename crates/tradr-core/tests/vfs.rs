//! Proves `Vfs` is dyn compatible and its futures are `Send` (rule B5),
//! driven to completion with no async runtime and no real filesystem. See
//! ADR-0013 and ADR-0014.

use std::collections::HashMap;
use std::future::Future;
use std::task::{Context, Poll, Waker};

use tradr_core::{
    BoxFuture, DirEntry, EntryKind, Metadata, ReadAt, RelPath, RootId, UnixTime, Vfs, VfsError,
    WriteAt,
};

/// An in-memory double, real enough for `list` and `open_read` to prove
/// the trait is usable; every other method is a fixed rejection, since
/// nothing here drives them.
struct FakeVfs {
    files: HashMap<String, Vec<u8>>,
}

/// The `ReadAt` handle `FakeVfs::open_read` hands back.
struct FakeReadAt {
    bytes: Vec<u8>,
}

impl ReadAt for FakeReadAt {
    fn read_at<'a>(
        &'a self,
        offset: u64,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<usize, VfsError>> {
        Box::pin(async move {
            let offset = offset as usize;
            let available = self.bytes.get(offset..).unwrap_or(&[]);
            let n = available.len().min(buf.len());
            buf[..n].copy_from_slice(&available[..n]);
            Ok(n)
        })
    }
}

impl Vfs for FakeVfs {
    fn list<'a>(
        &'a self,
        _root: RootId,
        _at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Vec<DirEntry>, VfsError>> {
        Box::pin(async move {
            Ok(self
                .files
                .iter()
                .map(|(name, bytes)| DirEntry {
                    name: name.clone(),
                    kind: EntryKind::File,
                    size_bytes: bytes.len() as u64,
                    modified: UnixTime::from_secs(0),
                })
                .collect())
        })
    }

    fn stat<'a>(
        &'a self,
        _root: RootId,
        _at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Metadata, VfsError>> {
        Box::pin(async move { Err(VfsError::NotFound) })
    }

    fn open_read<'a>(
        &'a self,
        _root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn ReadAt>, VfsError>> {
        Box::pin(async move {
            let bytes = self
                .files
                .get(&at.to_string())
                .cloned()
                .ok_or(VfsError::NotFound)?;
            Ok(Box::new(FakeReadAt { bytes }) as Box<dyn ReadAt>)
        })
    }

    fn create_dir<'a>(
        &'a self,
        _root: RootId,
        _at: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move { Err(VfsError::ReadOnly) })
    }

    fn open_write<'a>(
        &'a self,
        _root: RootId,
        _at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn WriteAt>, VfsError>> {
        Box::pin(async move { Err(VfsError::ReadOnly) })
    }

    fn rename<'a>(
        &'a self,
        _root: RootId,
        _from: &'a RelPath,
        _to: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move { Err(VfsError::ReadOnly) })
    }

    fn remove<'a>(
        &'a self,
        _root: RootId,
        _at: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move { Err(VfsError::ReadOnly) })
    }
}

// Compiles only if the future `F` produces is `Send`, the bound a
// multi-threaded executor needs (ADR-0013).
fn assert_send<F: Future + Send>(_: F) {}

#[test]
fn vfs_is_dyn_compatible_and_its_futures_run_to_completion_without_a_runtime() {
    let mut files = HashMap::new();
    files.insert("report.pdf".to_string(), b"hello".to_vec());
    let vfs: Box<dyn Vfs> = Box::new(FakeVfs { files });

    let root = RootId::new(1);
    let listing_at = RelPath::root();
    let read_at = RelPath::new("report.pdf").expect("a plain filename is a valid RelPath");

    assert_send(vfs.list(root, &listing_at));

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    let mut listing = vfs.list(root, &listing_at);
    let entries = match listing.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(entries)) => entries,
        Poll::Ready(Err(e)) => panic!("unexpected error: {e}"),
        Poll::Pending => panic!("a fake vfs must complete on the first poll"),
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "report.pdf");
    assert_eq!(entries[0].size_bytes, 5);

    let mut opening = vfs.open_read(root, &read_at);
    let reader = match opening.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(reader)) => reader,
        Poll::Ready(Err(e)) => panic!("unexpected error: {e}"),
        Poll::Pending => panic!("a fake vfs must complete on the first poll"),
    };

    let mut buf = [0u8; 5];
    let mut reading = reader.read_at(0, &mut buf);
    let n = match reading.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(n)) => n,
        Poll::Ready(Err(e)) => panic!("unexpected error: {e}"),
        Poll::Pending => panic!("a fake vfs must complete on the first poll"),
    };
    drop(reading);
    assert_eq!(&buf[..n], b"hello");
}

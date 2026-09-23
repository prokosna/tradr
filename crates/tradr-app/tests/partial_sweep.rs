//! Supervisor-written tests for DCR-154's sweep as DCR-155 amended it
//! (docs/04, "Sweeping what an interrupted transfer left"). The sweep
//! removes files from the receive root, so most of these pin what it must
//! leave alone.

use std::collections::BTreeMap;
use std::sync::Mutex;

use tradr_app::partial_sweep::{PARTIAL_RETENTION_SECS, sweep_stale_partials};
use tradr_core::{
    BoxFuture, DirEntry, EntryKind, Metadata, ReadAt, RelPath, RootId, TransferId, UnixTime, Vfs,
    VfsError, WriteAt,
};
use tradr_vfs::{partial_dir_rel_path, partial_root_rel_path};

const NOW: i64 = 1_800_000_000;
const TID_A: &str = "0190d7a0-1234-7abc-8def-0123456789ab";
const TID_B: &str = "0190d7a0-5678-7abc-9def-0123456789ab";

fn root() -> RootId {
    RootId::new(1)
}

fn stale() -> UnixTime {
    UnixTime::from_secs(NOW - PARTIAL_RETENTION_SECS as i64 - 1)
}

fn fresh() -> UnixTime {
    UnixTime::from_secs(NOW - 6 * 24 * 3600)
}

fn tid(s: &str) -> TransferId {
    s.parse().expect("test transfer id is a valid v7 id")
}

// In memory, so modification times are exact on every platform.
#[derive(Default)]
struct FakeVfs {
    nodes: Mutex<BTreeMap<String, (EntryKind, UnixTime)>>,
    removed: Mutex<Vec<String>>,
    fail_list_at: Option<(String, VfsError)>,
}

impl FakeVfs {
    fn dir(self, path: &str, modified: UnixTime) -> Self {
        self.insert(path, EntryKind::Directory, modified)
    }

    fn file(self, path: &str, modified: UnixTime) -> Self {
        self.insert(path, EntryKind::File, modified)
    }

    fn insert(self, path: &str, kind: EntryKind, modified: UnixTime) -> Self {
        self.nodes
            .lock()
            .unwrap()
            .insert(path.to_string(), (kind, modified));
        self
    }

    fn exists(&self, path: &str) -> bool {
        self.nodes.lock().unwrap().contains_key(path)
    }

    fn removed(&self) -> Vec<String> {
        self.removed.lock().unwrap().clone()
    }

    fn children(&self, at: &str) -> Vec<(String, EntryKind, UnixTime)> {
        let prefix = if at.is_empty() {
            String::new()
        } else {
            format!("{at}/")
        };
        self.nodes
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(path, (kind, modified))| {
                let rest = path.strip_prefix(&prefix)?;
                if rest.is_empty() || rest.contains('/') {
                    return None;
                }
                Some((rest.to_string(), *kind, *modified))
            })
            .collect()
    }
}

impl Vfs for FakeVfs {
    fn list<'a>(
        &'a self,
        _root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Vec<DirEntry>, VfsError>> {
        Box::pin(async move {
            let key = at.as_str();
            if let Some((path, e)) = &self.fail_list_at
                && path == key
            {
                return Err(*e);
            }
            match self.nodes.lock().unwrap().get(key) {
                None if !key.is_empty() => return Err(VfsError::NotFound),
                Some((EntryKind::File, _)) => return Err(VfsError::WrongKind),
                _ => {}
            }
            Ok(self
                .children(key)
                .into_iter()
                .map(|(name, kind, modified)| DirEntry {
                    name,
                    kind,
                    size_bytes: 0,
                    modified,
                })
                .collect())
        })
    }

    fn stat<'a>(
        &'a self,
        _root: RootId,
        at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Metadata, VfsError>> {
        Box::pin(async move {
            match self.nodes.lock().unwrap().get(at.as_str()) {
                Some((kind, modified)) => Ok(Metadata {
                    kind: *kind,
                    size_bytes: 0,
                    modified: *modified,
                }),
                None => Err(VfsError::NotFound),
            }
        })
    }

    fn open_read<'a>(
        &'a self,
        _root: RootId,
        _at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn ReadAt>, VfsError>> {
        Box::pin(async { Err(VfsError::Io(std::io::ErrorKind::Unsupported)) })
    }

    fn create_dir<'a>(
        &'a self,
        _root: RootId,
        _at: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async { Err(VfsError::Io(std::io::ErrorKind::Unsupported)) })
    }

    fn open_write<'a>(
        &'a self,
        _root: RootId,
        _at: &'a RelPath,
    ) -> BoxFuture<'a, Result<Box<dyn WriteAt>, VfsError>> {
        Box::pin(async { Err(VfsError::Io(std::io::ErrorKind::Unsupported)) })
    }

    fn rename<'a>(
        &'a self,
        _root: RootId,
        _from: &'a RelPath,
        _to: &'a RelPath,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async { Err(VfsError::Io(std::io::ErrorKind::Unsupported)) })
    }

    fn remove<'a>(&'a self, _root: RootId, at: &'a RelPath) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let key = at.as_str().to_string();
            let kind = match self.nodes.lock().unwrap().get(&key) {
                Some((kind, _)) => *kind,
                None => return Err(VfsError::NotFound),
            };
            // Mirrors the trait's contract: a non-empty directory is refused.
            if kind == EntryKind::Directory && !self.children(&key).is_empty() {
                return Err(VfsError::WrongKind);
            }
            self.nodes.lock().unwrap().remove(&key);
            self.removed.lock().unwrap().push(key);
            Ok(())
        })
    }
}

// Stands in for `list_partial_root`, which the fake needs no deny list to skip.
async fn sweep(vfs: &FakeVfs) -> Result<Vec<TransferId>, VfsError> {
    let listing = match vfs.list(root(), &partial_root_rel_path()).await {
        Ok(entries) => entries,
        Err(VfsError::NotFound) => Vec::new(),
        Err(e) => return Err(e),
    };
    sweep_stale_partials(vfs, root(), UnixTime::from_secs(NOW), &listing).await
}

fn transfer_dir(id: &str) -> String {
    format!(".tradr-partial/{id}")
}

#[test]
fn the_retention_is_seven_days() {
    assert_eq!(PARTIAL_RETENTION_SECS, 604_800);
}

#[test]
fn the_partial_root_is_the_parent_of_every_transfer_directory() {
    assert_eq!(partial_root_rel_path().as_str(), ".tradr-partial");
    assert_eq!(
        partial_dir_rel_path(tid(TID_A)).as_str(),
        format!(".tradr-partial/{TID_A}")
    );
}

#[tokio::test]
async fn a_device_with_no_partial_directory_sweeps_nothing() {
    let vfs = FakeVfs::default().file("photo.jpg", stale());
    assert_eq!(sweep(&vfs).await, Ok(Vec::new()));
    assert!(vfs.removed().is_empty());
}

#[tokio::test]
async fn a_stale_transfer_directory_is_removed_whole() {
    let dir = transfer_dir(TID_A);
    let vfs = FakeVfs::default()
        .dir(".tradr-partial", stale())
        .dir(&dir, stale())
        .file(&format!("{dir}/item-1"), stale())
        .file(&format!("{dir}/item-2"), stale());

    assert_eq!(sweep(&vfs).await, Ok(vec![tid(TID_A)]));
    assert!(!vfs.exists(&dir));
    assert!(!vfs.exists(&format!("{dir}/item-1")));
    assert!(!vfs.exists(&format!("{dir}/item-2")));
    assert_eq!(vfs.removed().last(), Some(&dir));
}

#[tokio::test]
async fn the_partial_root_itself_is_kept() {
    let dir = transfer_dir(TID_A);
    let vfs = FakeVfs::default()
        .dir(".tradr-partial", stale())
        .dir(&dir, stale())
        .file(&format!("{dir}/item-1"), stale());

    assert_eq!(sweep(&vfs).await, Ok(vec![tid(TID_A)]));
    assert!(vfs.exists(".tradr-partial"));
}

#[tokio::test]
async fn an_empty_stale_transfer_directory_is_removed() {
    let dir = transfer_dir(TID_A);
    let vfs = FakeVfs::default()
        .dir(".tradr-partial", stale())
        .dir(&dir, stale());

    assert_eq!(sweep(&vfs).await, Ok(vec![tid(TID_A)]));
    assert!(!vfs.exists(&dir));
}

#[tokio::test]
async fn one_fresh_file_keeps_the_whole_directory() {
    let dir = transfer_dir(TID_A);
    let vfs = FakeVfs::default()
        .dir(".tradr-partial", stale())
        .dir(&dir, stale())
        .file(&format!("{dir}/item-1"), stale())
        .file(&format!("{dir}/item-2"), fresh());

    assert_eq!(sweep(&vfs).await, Ok(Vec::new()));
    assert!(vfs.removed().is_empty());
}

#[tokio::test]
async fn a_fresh_directory_time_keeps_stale_files() {
    let dir = transfer_dir(TID_A);
    let vfs = FakeVfs::default()
        .dir(".tradr-partial", stale())
        .dir(&dir, fresh())
        .file(&format!("{dir}/item-1"), stale());

    assert_eq!(sweep(&vfs).await, Ok(Vec::new()));
    assert!(vfs.removed().is_empty());
}

#[tokio::test]
async fn exactly_seven_days_is_not_yet_stale() {
    let dir = transfer_dir(TID_A);
    let boundary = UnixTime::from_secs(NOW - PARTIAL_RETENTION_SECS as i64);
    let vfs = FakeVfs::default()
        .dir(".tradr-partial", stale())
        .dir(&dir, boundary)
        .file(&format!("{dir}/item-1"), boundary);

    assert_eq!(sweep(&vfs).await, Ok(Vec::new()));
    assert!(vfs.removed().is_empty());
}

#[tokio::test]
async fn only_the_stale_one_of_two_transfers_goes() {
    let a = transfer_dir(TID_A);
    let b = transfer_dir(TID_B);
    let vfs = FakeVfs::default()
        .dir(".tradr-partial", stale())
        .dir(&a, stale())
        .file(&format!("{a}/item-1"), stale())
        .dir(&b, stale())
        .file(&format!("{b}/item-1"), fresh());

    assert_eq!(sweep(&vfs).await, Ok(vec![tid(TID_A)]));
    assert!(!vfs.exists(&a));
    assert!(vfs.exists(&b));
    assert!(vfs.exists(&format!("{b}/item-1")));
}

#[tokio::test]
async fn a_name_that_is_not_a_transfer_id_is_left_alone() {
    let vfs = FakeVfs::default()
        .dir(".tradr-partial", stale())
        .dir(".tradr-partial/notes", stale())
        .file(".tradr-partial/notes/item-1", stale());

    assert_eq!(sweep(&vfs).await, Ok(Vec::new()));
    assert!(vfs.removed().is_empty());
}

#[tokio::test]
async fn a_transfer_id_that_does_not_display_back_to_itself_is_left_alone() {
    let upper = TID_A.to_uppercase();
    let dir = format!(".tradr-partial/{upper}");
    let vfs = FakeVfs::default()
        .dir(".tradr-partial", stale())
        .dir(&dir, stale())
        .file(&format!("{dir}/item-1"), stale());

    assert_eq!(sweep(&vfs).await, Ok(Vec::new()));
    assert!(vfs.removed().is_empty());
}

#[tokio::test]
async fn a_file_named_like_a_transfer_is_left_alone() {
    let vfs = FakeVfs::default()
        .dir(".tradr-partial", stale())
        .file(&transfer_dir(TID_A), stale());

    assert_eq!(sweep(&vfs).await, Ok(Vec::new()));
    assert!(vfs.removed().is_empty());
}

#[tokio::test]
async fn a_name_that_is_not_an_item_id_keeps_the_whole_directory() {
    let dir = transfer_dir(TID_A);
    let vfs = FakeVfs::default()
        .dir(".tradr-partial", stale())
        .dir(&dir, stale())
        .file(&format!("{dir}/item-1"), stale())
        .file(&format!("{dir}/Report.pdf"), stale());

    assert_eq!(sweep(&vfs).await, Ok(Vec::new()));
    assert!(vfs.removed().is_empty());
}

#[tokio::test]
async fn a_directory_inside_a_transfer_keeps_the_whole_directory() {
    let dir = transfer_dir(TID_A);
    let vfs = FakeVfs::default()
        .dir(".tradr-partial", stale())
        .dir(&dir, stale())
        .file(&format!("{dir}/item-1"), stale())
        .dir(&format!("{dir}/item-2"), stale());

    assert_eq!(sweep(&vfs).await, Ok(Vec::new()));
    assert!(vfs.removed().is_empty());
}

#[tokio::test]
async fn nothing_outside_the_partial_root_is_touched() {
    let dir = transfer_dir(TID_A);
    let vfs = FakeVfs::default()
        .file("photo.jpg", stale())
        .dir(TID_B, stale())
        .file(&format!("{TID_B}/item-1"), stale())
        .dir(".tradr-partial", stale())
        .dir(&dir, stale())
        .file(&format!("{dir}/item-1"), stale());

    assert_eq!(sweep(&vfs).await, Ok(vec![tid(TID_A)]));
    assert!(vfs.exists("photo.jpg"));
    assert!(vfs.exists(TID_B));
    assert!(vfs.exists(&format!("{TID_B}/item-1")));
    assert!(
        vfs.removed()
            .iter()
            .all(|p| p.starts_with(".tradr-partial/"))
    );
}

#[tokio::test]
async fn a_listing_failure_inside_a_transfer_directory_is_returned() {
    let dir = transfer_dir(TID_A);
    let mut vfs = FakeVfs::default()
        .dir(".tradr-partial", stale())
        .dir(&dir, stale())
        .file(&format!("{dir}/item-1"), stale());
    vfs.fail_list_at = Some((dir, VfsError::Io(std::io::ErrorKind::PermissionDenied)));

    assert_eq!(
        sweep(&vfs).await,
        Err(VfsError::Io(std::io::ErrorKind::PermissionDenied))
    );
    assert!(vfs.removed().is_empty());
}

#[tokio::test]
async fn an_empty_listing_sweeps_nothing() {
    let vfs = FakeVfs::default().file("photo.jpg", stale());
    assert_eq!(
        sweep_stale_partials(&vfs, root(), UnixTime::from_secs(NOW), &[]).await,
        Ok(Vec::new())
    );
    assert!(vfs.removed().is_empty());
}

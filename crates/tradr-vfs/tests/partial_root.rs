//! Supervisor-authored tests for `list_partial_root` (DCR-155, docs/04).
//! Critical Module: boundary enforcement in tradr-vfs. The operation skips
//! one deny pattern, so these pin that it skips nothing else.

use tradr_core::{EntryKind, RelPath, RootId, Vfs, VfsError};
use tradr_vfs::NativeVfs;

const VALID_V7: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

fn registered(dir: &tempfile::TempDir) -> (NativeVfs, RootId) {
    let vfs = NativeVfs::new();
    let root = RootId::new(7);
    vfs.register_root(root, dir.path().to_path_buf(), false)
        .expect("register root");
    (vfs, root)
}

#[tokio::test]
async fn a_missing_partial_root_lists_as_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vfs, root) = registered(&dir);

    assert_eq!(vfs.list_partial_root(root).await, Ok(Vec::new()));
}

#[tokio::test]
async fn the_partial_root_lists_its_direct_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let partial = dir.path().join(".tradr-partial");
    std::fs::create_dir_all(partial.join(VALID_V7)).expect("transfer dir");
    std::fs::write(partial.join(VALID_V7).join("item-1"), b"x").expect("partial file");
    std::fs::write(partial.join("stray"), b"y").expect("stray file");
    let (vfs, root) = registered(&dir);

    let mut entries = vfs.list_partial_root(root).await.expect("listing");
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let seen: Vec<(&str, EntryKind)> = entries.iter().map(|e| (e.name.as_str(), e.kind)).collect();
    assert_eq!(
        seen,
        vec![(VALID_V7, EntryKind::Directory), ("stray", EntryKind::File)]
    );
}

#[tokio::test]
async fn the_trait_listing_of_the_partial_root_stays_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".tradr-partial").join(VALID_V7))
        .expect("transfer dir");
    let (vfs, root) = registered(&dir);

    assert!(vfs.list_partial_root(root).await.is_ok());
    let rel = RelPath::new(".tradr-partial").expect("relpath");
    assert_eq!(vfs.list(root, &rel).await, Err(VfsError::DenyListed));
}

#[tokio::test]
async fn a_partial_root_that_is_a_file_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(".tradr-partial"), b"not a directory").expect("file");
    let (vfs, root) = registered(&dir);

    assert_eq!(vfs.list_partial_root(root).await, Err(VfsError::WrongKind));
}

#[tokio::test]
async fn an_unregistered_root_is_refused() {
    let vfs = NativeVfs::new();

    assert!(vfs.list_partial_root(RootId::new(99)).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn a_partial_root_that_is_a_symlink_out_of_the_root_is_not_followed() {
    let outside = tempfile::tempdir().expect("outside tempdir");
    std::fs::create_dir_all(outside.path().join(VALID_V7)).expect("outside dir");
    let dir = tempfile::tempdir().expect("tempdir");
    std::os::unix::fs::symlink(outside.path(), dir.path().join(".tradr-partial")).expect("symlink");
    let (vfs, root) = registered(&dir);

    let res = vfs.list_partial_root(root).await;
    assert!(
        res.is_err(),
        "a symlinked partial root must be refused, got {res:?}"
    );
}

#[tokio::test]
async fn the_root_listing_still_hides_the_partial_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".tradr-partial").join(VALID_V7))
        .expect("transfer dir");
    std::fs::write(dir.path().join("photo.jpg"), b"z").expect("ordinary file");
    let (vfs, root) = registered(&dir);

    let names: Vec<String> = vfs
        .list(root, &RelPath::root())
        .await
        .expect("root listing")
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec!["photo.jpg".to_string()]);
}

// DCR-156: below the partial root, `list` filters by the rule every other operation already uses.
#[tokio::test]
async fn a_transfer_directory_lists_its_partial_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let transfer = dir.path().join(".tradr-partial").join(VALID_V7);
    std::fs::create_dir_all(&transfer).expect("transfer dir");
    std::fs::write(transfer.join("item-1"), b"x").expect("partial file");
    let (vfs, root) = registered(&dir);

    let rel = RelPath::new(&format!(".tradr-partial/{VALID_V7}")).expect("relpath");
    let names: Vec<String> = vfs
        .list(root, &rel)
        .await
        .expect("transfer listing")
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec!["item-1".to_string()]);
}

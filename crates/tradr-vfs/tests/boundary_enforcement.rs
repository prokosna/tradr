//! Supervisor-authored tests for VFS boundary enforcement and partial file lifecycle.
//! Critical Module: Boundary enforcement in tradr-vfs.
//! See docs/04-protocol.md, docs/06-shares-and-browsing.md, and AGENTS.md section 6.

use tradr_core::{ItemId, RelPath, RootId, TransferId, Vfs, VfsError};
use tradr_vfs::{NativeVfs, partial_file_rel_path, sanitize_destination_path};

const VALID_V7: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

fn sample_transfer() -> TransferId {
    VALID_V7.parse().expect("valid transfer id")
}

#[tokio::test]
async fn read_only_root_refuses_modifications() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(2);
    vfs.register_root(root, dir.path().to_path_buf(), true)
        .expect("register ro root");

    let rel = RelPath::new("file.txt").expect("relpath");
    assert_eq!(
        vfs.open_write(root, &rel).await.unwrap_err(),
        VfsError::ReadOnly
    );
    assert_eq!(
        vfs.create_dir(root, &rel).await.unwrap_err(),
        VfsError::ReadOnly
    );
    assert_eq!(
        vfs.rename(root, &rel, &rel).await.unwrap_err(),
        VfsError::ReadOnly
    );
    assert_eq!(
        vfs.remove(root, &rel).await.unwrap_err(),
        VfsError::ReadOnly
    );
}

#[tokio::test]
async fn partial_directory_is_inaccessible_to_peers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(2);
    vfs.register_root(root, dir.path().to_path_buf(), false)
        .expect("register root");

    // Create the actual hidden directory
    std::fs::create_dir_all(dir.path().join(".tradr-partial")).unwrap();

    // A peer tries to access it
    let rel = RelPath::new(".tradr-partial").expect("relpath");

    // It must be denied by boundary enforcement
    assert_eq!(
        vfs.list(root, &rel).await.unwrap_err(),
        VfsError::DenyListed
    );
}

#[tokio::test]
async fn partial_file_write_sync_and_atomic_rename() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(3);
    vfs.register_root(root, dir.path().to_path_buf(), false)
        .expect("register rw root");

    let transfer = sample_transfer();
    let item_id = ItemId::new("item_0").unwrap();
    let partial_rel = partial_file_rel_path(transfer, &item_id);

    // 1. Create partial directory .tradr-partial/<transfer_id>/
    let parent_dir = RelPath::new(&format!(".tradr-partial/{transfer}")).expect("parent rel");
    vfs.create_dir(root, &parent_dir).await.expect("create dir");

    // 2. Open partial file for writing and write chunk 0 piece
    let mut writer = vfs
        .open_write(root, &partial_rel)
        .await
        .expect("open write");
    writer
        .write_at(0, b"first-piece-")
        .await
        .expect("write at 0");
    writer
        .write_at(12, b"second-piece")
        .await
        .expect("write at 12");
    writer.sync().await.expect("sync");
    drop(writer);

    // 3. Verify file exists with exact content
    let partial_full_path = dir.path().join(partial_rel.as_str());
    assert_eq!(
        std::fs::read(&partial_full_path).unwrap(),
        b"first-piece-second-piece"
    );

    // 4. Atomic rename into destination path
    let dest_rel = sanitize_destination_path("output.txt").expect("dest rel");
    vfs.rename(root, &partial_rel, &dest_rel)
        .await
        .expect("atomic rename");

    // Partial file is gone, destination exists
    assert!(!partial_full_path.exists());
    let dest_full_path = dir.path().join(dest_rel.as_str());
    assert_eq!(
        std::fs::read(&dest_full_path).unwrap(),
        b"first-piece-second-piece"
    );
}

#[tokio::test]
async fn remove_refuses_a_non_empty_directory_and_leaves_it_whole() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(5);
    vfs.register_root(root, dir.path().to_path_buf(), false)
        .expect("register rw root");

    let subdir = RelPath::new("keep").expect("relpath");
    let child = RelPath::new("keep/child.txt").expect("relpath");
    vfs.create_dir(root, &subdir).await.expect("create dir");
    let mut w = vfs.open_write(root, &child).await.expect("open write");
    w.write_at(0, b"payload").await.expect("write");
    w.sync().await.expect("sync");
    drop(w);

    assert_eq!(
        vfs.remove(root, &subdir).await.unwrap_err(),
        VfsError::WrongKind
    );

    // A recursing remove would take the child with it, and a RelPath is
    // peer-influenced, so the refusal is the contract rather than a detail.
    assert_eq!(
        std::fs::read(dir.path().join("keep/child.txt")).expect("child survives"),
        b"payload"
    );
}

#[tokio::test]
async fn remove_takes_a_file_and_an_already_empty_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(6);
    vfs.register_root(root, dir.path().to_path_buf(), false)
        .expect("register rw root");

    let empty = RelPath::new("empty").expect("relpath");
    let file = RelPath::new("lone.txt").expect("relpath");
    vfs.create_dir(root, &empty).await.expect("create dir");
    let mut w = vfs.open_write(root, &file).await.expect("open write");
    w.write_at(0, b"x").await.expect("write");
    w.sync().await.expect("sync");
    drop(w);

    vfs.remove(root, &file).await.expect("a file is removable");
    vfs.remove(root, &empty)
        .await
        .expect("an empty directory is removable");

    assert!(!dir.path().join("lone.txt").exists());
    assert!(!dir.path().join("empty").exists());
}

#[tokio::test]
async fn remove_reports_an_absent_entry_as_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(7);
    vfs.register_root(root, dir.path().to_path_buf(), false)
        .expect("register rw root");

    assert_eq!(
        vfs.remove(root, &RelPath::new("nothing.txt").expect("relpath"))
            .await
            .unwrap_err(),
        VfsError::NotFound
    );
}

#[tokio::test]
async fn open_write_does_not_truncate_existing_partial_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(4);
    vfs.register_root(root, dir.path().to_path_buf(), false)
        .expect("register rw root");

    let rel = RelPath::new("resumed.bin").expect("relpath");

    // First write: write bytes at offset 0
    let mut w1 = vfs.open_write(root, &rel).await.expect("open write 1");
    w1.write_at(0, &[1, 2, 3, 4]).await.expect("write 1");
    w1.sync().await.expect("sync 1");
    drop(w1);

    // Second write (e.g. transfer resumption after disconnect):
    // open_write must NOT truncate 0..4 when writing at offset 4
    let mut w2 = vfs.open_write(root, &rel).await.expect("open write 2");
    w2.write_at(4, &[5, 6, 7, 8]).await.expect("write 2");
    w2.sync().await.expect("sync 2");
    drop(w2);

    let full_path = dir.path().join(rel.as_str());
    assert_eq!(
        std::fs::read(&full_path).unwrap(),
        &[1, 2, 3, 4, 5, 6, 7, 8]
    );
}

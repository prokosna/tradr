//! Integration tests for prepare_item_with_progress (WI-M8-072a).

use tradr_app::transfer::{prepare_item, prepare_item_with_progress};
use tradr_core::{REFERENCE_CHUNK_SIZE_BYTES, RelPath, RootId};
use tradr_vfs::NativeVfs;

#[tokio::test]
async fn prepare_item_with_progress_two_and_half_chunks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_size = (REFERENCE_CHUNK_SIZE_BYTES * 5) / 2;
    let content = vec![0x42u8; file_size as usize];
    let rel_path = RelPath::new("two_and_half_chunks.bin").expect("rel path");
    let file_path = dir.path().join("two_and_half_chunks.bin");
    std::fs::write(&file_path, &content).expect("write file");

    let vfs = NativeVfs::new();
    let root = RootId::new(1);
    vfs.register_root(root, dir.path().to_path_buf(), false)
        .expect("register root");

    let spool_progress = vfs.scratch_file().expect("scratch file for progress");
    let mut reports = Vec::new();
    let mut on_read = |bytes: u64| {
        reports.push(bytes);
    };

    let prepared_progress =
        prepare_item_with_progress(&vfs, root, &rel_path, spool_progress, &mut on_read)
            .await
            .expect("prepare_item_with_progress");

    let spool_plain = vfs.scratch_file().expect("scratch file for plain");
    let prepared_plain = prepare_item(&vfs, root, &rel_path, spool_plain)
        .await
        .expect("prepare_item");

    assert_eq!(reports.len(), 3);
    assert_eq!(
        reports,
        vec![
            REFERENCE_CHUNK_SIZE_BYTES,
            REFERENCE_CHUNK_SIZE_BYTES * 2,
            file_size,
        ]
    );
    assert_eq!(*reports.last().expect("last report"), file_size);
    assert_eq!(prepared_progress.size(), prepared_plain.size());
    assert_eq!(prepared_progress.hash(), prepared_plain.hash());
    assert_eq!(prepared_progress.size(), file_size);
}

#[tokio::test]
async fn prepare_item_with_progress_empty_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rel_path = RelPath::new("empty.bin").expect("rel path");
    let file_path = dir.path().join("empty.bin");
    std::fs::write(&file_path, b"").expect("write empty file");

    let vfs = NativeVfs::new();
    let root = RootId::new(1);
    vfs.register_root(root, dir.path().to_path_buf(), false)
        .expect("register root");

    let spool_progress = vfs.scratch_file().expect("scratch file for progress");
    let mut reports = Vec::new();
    let mut on_read = |bytes: u64| {
        reports.push(bytes);
    };

    let prepared_progress =
        prepare_item_with_progress(&vfs, root, &rel_path, spool_progress, &mut on_read)
            .await
            .expect("prepare_item_with_progress");

    let spool_plain = vfs.scratch_file().expect("scratch file for plain");
    let prepared_plain = prepare_item(&vfs, root, &rel_path, spool_plain)
        .await
        .expect("prepare_item");

    assert!(reports.is_empty());
    assert_eq!(prepared_progress.size(), 0);
    assert_eq!(prepared_plain.size(), 0);
    assert_eq!(prepared_progress.size(), prepared_plain.size());
    assert_eq!(prepared_progress.hash(), prepared_plain.hash());
}

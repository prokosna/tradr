//! Integration tests for adopted file registry and staging lifecycle (WI-M8-055b).
#![cfg(unix)]

use tradr_app::adopted::AdoptedFiles;
use tradr_app::transfer::prepare_item;
use tradr_core::{RelPath, RootId, Vfs, VfsError};
use tradr_vfs::NativeVfs;

#[tokio::test]
async fn adopted_file_yields_send_item_matching_integrity_outboard_hash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("photo.jpg");
    let content = b"Deterministic payload for adopted file integrity test.".to_vec();
    std::fs::write(&file_path, &content).expect("write file");
    let file = std::fs::File::open(&file_path).expect("open file");

    let registry = AdoptedFiles::new();
    let id = registry.adopt(file, "photo.jpg").expect("adopt");

    let vfs = NativeVfs::new();
    let items = registry
        .send_items(&vfs, std::slice::from_ref(&id))
        .await
        .expect("send_items");

    assert_eq!(items.len(), 1);
    assert_eq!(items[0].rel_path.as_str(), "photo.jpg");
    assert_eq!(items[0].size_bytes, content.len() as u64);

    let spool = tempfile::tempfile().expect("spool");
    let prepared = prepare_item(&vfs, items[0].root, &items[0].rel_path, spool)
        .await
        .expect("prepare_item");

    let (_outboard, expected_hash) = tradr_integrity::outboard(&content);
    assert_eq!(prepared.hash(), &expected_hash);
    assert_eq!(prepared.size(), content.len() as u64);

    registry.unstage(&vfs, &items).expect("unstage");
    registry.release(&id).expect("release");
}

#[tokio::test]
async fn staged_roots_are_distinct_and_differ_from_downloads_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path1 = dir.path().join("f1.bin");
    let path2 = dir.path().join("f2.bin");
    std::fs::write(&path1, b"first").expect("write f1");
    std::fs::write(&path2, b"second").expect("write f2");

    let registry = AdoptedFiles::new();
    let id1 = registry
        .adopt(std::fs::File::open(&path1).expect("open f1"), "f1.bin")
        .expect("adopt f1");
    let id2 = registry
        .adopt(std::fs::File::open(&path2).expect("open f2"), "f2.bin")
        .expect("adopt f2");

    let vfs = NativeVfs::new();
    let items = registry
        .send_items(&vfs, &[id1.clone(), id2.clone()])
        .await
        .expect("send_items distinct");

    assert_eq!(items.len(), 2);
    assert_ne!(items[0].root, items[1].root);
    assert_ne!(items[0].root, RootId::new(1));
    assert_ne!(items[1].root, RootId::new(1));

    registry.unstage(&vfs, &items).expect("unstage distinct");

    let items_same = registry
        .send_items(&vfs, &[id1.clone(), id1.clone()])
        .await
        .expect("send_items duplicate");

    assert_eq!(items_same.len(), 2);
    assert_ne!(items_same[0].root, items_same[1].root);
    assert_ne!(items_same[0].root, RootId::new(1));
    assert_ne!(items_same[1].root, RootId::new(1));

    registry
        .unstage(&vfs, &items_same)
        .expect("unstage duplicate");
}

#[tokio::test]
async fn unstage_removes_roots_and_allows_restaging() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("restage.txt");
    std::fs::write(&path, b"restageable").expect("write");

    let registry = AdoptedFiles::new();
    let id = registry
        .adopt(std::fs::File::open(&path).expect("open"), "restage.txt")
        .expect("adopt");

    let vfs = NativeVfs::new();
    let items = registry
        .send_items(&vfs, std::slice::from_ref(&id))
        .await
        .expect("send_items");
    let root = items[0].root;
    let rel_path = items[0].rel_path.clone();

    assert!(vfs.stat(root, &rel_path).await.is_ok());

    registry.unstage(&vfs, &items).expect("unstage");

    let stat_err = vfs.stat(root, &rel_path).await.err();
    assert_eq!(stat_err, Some(VfsError::NotFound));

    let items2 = registry
        .send_items(&vfs, std::slice::from_ref(&id))
        .await
        .expect("restage send_items");
    assert_eq!(items2.len(), 1);
    assert_ne!(items2[0].root, root);
    assert!(vfs.stat(items2[0].root, &items2[0].rel_path).await.is_ok());

    registry.unstage(&vfs, &items2).expect("unstage items2");
}

#[tokio::test]
async fn unknown_id_refused_and_rolls_back_partially_staged_roots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("known.txt");
    std::fs::write(&path, b"known content").expect("write");

    let registry = AdoptedFiles::new();
    let known_id = registry
        .adopt(std::fs::File::open(&path).expect("open"), "known.txt")
        .expect("adopt");

    let vfs = NativeVfs::new();
    let missing_id = "adopted-missing-999".to_string();

    let err = registry
        .send_items(&vfs, &[known_id.clone(), missing_id.clone()])
        .await
        .expect_err("unknown id in send_items");
    assert!(err.contains(&missing_id));

    let first_root = RootId::new(1u64 << 32);
    let rel_path = RelPath::new("known.txt").expect("rel path");
    assert_eq!(
        vfs.stat(first_root, &rel_path).await.err(),
        Some(VfsError::NotFound)
    );

    let release_err = registry
        .release(&missing_id)
        .expect_err("release unknown id");
    assert!(release_err.contains(&missing_id));
}

#[tokio::test]
async fn release_drops_file_and_refuses_subsequent_send_items() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("released.txt");
    std::fs::write(&path, b"content").expect("write");

    let registry = AdoptedFiles::new();
    let id = registry
        .adopt(std::fs::File::open(&path).expect("open"), "released.txt")
        .expect("adopt");

    registry.release(&id).expect("release");

    let vfs = NativeVfs::new();
    let err = registry
        .send_items(&vfs, std::slice::from_ref(&id))
        .await
        .expect_err("send_items after release");
    assert!(err.contains(&id));
}

#[tokio::test]
async fn invalid_names_refused_without_breaking_following_adoption() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("target.txt");
    std::fs::write(&path, b"data").expect("write");

    let registry = AdoptedFiles::new();

    let f1 = std::fs::File::open(&path).expect("open f1");
    let err_slash = registry.adopt(f1, "nested/name.txt");
    assert!(err_slash.is_err());

    let f2 = std::fs::File::open(&path).expect("open f2");
    let err_empty = registry.adopt(f2, "");
    assert!(err_empty.is_err());

    let f3 = std::fs::File::open(&path).expect("open f3");
    let valid_id = registry
        .adopt(f3, "valid_name.txt")
        .expect("following adoption works");

    let vfs = NativeVfs::new();
    let items = registry
        .send_items(&vfs, std::slice::from_ref(&valid_id))
        .await
        .expect("send_items for valid adoption");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].rel_path.as_str(), "valid_name.txt");

    registry.unstage(&vfs, &items).expect("unstage");
}

#[tokio::test]
async fn unregister_open_file_ignores_directory_root_and_leaves_it_readable() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("hello.txt"), b"directory content").expect("write");

    let vfs = NativeVfs::new();
    let dir_root = RootId::new(42);
    vfs.register_root(dir_root, dir.path().to_path_buf(), false)
        .expect("register_root");

    let res = vfs.unregister_open_file(dir_root);
    assert_eq!(res, Err(VfsError::NotFound));

    let rel_path = RelPath::new("hello.txt").expect("rel path");
    let meta = vfs
        .stat(dir_root, &rel_path)
        .await
        .expect("root remains readable");
    assert_eq!(meta.size_bytes, 17);
}

//! Supervisor-authored tests for `Vfs::rename_no_replace` (DCR-171).
//! Critical Module: boundary enforcement in tradr-vfs. Placement must never
//! replace a file, even when two of this process's placements race for a name.

use std::sync::Arc;

use tradr_core::{RelPath, RootId, Vfs, VfsError};
use tradr_vfs::NativeVfs;

fn rel(s: &str) -> RelPath {
    RelPath::new(s).expect("relpath")
}

fn setup(read_only: bool) -> (tempfile::TempDir, NativeVfs, RootId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(7);
    vfs.register_root(root, dir.path().to_path_buf(), read_only)
        .expect("register root");
    (dir, vfs, root)
}

#[tokio::test]
async fn moves_a_file_onto_a_free_name() {
    let (dir, vfs, root) = setup(false);
    std::fs::write(dir.path().join("a.txt"), b"alpha").expect("write a");

    vfs.rename_no_replace(root, &rel("a.txt"), &rel("b.txt"))
        .await
        .expect("a free name is taken");

    assert!(!dir.path().join("a.txt").exists());
    assert_eq!(
        std::fs::read(dir.path().join("b.txt")).expect("read b"),
        b"alpha"
    );
}

#[tokio::test]
async fn creates_missing_parent_directories_as_rename_does() {
    let (dir, vfs, root) = setup(false);
    std::fs::write(dir.path().join("a.txt"), b"alpha").expect("write a");

    vfs.rename_no_replace(root, &rel("a.txt"), &rel("inbox/new/b.txt"))
        .await
        .expect("parents are created");

    assert_eq!(
        std::fs::read(dir.path().join("inbox/new/b.txt")).expect("read b"),
        b"alpha"
    );
}

#[tokio::test]
async fn refuses_an_existing_file_and_leaves_both_untouched() {
    let (dir, vfs, root) = setup(false);
    std::fs::write(dir.path().join("a.txt"), b"alpha").expect("write a");
    std::fs::write(dir.path().join("b.txt"), b"bravo").expect("write b");

    assert_eq!(
        vfs.rename_no_replace(root, &rel("a.txt"), &rel("b.txt"))
            .await
            .unwrap_err(),
        VfsError::AlreadyExists
    );

    assert_eq!(
        std::fs::read(dir.path().join("a.txt")).expect("a"),
        b"alpha"
    );
    assert_eq!(
        std::fs::read(dir.path().join("b.txt")).expect("b"),
        b"bravo"
    );
}

#[tokio::test]
async fn refuses_an_existing_directory() {
    let (dir, vfs, root) = setup(false);
    std::fs::write(dir.path().join("a.txt"), b"alpha").expect("write a");
    std::fs::create_dir(dir.path().join("b")).expect("mkdir b");

    assert_eq!(
        vfs.rename_no_replace(root, &rel("a.txt"), &rel("b"))
            .await
            .unwrap_err(),
        VfsError::AlreadyExists
    );
    assert!(dir.path().join("a.txt").exists());
    assert!(dir.path().join("b").is_dir());
}

#[cfg(unix)]
#[tokio::test]
async fn never_replaces_a_symlink_at_the_target() {
    let (dir, vfs, root) = setup(false);
    let outside = tempfile::tempdir().expect("outside");
    std::fs::write(outside.path().join("secret"), b"secret").expect("write secret");
    std::fs::write(dir.path().join("a.txt"), b"alpha").expect("write a");
    std::os::unix::fs::symlink(outside.path().join("secret"), dir.path().join("b.txt"))
        .expect("symlink");

    assert!(
        vfs.rename_no_replace(root, &rel("a.txt"), &rel("b.txt"))
            .await
            .is_err()
    );

    assert!(
        std::fs::symlink_metadata(dir.path().join("b.txt"))
            .expect("link still there")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read(outside.path().join("secret")).expect("secret"),
        b"secret"
    );
    assert!(dir.path().join("a.txt").exists());
}

#[tokio::test]
async fn a_read_only_root_refuses() {
    let (dir, vfs, root) = setup(true);
    std::fs::write(dir.path().join("a.txt"), b"alpha").expect("write a");

    assert_eq!(
        vfs.rename_no_replace(root, &rel("a.txt"), &rel("b.txt"))
            .await
            .unwrap_err(),
        VfsError::ReadOnly
    );
    assert!(dir.path().join("a.txt").exists());
}

#[tokio::test]
async fn refuses_a_target_inside_the_partial_directory() {
    let (dir, vfs, root) = setup(false);
    std::fs::write(dir.path().join("a.txt"), b"alpha").expect("write a");
    std::fs::create_dir(dir.path().join(".tradr-partial")).expect("mkdir partial");

    assert_eq!(
        vfs.rename_no_replace(root, &rel("a.txt"), &rel(".tradr-partial/a.txt"))
            .await
            .unwrap_err(),
        VfsError::DenyListed
    );
    assert!(dir.path().join("a.txt").exists());
}

#[tokio::test]
async fn a_missing_source_is_not_found() {
    let (_dir, vfs, root) = setup(false);

    assert_eq!(
        vfs.rename_no_replace(root, &rel("absent.txt"), &rel("b.txt"))
            .await
            .unwrap_err(),
        VfsError::NotFound
    );
}

// Many rounds of many racers, because one round can pass by luck.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn racing_placements_onto_one_name_let_exactly_one_win() {
    const RACERS: usize = 16;
    const ROUNDS: usize = 40;

    let (dir, vfs, root) = setup(false);
    let vfs = Arc::new(vfs);

    for round in 0..ROUNDS {
        let target = format!("photo-{round}.jpg");
        for i in 0..RACERS {
            std::fs::write(dir.path().join(format!("src-{round}-{i}")), format!("{i}"))
                .expect("write source");
        }

        let barrier = Arc::new(tokio::sync::Barrier::new(RACERS));
        let mut tasks = Vec::with_capacity(RACERS);
        for i in 0..RACERS {
            let vfs = Arc::clone(&vfs);
            let barrier = Arc::clone(&barrier);
            let from = rel(&format!("src-{round}-{i}"));
            let to = rel(&target);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                vfs.rename_no_replace(root, &from, &to).await
            }));
        }

        let mut wins = 0;
        let mut refusals = 0;
        for task in tasks {
            match task.await.expect("join") {
                Ok(()) => wins += 1,
                Err(VfsError::AlreadyExists) => refusals += 1,
                Err(other) => panic!("unexpected error in round {round}: {other:?}"),
            }
        }
        assert_eq!(wins, 1, "round {round}: exactly one placement wins");
        assert_eq!(
            refusals,
            RACERS - 1,
            "round {round}: every other is refused"
        );

        let remaining = (0..RACERS)
            .filter(|i| dir.path().join(format!("src-{round}-{i}")).exists())
            .count();
        assert_eq!(
            remaining,
            RACERS - 1,
            "round {round}: every refused source is left where it was"
        );
    }
}

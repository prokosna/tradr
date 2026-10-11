//! Supervisor-authored tests for `NativeVfs::host_file_path` (ADR-0026, DCR-186).
//! Critical Module: boundary enforcement in tradr-vfs. The method is the one
//! place a location leaves this crate, so it must answer exactly where the
//! validated open reaches and refuse everything that open refuses.

use std::path::{Path, PathBuf};

use tradr_core::{RelPath, RootId, Vfs, VfsError};
use tradr_vfs::NativeVfs;

fn rooted(dir: &Path, read_only: bool) -> (NativeVfs, RootId) {
    let vfs = NativeVfs::new();
    let root = RootId::new(1);
    vfs.register_root(root, dir.to_path_buf(), read_only)
        .expect("register root");
    (vfs, root)
}

fn rel(s: &str) -> RelPath {
    RelPath::new(s).unwrap_or_else(|e| panic!("{s} must be a valid RelPath: {e}"))
}

fn canonical(dir: &Path) -> PathBuf {
    dir.canonicalize().expect("canonical root")
}

// The refusal must be the validated open's own refusal, so the two cannot
// drift apart: whatever `open_read` will not open has no location.
async fn assert_refused_as_open_read(vfs: &NativeVfs, root: RootId, at: &str) -> VfsError {
    let at = rel(at);
    let opened = match vfs.open_read(root, &at).await {
        Ok(_) => panic!("{at} must not be openable for this test to mean anything"),
        Err(e) => e,
    };
    let located = vfs
        .host_file_path(root, &at)
        .expect_err("a target open_read refuses has no location");
    assert_eq!(located, opened, "refusal differs from open_read's for {at}");
    located
}

#[tokio::test]
async fn a_regular_file_answers_the_root_joined_with_its_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("report.pdf"), b"pdf").expect("write");
    let (vfs, root) = rooted(dir.path(), false);

    let path = vfs
        .host_file_path(root, &rel("report.pdf"))
        .expect("a regular file has a location");
    assert_eq!(path, canonical(dir.path()).join("report.pdf"));
    assert_eq!(std::fs::read(&path).expect("read back"), b"pdf");
}

#[tokio::test]
async fn a_nested_file_answers_every_component_in_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("a").join("b")).expect("mkdir");
    std::fs::write(dir.path().join("a").join("b").join("c.txt"), b"c").expect("write");
    let (vfs, root) = rooted(dir.path(), false);

    let path = vfs
        .host_file_path(root, &rel("a/b/c.txt"))
        .expect("a nested regular file has a location");
    assert_eq!(
        path,
        canonical(dir.path()).join("a").join("b").join("c.txt")
    );
}

#[tokio::test]
async fn a_name_with_spaces_and_non_ascii_survives_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let name = "旅行 の 写真 (1).jpg";
    std::fs::write(dir.path().join(name), b"jpg").expect("write");
    let (vfs, root) = rooted(dir.path(), false);

    let path = vfs
        .host_file_path(root, &rel(name))
        .expect("a regular file has a location");
    assert_eq!(std::fs::read(&path).expect("read back"), b"jpg");
    assert!(path.starts_with(canonical(dir.path())));
}

#[tokio::test]
async fn a_read_only_root_answers_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), b"a").expect("write");
    let (vfs, root) = rooted(dir.path(), true);

    assert_eq!(
        vfs.host_file_path(root, &rel("a.txt")).expect("location"),
        canonical(dir.path()).join("a.txt")
    );
}

#[tokio::test]
async fn a_missing_file_is_not_found_and_is_not_created() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vfs, root) = rooted(dir.path(), false);

    let err = assert_refused_as_open_read(&vfs, root, "gone.txt").await;
    assert_eq!(err, VfsError::NotFound);
    assert!(!dir.path().join("gone.txt").exists());
    assert_eq!(std::fs::read_dir(dir.path()).expect("read dir").count(), 0);
}

#[tokio::test]
async fn a_missing_parent_is_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vfs, root) = rooted(dir.path(), false);

    let err = assert_refused_as_open_read(&vfs, root, "nowhere/gone.txt").await;
    assert_eq!(err, VfsError::NotFound);
    assert!(!dir.path().join("nowhere").exists());
}

#[tokio::test]
async fn a_directory_has_no_location() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("photos")).expect("mkdir");
    let (vfs, root) = rooted(dir.path(), false);

    let err = assert_refused_as_open_read(&vfs, root, "photos").await;
    assert_eq!(err, VfsError::WrongKind);
}

#[tokio::test]
async fn the_root_itself_has_no_location() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vfs, root) = rooted(dir.path(), false);

    let at = RelPath::root();
    assert_eq!(
        vfs.open_read(root, &at).await.err(),
        Some(VfsError::WrongKind)
    );
    assert_eq!(
        vfs.host_file_path(root, &at).unwrap_err(),
        VfsError::WrongKind
    );
}

#[tokio::test]
async fn a_deny_listed_file_has_no_location_even_though_it_exists() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join(".ssh")).expect("mkdir");
    std::fs::write(dir.path().join(".ssh").join("id_rsa"), b"key").expect("write");
    std::fs::write(dir.path().join("server.pem"), b"pem").expect("write");
    let (vfs, root) = rooted(dir.path(), false);

    assert_eq!(
        assert_refused_as_open_read(&vfs, root, ".ssh/id_rsa").await,
        VfsError::DenyListed
    );
    assert_eq!(
        assert_refused_as_open_read(&vfs, root, "server.pem").await,
        VfsError::DenyListed
    );
}

#[tokio::test]
async fn an_unregistered_root_has_no_location() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), b"a").expect("write");
    let (vfs, _root) = rooted(dir.path(), false);

    assert_refused_as_open_read(&vfs, RootId::new(99), "a.txt").await;
}

#[tokio::test]
async fn a_file_in_another_root_is_not_reachable_through_this_one() {
    let ours = tempfile::tempdir().expect("tempdir");
    let theirs = tempfile::tempdir().expect("tempdir");
    std::fs::write(theirs.path().join("secret.txt"), b"s").expect("write");
    let (vfs, root) = rooted(ours.path(), false);
    vfs.register_root(RootId::new(2), theirs.path().to_path_buf(), false)
        .expect("register second root");

    let err = assert_refused_as_open_read(&vfs, root, "secret.txt").await;
    assert_eq!(err, VfsError::NotFound);
    assert_eq!(
        vfs.host_file_path(RootId::new(2), &rel("secret.txt"))
            .expect("its own root answers"),
        canonical(theirs.path()).join("secret.txt")
    );
}

#[cfg(unix)]
mod symlinks {
    use super::*;
    use std::os::unix::fs::symlink;

    // docs/06 step 6 rejects a symlink even when it resolves inside, and the
    // location of a link is the location of whatever it is repointed at.
    #[tokio::test]
    async fn a_symlink_to_a_file_inside_the_root_has_no_location() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("real.txt"), b"r").expect("write");
        symlink(dir.path().join("real.txt"), dir.path().join("link.txt")).expect("symlink");
        let (vfs, root) = rooted(dir.path(), false);

        assert_refused_as_open_read(&vfs, root, "link.txt").await;
        assert!(vfs.host_file_path(root, &rel("real.txt")).is_ok());
    }

    #[tokio::test]
    async fn a_symlink_to_a_file_outside_the_root_has_no_location() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("tempdir");
        std::fs::write(outside.path().join("secret.txt"), b"s").expect("write");
        symlink(
            outside.path().join("secret.txt"),
            dir.path().join("innocent.txt"),
        )
        .expect("symlink");
        let (vfs, root) = rooted(dir.path(), false);

        assert_refused_as_open_read(&vfs, root, "innocent.txt").await;
    }

    #[tokio::test]
    async fn a_symlinked_directory_component_has_no_location_beneath_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("tempdir");
        std::fs::write(outside.path().join("secret.txt"), b"s").expect("write");
        symlink(outside.path(), dir.path().join("sub")).expect("symlink");
        let (vfs, root) = rooted(dir.path(), false);

        assert_refused_as_open_read(&vfs, root, "sub/secret.txt").await;
    }

    #[tokio::test]
    async fn a_dangling_symlink_has_no_location() {
        let dir = tempfile::tempdir().expect("tempdir");
        symlink(dir.path().join("nothing"), dir.path().join("dangling")).expect("symlink");
        let (vfs, root) = rooted(dir.path(), false);

        assert_refused_as_open_read(&vfs, root, "dangling").await;
    }

    // A root registered through a link answers under the directory the link
    // names, since that is the directory the validated open descends from.
    #[tokio::test]
    async fn a_root_registered_through_a_symlink_answers_under_its_real_directory() {
        let real = tempfile::tempdir().expect("tempdir");
        let holder = tempfile::tempdir().expect("tempdir");
        std::fs::write(real.path().join("a.txt"), b"a").expect("write");
        let alias = holder.path().join("alias");
        symlink(real.path(), &alias).expect("symlink");
        let (vfs, root) = rooted(&alias, false);

        assert_eq!(
            vfs.host_file_path(root, &rel("a.txt")).expect("location"),
            canonical(real.path()).join("a.txt")
        );
    }

    // ADR-0026: a root over an open descriptor has no location to give.
    #[tokio::test]
    async fn an_open_file_root_has_no_location() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("video.mp4");
        std::fs::write(&file_path, b"v").expect("write");
        let vfs = NativeVfs::new();
        let root = RootId::new(7);
        vfs.register_open_file(
            root,
            std::fs::File::open(&file_path).expect("open"),
            "video.mp4",
        )
        .expect("register open file");

        assert!(vfs.open_read(root, &rel("video.mp4")).await.is_ok());
        assert_eq!(
            vfs.host_file_path(root, &rel("video.mp4")).unwrap_err(),
            VfsError::UnsupportedEntry
        );
    }
}

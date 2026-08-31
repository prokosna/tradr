//! Supervisor-authored tests for the Share Root boundary (CLAUDE.md
//! section 6). docs/06 says validation and opening are never separated,
//! and that a symlink is rejected even when it resolves inside the root.
//! Before WI-M1-018 this crate had no symlink test of any kind.

#![cfg(unix)]

use std::os::unix::fs::symlink;
use std::path::Path;
use tradr_core::{RelPath, RootId, Vfs, VfsError};
use tradr_vfs::NativeVfs;
use tradr_vfs::sanitization::sanitize_destination_path;

fn rooted(dir: &Path) -> (NativeVfs, RootId) {
    let vfs = NativeVfs::new();
    let root = RootId::new(1);
    vfs.register_root(root, dir.to_path_buf(), false)
        .expect("register root");
    (vfs, root)
}

fn rel(s: &str) -> RelPath {
    RelPath::new(s).unwrap_or_else(|e| panic!("{s} must be a valid RelPath: {e}"))
}

// docs/06 step 6 rejects a symlink "even when it resolves inside, to avoid
// TOCTOU": what a name resolves to at check time is not what it resolves
// to at open time, and only refusing the kind outright closes that.
#[tokio::test]
async fn a_symlink_into_the_root_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("real.txt"), b"inside").expect("write");
    symlink("real.txt", dir.path().join("link.txt")).expect("symlink");
    let (vfs, root) = rooted(dir.path());

    assert!(
        vfs.open_read(root, &rel("link.txt")).await.is_err(),
        "a symlink resolving inside the root is still a symlink"
    );
    assert!(vfs.stat(root, &rel("link.txt")).await.is_err());
}

#[tokio::test]
async fn a_symlink_out_of_the_root_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    std::fs::write(outside.path().join("secret"), b"not yours").expect("write");
    symlink(outside.path().join("secret"), dir.path().join("escape")).expect("symlink");
    let (vfs, root) = rooted(dir.path());

    assert!(vfs.open_read(root, &rel("escape")).await.is_err());
    assert!(vfs.stat(root, &rel("escape")).await.is_err());
}

#[tokio::test]
async fn a_symlink_as_an_intermediate_component_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    std::fs::create_dir(outside.path().join("d")).expect("mkdir");
    std::fs::write(outside.path().join("d/secret"), b"not yours").expect("write");
    std::fs::create_dir(dir.path().join("inner")).expect("mkdir");
    std::fs::write(dir.path().join("inner/ok.txt"), b"inside").expect("write");
    symlink(outside.path().join("d"), dir.path().join("hop")).expect("symlink out");
    symlink("inner", dir.path().join("alias")).expect("symlink in");
    let (vfs, root) = rooted(dir.path());

    assert!(
        vfs.open_read(root, &rel("hop/secret")).await.is_err(),
        "a symlinked directory must not be a way out of the root"
    );
    assert!(
        vfs.open_read(root, &rel("alias/ok.txt")).await.is_err(),
        "nor a way in, since the kind is what is refused"
    );
}

// The sharp case: nothing exists at the far end, so an existence check
// walks past the link and validates an ancestor instead. The open then
// creates the file the link points at, outside the root.
#[tokio::test]
async fn a_dangling_symlink_is_not_followed_into_a_new_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    let target = outside.path().join("planted");
    symlink(&target, dir.path().join("bait")).expect("symlink");
    let (vfs, root) = rooted(dir.path());

    assert!(
        vfs.open_write(root, &rel("bait")).await.is_err(),
        "writing through a dangling symlink creates a file outside the root"
    );
    assert!(
        !target.exists(),
        "the file at the far end of the link must never have been created"
    );
}

#[tokio::test]
async fn every_operation_refuses_an_escape_not_only_reads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    let victim = outside.path().join("victim");
    std::fs::write(&victim, b"not yours").expect("write");
    std::fs::write(dir.path().join("ordinary.txt"), b"mine").expect("write");
    symlink(&victim, dir.path().join("escape")).expect("symlink");
    let (vfs, root) = rooted(dir.path());

    assert!(vfs.open_write(root, &rel("escape")).await.is_err());
    assert!(vfs.remove(root, &rel("escape")).await.is_err());
    assert!(vfs.list(root, &rel("escape")).await.is_err());
    assert!(vfs.create_dir(root, &rel("escape/sub")).await.is_err());
    assert!(
        vfs.rename(root, &rel("ordinary.txt"), &rel("escape"))
            .await
            .is_err(),
        "a rename must not be a way to write through an escape"
    );
    assert!(
        victim.exists() && std::fs::read(&victim).expect("read") == b"not yours",
        "the file outside the root must be untouched by every one of those"
    );
}

#[tokio::test]
async fn a_listing_shows_files_and_directories_and_no_symlinks() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("real.txt"), b"x").expect("write");
    std::fs::create_dir(dir.path().join("realdir")).expect("mkdir");
    symlink("real.txt", dir.path().join("link.txt")).expect("symlink");
    symlink("nowhere", dir.path().join("dangling")).expect("symlink");
    let (vfs, root) = rooted(dir.path());

    let names: Vec<String> = vfs
        .list(root, &RelPath::root())
        .await
        .expect("listing the Share Root")
        .into_iter()
        .map(|e| e.name)
        .collect();

    assert!(names.iter().any(|n| n == "real.txt"));
    assert!(names.iter().any(|n| n == "realdir"));
    assert!(
        !names.iter().any(|n| n == "link.txt" || n == "dangling"),
        "docs/06 refuses symlinks, so a listing must not offer one"
    );
}

#[tokio::test]
async fn an_ordinary_nested_path_still_works() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("a/b")).expect("mkdir");
    std::fs::write(dir.path().join("a/b/c.txt"), b"hello").expect("write");
    let (vfs, root) = rooted(dir.path());

    let meta = vfs
        .stat(root, &rel("a/b/c.txt"))
        .await
        .expect("a plain path beneath the root must resolve");
    assert_eq!(meta.size_bytes, 5);
}

// docs/06 step 2 assigns Unicode normalization to this crate, which then
// rebuilds a RelPath from the normalized string so one copy of the rules
// applies to both forms.
#[test]
fn a_decomposed_name_is_normalized_to_its_composed_form() {
    let decomposed = "cafe\u{0301}.txt";
    let composed = "caf\u{00e9}.txt";

    let sanitized = sanitize_destination_path(decomposed).expect("a valid name in either form");
    assert_eq!(
        sanitized.as_str(),
        composed,
        "two spellings of one name must not become two files"
    );
    assert_eq!(
        sanitize_destination_path(composed)
            .expect("already composed")
            .as_str(),
        composed,
        "and normalizing an already-composed name must change nothing"
    );
}

// NFKC maps fullwidth forms onto ASCII, so a normalization that reached
// for it would manufacture a separator and a parent traversal out of a
// name that contained neither. NFC does not, and the RelPath rebuild is
// the second answer if it ever did.
#[test]
fn normalization_never_manufactures_a_separator_or_a_traversal() {
    let fullwidth = "\u{ff0e}\u{ff0e}\u{ff0f}etc\u{ff0f}passwd";

    if let Ok(path) = sanitize_destination_path(fullwidth) {
        assert!(
            !path.as_str().contains("../"),
            "normalization turned a fullwidth name into a traversal: {}",
            path.as_str()
        );
        assert!(
            path.components().all(|c| c != ".."),
            "normalization produced a parent component"
        );
    }
}

#[tokio::test]
async fn a_normalized_name_reaches_the_file_written_under_either_spelling() {
    let dir = tempfile::tempdir().expect("tempdir");
    let composed = "caf\u{00e9}.txt";
    std::fs::write(dir.path().join(composed), b"hello").expect("write");
    let (vfs, root) = rooted(dir.path());

    let sanitized = sanitize_destination_path("cafe\u{0301}.txt").expect("valid");
    let meta = vfs
        .stat(root, &sanitized)
        .await
        .expect("the decomposed spelling must reach the composed file");
    assert_eq!(meta.size_bytes, 5);
    assert!(matches!(
        vfs.open_read(root, &rel("missing.txt")).await,
        Err(VfsError::NotFound)
    ));
}

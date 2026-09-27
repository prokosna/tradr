//! Supervisor-authored tests for a single-file root over an already-open
//! file (CLAUDE.md section 6, ADR-0023, DCR-165). Boundary enforcement is
//! the module: the root exposes exactly one name, for reading, and nothing
//! a caller names can reach past it or change it.
#![cfg(unix)]

use std::io::{Seek, SeekFrom, Write};

use tradr_core::{EntryKind, RelPath, RootId, Vfs, VfsError};
use tradr_vfs::NativeVfs;

fn root_id() -> RootId {
    RootId::new(7)
}

const NAME: &str = "holiday video.mp4";

// Deterministic and not a run of equal bytes, so a read from the wrong
// offset cannot happen to match.
fn content(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x: u32 = 0x9e37_79b9;
    while out.len() < len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

// The descriptor Android hands over is positioned wherever the provider
// left it, so the file is registered with its offset at the end.
fn adopted(data: &[u8]) -> (tempfile::TempDir, std::fs::File) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(dir.path().join("backing"))
        .expect("backing file");
    file.write_all(data).expect("write");
    file.seek(SeekFrom::End(0)).expect("seek to end");
    (dir, file)
}

fn registered(data: &[u8]) -> (tempfile::TempDir, NativeVfs) {
    let (dir, file) = adopted(data);
    let vfs = NativeVfs::new();
    vfs.register_open_file(root_id(), file, NAME)
        .expect("a plain name registers");
    (dir, vfs)
}

fn rel(s: &str) -> RelPath {
    RelPath::new(s).expect("valid relative path")
}

async fn read_exact_at(vfs: &NativeVfs, offset: u64, len: usize) -> Vec<u8> {
    let handle = vfs
        .open_read(root_id(), &rel(NAME))
        .await
        .expect("open_read");
    let mut out = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        let n = handle
            .read_at(offset + filled as u64, &mut out[filled..])
            .await
            .expect("read_at");
        assert!(
            n > 0,
            "unexpected end of file at {}",
            offset + filled as u64
        );
        filled += n;
    }
    out
}

#[tokio::test]
async fn stat_reports_the_file_under_its_name() {
    let data = content(3 * 1024 * 1024 + 17);
    let (_dir, vfs) = registered(&data);

    let meta = vfs.stat(root_id(), &rel(NAME)).await.expect("stat");
    assert_eq!(meta.kind, EntryKind::File);
    assert_eq!(meta.size_bytes, data.len() as u64);
}

#[tokio::test]
async fn reads_are_positioned_whatever_the_descriptor_offset_was() {
    let data = content(3 * 1024 * 1024 + 17);
    let (_dir, vfs) = registered(&data);

    for offset in [0usize, 1, 1024 * 1024, 3 * 1024 * 1024] {
        let len = 17.min(data.len() - offset);
        let got = read_exact_at(&vfs, offset as u64, len).await;
        assert_eq!(got, data[offset..offset + len], "bytes at {offset}");
    }
    assert_eq!(read_exact_at(&vfs, 0, data.len()).await, data);
}

#[tokio::test]
async fn a_read_at_the_end_answers_zero() {
    let data = content(4096);
    let (_dir, vfs) = registered(&data);

    let handle = vfs
        .open_read(root_id(), &rel(NAME))
        .await
        .expect("open_read");
    let mut buf = [0u8; 16];
    assert_eq!(handle.read_at(4096, &mut buf).await, Ok(0));
}

// Two handles over one adopted file share one open file description, so
// a handle that seeks before reading can read at the other's offset. Only
// a positioned read is correct here, whatever the scheduling.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_handles_never_read_at_each_others_offset() {
    let data = content(2 * 1024 * 1024);
    let (_dir, vfs) = registered(&data);
    let a = vfs
        .open_read(root_id(), &rel(NAME))
        .await
        .expect("open_read a");
    let b = vfs
        .open_read(root_id(), &rel(NAME))
        .await
        .expect("open_read b");

    for i in 0..300u64 {
        let off_a = (i * 4099) % (1024 * 1024);
        let off_b = 1024 * 1024 + (i * 7919) % (1024 * 1024 - 64);
        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];
        let (ra, rb) = tokio::join!(a.read_at(off_a, &mut buf_a), b.read_at(off_b, &mut buf_b));
        let (na, nb) = (ra.expect("read a"), rb.expect("read b"));
        assert_eq!(buf_a[..na], data[off_a as usize..off_a as usize + na]);
        assert_eq!(buf_b[..nb], data[off_b as usize..off_b as usize + nb]);
    }
}

#[tokio::test]
async fn listing_the_root_shows_exactly_the_one_name() {
    let data = content(5000);
    let (_dir, vfs) = registered(&data);

    let entries = vfs.list(root_id(), &RelPath::root()).await.expect("list");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, NAME);
    assert_eq!(entries[0].kind, EntryKind::File);
    assert_eq!(entries[0].size_bytes, 5000);
}

#[tokio::test]
async fn no_other_name_is_reachable() {
    let (dir, vfs) = registered(&content(100));
    std::fs::write(dir.path().join("neighbour"), b"secret").expect("neighbour");

    for other in [
        "neighbour",
        "backing",
        "holiday video.mp4/inner",
        "Holiday Video.mp4",
    ] {
        assert_eq!(
            vfs.stat(root_id(), &rel(other)).await,
            Err(VfsError::NotFound),
            "stat {other}"
        );
        assert!(
            matches!(
                vfs.open_read(root_id(), &rel(other)).await,
                Err(VfsError::NotFound)
            ),
            "open_read {other}"
        );
        assert_eq!(
            vfs.list(root_id(), &rel(other)).await,
            Err(VfsError::NotFound),
            "list {other}"
        );
    }
}

#[tokio::test]
async fn nothing_can_be_written_created_moved_or_removed() {
    let data = content(100);
    let (dir, vfs) = registered(&data);

    assert!(matches!(
        vfs.open_write(root_id(), &rel(NAME)).await,
        Err(VfsError::ReadOnly)
    ));
    assert!(matches!(
        vfs.open_write(root_id(), &rel("new")).await,
        Err(VfsError::ReadOnly)
    ));
    assert_eq!(
        vfs.create_dir(root_id(), &rel("dir")).await,
        Err(VfsError::ReadOnly)
    );
    assert_eq!(
        vfs.rename(root_id(), &rel(NAME), &rel("moved")).await,
        Err(VfsError::ReadOnly)
    );
    assert_eq!(
        vfs.remove(root_id(), &rel(NAME)).await,
        Err(VfsError::ReadOnly)
    );

    assert_eq!(
        std::fs::read(dir.path().join("backing")).expect("read"),
        data
    );
    assert_eq!(
        vfs.stat(root_id(), &rel(NAME))
            .await
            .expect("stat")
            .size_bytes,
        100
    );
}

#[test]
fn a_name_that_is_not_one_plain_component_is_refused() {
    for bad in ["", ".", "..", "a/b", "/abs", "../escape", "a\0b"] {
        let (_dir, file) = adopted(b"x");
        assert!(
            NativeVfs::new()
                .register_open_file(root_id(), file, bad)
                .is_err(),
            "{bad:?} must not register"
        );
    }
}

#[tokio::test]
async fn a_directory_root_beside_it_is_unaffected() {
    let (_dir, vfs) = registered(&content(100));
    let share = tempfile::tempdir().expect("share");
    std::fs::write(share.path().join("a.txt"), b"abc").expect("a.txt");
    let share_root = RootId::new(8);
    vfs.register_root(share_root, share.path().to_path_buf(), false)
        .expect("register_root");

    assert_eq!(
        vfs.stat(share_root, &rel("a.txt"))
            .await
            .expect("stat")
            .size_bytes,
        3
    );
    assert_eq!(
        vfs.stat(share_root, &rel(NAME)).await,
        Err(VfsError::NotFound)
    );
}

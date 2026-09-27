#![cfg(unix)]

use std::io::{Read, Seek, SeekFrom, Write};
use tradr_vfs::NativeVfs;

#[test]
fn scratch_file_in_configured_dir_is_usable_and_leaves_directory_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new().with_scratch_dir(dir.path().to_path_buf());

    let mut file = vfs.scratch_file().expect("scratch file");
    let payload = b"spooled outboard data chunk";
    file.write_all(payload).expect("write");
    file.seek(SeekFrom::Start(0)).expect("seek");

    let mut read_back = Vec::new();
    file.read_to_end(&mut read_back).expect("read");
    assert_eq!(read_back, payload);

    let entries_open: Vec<_> = std::fs::read_dir(dir.path()).expect("read_dir").collect();
    assert!(
        entries_open.is_empty(),
        "directory must hold no entries while scratch file is open"
    );

    drop(file);

    let entries_dropped: Vec<_> = std::fs::read_dir(dir.path()).expect("read_dir").collect();
    assert!(
        entries_dropped.is_empty(),
        "directory must hold no entries after scratch file is dropped"
    );
}

#[test]
fn scratch_file_with_default_directory_is_usable() {
    let vfs = NativeVfs::new();

    let mut file = vfs.scratch_file().expect("scratch file in default dir");
    let payload = b"default tempdir payload";
    file.write_all(payload).expect("write");
    file.seek(SeekFrom::Start(0)).expect("seek");

    let mut read_back = Vec::new();
    file.read_to_end(&mut read_back).expect("read");
    assert_eq!(read_back, payload);
}

#[test]
fn scratch_file_in_nonexistent_directory_returns_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing_dir = dir.path().join("missing-dir");
    let vfs = NativeVfs::new().with_scratch_dir(missing_dir);

    let res = vfs.scratch_file();
    assert!(
        res.is_err(),
        "allocating scratch file in nonexistent directory must return Err"
    );
}

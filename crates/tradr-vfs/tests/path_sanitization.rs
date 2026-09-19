//! Supervisor-authored tests for path sanitization in tradr-vfs.
//! Critical Module: Filename sanitization and boundary enforcement.
//! See docs/04-protocol.md and AGENTS.md section 6.

use tradr_core::{ItemId, RootId, TransferId};
use tradr_vfs::{
    NativeVfs, SanitizationError, partial_dir_rel_path, partial_file_rel_path, resolve_collision,
    sanitize_destination_path,
};

const VALID_V7: &str = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";

fn sample_transfer() -> TransferId {
    VALID_V7.parse().expect("valid transfer id")
}

#[test]
fn rejects_absolute_paths() {
    assert_eq!(
        sanitize_destination_path("/etc/passwd"),
        Err(SanitizationError::AbsolutePath)
    );
    assert_eq!(
        sanitize_destination_path("C:\\Windows\\System32"),
        Err(SanitizationError::AbsolutePath)
    );
    assert_eq!(
        sanitize_destination_path("\\\\server\\share"),
        Err(SanitizationError::AbsolutePath)
    );
}

#[test]
fn rejects_parent_directory_traversal() {
    assert_eq!(
        sanitize_destination_path("../secret.txt"),
        Err(SanitizationError::ParentTraversal)
    );
    assert_eq!(
        sanitize_destination_path("docs/../../etc/shadow"),
        Err(SanitizationError::ParentTraversal)
    );
    assert_eq!(
        sanitize_destination_path("a/b/../c"),
        Err(SanitizationError::ParentTraversal)
    );
}

#[test]
fn rejects_control_characters_and_nul() {
    assert_eq!(
        sanitize_destination_path("bad\0file.txt"),
        Err(SanitizationError::ControlCharacters)
    );
    assert_eq!(
        sanitize_destination_path("line\nbreak.txt"),
        Err(SanitizationError::ControlCharacters)
    );
    assert_eq!(
        sanitize_destination_path("tab\tchar.txt"),
        Err(SanitizationError::ControlCharacters)
    );
}

#[test]
fn rejects_bidi_overrides_and_isolates() {
    // U+202E Right-to-Left Override
    assert_eq!(
        sanitize_destination_path("report\u{202E}fdp.exe"),
        Err(SanitizationError::BidiOverride)
    );
    // U+202A Left-to-Right Embedding
    assert_eq!(
        sanitize_destination_path("file\u{202A}test.txt"),
        Err(SanitizationError::BidiOverride)
    );
    // U+2066 Left-to-Right Isolate
    assert_eq!(
        sanitize_destination_path("file\u{2066}test.txt"),
        Err(SanitizationError::BidiOverride)
    );
    // U+2028 Line Separator
    assert_eq!(
        sanitize_destination_path("file\u{2028}test.txt"),
        Err(SanitizationError::BidiOverride)
    );
}

#[test]
fn allows_legitimate_directional_marks() {
    // U+200E Left-to-Right Mark and U+200F Right-to-Left Mark are permitted
    let ltr_name = "test\u{200E}doc.txt";
    let rtl_name = "עברית\u{200F}.txt";

    let sanitized_ltr = sanitize_destination_path(ltr_name).expect("LTR mark is permitted");
    assert_eq!(sanitized_ltr.as_str(), ltr_name);

    let sanitized_rtl = sanitize_destination_path(rtl_name).expect("RTL mark is permitted");
    assert_eq!(sanitized_rtl.as_str(), rtl_name);
}

#[test]
fn sanitizes_windows_reserved_names() {
    let reserved = [
        ("CON", "CON_"),
        ("con.txt", "con_.txt"),
        ("aux", "aux_"),
        ("NUL.tar.gz", "NUL_.tar.gz"),
        ("com1", "com1_"),
        ("LPT9.doc", "LPT9_.doc"),
        ("photos/prn/image.png", "photos/prn_/image.png"),
    ];

    for (input, expected) in reserved {
        let sanitized = sanitize_destination_path(input).expect("reserved name must sanitize");
        assert_eq!(sanitized.as_str(), expected);
    }
}

#[test]
fn replaces_a_colon_so_no_component_can_name_an_alternate_data_stream() {
    let cases = [
        ("report.pdf:evil.exe", "report.pdf_evil.exe"),
        ("ab:cd:ef.txt", "ab_cd_ef.txt"),
        ("dir:x/file.txt", "dir_x/file.txt"),
        ("notes:", "notes_"),
        (":leading", "_leading"),
    ];

    for (input, expected) in cases {
        let sanitized =
            sanitize_destination_path(input).expect("a colon must transform, not refuse");
        assert_eq!(sanitized.as_str(), expected);
        assert!(
            !sanitized.as_str().contains(':'),
            "no colon may survive sanitization: {input:?}"
        );
    }
}

#[test]
fn a_colon_bearing_name_is_transformed_rather_than_refused() {
    let sanitized = sanitize_destination_path("2026-08-22T10:00:00.log")
        .expect("an ordinary timestamped name must not be refused");

    assert_eq!(sanitized.as_str(), "2026-08-22T10_00_00.log");
}

#[test]
fn a_drive_prefixed_path_is_still_refused_rather_than_transformed() {
    assert_eq!(
        sanitize_destination_path("C:\\Windows\\System32"),
        Err(SanitizationError::AbsolutePath)
    );
    assert_eq!(
        sanitize_destination_path("D:/data/file.txt"),
        Err(SanitizationError::AbsolutePath)
    );
    // One letter then a colon is the drive position, so it is refused
    // rather than transformed; the colon rule starts after it.
    assert_eq!(
        sanitize_destination_path("a:b.txt"),
        Err(SanitizationError::AbsolutePath)
    );
}

// DF-85: this asserts the outcome and deliberately not the order the two
// transforms run in, which no input can distinguish.
#[test]
fn a_reserved_name_carrying_a_colon_comes_out_safe() {
    let cases = [
        ("CON:", "CON_"),
        ("con:.txt", "con_.txt"),
        ("NUL:x", "NUL_x"),
    ];

    for (input, expected) in cases {
        let sanitized =
            sanitize_destination_path(input).expect("a reserved name with a colon must sanitize");
        assert_eq!(sanitized.as_str(), expected);
        assert!(!sanitized.as_str().contains(':'));
    }
}

#[test]
fn strips_trailing_dots_and_spaces() {
    let cases = [
        ("folder. /file.txt. ", "folder/file.txt"),
        ("docs. /", "docs"),
        ("test. ...", "test"),
        ("my document   ", "my document"),
    ];

    for (input, expected) in cases {
        let sanitized = sanitize_destination_path(input).expect("trailing dots/spaces must strip");
        assert_eq!(sanitized.as_str(), expected);
    }
}

#[test]
fn partial_file_rel_path_constructs_ordinal_location() {
    let item0 = ItemId::new("item_0").unwrap();
    let path0 = partial_file_rel_path(sample_transfer(), &item0);
    assert_eq!(
        path0.as_str(),
        ".tradr-partial/017f22e2-79b0-7cc3-98c4-dc0c0c07398f/item_0"
    );

    let item42 = ItemId::new("item_42").unwrap();
    let path42 = partial_file_rel_path(sample_transfer(), &item42);
    assert_eq!(
        path42.as_str(),
        ".tradr-partial/017f22e2-79b0-7cc3-98c4-dc0c0c07398f/item_42"
    );
}

#[test]
fn partial_dir_and_file_rel_paths_agree() {
    let transfer = sample_transfer();
    let dir = partial_dir_rel_path(transfer);
    let item = ItemId::new("item_0").unwrap();
    let file = partial_file_rel_path(transfer, &item);

    assert_eq!(
        dir.as_str(),
        ".tradr-partial/017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
    );
    let expected_prefix = format!("{}/", dir.as_str());
    assert!(
        file.as_str().starts_with(&expected_prefix),
        "file path {file:?} must be inside directory {dir:?}"
    );
    assert_eq!(&file.as_str()[expected_prefix.len()..], &item.to_string());
}

#[tokio::test]
async fn resolve_collision_numbers_existing_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vfs = NativeVfs::new();
    let root = RootId::new(1);
    vfs.register_root(root, dir.path().to_path_buf(), false)
        .expect("register root");

    let rel = sanitize_destination_path("photo.jpg").unwrap();

    // No file exists yet -> original path returned
    let res0 = resolve_collision(&vfs, root, &rel).await.unwrap();
    assert_eq!(res0.as_str(), "photo.jpg");

    // Create photo.jpg
    std::fs::write(dir.path().join("photo.jpg"), b"first").unwrap();
    let res1 = resolve_collision(&vfs, root, &rel).await.unwrap();
    assert_eq!(res1.as_str(), "photo (2).jpg");

    // Create photo (2).jpg
    std::fs::write(dir.path().join("photo (2).jpg"), b"second").unwrap();
    let res2 = resolve_collision(&vfs, root, &rel).await.unwrap();
    assert_eq!(res2.as_str(), "photo (3).jpg");
}

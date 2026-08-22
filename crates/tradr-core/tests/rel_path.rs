//! Supervisor-authored tests for `RelPath`, written before the implementation.
//! A `relative_path` arrives from the peer, so it is attacker-controlled. See
//! CLAUDE.md section 6, docs/06 "Resolution" step 2, and docs/04 "Name
//! collisions and sanitization". `RelPath` carries the rejecting rules only;
//! every transforming rule belongs to `tradr-vfs`, and so does NFC (DCR-012).

use tradr_core::RelPath;

fn accepted(candidate: &str) -> RelPath {
    match RelPath::new(candidate) {
        Ok(path) => path,
        Err(e) => panic!("{candidate:?} should have been accepted, got {e:?}"),
    }
}

#[test]
fn accepts_a_single_component() {
    assert_eq!(accepted("report.pdf").to_string(), "report.pdf");
}

#[test]
fn accepts_several_components() {
    let path = accepted("scans/2026/august/report.pdf");
    assert_eq!(
        path.components().collect::<Vec<_>>(),
        ["scans", "2026", "august", "report.pdf"]
    );
}

#[test]
fn accepts_non_ascii_names() {
    // Filenames are Unicode. Unlike ItemId, this type is a real name.
    for candidate in [
        "日本語.txt",
        "café.txt",
        "Ω.dat",
        "🙂.png",
        "Ελληνικά/α.txt",
    ] {
        assert!(
            RelPath::new(candidate).is_ok(),
            "{candidate:?} is a legal filename and must be accepted"
        );
    }
}

#[test]
fn accepts_spaces_inside_a_component() {
    assert!(RelPath::new("my documents/holiday photo.jpg").is_ok());
}

#[test]
fn accepts_leading_dots_and_names_that_are_only_dots() {
    // ".hidden" is an ordinary file. "..." is neither "." nor "..".
    for candidate in [".hidden", ".config/app.toml", "...", "....", "a/..."] {
        assert!(
            RelPath::new(candidate).is_ok(),
            "{candidate:?} is not a traversal component and must be accepted"
        );
    }
}

#[test]
fn accepts_windows_reserved_names() {
    // docs/04 says a reserved name is APPENDED WITH "_", not rejected, and
    // that transform is tradr-vfs's. Rejecting here would make a Linux file
    // named "con" unbrowsable. ItemId rejects these; this type must not.
    for candidate in ["con", "PRN", "aux/file.txt", "nul", "com1", "lpt9", "a/CON"] {
        assert!(
            RelPath::new(candidate).is_ok(),
            "{candidate:?} is reserved on Windows, which tradr-vfs handles by \
             appending '_'; RelPath must not reject it"
        );
    }
}

#[test]
fn accepts_trailing_dots_and_spaces() {
    // Also a transform in docs/04, "Strip", and so also not this type's.
    for candidate in ["report.", "report ", "a./b", "a /b"] {
        assert!(
            RelPath::new(candidate).is_ok(),
            "{candidate:?} is stripped by tradr-vfs, not rejected here"
        );
    }
}

#[test]
fn the_root_is_a_distinct_constructor_and_the_empty_string_is_not() {
    // Listing a Share Root needs a zero-component path. Reaching it from a
    // wire string must not be possible, so the empty string is rejected and
    // the root has its own constructor.
    let root = RelPath::root();
    assert_eq!(root.components().count(), 0);
    assert_eq!(root.to_string(), "");
    assert!(RelPath::new("").is_err());
}

#[test]
fn rejects_absolute_paths() {
    for candidate in ["/", "/etc/passwd", "//server/share", "/a"] {
        assert!(
            RelPath::new(candidate).is_err(),
            "{candidate:?} is absolute"
        );
    }
}

#[test]
fn rejects_windows_drive_and_unc_forms() {
    for candidate in [
        "C:\\Windows",
        "C:/Windows",
        "c:/windows",
        "C:",
        "C:file.txt",
        "Z:\\a",
        "\\\\server\\share",
    ] {
        assert!(
            RelPath::new(candidate).is_err(),
            "{candidate:?} names a Windows drive or UNC root"
        );
    }
}

#[test]
fn rejects_backslash_anywhere() {
    // One separator only. A backslash left in a component becomes a
    // separator the moment the path reaches Windows, so a check written
    // against '/' alone would pass here and traverse there.
    for candidate in ["a\\b", "a\\..\\b", "a/b\\c", "\\a", "a\\"] {
        assert!(
            RelPath::new(candidate).is_err(),
            "{candidate:?} contains a backslash"
        );
    }
}

#[test]
fn rejects_parent_traversal_in_every_position() {
    for candidate in [
        "..",
        "../etc/passwd",
        "a/..",
        "a/../b",
        "a/b/..",
        "../..",
        "a/../../b",
    ] {
        assert!(
            RelPath::new(candidate).is_err(),
            "{candidate:?} contains a '..' component"
        );
    }
}

#[test]
fn rejects_current_directory_components() {
    for candidate in [".", "./a", "a/.", "a/./b"] {
        assert!(
            RelPath::new(candidate).is_err(),
            "{candidate:?} contains a '.' component"
        );
    }
}

#[test]
fn rejects_empty_components() {
    // Including a trailing separator, which would otherwise make
    // "a/b" and "a/b/" two spellings of one path.
    for candidate in ["a//b", "a/", "a/b/", "a///b"] {
        assert!(
            RelPath::new(candidate).is_err(),
            "{candidate:?} has an empty component"
        );
    }
}

#[test]
fn rejects_nul_and_control_characters() {
    for candidate in ["a\0b", "a\nb", "a\rb", "a\tb", "\u{7f}", "a/b\u{1}c"] {
        assert!(
            RelPath::new(candidate).is_err(),
            "{candidate:?} contains a control character"
        );
    }
}

#[test]
fn rejects_every_ascii_control_character_in_a_component() {
    for byte in 0u8..=0x1f {
        let candidate = format!("a{}b", byte as char);
        assert!(
            RelPath::new(&candidate).is_err(),
            "a component containing U+{byte:04X} must be rejected"
        );
    }
    assert!(RelPath::new("a\u{7f}b").is_err(), "DEL must be rejected");
}

#[test]
fn rejects_a_name_that_reorders_its_own_display() {
    // The concrete attack docs/04 describes: this renders as
    // "reportexe.pdf" to the user deciding whether to accept it.
    assert!(RelPath::new("report\u{202e}fdp.exe").is_err());
}

#[test]
fn rejects_bidirectional_overrides_embeddings_and_isolates() {
    // None of these is a control character, so a check written against
    // char::is_control alone lets every one of them through.
    for c in [
        '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}',
        '\u{2068}', '\u{2069}',
    ] {
        assert!(
            !c.is_control(),
            "U+{:04X} is not a control character, which is why it needs its own rule",
            c as u32
        );
        for candidate in [format!("a{c}b"), format!("dir/a{c}b"), format!("{c}a")] {
            assert!(
                RelPath::new(&candidate).is_err(),
                "{candidate:?} carries U+{:04X}, a bidi override",
                c as u32
            );
        }
    }
}

#[test]
fn rejects_line_and_paragraph_separators() {
    for c in ['\u{2028}', '\u{2029}'] {
        assert!(!c.is_control());
        assert!(
            RelPath::new(&format!("a{c}b")).is_err(),
            "U+{:04X} breaks any single-line rendering of a name",
            c as u32
        );
    }
}

#[test]
fn accepts_directional_marks_and_rtl_names() {
    // U+200E and U+200F cannot reverse a run, and RTL filenames carry them.
    // Rejecting them would cost every RTL user something real to defend
    // against nothing, which is the over-rejection this suite guards.
    for candidate in [
        "a\u{200e}b",
        "a\u{200f}b",
        "تقرير.pdf",
        "דוח.pdf",
        "dir/\u{200f}تقرير.pdf",
    ] {
        assert!(
            RelPath::new(candidate).is_ok(),
            "{candidate:?} is a legitimate right-to-left name"
        );
    }
}

#[test]
fn accepts_every_other_printable_ascii_in_a_component() {
    // The complement of the check above, so that the rejection is known to
    // be narrow rather than merely present. '/' makes two components and
    // '\\' is rejected on its own. ':' is excluded because this probe puts
    // the character at index 1, where "x:" is a drive prefix; the test below
    // covers ':' in the positions where it is a legal character.
    for byte in 0x20u8..=0x7e {
        let c = byte as char;
        if c == '/' || c == '\\' || c == ':' {
            continue;
        }
        let candidate = format!("x{c}y");
        assert!(
            RelPath::new(&candidate).is_ok(),
            "{candidate:?} is printable ASCII and must be accepted"
        );
    }
}

#[test]
fn accepts_a_colon_outside_the_drive_position() {
    // "2026-08-22T10:00:00.log" is an ordinary Linux filename. On Windows a
    // colon also opens an alternate data stream, a hazard the Windows Vfs
    // handles the way it handles reserved names. Rejecting the character
    // here would cost every platform to defend one.
    for candidate in [
        "2026-08-22T10:00:00.log",
        "xx:y",
        "a/x:y",
        "dir/2026-08-22T10:00:00.log",
    ] {
        assert!(
            RelPath::new(candidate).is_ok(),
            "{candidate:?} uses ':' outside the drive position"
        );
    }
}

#[test]
fn accepts_a_component_of_the_maximum_length() {
    // 255 bytes is NAME_MAX on Linux and the per-component limit on Windows,
    // so it is the one length bound that holds on every target.
    let component = "a".repeat(255);
    assert!(RelPath::new(&component).is_ok(), "255 bytes is the bound");
    assert!(RelPath::new(&format!("{component}/{component}")).is_ok());
}

#[test]
fn rejects_a_component_longer_than_the_maximum() {
    let component = "a".repeat(256);
    assert!(RelPath::new(&component).is_err());
    assert!(RelPath::new(&format!("ok/{component}")).is_err());
    assert!(RelPath::new(&format!("{component}/ok")).is_err());
}

#[test]
fn the_component_bound_counts_bytes_not_characters() {
    // A UTF-8 byte is the unit a POSIX filesystem counts, and counting
    // characters instead would admit a name no Linux filesystem can hold.
    let over = "あ".repeat(86); // 258 bytes, 86 characters
    assert_eq!(over.len(), 258);
    assert_eq!(over.chars().count(), 86);
    assert!(RelPath::new(&over).is_err(), "258 bytes is over the bound");
}

#[test]
fn total_length_is_not_bounded_here() {
    // docs/04 rejects a path beyond "the OS limit", which differs per target
    // and belongs to tradr-vfs. Layer 0 bounds the component and stops.
    let deep = std::iter::repeat_n("component", 600)
        .collect::<Vec<_>>()
        .join("/");
    assert!(deep.len() > 4096);
    assert!(
        RelPath::new(&deep).is_ok(),
        "the total-length limit is tradr-vfs's, not this type's"
    );
}

#[test]
fn every_accepted_path_displays_as_itself() {
    // The string form reaches logs and the UI, so two spellings must never
    // denote one path. Nothing is normalized, trimmed or case-folded here.
    for candidate in [
        "a",
        "a/b/c",
        "日本語/ファイル.txt",
        "report.",
        "CON",
        "...",
        &"a".repeat(255),
    ] {
        assert_eq!(accepted(candidate).to_string(), candidate);
    }
}

#[test]
fn components_rejoined_reproduce_the_path() {
    let candidate = "scans/2026/report.pdf";
    let path = accepted(candidate);
    assert_eq!(path.components().collect::<Vec<_>>().join("/"), candidate);
}

#[test]
fn equal_paths_compare_equal_and_differing_case_does_not() {
    assert_eq!(accepted("a/b"), accepted("a/b"));
    assert_ne!(
        accepted("a/b"),
        accepted("A/B"),
        "case folding belongs to no layer here; two names are two names"
    );
}

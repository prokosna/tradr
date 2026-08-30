//! A `relative_path` naming an Item inside a Share, as it arrives from a
//! peer. See `docs/06-shares-and-browsing.md`, "Enforcing the Share Root
//! boundary", and `docs/04-protocol.md`, "Name collisions and sanitization".
//! Only the rejecting rules live here (absolute paths, drive/UNC forms,
//! `..`, control characters); `tradr-vfs` owns every transforming rule.

use std::fmt;

/// The most bytes a single path component may occupy. 255 is `NAME_MAX` on
/// Linux and the per-component limit on Windows, so it is the one bound
/// that holds regardless of which filesystem eventually receives the path.
pub const REL_PATH_COMPONENT_MAX_LEN: usize = 255;

/// A relative path, made of `/`-separated components, that has been checked
/// against every rule attacker-controlled input must satisfy before it is
/// safe to hand to `tradr-vfs` for joining against a Share Root. Construct
/// with [`RelPath::new`], or [`RelPath::root`] for the zero-component path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelPath {
    value: String,
}

/// An error constructing a `RelPath` from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelPathError {
    /// The input was empty. Use [`RelPath::root`] for the zero-component path.
    Empty,
    /// The input started with `/`.
    Absolute,
    /// The input contained a backslash, which becomes a path separator the
    /// moment it reaches Windows.
    Backslash,
    /// The input started with an ASCII letter followed by `:`, which names a
    /// Windows drive.
    DriveLetter,
    /// The input contained a control character.
    ControlCharacter(char),
    /// The input contained a bidirectional override, embedding, or isolate,
    /// or a line or paragraph separator: none is a control character, but
    /// each can make what renders differ from what is on the wire. See
    /// `docs/04-protocol.md`, "Why a filename may not reorder itself".
    MisleadingDisplay(char),
    /// A component was empty, which happens with a leading, trailing, or
    /// doubled separator.
    EmptyComponent,
    /// A component was exactly `.` or `..`.
    DotComponent(String),
    /// A component was longer than [`REL_PATH_COMPONENT_MAX_LEN`] bytes.
    ComponentTooLong(usize),
}

impl fmt::Display for RelPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "relative path is empty"),
            Self::Absolute => write!(f, "relative path is absolute"),
            Self::Backslash => write!(f, "relative path contains a backslash"),
            Self::DriveLetter => write!(f, "relative path names a Windows drive"),
            Self::ControlCharacter(c) => {
                write!(f, "relative path contains control character {c:?}")
            }
            Self::MisleadingDisplay(c) => write!(
                f,
                "relative path contains U+{:04X}, which can render differently than it reads",
                *c as u32
            ),
            Self::EmptyComponent => write!(f, "relative path has an empty component"),
            Self::DotComponent(s) => write!(f, "relative path has a {s:?} component"),
            Self::ComponentTooLong(len) => write!(
                f,
                "a component is {len} bytes, over the {REL_PATH_COMPONENT_MAX_LEN}-byte bound"
            ),
        }
    }
}

impl std::error::Error for RelPathError {}

// A drive letter is only meaningful at the very start of the path; a colon
// anywhere else is an ordinary character.
fn has_drive_letter_prefix(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some(first), Some(':')) if first.is_ascii_alphabetic()
    )
}

// Not control characters, so char::is_control misses them, but each lets a
// name's rendering differ from its bytes: U+202A-202E and U+2066-2069 can
// reorder a run, and U+2028/U+2029 fake a line break. U+200E/U+200F are
// deliberately excluded: they cannot reverse a run and RTL filenames need them.
fn is_misleading_display_character(c: char) -> bool {
    matches!(
        c,
        '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}'
    )
}

impl RelPath {
    /// Validates `s` against the rejecting rules in `docs/04-protocol.md`,
    /// "Name collisions and sanitization", and builds a `RelPath` from it.
    /// Nothing is trimmed, folded, or normalized: an accepted `s` reproduces
    /// itself exactly from `Display`.
    pub fn new(s: &str) -> Result<Self, RelPathError> {
        if s.is_empty() {
            return Err(RelPathError::Empty);
        }
        if s.starts_with('/') {
            return Err(RelPathError::Absolute);
        }
        if s.contains('\\') {
            return Err(RelPathError::Backslash);
        }
        if has_drive_letter_prefix(s) {
            return Err(RelPathError::DriveLetter);
        }
        if let Some(c) = s.chars().find(|c| c.is_control()) {
            return Err(RelPathError::ControlCharacter(c));
        }
        if let Some(c) = s.chars().find(|&c| is_misleading_display_character(c)) {
            return Err(RelPathError::MisleadingDisplay(c));
        }
        for component in s.split('/') {
            if component.is_empty() {
                return Err(RelPathError::EmptyComponent);
            }
            if component == "." || component == ".." {
                return Err(RelPathError::DotComponent(component.to_string()));
            }
            if component.len() > REL_PATH_COMPONENT_MAX_LEN {
                return Err(RelPathError::ComponentTooLong(component.len()));
            }
        }

        Ok(Self {
            value: s.to_string(),
        })
    }

    /// The zero-component path, used to address a Share Root itself. Not
    /// reachable through [`RelPath::new`]: the empty string is rejected
    /// there so that no wire value can name the root implicitly.
    pub fn root() -> Self {
        Self {
            value: String::new(),
        }
    }

    /// The `/`-separated components of this path, in order. Empty for
    /// [`RelPath::root`].
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.value.split('/').filter(|c| !c.is_empty())
    }

    /// Returns the relative path as a string slice.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl AsRef<str> for RelPath {
    fn as_ref(&self) -> &str {
        &self.value
    }
}

impl AsRef<std::path::Path> for RelPath {
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.value)
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

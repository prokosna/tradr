//! Destination path sanitization and partial file path construction.

use std::fmt;
use tradr_core::{ItemId, RelPath, RelPathError, RootId, TransferId, Vfs, VfsError};
use unicode_normalization::UnicodeNormalization;

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Errors encountered when sanitizing destination file paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanitizationError {
    /// Path was absolute, UNC, or began with a drive letter.
    AbsolutePath,
    /// Path contained a parent directory traversal component (`..`).
    ParentTraversal,
    /// Path contained ASCII control characters or NUL.
    ControlCharacters,
    /// Path contained bidirectional overrides, embeddings, or isolates.
    BidiOverride,
    /// Path failed validation as a relative path.
    InvalidRelPath(RelPathError),
}

impl fmt::Display for SanitizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AbsolutePath => write!(f, "destination path is absolute"),
            Self::ParentTraversal => write!(f, "destination path contains parent traversal ('..')"),
            Self::ControlCharacters => {
                write!(f, "destination path contains control characters or NUL")
            }
            Self::BidiOverride => {
                write!(
                    f,
                    "destination path contains bidirectional overrides or isolates"
                )
            }
            Self::InvalidRelPath(err) => write!(f, "invalid relative path: {err}"),
        }
    }
}

impl std::error::Error for SanitizationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidRelPath(err) => Some(err),
            _ => None,
        }
    }
}

impl From<RelPathError> for SanitizationError {
    fn from(err: RelPathError) -> Self {
        match err {
            RelPathError::Absolute | RelPathError::DriveLetter | RelPathError::Backslash => {
                Self::AbsolutePath
            }
            RelPathError::ControlCharacter(_) => Self::ControlCharacters,
            RelPathError::MisleadingDisplay(_) => Self::BidiOverride,
            RelPathError::DotComponent(ref s) if s == ".." => Self::ParentTraversal,
            other => Self::InvalidRelPath(other),
        }
    }
}

fn is_bidi_override_char(c: char) -> bool {
    matches!(
        c,
        '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}'
    )
}

fn has_drive_prefix(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some(first), Some(':')) if first.is_ascii_alphabetic()
    )
}

/// Sanitizes a raw destination path from a peer according to protocol rules.
pub fn sanitize_destination_path(raw_path: &str) -> Result<RelPath, SanitizationError> {
    let normalized: String = raw_path.nfc().collect();
    if normalized.starts_with('/') || normalized.starts_with('\\') || has_drive_prefix(&normalized)
    {
        return Err(SanitizationError::AbsolutePath);
    }
    if normalized.chars().any(|c| c.is_control()) {
        return Err(SanitizationError::ControlCharacters);
    }
    if normalized.chars().any(is_bidi_override_char) {
        return Err(SanitizationError::BidiOverride);
    }
    if normalized.split('/').any(|comp| comp == "..") {
        return Err(SanitizationError::ParentTraversal);
    }

    let mut sanitized_components = Vec::new();
    for comp in normalized.split('/') {
        let trimmed = comp.trim_end_matches(['.', ' ']);
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == ".." {
            return Err(SanitizationError::ParentTraversal);
        }

        let (stem, ext) = match trimmed.find('.') {
            Some(idx) => (&trimmed[..idx], &trimmed[idx..]),
            None => (trimmed, ""),
        };

        if WINDOWS_RESERVED
            .iter()
            .any(|&reserved| reserved.eq_ignore_ascii_case(stem))
        {
            sanitized_components.push(format!("{stem}_{ext}"));
        } else {
            sanitized_components.push(trimmed.to_string());
        }
    }

    if sanitized_components.is_empty() {
        return RelPath::new("").map_err(SanitizationError::from);
    }

    let joined = sanitized_components.join("/");
    RelPath::new(&joined).map_err(SanitizationError::from)
}

/// Returns the relative path for a transfer's partial file given its item id.
pub fn partial_file_rel_path(transfer_id: TransferId, item_id: &ItemId) -> RelPath {
    RelPath::new(&format!(".tradr-partial/{transfer_id}/{item_id}"))
        .expect("partial file path must be a valid RelPath")
}

/// Resolves destination collisions by appending numeric suffixes if the file exists.
pub async fn resolve_collision(
    vfs: &impl Vfs,
    root: RootId,
    rel_path: &RelPath,
) -> Result<RelPath, VfsError> {
    match vfs.stat(root, rel_path).await {
        Ok(_) => {}
        Err(VfsError::NotFound) => return Ok(rel_path.clone()),
        Err(e) => return Err(e),
    }

    let rel_str = rel_path.as_str();
    let (parent_prefix, file_name) = match rel_str.rfind('/') {
        Some(idx) => (&rel_str[..=idx], &rel_str[idx + 1..]),
        None => ("", rel_str),
    };

    let (stem, ext) = if file_name.starts_with('.') && !file_name[1..].contains('.') {
        (file_name, "")
    } else if let Some(dot_idx) = file_name.rfind('.') {
        if dot_idx > 0 {
            (&file_name[..dot_idx], &file_name[dot_idx..])
        } else {
            (file_name, "")
        }
    } else {
        (file_name, "")
    };

    for counter in 2.. {
        let candidate_rel_str = format!("{parent_prefix}{stem} ({counter}){ext}");
        let candidate_rel = RelPath::new(&candidate_rel_str)
            .map_err(|_| VfsError::Io(std::io::ErrorKind::InvalidInput))?;
        match vfs.stat(root, &candidate_rel).await {
            Ok(_) => continue,
            Err(VfsError::NotFound) => return Ok(candidate_rel),
            Err(e) => return Err(e),
        }
    }

    unreachable!("infinite sequence of counter values");
}

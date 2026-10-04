use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tradr_core::SecretStore;

use super::api::Session;

const SETTINGS_FILE: &str = "brokr.json";
const JOIN_TOKEN_SLOT: &str = "brokr-join-token";
const SESSION_SLOT: &str = "brokr-session";
const MAX_TEMP_ATTEMPTS: u32 = 100;

/// Why reading or writing the Brokr settings failed. No variant carries a
/// token.
#[derive(Debug)]
pub enum SettingsError {
    /// The settings file could not be read, written or removed.
    Io(String),
    /// What was stored did not have the expected shape.
    Malformed(String),
    /// The secret store refused.
    Secret(String),
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(m) => write!(f, "brokr settings storage error: {m}"),
            Self::Malformed(m) => write!(f, "brokr settings are unreadable: {m}"),
            Self::Secret(m) => write!(f, "brokr secret storage error: {m}"),
        }
    }
}

impl std::error::Error for SettingsError {}

/// Where this device's Brokr is. The tokens live in a secret store, not here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokrSettings {
    /// The Brokr's base URL.
    pub url: String,
}

/// The deployment's shared join token. Its `Debug` hides it.
#[derive(Clone, PartialEq, Eq)]
pub struct JoinToken(String);

impl JoinToken {
    /// Wraps a join token.
    pub fn new(token: String) -> Self {
        Self(token)
    }

    /// The token, for the registration request that carries it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for JoinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JoinToken(<redacted>)")
    }
}

fn io(e: impl fmt::Display) -> SettingsError {
    SettingsError::Io(e.to_string())
}

fn secret(e: impl fmt::Display) -> SettingsError {
    SettingsError::Secret(e.to_string())
}

fn create_temp_sibling(path: &Path) -> Result<(std::fs::File, PathBuf), SettingsError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    for _ in 0..MAX_TEMP_ATTEMPTS {
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut name = path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(format!(".tmp-{}-{count}", std::process::id()));
        let temp = path.with_file_name(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
        {
            Ok(file) => return Ok((file, temp)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(io(e)),
        }
    }
    Err(io("no fresh temporary file name was free"))
}

/// Reads the settings in `dir`, or `None` when none were saved.
pub fn load_settings(dir: &Path) -> Result<Option<BrokrSettings>, SettingsError> {
    match std::fs::read(dir.join(SETTINGS_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| SettingsError::Malformed(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io(e)),
    }
}

/// Writes the settings into `dir`, replacing any saved before. A reader never
/// sees a half-written file.
pub fn save_settings(dir: &Path, settings: &BrokrSettings) -> Result<(), SettingsError> {
    std::fs::create_dir_all(dir).map_err(io)?;
    let path = dir.join(SETTINGS_FILE);
    let bytes = serde_json::to_vec(settings).map_err(io)?;
    let (mut file, temp) = create_temp_sibling(&path)?;
    let written = file.write_all(&bytes).and_then(|()| file.sync_all());
    drop(file);
    let result = written
        .and_then(|()| std::fs::rename(&temp, &path))
        .map_err(io);
    if result.is_err() {
        std::fs::remove_file(&temp).map_err(io)?;
    }
    result
}

/// Forgets the saved settings; none saved is a success.
pub fn clear_settings(dir: &Path) -> Result<(), SettingsError> {
    match std::fs::remove_file(dir.join(SETTINGS_FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io(e)),
    }
}

fn load_text(store: &dyn SecretStore, slot: &str) -> Result<Option<String>, SettingsError> {
    match store.load(slot).map_err(secret)? {
        Some(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| SettingsError::Malformed(format!("the {slot} slot is not text"))),
        None => Ok(None),
    }
}

/// Reads the join token, or `None` when none was saved.
pub fn load_join_token(store: &dyn SecretStore) -> Result<Option<JoinToken>, SettingsError> {
    Ok(load_text(store, JOIN_TOKEN_SLOT)?.map(JoinToken::new))
}

/// Stores the join token, replacing any saved before.
pub fn save_join_token(store: &dyn SecretStore, token: &JoinToken) -> Result<(), SettingsError> {
    store
        .store(JOIN_TOKEN_SLOT, token.as_str().as_bytes())
        .map_err(secret)
}

/// Forgets the join token; none saved is a success.
pub fn clear_join_token(store: &dyn SecretStore) -> Result<(), SettingsError> {
    store.remove(JOIN_TOKEN_SLOT).map_err(secret)
}

/// Reads the session token, or `None` when none was saved.
pub fn load_session(store: &dyn SecretStore) -> Result<Option<Session>, SettingsError> {
    Ok(load_text(store, SESSION_SLOT)?.map(Session::new))
}

/// Stores the session token, replacing any saved before.
pub fn save_session(store: &dyn SecretStore, session: &Session) -> Result<(), SettingsError> {
    store
        .store(SESSION_SLOT, session.as_str().as_bytes())
        .map_err(secret)
}

/// Forgets the session token; none saved is a success.
pub fn clear_session(store: &dyn SecretStore) -> Result<(), SettingsError> {
    store.remove(SESSION_SLOT).map_err(secret)
}

//! The Link derivations and the persisted Link registry
//! (docs/11-account-linking.md, "Deriving the Link Secret" and "State
//! after linking"). A Critical Module (CLAUDE.md section 6): what
//! `linked_accounts` reports is exactly what docs/05 step 6 grants
//! `TrustTier::Linked` to.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tradr_core::{Fingerprint, HalfSecret, LinkId, LinkSecret, PublicKeyPoint, UnixTime};

use crate::attestation::AccountId;

/// The context string `derive_link_secret` hands to `BLAKE3::derive_key`
/// (DCR-066). A compile-time constant rather than a negotiated salt,
/// which is what carries the domain separation a salt would otherwise
/// carry here.
const LINK_SECRET_CONTEXT: &str = "tradr-link-v1";

/// The tag `device_fingerprint` prefixes to both keys before hashing
/// (docs/05, "Fingerprint -- the option not to trust Google").
const FINGERPRINT_TAG: &[u8] = b"tradr-fp-v1";

/// Derives the 32-byte Link Secret both sides of a link compute alike:
/// `BLAKE3::derive_key("tradr-link-v1", half_A || half_B)` (DCR-066). The
/// order is by role -- the inviter's half first, the replier's second --
/// and must never be sorted or normalised: doing so would let one side
/// try both orders against a target.
pub fn derive_link_secret(half_a: &HalfSecret, half_b: &HalfSecret) -> LinkSecret {
    let mut key_material = Vec::with_capacity(half_a.as_bytes().len() + half_b.as_bytes().len());
    key_material.extend_from_slice(half_a.as_bytes());
    key_material.extend_from_slice(half_b.as_bytes());
    let bytes = blake3::derive_key(LINK_SECRET_CONTEXT, &key_material);
    LinkSecret::from_bytes(&bytes).expect("blake3::derive_key always returns 32 bytes")
}

/// Derives a Link's identifier from its Link Secret: a plain `BLAKE3`
/// hash, truncated to `LinkId`'s length, and never a second
/// `derive_key` (docs/11, "`link_id` is a plain hash and not a second
/// `derive_key`").
pub fn derive_link_id(secret: &LinkSecret) -> LinkId {
    let digest = blake3::hash(secret.as_bytes());
    LinkId::from_link_secret_digest(digest.as_bytes())
}

/// Derives the Fingerprint a device renders as twelve words:
/// `BLAKE3("tradr-fp-v1" || identity_pub || agreement_pub)` (docs/05,
/// "Why 132 bits, when the words were always twelve"). The tag and the
/// two keys are concatenated in that fixed order, so swapping the keys
/// renders a different Fingerprint.
pub fn device_fingerprint(
    identity_pub: &PublicKeyPoint,
    agreement_pub: &PublicKeyPoint,
) -> Fingerprint {
    let mut input = Vec::with_capacity(FINGERPRINT_TAG.len() + identity_pub.as_bytes().len() * 2);
    input.extend_from_slice(FINGERPRINT_TAG);
    input.extend_from_slice(identity_pub.as_bytes());
    input.extend_from_slice(agreement_pub.as_bytes());
    let digest = blake3::hash(&input);
    Fingerprint::from_key_digest(digest.as_bytes())
}

/// One Link this device holds with a peer's account (docs/11, "State
/// after linking"): the account, the id removal and Fingerprint
/// verification address it by, and the created-at and verified flags. Per
/// DCR-069, `peer_email`, `policy` and `known_devices` are absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    link_id: LinkId,
    peer_account: AccountId,
    peer_label: Option<String>,
    created_at: UnixTime,
    fingerprint_verified: bool,
}

impl Link {
    /// Builds a `Link` from everything mandatory. `peer_label` and
    /// `fingerprint_verified` start absent and `false` respectively, set
    /// through `with_label` and `with_fingerprint_verified`.
    pub fn new(link_id: LinkId, peer_account: AccountId, created_at: UnixTime) -> Self {
        Self {
            link_id,
            peer_account,
            peer_label: None,
            created_at,
            fingerprint_verified: false,
        }
    }

    /// Records the label the user gave this peer.
    pub fn with_label(mut self, label: &str) -> Self {
        self.peer_label = Some(label.to_string());
        self
    }

    /// Records whether this peer's Fingerprint has been verified.
    pub fn with_fingerprint_verified(mut self, verified: bool) -> Self {
        self.fingerprint_verified = verified;
        self
    }

    /// This Link's identifier.
    pub fn link_id(&self) -> LinkId {
        self.link_id
    }

    /// The peer's account.
    pub fn peer_account(&self) -> &AccountId {
        &self.peer_account
    }

    /// The label the user gave this peer, if any.
    pub fn peer_label(&self) -> Option<&str> {
        self.peer_label.as_deref()
    }

    /// When this Link was created.
    pub fn created_at(&self) -> UnixTime {
        self.created_at
    }

    /// Whether this peer's Fingerprint has been verified.
    pub fn fingerprint_verified(&self) -> bool {
        self.fingerprint_verified
    }

    // Builds the record this Link serializes to on disk.
    fn to_record(&self) -> LinkRecord {
        LinkRecord {
            link_id: self.link_id.to_string(),
            peer_iss: self.peer_account.iss().to_string(),
            peer_sub: self.peer_account.sub().to_string(),
            peer_label: self.peer_label.clone(),
            created_at: self.created_at.as_secs(),
            fingerprint_verified: self.fingerprint_verified,
        }
    }

    // Rebuilds a Link from its on-disk record. `link_id` must already be
    // the lowercase hex this module ever writes, or this is a malformed
    // file rather than a silently-skipped record (docs/11, "What the
    // registry refuses").
    fn from_record(record: LinkRecord) -> Result<Self, LinkRegistryError> {
        let link_id = record
            .link_id
            .parse::<LinkId>()
            .map_err(|source| LinkRegistryError::Malformed(source.to_string()))?;
        let peer_account = AccountId::new(&record.peer_iss, &record.peer_sub);
        let created_at = UnixTime::from_secs(record.created_at);

        let mut link = Self::new(link_id, peer_account, created_at)
            .with_fingerprint_verified(record.fingerprint_verified);
        if let Some(label) = record.peer_label {
            link = link.with_label(&label);
        }
        Ok(link)
    }
}

/// The on-disk shape of one `Link` (docs/11, "State after linking",
/// DCR-069). Kept distinct from `Link` itself so a field this module has
/// already validated -- a `link_id`, an `(iss, sub)` pair -- is never
/// assumed valid again on the way back off disk.
#[derive(Debug, Serialize, Deserialize)]
struct LinkRecord {
    link_id: String,
    peer_iss: String,
    peer_sub: String,
    peer_label: Option<String>,
    created_at: i64,
    fingerprint_verified: bool,
}

/// The whole file `links.json` holds.
#[derive(Debug, Default, Serialize, Deserialize)]
struct LinkFile {
    links: Vec<LinkRecord>,
}

/// An error from the Link registry.
#[non_exhaustive]
#[derive(Debug)]
pub enum LinkRegistryError {
    /// The registry file was not valid JSON in the shape this module
    /// writes, a field inside it was not a shape this module ever
    /// produces, or it named one account or one `link_id` more than once.
    /// An empty registry in its place would silently withdraw
    /// `TrustTier::Linked` from every peer at once.
    Malformed(String),
    /// `add` was called with a Link whose account this registry already
    /// holds a Link for. Linking is per account, so two Links naming one
    /// `(iss, sub)` are two answers to a question that has one.
    AccountAlreadyLinked,
    /// `add` was called with a `link_id` this registry already holds.
    DuplicateLinkId,
    /// `remove` or `set_fingerprint_verified` was called with a `link_id`
    /// this registry does not hold.
    UnknownLink,
    /// The registry file could not be read or written.
    Io(std::io::Error),
}

impl fmt::Display for LinkRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "link registry is malformed: {reason}"),
            Self::AccountAlreadyLinked => {
                write!(f, "this account is already linked")
            }
            Self::DuplicateLinkId => write!(f, "this link id is already in use"),
            Self::UnknownLink => write!(f, "no link in this registry has this id"),
            Self::Io(source) => write!(f, "link registry i/o error: {source}"),
        }
    }
}

impl std::error::Error for LinkRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::Malformed(_)
            | Self::AccountAlreadyLinked
            | Self::DuplicateLinkId
            | Self::UnknownLink => None,
        }
    }
}

/// The Link registry: every account this device has linked with, backed
/// by `links.json` in the application data directory, beside
/// `static-peers.json` (docs/11, "State after linking").
pub struct LinkRegistry {
    path: PathBuf,
    links: Vec<Link>,
}

impl LinkRegistry {
    /// Loads the registry at `path`. A missing file is an empty registry,
    /// which is what a first run looks like; a malformed one is refused
    /// rather than silently replaced, since starting over withdraws
    /// `TrustTier::Linked` from every peer at once.
    pub fn load(path: &Path) -> Result<Self, LinkRegistryError> {
        let raw = match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => return Err(LinkRegistryError::Io(source)),
        };

        let file: LinkFile = match raw {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|source| LinkRegistryError::Malformed(source.to_string()))?,
            None => LinkFile::default(),
        };

        let mut links: Vec<Link> = Vec::with_capacity(file.links.len());
        for record in file.links {
            let link = Link::from_record(record)?;
            if links
                .iter()
                .any(|existing| existing.link_id == link.link_id)
            {
                return Err(LinkRegistryError::Malformed(format!(
                    "link id {} appears more than once",
                    link.link_id
                )));
            }
            if links
                .iter()
                .any(|existing| existing.peer_account == link.peer_account)
            {
                return Err(LinkRegistryError::Malformed(format!(
                    "account ({}, {}) is linked more than once",
                    link.peer_account.iss(),
                    link.peer_account.sub()
                )));
            }
            links.push(link);
        }

        Ok(Self {
            path: path.to_path_buf(),
            links,
        })
    }

    /// Every Link this registry currently holds.
    pub fn links(&self) -> &[Link] {
        &self.links
    }

    /// The Link carrying `id`, if this registry has one.
    pub fn link(&self, id: &LinkId) -> Option<&Link> {
        self.links.iter().find(|link| &link.link_id == id)
    }

    /// Every account currently linked, built fresh from `links` on each
    /// call so no second source of truth can drift from it. What docs/05
    /// step 6 reads as `AttestationPolicy::linked_accounts`.
    pub fn linked_accounts(&self) -> Vec<AccountId> {
        self.links
            .iter()
            .map(|link| link.peer_account.clone())
            .collect()
    }

    /// Registers `link`. Refuses a second Link to an account this
    /// registry already holds one for (`AccountAlreadyLinked`) and a
    /// `link_id` this registry already holds (`DuplicateLinkId`); either
    /// refusal changes neither memory nor disk.
    pub fn add(&mut self, link: Link) -> Result<(), LinkRegistryError> {
        if self
            .links
            .iter()
            .any(|existing| existing.peer_account == link.peer_account)
        {
            return Err(LinkRegistryError::AccountAlreadyLinked);
        }
        if self
            .links
            .iter()
            .any(|existing| existing.link_id == link.link_id)
        {
            return Err(LinkRegistryError::DuplicateLinkId);
        }

        let mut prospective = self.links.clone();
        prospective.push(link);
        self.persist(&prospective)?;

        self.links = prospective;
        Ok(())
    }

    /// Removes the Link carrying `id`. Removal takes effect at once: the
    /// account leaves `linked_accounts` before this call returns
    /// (docs/11, "Removing a link").
    pub fn remove(&mut self, id: &LinkId) -> Result<(), LinkRegistryError> {
        let index = self
            .links
            .iter()
            .position(|link| &link.link_id == id)
            .ok_or(LinkRegistryError::UnknownLink)?;

        let mut prospective = self.links.clone();
        prospective.remove(index);
        self.persist(&prospective)?;

        self.links = prospective;
        Ok(())
    }

    /// Marks the Link carrying `id` as Fingerprint-verified or not. Refuses
    /// an id this registry does not hold, changing nothing.
    pub fn set_fingerprint_verified(
        &mut self,
        id: &LinkId,
        verified: bool,
    ) -> Result<(), LinkRegistryError> {
        let index = self
            .links
            .iter()
            .position(|link| &link.link_id == id)
            .ok_or(LinkRegistryError::UnknownLink)?;

        let mut prospective = self.links.clone();
        prospective[index].fingerprint_verified = verified;
        self.persist(&prospective)?;

        self.links = prospective;
        Ok(())
    }

    // Writes `links` to `self.path` whole, via a fresh temporary file
    // renamed over the target, so a reader never observes a partial write
    // and a mutation is either fully on disk or not there at all.
    fn persist(&self, links: &[Link]) -> Result<(), LinkRegistryError> {
        let file = LinkFile {
            links: links.iter().map(Link::to_record).collect(),
        };
        // Every field of `LinkRecord` is already a validated String, an
        // Option of one, an i64 or a bool, none of which serde_json can
        // refuse to serialize.
        let json =
            serde_json::to_vec_pretty(&file).expect("a LinkFile serializes to json without error");

        let dir = self.path.parent().filter(|dir| !dir.as_os_str().is_empty());
        if let Some(dir) = dir {
            fs::create_dir_all(dir).map_err(LinkRegistryError::Io)?;
        }

        let temp_path = temp_path_for(&self.path);
        fs::write(&temp_path, &json).map_err(LinkRegistryError::Io)?;
        fs::rename(&temp_path, &self.path).map_err(LinkRegistryError::Io)
    }
}

// A temporary path in the same directory as `path`, so the rename that
// follows a successful write is same-filesystem and therefore atomic.
fn temp_path_for(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(OsStr::to_os_string)
        .unwrap_or_default();
    name.push(format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}

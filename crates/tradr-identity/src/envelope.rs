//! Deferred Delivery envelope serialization, sealing, and opening (docs/13, ADR-0025, DCR-173).

use std::fmt;
use std::mem;

use serde::{Deserialize, Serialize};
use tradr_core::{
    ContentHash, DeviceId, DomainTag, KeyBinding, KeyBindingRefused, KeyStore, KeyStoreError,
    PublicIdentity, PublicKeyPoint, RelPath, Rng, SharedSecret, Signature, TransferId, TrustTier,
    UnixTime,
};

use crate::hpke::{
    HpkeError, ReceiverContext, SenderContext, setup_base_receiver, setup_base_sender,
};
use crate::key_binding::{parse_verifying_key, signature_verifies, verify_key_binding};

/// The byte length of the unencrypted outer header.
pub const OUTER_HEADER_LEN: usize = 106;

const CHUNK_SIZE: usize = 1024 * 1024;
const TAG_LEN: usize = 16;
const MAX_MANIFEST_RECORD: usize = 16 * 1024 * 1024;
const THIRTY_DAYS_SECS: i64 = 30 * 24 * 3600;
const THREE_HUNDRED_SECS: i64 = 300;

/// Sender material required to seal a Deferred Delivery envelope.
#[derive(Clone)]
pub struct EnvelopeSender {
    identity: PublicIdentity,
    key_binding: KeyBinding,
    attestation_token: String,
}

impl EnvelopeSender {
    /// Builds envelope sender material from an identity, key binding, and attestation token.
    pub fn new(
        identity: PublicIdentity,
        key_binding: KeyBinding,
        attestation_token: String,
    ) -> Self {
        Self {
            identity,
            key_binding,
            attestation_token,
        }
    }

    /// The sender's public identity.
    pub fn identity(&self) -> &PublicIdentity {
        &self.identity
    }

    /// The sender's key binding.
    pub fn key_binding(&self) -> &KeyBinding {
        &self.key_binding
    }

    /// The sender's unverified attestation token.
    pub fn attestation_token(&self) -> &str {
        &self.attestation_token
    }
}

// Bearer token is omitted to avoid leaking credential material into log records.
impl fmt::Debug for EnvelopeSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopeSender")
            .field("identity", &self.identity)
            .field("key_binding", &self.key_binding)
            .field("attestation_token", &"[redacted]")
            .finish()
    }
}

/// A single item carried inside a Deferred Delivery envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeItem {
    rel_path: RelPath,
    size: u64,
    content_hash: ContentHash,
}

impl EnvelopeItem {
    /// Builds an envelope item from its relative path, size, and BLAKE3 content hash.
    pub fn new(rel_path: RelPath, size: u64, content_hash: ContentHash) -> Self {
        Self {
            rel_path,
            size,
            content_hash,
        }
    }

    /// Relative path of the item within the transfer.
    pub fn rel_path(&self) -> &RelPath {
        &self.rel_path
    }

    /// Declared size in bytes of the item.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// BLAKE3 content hash of the item contents.
    pub fn content_hash(&self) -> &ContentHash {
        &self.content_hash
    }
}

/// The unencrypted outer header of an envelope, readable by routing intermediaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterHeader {
    version: u8,
    recipient_device_id: DeviceId,
    sender_device_id: DeviceId,
    enc: [u8; 65],
    total_len: u64,
}

impl OuterHeader {
    /// Recipient device identifier to which the envelope is addressed.
    pub fn recipient_device_id(&self) -> DeviceId {
        self.recipient_device_id
    }

    /// Sender device identifier claiming authorship of the envelope.
    pub fn sender_device_id(&self) -> DeviceId {
        self.sender_device_id
    }

    /// Declared total length of the envelope including the outer header.
    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    pub(crate) fn enc(&self) -> &[u8; 65] {
        &self.enc
    }
}

/// A verified and decrypted Deferred Delivery envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedEnvelope {
    transfer_id: TransferId,
    sender: PublicIdentity,
    created_at: UnixTime,
    tier: TrustTier,
    items: Vec<EnvelopeItem>,
    contents: Vec<Vec<u8>>,
}

impl OpenedEnvelope {
    /// Identifier of the delivered transfer.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// Verified public identity of the sender.
    pub fn sender(&self) -> &PublicIdentity {
        &self.sender
    }

    /// Timestamp at which the envelope was created by the sender.
    pub fn created_at(&self) -> UnixTime {
        self.created_at
    }

    /// Trust tier assigned to the sender by attestation verification.
    pub fn tier(&self) -> TrustTier {
        self.tier
    }

    /// Items described in the envelope manifest.
    pub fn items(&self) -> &[EnvelopeItem] {
        &self.items
    }

    /// Decrypted file byte payloads corresponding to `items`.
    pub fn contents(&self) -> &[Vec<u8>] {
        &self.contents
    }
}

/// Errors produced when sealing, parsing, or opening a Deferred Delivery envelope.
#[derive(Debug)]
pub enum EnvelopeError {
    /// Outer header is shorter than the required 106 bytes.
    HeaderTooShort,
    /// Envelope wire version is unsupported.
    UnsupportedVersion(u8),
    /// Outer header total length does not match the actual envelope length.
    TotalLengthMismatch {
        /// Expected byte length declared in the outer header.
        expected: u64,
        /// Actual byte length of the slice.
        actual: u64,
    },
    /// Envelope recipient device ID does not match the local device.
    RecipientMismatch,
    /// Envelope sender device ID does not match the manifest identity key.
    SenderMismatch,
    /// Envelope payload or record length extends beyond available bytes.
    Truncated,
    /// Envelope contains no data records following the manifest record.
    NoDataRecords,
    /// Item byte length does not match its declared size.
    ItemSizeMismatch,
    /// Item payload does not match the declared BLAKE3 content hash.
    ContentHashMismatch,
    /// Manifest signature verification failed against the sender identity key.
    SignatureInvalid,
    /// Key binding verification failed.
    KeyBinding(KeyBindingRefused),
    /// Creation time is outside the valid 30-day past or 300-second future window.
    CreatedAtOutOfRange {
        /// Creation timestamp from the envelope.
        created_at: UnixTime,
        /// Reference clock timestamp.
        now: UnixTime,
    },
    /// Attestation verification resolved to an untrusted tier.
    UntrustedTier(TrustTier),
    /// Attestation verification callback rejected the token.
    AttestationRefused(String),
    /// HPKE setup, sealing, or opening failed.
    Hpke(HpkeError),
    /// KeyStore operation failed.
    KeyStore(KeyStoreError),
    /// JSON serialization or deserialization error.
    Json(String),
    /// Manifest or header field was malformed or could not be decoded.
    ManifestMalformed(String),
    /// Bytes arrived after the final record of the envelope.
    TrailingBytes,
    /// The reader or writer was used again after it reported an error.
    AlreadyFailed,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTooShort => write!(f, "envelope outer header is shorter than 106 bytes"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported envelope version {v}"),
            Self::TotalLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "envelope length mismatch: header declares {expected} bytes, got {actual}"
                )
            }
            Self::RecipientMismatch => write!(f, "envelope recipient device id does not match"),
            Self::SenderMismatch => write!(f, "envelope sender device id does not match identity"),
            Self::Truncated => write!(f, "envelope truncated or record extends beyond length"),
            Self::NoDataRecords => write!(f, "envelope contains no data records"),
            Self::ItemSizeMismatch => write!(f, "item byte length does not match declared size"),
            Self::ContentHashMismatch => write!(f, "item content hash does not match payload"),
            Self::SignatureInvalid => write!(f, "manifest signature is invalid"),
            Self::KeyBinding(e) => write!(f, "key binding verification refused: {e}"),
            Self::CreatedAtOutOfRange { created_at, now } => {
                write!(
                    f,
                    "envelope created_at {created_at:?} out of range relative to now {now:?}"
                )
            }
            Self::UntrustedTier(t) => {
                write!(f, "attestation tier {t:?} is not trusted for delivery")
            }
            Self::AttestationRefused(msg) => write!(f, "attestation refused: {msg}"),
            Self::Hpke(e) => write!(f, "hpke operation failed: {e}"),
            Self::KeyStore(e) => write!(f, "key store error: {e}"),
            Self::Json(msg) => write!(f, "manifest json error: {msg}"),
            Self::ManifestMalformed(msg) => write!(f, "manifest malformed: {msg}"),
            Self::TrailingBytes => write!(f, "bytes after the final envelope record"),
            Self::AlreadyFailed => write!(f, "envelope stream already failed"),
        }
    }
}

impl std::error::Error for EnvelopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KeyBinding(e) => Some(e),
            Self::Hpke(e) => Some(e),
            Self::KeyStore(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ManifestWire {
    transfer_id: String,
    identity_pub: String,
    agreement_pub: String,
    key_binding: KeyBindingWire,
    attestation_token: String,
    created_at: i64,
    items: Vec<ManifestItemWire>,
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct KeyBindingWire {
    agreement_pub: String,
    signature: String,
    not_after: i64,
}

#[derive(Serialize, Deserialize)]
struct ManifestItemWire {
    rel_path: String,
    size: u64,
    content_hash: String,
}

fn decode_hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = decode_hex_nibble(bytes[i])?;
        let lo = decode_hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_CHARS[(b >> 4) as usize]);
        out.push(HEX_CHARS[(b & 0x0f) as usize]);
    }
    String::from_utf8(out).unwrap_or_default()
}

fn transfer_id_to_bytes(id: &TransferId) -> [u8; 16] {
    let s = id.to_string();
    let mut bytes = [0u8; 16];
    let mut out = 0;
    let mut cursor = 0;
    let s_bytes = s.as_bytes();
    while out < 16 && cursor < s_bytes.len() {
        if s_bytes[cursor] == b'-' {
            cursor += 1;
            continue;
        }
        if cursor + 2 <= s_bytes.len() {
            let hi = match decode_hex_nibble(s_bytes[cursor]) {
                Some(h) => h,
                None => break,
            };
            let lo = match decode_hex_nibble(s_bytes[cursor + 1]) {
                Some(l) => l,
                None => break,
            };
            bytes[out] = (hi << 4) | lo;
            out += 1;
            cursor += 2;
            continue;
        }
        break;
    }
    bytes
}

fn make_aad(seq: u64, is_final: bool) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = if is_final { 1 } else { 0 };
    aad
}

fn make_hpke_info(recipient_id: &DeviceId, sender_id: &DeviceId) -> [u8; 49] {
    let mut info = [0u8; 49];
    info[..17].copy_from_slice(b"tradr-deferred-v1");
    info[17..33].copy_from_slice(recipient_id.as_bytes());
    info[33..49].copy_from_slice(sender_id.as_bytes());
    info
}

fn build_signature_payload(
    enc: &[u8; 65],
    recipient_device_id: &DeviceId,
    sender_device_id: &DeviceId,
    created_at_secs: i64,
    transfer_id_bytes: &[u8; 16],
    items: &[(&str, u64, &[u8])],
) -> Result<Vec<u8>, EnvelopeError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(enc);
    payload.extend_from_slice(recipient_device_id.as_bytes());
    payload.extend_from_slice(sender_device_id.as_bytes());
    payload.extend_from_slice(&created_at_secs.to_be_bytes());
    payload.extend_from_slice(transfer_id_bytes);
    for (path, size, hash) in items {
        let path_bytes = path.as_bytes();
        let path_len = match u32::try_from(path_bytes.len()) {
            Ok(l) => l,
            Err(_) => {
                return Err(EnvelopeError::ManifestMalformed(
                    "item path length exceeds u32".into(),
                ));
            }
        };
        payload.extend_from_slice(&path_len.to_be_bytes());
        payload.extend_from_slice(path_bytes);
        payload.extend_from_slice(&size.to_be_bytes());
        payload.extend_from_slice(hash);
    }
    Ok(payload)
}

/// Parses the outer routing header of an envelope.
pub fn parse_outer_header(bytes: &[u8]) -> Result<OuterHeader, EnvelopeError> {
    if bytes.len() < OUTER_HEADER_LEN {
        return Err(EnvelopeError::HeaderTooShort);
    }
    let version = bytes[0];
    if version != 1 {
        return Err(EnvelopeError::UnsupportedVersion(version));
    }
    let recipient_device_id = match DeviceId::from_bytes(&bytes[1..17]) {
        Ok(id) => id,
        Err(_) => {
            return Err(EnvelopeError::ManifestMalformed(
                "recipient device id".into(),
            ));
        }
    };
    let sender_device_id = match DeviceId::from_bytes(&bytes[17..33]) {
        Ok(id) => id,
        Err(_) => return Err(EnvelopeError::ManifestMalformed("sender device id".into())),
    };
    let mut enc = [0u8; 65];
    enc.copy_from_slice(&bytes[33..98]);
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&bytes[98..106]);
    let total_len = u64::from_be_bytes(len_bytes);

    Ok(OuterHeader {
        version,
        recipient_device_id,
        sender_device_id,
        enc,
        total_len,
    })
}

/// Streams a Deferred Delivery envelope out as the items' bytes arrive.
pub struct EnvelopeWriter {
    ctx: SenderContext,
    buf: Vec<u8>,
    declared: u64,
    pushed: u64,
    emitted: u64,
    seq: u64,
    sealed_final: bool,
    total_len: u64,
    failed: bool,
}

impl fmt::Debug for EnvelopeWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopeWriter")
            .field("declared", &self.declared)
            .field("pushed", &self.pushed)
            .finish_non_exhaustive()
    }
}

impl EnvelopeWriter {
    /// Seals the manifest and returns the writer with the outer header and manifest record.
    pub fn new(
        recipient: &PublicIdentity,
        sender: &EnvelopeSender,
        key_store: &dyn KeyStore,
        rng: &dyn Rng,
        transfer_id: TransferId,
        created_at: UnixTime,
        items: Vec<EnvelopeItem>,
    ) -> Result<(EnvelopeWriter, Vec<u8>), EnvelopeError> {
        let mut declared: u64 = 0;
        for item in &items {
            declared = declared
                .checked_add(item.size())
                .ok_or(EnvelopeError::ItemSizeMismatch)?;
        }

        let recipient_id = recipient.device_id();
        let sender_id = sender.identity().device_id();
        let info = make_hpke_info(&recipient_id, &sender_id);
        let (enc, mut ctx) = setup_base_sender(recipient.agreement_pub(), rng, &info)
            .map_err(EnvelopeError::Hpke)?;

        let transfer_id_bytes = transfer_id_to_bytes(&transfer_id);
        let items_meta: Vec<(&str, u64, &[u8])> = items
            .iter()
            .map(|it| {
                (
                    it.rel_path().as_str(),
                    it.size(),
                    it.content_hash().as_bytes().as_slice(),
                )
            })
            .collect();
        let sig_message = build_signature_payload(
            &enc,
            &recipient_id,
            &sender_id,
            created_at.as_secs(),
            &transfer_id_bytes,
            &items_meta,
        )?;
        let manifest_sig = key_store
            .sign(DomainTag::DeferredDelivery, &sig_message)
            .map_err(EnvelopeError::KeyStore)?;

        let manifest_wire = ManifestWire {
            transfer_id: transfer_id.to_string(),
            identity_pub: encode_hex(sender.identity().identity_pub().as_bytes()),
            agreement_pub: encode_hex(sender.identity().agreement_pub().as_bytes()),
            key_binding: KeyBindingWire {
                agreement_pub: encode_hex(sender.key_binding().agreement_pub().as_bytes()),
                signature: encode_hex(sender.key_binding().signature().as_bytes()),
                not_after: sender.key_binding().not_after().as_secs(),
            },
            attestation_token: sender.attestation_token().to_string(),
            created_at: created_at.as_secs(),
            items: items
                .iter()
                .map(|it| ManifestItemWire {
                    rel_path: it.rel_path().as_str().to_string(),
                    size: it.size(),
                    content_hash: encode_hex(it.content_hash().as_bytes()),
                })
                .collect(),
            signature: encode_hex(manifest_sig.as_bytes()),
        };
        let manifest_json =
            serde_json::to_vec(&manifest_wire).map_err(|e| EnvelopeError::Json(e.to_string()))?;
        let sealed_manifest = ctx
            .seal(&make_aad(0, false), &manifest_json)
            .map_err(EnvelopeError::Hpke)?;
        if sealed_manifest.len() > MAX_MANIFEST_RECORD {
            return Err(EnvelopeError::ManifestMalformed(
                "manifest record too large".into(),
            ));
        }

        let overhead = (4 + TAG_LEN) as u64;
        let data_len = if declared == 0 {
            overhead
        } else {
            declared
                .div_ceil(CHUNK_SIZE as u64)
                .checked_mul(overhead)
                .and_then(|o| o.checked_add(declared))
                .ok_or(EnvelopeError::ItemSizeMismatch)?
        };
        let total_len = (OUTER_HEADER_LEN as u64)
            .checked_add(4)
            .and_then(|t| t.checked_add(sealed_manifest.len() as u64))
            .and_then(|t| t.checked_add(data_len))
            .ok_or(EnvelopeError::ItemSizeMismatch)?;

        let mut head = Vec::with_capacity(OUTER_HEADER_LEN + 4 + sealed_manifest.len());
        head.push(1u8);
        head.extend_from_slice(recipient_id.as_bytes());
        head.extend_from_slice(sender_id.as_bytes());
        head.extend_from_slice(&enc);
        head.extend_from_slice(&total_len.to_be_bytes());
        append_record(&mut head, &sealed_manifest)?;

        let writer = EnvelopeWriter {
            ctx,
            buf: Vec::new(),
            declared,
            pushed: 0,
            emitted: 0,
            seq: 1,
            sealed_final: false,
            total_len,
            failed: false,
        };
        Ok((writer, head))
    }

    /// The exact byte length of the whole envelope, as written into the outer header.
    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    /// Accepts item bytes back to back and returns the sealed records that became complete.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        if self.failed {
            return Err(EnvelopeError::AlreadyFailed);
        }
        let result = self.push_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn push_inner(&mut self, bytes: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        let new_pushed = self
            .pushed
            .checked_add(bytes.len() as u64)
            .filter(|p| *p <= self.declared)
            .ok_or(EnvelopeError::ItemSizeMismatch)?;
        self.pushed = new_pushed;

        let mut out = Vec::new();
        let mut rest = bytes;
        if !self.buf.is_empty() {
            let take = (CHUNK_SIZE - self.buf.len()).min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.buf.len() == CHUNK_SIZE {
                let chunk = mem::take(&mut self.buf);
                self.seal_data(&chunk, &mut out)?;
            }
        }
        while rest.len() >= CHUNK_SIZE {
            let (chunk, tail) = rest.split_at(CHUNK_SIZE);
            self.seal_data(chunk, &mut out)?;
            rest = tail;
        }
        self.buf.extend_from_slice(rest);
        Ok(out)
    }

    /// Returns the remaining records, the last one marked final; fails unless all bytes arrived.
    pub fn finish(mut self) -> Result<Vec<u8>, EnvelopeError> {
        if self.failed {
            return Err(EnvelopeError::AlreadyFailed);
        }
        if self.pushed != self.declared {
            return Err(EnvelopeError::ItemSizeMismatch);
        }
        let mut out = Vec::new();
        if !self.sealed_final {
            let chunk = mem::take(&mut self.buf);
            self.seal_data(&chunk, &mut out)?;
        }
        Ok(out)
    }

    fn seal_data(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), EnvelopeError> {
        let is_final = self.emitted + chunk.len() as u64 == self.declared;
        let sealed = self
            .ctx
            .seal(&make_aad(self.seq, is_final), chunk)
            .map_err(EnvelopeError::Hpke)?;
        append_record(out, &sealed)?;
        self.emitted += chunk.len() as u64;
        self.seq += 1;
        self.sealed_final = is_final;
        Ok(())
    }
}

fn append_record(out: &mut Vec<u8>, sealed: &[u8]) -> Result<(), EnvelopeError> {
    let len = u32::try_from(sealed.len()).map_err(|_| EnvelopeError::ItemSizeMismatch)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(sealed);
    Ok(())
}

/// The verified manifest of a Deferred Delivery envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedManifest {
    transfer_id: TransferId,
    sender: PublicIdentity,
    created_at: UnixTime,
    tier: TrustTier,
    items: Vec<EnvelopeItem>,
}

impl OpenedManifest {
    /// Identifier of the delivered transfer.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// Verified public identity of the sender.
    pub fn sender(&self) -> &PublicIdentity {
        &self.sender
    }

    /// Timestamp at which the envelope was created by the sender.
    pub fn created_at(&self) -> UnixTime {
        self.created_at
    }

    /// Trust tier assigned to the sender by attestation verification.
    pub fn tier(&self) -> TrustTier {
        self.tier
    }

    /// Items described in the manifest, in the order their bytes follow.
    pub fn items(&self) -> &[EnvelopeItem] {
        &self.items
    }
}

/// Something the reader produced from the bytes fed so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReaderEvent {
    /// The manifest passed acceptance checks 1 to 7; always the first event.
    Manifest(OpenedManifest),
    /// Plaintext bytes of the item at `index`, not yet verified against its hash.
    ItemData {
        /// Position of the item in the manifest.
        index: usize,
        /// The decrypted bytes.
        bytes: Vec<u8>,
    },
    /// The item at `index` is complete and its BLAKE3 matches its content hash.
    ItemVerified {
        /// Position of the item in the manifest.
        index: usize,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Header,
    Len { manifest: bool },
    Body { manifest: bool, len: usize },
    Done,
}

type AgreeFn<'a> = &'a dyn Fn(&PublicKeyPoint) -> Result<SharedSecret, KeyStoreError>;
type AttestFn<'a> = &'a dyn Fn(&str, &PublicIdentity, UnixTime) -> Result<TrustTier, String>;

/// Opens a Deferred Delivery envelope from bytes fed in arbitrary slices.
pub struct EnvelopeReader<'a> {
    recipient: &'a PublicIdentity,
    agree: AgreeFn<'a>,
    now: UnixTime,
    verify_attestation: AttestFn<'a>,
    buf: Vec<u8>,
    stage: Stage,
    header: Option<OuterHeader>,
    ctx: Option<ReceiverContext>,
    remaining: u64,
    seq: u64,
    manifest: Option<OpenedManifest>,
    current: usize,
    current_left: u64,
    hasher: blake3::Hasher,
    failed: bool,
}

impl fmt::Debug for EnvelopeReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopeReader").finish_non_exhaustive()
    }
}

impl<'a> EnvelopeReader<'a> {
    /// Starts reading an envelope addressed to `recipient`.
    pub fn new(
        recipient: &'a PublicIdentity,
        agree: AgreeFn<'a>,
        now: UnixTime,
        verify_attestation: AttestFn<'a>,
    ) -> EnvelopeReader<'a> {
        EnvelopeReader {
            recipient,
            agree,
            now,
            verify_attestation,
            buf: Vec::new(),
            stage: Stage::Header,
            header: None,
            ctx: None,
            remaining: 0,
            seq: 1,
            manifest: None,
            current: 0,
            current_left: 0,
            hasher: blake3::Hasher::new(),
            failed: false,
        }
    }

    /// Accepts the next bytes of the envelope and returns the events they completed.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<ReaderEvent>, EnvelopeError> {
        if self.failed {
            return Err(EnvelopeError::AlreadyFailed);
        }
        let result = self.feed_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Returns the manifest once the final record was read and every item verified.
    pub fn finish(self) -> Result<OpenedManifest, EnvelopeError> {
        if self.failed {
            return Err(EnvelopeError::AlreadyFailed);
        }
        match (self.stage, self.manifest) {
            (Stage::Done, Some(manifest)) => Ok(manifest),
            _ => Err(EnvelopeError::Truncated),
        }
    }

    fn feed_inner(&mut self, mut input: &[u8]) -> Result<Vec<ReaderEvent>, EnvelopeError> {
        let mut events = Vec::new();
        loop {
            let need = match self.stage {
                Stage::Done => {
                    if input.is_empty() {
                        return Ok(events);
                    }
                    return Err(EnvelopeError::TrailingBytes);
                }
                Stage::Header => OUTER_HEADER_LEN,
                Stage::Len { .. } => 4,
                Stage::Body { len, .. } => len,
            };
            let take = (need - self.buf.len()).min(input.len());
            self.buf.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.buf.len() < need {
                return Ok(events);
            }
            let unit = mem::take(&mut self.buf);
            self.advance(&unit, &mut events)?;
        }
    }

    fn advance(&mut self, unit: &[u8], events: &mut Vec<ReaderEvent>) -> Result<(), EnvelopeError> {
        match self.stage {
            Stage::Header => self.read_header(unit),
            Stage::Len { manifest } => self.read_len(unit, manifest),
            Stage::Body { manifest, len } => {
                self.remaining -= len as u64;
                if manifest {
                    self.read_manifest(unit, events)
                } else {
                    self.read_data(unit, events)
                }
            }
            Stage::Done => Err(EnvelopeError::TrailingBytes),
        }
    }

    fn read_header(&mut self, unit: &[u8]) -> Result<(), EnvelopeError> {
        let header = parse_outer_header(unit)?;
        self.remaining = header
            .total_len
            .checked_sub(OUTER_HEADER_LEN as u64)
            .ok_or(EnvelopeError::TotalLengthMismatch {
                expected: header.total_len,
                actual: OUTER_HEADER_LEN as u64,
            })?;
        if header.recipient_device_id() != self.recipient.device_id() {
            return Err(EnvelopeError::RecipientMismatch);
        }
        let info = make_hpke_info(&self.recipient.device_id(), &header.sender_device_id());
        self.ctx = Some(
            setup_base_receiver(
                header.enc(),
                self.recipient.agreement_pub(),
                &info,
                self.agree,
            )
            .map_err(EnvelopeError::Hpke)?,
        );
        self.header = Some(header);
        self.stage = Stage::Len { manifest: true };
        Ok(())
    }

    fn read_len(&mut self, unit: &[u8], manifest: bool) -> Result<(), EnvelopeError> {
        self.remaining = self
            .remaining
            .checked_sub(4)
            .ok_or(EnvelopeError::Truncated)?;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(unit);
        let len = u32::from_be_bytes(raw) as usize;
        if len as u64 > self.remaining {
            return Err(EnvelopeError::Truncated);
        }
        let in_range = if manifest {
            len <= MAX_MANIFEST_RECORD
        } else {
            (TAG_LEN..=CHUNK_SIZE + TAG_LEN).contains(&len)
        };
        if !in_range {
            return Err(EnvelopeError::ManifestMalformed(
                "record length out of range".into(),
            ));
        }
        self.stage = Stage::Body { manifest, len };
        Ok(())
    }

    fn read_manifest(
        &mut self,
        record: &[u8],
        events: &mut Vec<ReaderEvent>,
    ) -> Result<(), EnvelopeError> {
        let (Some(header), Some(ctx)) = (self.header.as_ref(), self.ctx.as_mut()) else {
            return Err(EnvelopeError::Truncated);
        };
        let manifest_json = ctx
            .open(&make_aad(0, false), record)
            .map_err(EnvelopeError::Hpke)?;
        let manifest = check_manifest(header, &manifest_json, self.now, self.verify_attestation)?;
        if self.remaining == 0 {
            return Err(EnvelopeError::NoDataRecords);
        }
        self.current_left = manifest.items.first().map_or(0, EnvelopeItem::size);
        self.manifest = Some(manifest.clone());
        events.push(ReaderEvent::Manifest(manifest));
        self.stage = Stage::Len { manifest: false };
        self.distribute(&[], events)
    }

    fn read_data(
        &mut self,
        record: &[u8],
        events: &mut Vec<ReaderEvent>,
    ) -> Result<(), EnvelopeError> {
        let is_final = self.remaining == 0;
        let Some(ctx) = self.ctx.as_mut() else {
            return Err(EnvelopeError::Truncated);
        };
        let plaintext = ctx
            .open(&make_aad(self.seq, is_final), record)
            .map_err(EnvelopeError::Hpke)?;
        self.seq += 1;
        if !is_final && plaintext.len() != CHUNK_SIZE {
            return Err(EnvelopeError::ItemSizeMismatch);
        }
        self.distribute(&plaintext, events)?;
        if is_final {
            let item_count = self.manifest.as_ref().map_or(0, |m| m.items.len());
            if self.current != item_count {
                return Err(EnvelopeError::ItemSizeMismatch);
            }
            self.stage = Stage::Done;
        } else {
            self.stage = Stage::Len { manifest: false };
        }
        Ok(())
    }

    fn distribute(
        &mut self,
        mut plaintext: &[u8],
        events: &mut Vec<ReaderEvent>,
    ) -> Result<(), EnvelopeError> {
        let Some(manifest) = self.manifest.as_ref() else {
            return Err(EnvelopeError::Truncated);
        };
        loop {
            if self.current >= manifest.items.len() {
                return if plaintext.is_empty() {
                    Ok(())
                } else {
                    Err(EnvelopeError::ItemSizeMismatch)
                };
            }
            if self.current_left == 0 {
                let digest: [u8; 32] = self.hasher.finalize().into();
                if &digest != manifest.items[self.current].content_hash().as_bytes() {
                    return Err(EnvelopeError::ContentHashMismatch);
                }
                events.push(ReaderEvent::ItemVerified {
                    index: self.current,
                });
                self.hasher = blake3::Hasher::new();
                self.current += 1;
                self.current_left = manifest
                    .items
                    .get(self.current)
                    .map_or(0, EnvelopeItem::size);
                continue;
            }
            if plaintext.is_empty() {
                return Ok(());
            }
            let take = usize::try_from(self.current_left)
                .map_or(plaintext.len(), |left| left.min(plaintext.len()));
            let (piece, rest) = plaintext.split_at(take);
            self.hasher.update(piece);
            events.push(ReaderEvent::ItemData {
                index: self.current,
                bytes: piece.to_vec(),
            });
            self.current_left -= take as u64;
            plaintext = rest;
        }
    }
}

fn check_manifest(
    header: &OuterHeader,
    manifest_json: &[u8],
    now: UnixTime,
    verify_attestation: AttestFn<'_>,
) -> Result<OpenedManifest, EnvelopeError> {
    let manifest: ManifestWire = serde_json::from_slice(manifest_json)
        .map_err(|e| EnvelopeError::ManifestMalformed(e.to_string()))?;

    let identity_pub_bytes = decode_hex(&manifest.identity_pub)
        .ok_or_else(|| EnvelopeError::ManifestMalformed("identity_pub hex".into()))?;
    let identity_pub = PublicKeyPoint::from_bytes(&identity_pub_bytes)
        .map_err(|e| EnvelopeError::ManifestMalformed(e.to_string()))?;

    let digest: [u8; 32] = blake3::hash(identity_pub.as_bytes()).into();
    let derived_device_id = DeviceId::from_identity_digest(&digest);
    if derived_device_id != header.sender_device_id() {
        return Err(EnvelopeError::SenderMismatch);
    }

    let transfer_id: TransferId = manifest
        .transfer_id
        .parse()
        .map_err(|_| EnvelopeError::ManifestMalformed("transfer_id format".into()))?;
    let transfer_id_bytes = transfer_id_to_bytes(&transfer_id);

    let mut items_meta = Vec::with_capacity(manifest.items.len());
    for item in &manifest.items {
        let hash = decode_hex(&item.content_hash)
            .ok_or_else(|| EnvelopeError::ManifestMalformed("content_hash hex".into()))?;
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| EnvelopeError::ManifestMalformed("content_hash length".into()))?;
        items_meta.push((item.rel_path.as_str(), item.size, hash));
    }
    let items_meta_refs: Vec<(&str, u64, &[u8])> = items_meta
        .iter()
        .map(|(p, s, h)| (*p, *s, h.as_slice()))
        .collect();

    let sig_payload = build_signature_payload(
        header.enc(),
        &header.recipient_device_id(),
        &header.sender_device_id(),
        manifest.created_at,
        &transfer_id_bytes,
        &items_meta_refs,
    )?;

    let sig_bytes = decode_hex(&manifest.signature).ok_or(EnvelopeError::SignatureInvalid)?;
    let signature = Signature::from_bytes(sig_bytes);
    let verifying_key =
        parse_verifying_key(&identity_pub).map_err(|_| EnvelopeError::SignatureInvalid)?;
    if !signature_verifies(
        &verifying_key,
        DomainTag::DeferredDelivery,
        &sig_payload,
        &signature,
    ) {
        return Err(EnvelopeError::SignatureInvalid);
    }

    let agreement_pub_bytes = decode_hex(&manifest.agreement_pub)
        .ok_or_else(|| EnvelopeError::ManifestMalformed("agreement_pub hex".into()))?;
    let agreement_pub = PublicKeyPoint::from_bytes(&agreement_pub_bytes)
        .map_err(|e| EnvelopeError::ManifestMalformed(e.to_string()))?;

    let kb_agreement_bytes = decode_hex(&manifest.key_binding.agreement_pub)
        .ok_or_else(|| EnvelopeError::ManifestMalformed("key_binding agreement hex".into()))?;
    let kb_agreement = PublicKeyPoint::from_bytes(&kb_agreement_bytes)
        .map_err(|e| EnvelopeError::ManifestMalformed(e.to_string()))?;
    let kb_sig_bytes = decode_hex(&manifest.key_binding.signature)
        .ok_or_else(|| EnvelopeError::ManifestMalformed("key_binding signature hex".into()))?;
    let binding = KeyBinding::new(
        kb_agreement,
        Signature::from_bytes(kb_sig_bytes),
        UnixTime::from_secs(manifest.key_binding.not_after),
    );
    verify_key_binding(
        &identity_pub,
        &binding,
        &agreement_pub,
        UnixTime::from_secs(manifest.created_at),
    )
    .map_err(EnvelopeError::KeyBinding)?;

    let created_secs = manifest.created_at;
    let now_secs = now.as_secs();
    if created_secs < now_secs - THIRTY_DAYS_SECS || created_secs > now_secs + THREE_HUNDRED_SECS {
        return Err(EnvelopeError::CreatedAtOutOfRange {
            created_at: UnixTime::from_secs(created_secs),
            now,
        });
    }

    let sender_identity = PublicIdentity::new(identity_pub, agreement_pub, derived_device_id);
    let tier = match verify_attestation(
        &manifest.attestation_token,
        &sender_identity,
        UnixTime::from_secs(created_secs),
    ) {
        Ok(TrustTier::SameAccount) => TrustTier::SameAccount,
        Ok(TrustTier::Linked) => TrustTier::Linked,
        Ok(other) => return Err(EnvelopeError::UntrustedTier(other)),
        Err(e) => return Err(EnvelopeError::AttestationRefused(e)),
    };

    let mut items = Vec::with_capacity(manifest.items.len());
    let mut declared: u64 = 0;
    for (wire, (_, _, hash)) in manifest.items.iter().zip(&items_meta) {
        declared = declared
            .checked_add(wire.size)
            .ok_or(EnvelopeError::ItemSizeMismatch)?;
        let rel_path = RelPath::new(&wire.rel_path)
            .map_err(|e| EnvelopeError::ManifestMalformed(e.to_string()))?;
        items.push(EnvelopeItem::new(
            rel_path,
            wire.size,
            ContentHash::from_bytes(*hash),
        ));
    }

    Ok(OpenedManifest {
        transfer_id,
        sender: sender_identity,
        created_at: UnixTime::from_secs(created_secs),
        tier,
        items,
    })
}

/// Seals items into an encrypted Deferred Delivery envelope for `recipient`.
pub fn seal_envelope(
    recipient: &PublicIdentity,
    sender: &EnvelopeSender,
    key_store: &dyn KeyStore,
    rng: &dyn Rng,
    transfer_id: TransferId,
    created_at: UnixTime,
    items: &[(EnvelopeItem, &[u8])],
) -> Result<Vec<u8>, EnvelopeError> {
    for (item, bytes) in items {
        if u64::try_from(bytes.len()).ok() != Some(item.size()) {
            return Err(EnvelopeError::ItemSizeMismatch);
        }
    }
    let metas: Vec<EnvelopeItem> = items.iter().map(|(it, _)| it.clone()).collect();
    let (mut writer, mut out) = EnvelopeWriter::new(
        recipient,
        sender,
        key_store,
        rng,
        transfer_id,
        created_at,
        metas,
    )?;
    out.reserve(usize::try_from(writer.total_len()).unwrap_or(0));
    for (_, bytes) in items {
        out.extend(writer.push(bytes)?);
    }
    out.extend(writer.finish()?);
    Ok(out)
}

/// Opens, verifies, and decrypts a Deferred Delivery envelope.
pub fn open_envelope(
    bytes: &[u8],
    recipient: &PublicIdentity,
    agree: &dyn Fn(&PublicKeyPoint) -> Result<SharedSecret, KeyStoreError>,
    now: UnixTime,
    verify_attestation: &dyn Fn(&str, &PublicIdentity, UnixTime) -> Result<TrustTier, String>,
) -> Result<OpenedEnvelope, EnvelopeError> {
    let header = parse_outer_header(bytes)?;
    if header.total_len != bytes.len() as u64 {
        return Err(EnvelopeError::TotalLengthMismatch {
            expected: header.total_len,
            actual: bytes.len() as u64,
        });
    }

    let mut reader = EnvelopeReader::new(recipient, agree, now, verify_attestation);
    let mut contents: Vec<Vec<u8>> = Vec::new();
    for event in reader.feed(bytes)? {
        match event {
            ReaderEvent::Manifest(m) => contents = vec![Vec::new(); m.items().len()],
            ReaderEvent::ItemData { index, bytes } => {
                contents
                    .get_mut(index)
                    .ok_or(EnvelopeError::ItemSizeMismatch)?
                    .extend(bytes);
            }
            ReaderEvent::ItemVerified { .. } => {}
        }
    }
    let manifest = reader.finish()?;
    Ok(OpenedEnvelope {
        transfer_id: manifest.transfer_id,
        sender: manifest.sender,
        created_at: manifest.created_at,
        tier: manifest.tier,
        items: manifest.items,
        contents,
    })
}

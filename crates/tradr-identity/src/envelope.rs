//! Deferred Delivery envelope serialization, sealing, and opening (docs/13, ADR-0025, DCR-173).

use std::fmt;

use serde::{Deserialize, Serialize};
use tradr_core::{
    ContentHash, DeviceId, DomainTag, KeyBinding, KeyBindingRefused, KeyStore, KeyStoreError,
    PublicIdentity, PublicKeyPoint, RelPath, Rng, SharedSecret, Signature, TransferId, TrustTier,
    UnixTime,
};

use crate::hpke::{HpkeError, setup_base_receiver, setup_base_sender};
use crate::key_binding::{parse_verifying_key, signature_verifies, verify_key_binding};

/// The byte length of the unencrypted outer header.
pub const OUTER_HEADER_LEN: usize = 106;

const CHUNK_SIZE: usize = 1024 * 1024;
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
        let expected_len = match usize::try_from(item.size()) {
            Ok(len) => len,
            Err(_) => return Err(EnvelopeError::ItemSizeMismatch),
        };
        if bytes.len() != expected_len {
            return Err(EnvelopeError::ItemSizeMismatch);
        }
    }

    let recipient_id = recipient.device_id();
    let sender_id = sender.identity().device_id();
    let info = make_hpke_info(&recipient_id, &sender_id);

    let (enc, mut sender_ctx) =
        setup_base_sender(recipient.agreement_pub(), rng, &info).map_err(EnvelopeError::Hpke)?;

    let transfer_id_bytes = transfer_id_to_bytes(&transfer_id);
    let items_meta: Vec<(&str, u64, &[u8])> = items
        .iter()
        .map(|(it, _)| {
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

    let manifest_items: Vec<ManifestItemWire> = items
        .iter()
        .map(|(it, _)| ManifestItemWire {
            rel_path: it.rel_path().as_str().to_string(),
            size: it.size(),
            content_hash: encode_hex(it.content_hash().as_bytes()),
        })
        .collect();

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
        items: manifest_items,
        signature: encode_hex(manifest_sig.as_bytes()),
    };

    let manifest_json =
        serde_json::to_vec(&manifest_wire).map_err(|e| EnvelopeError::Json(e.to_string()))?;

    let aad_0 = make_aad(0, false);
    let sealed_manifest = sender_ctx
        .seal(&aad_0, &manifest_json)
        .map_err(EnvelopeError::Hpke)?;

    let mut sealed_records: Vec<Vec<u8>> = Vec::new();
    sealed_records.push(sealed_manifest);

    let total_item_bytes: usize = items.iter().map(|(_, b)| b.len()).sum();
    if total_item_bytes == 0 {
        let aad_1 = make_aad(1, true);
        let sealed_data = sender_ctx.seal(&aad_1, &[]).map_err(EnvelopeError::Hpke)?;
        sealed_records.push(sealed_data);
    } else {
        let mut combined = Vec::with_capacity(total_item_bytes);
        for (_, b) in items {
            combined.extend_from_slice(b);
        }
        let chunks: Vec<&[u8]> = combined.chunks(CHUNK_SIZE).collect();
        let num_chunks = chunks.len();
        for (i, chunk) in chunks.iter().enumerate() {
            let seq = (i + 1) as u64;
            let is_final = i == num_chunks - 1;
            let aad = make_aad(seq, is_final);
            let sealed_chunk = sender_ctx.seal(&aad, chunk).map_err(EnvelopeError::Hpke)?;
            sealed_records.push(sealed_chunk);
        }
    }

    let mut records_byte_len: usize = 0;
    for rec in &sealed_records {
        let rec_entry_len = match rec.len().checked_add(4) {
            Some(l) => l,
            None => return Err(EnvelopeError::ItemSizeMismatch),
        };
        records_byte_len = match records_byte_len.checked_add(rec_entry_len) {
            Some(l) => l,
            None => return Err(EnvelopeError::ItemSizeMismatch),
        };
    }

    let total_len = match (OUTER_HEADER_LEN as u64).checked_add(records_byte_len as u64) {
        Some(len) => len,
        None => return Err(EnvelopeError::ItemSizeMismatch),
    };

    let mut envelope = Vec::with_capacity(OUTER_HEADER_LEN + records_byte_len);
    envelope.push(1u8);
    envelope.extend_from_slice(recipient_id.as_bytes());
    envelope.extend_from_slice(sender_id.as_bytes());
    envelope.extend_from_slice(&enc);
    envelope.extend_from_slice(&total_len.to_be_bytes());

    for rec in sealed_records {
        let len_u32 = match u32::try_from(rec.len()) {
            Ok(l) => l,
            Err(_) => return Err(EnvelopeError::ItemSizeMismatch),
        };
        envelope.extend_from_slice(&len_u32.to_be_bytes());
        envelope.extend_from_slice(&rec);
    }

    Ok(envelope)
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
    if header.recipient_device_id() != recipient.device_id() {
        return Err(EnvelopeError::RecipientMismatch);
    }

    let info = make_hpke_info(&recipient.device_id(), &header.sender_device_id());
    let mut rx_ctx = setup_base_receiver(header.enc(), recipient.agreement_pub(), &info, agree)
        .map_err(EnvelopeError::Hpke)?;

    let mut cursor = OUTER_HEADER_LEN;

    if cursor + 4 > bytes.len() {
        return Err(EnvelopeError::Truncated);
    }
    let mut rec_0_len_bytes = [0u8; 4];
    rec_0_len_bytes.copy_from_slice(&bytes[cursor..cursor + 4]);
    let rec_0_len = u32::from_be_bytes(rec_0_len_bytes) as usize;
    cursor += 4;
    if cursor
        .checked_add(rec_0_len)
        .is_none_or(|end| end > bytes.len())
    {
        return Err(EnvelopeError::Truncated);
    }
    let rec_0_bytes = &bytes[cursor..cursor + rec_0_len];
    cursor += rec_0_len;

    let aad_0 = make_aad(0, false);
    let manifest_json = rx_ctx
        .open(&aad_0, rec_0_bytes)
        .map_err(EnvelopeError::Hpke)?;

    if cursor == bytes.len() {
        return Err(EnvelopeError::NoDataRecords);
    }

    let mut data_plaintexts = Vec::new();
    let mut seq = 1u64;
    loop {
        if cursor + 4 > bytes.len() {
            return Err(EnvelopeError::Truncated);
        }
        let mut rec_len_bytes = [0u8; 4];
        rec_len_bytes.copy_from_slice(&bytes[cursor..cursor + 4]);
        let rec_len = u32::from_be_bytes(rec_len_bytes) as usize;
        cursor += 4;
        if cursor
            .checked_add(rec_len)
            .is_none_or(|end| end > bytes.len())
        {
            return Err(EnvelopeError::Truncated);
        }
        let rec_bytes = &bytes[cursor..cursor + rec_len];
        cursor += rec_len;

        let is_final = cursor == bytes.len();
        let aad = make_aad(seq, is_final);
        let chunk_pt = rx_ctx.open(&aad, rec_bytes).map_err(EnvelopeError::Hpke)?;
        data_plaintexts.extend_from_slice(&chunk_pt);

        if is_final {
            break;
        }
        seq += 1;
    }

    let manifest: ManifestWire = serde_json::from_slice(&manifest_json)
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
        if hash.len() != 32 {
            return Err(EnvelopeError::ManifestMalformed(
                "content_hash length".into(),
            ));
        }
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

    let verifying_key = match parse_verifying_key(&identity_pub) {
        Ok(k) => k,
        Err(_) => return Err(EnvelopeError::SignatureInvalid),
    };

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
    let kb_sig = Signature::from_bytes(kb_sig_bytes);
    let kb_not_after = UnixTime::from_secs(manifest.key_binding.not_after);
    let binding = KeyBinding::new(kb_agreement, kb_sig, kb_not_after);

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

    let mut expected_total: u64 = 0;
    for item in &manifest.items {
        expected_total = match expected_total.checked_add(item.size) {
            Some(t) => t,
            None => return Err(EnvelopeError::ItemSizeMismatch),
        };
    }
    if data_plaintexts.len() as u64 != expected_total {
        return Err(EnvelopeError::ItemSizeMismatch);
    }

    let mut contents = Vec::with_capacity(manifest.items.len());
    let mut envelope_items = Vec::with_capacity(manifest.items.len());
    let mut offset = 0usize;

    for (idx, item_wire) in manifest.items.iter().enumerate() {
        let size = match usize::try_from(item_wire.size) {
            Ok(s) => s,
            Err(_) => return Err(EnvelopeError::ItemSizeMismatch),
        };
        if offset
            .checked_add(size)
            .is_none_or(|end| end > data_plaintexts.len())
        {
            return Err(EnvelopeError::ItemSizeMismatch);
        }
        let slice = &data_plaintexts[offset..offset + size];
        offset += size;

        let hash: [u8; 32] = blake3::hash(slice).into();
        let expected_hash = &items_meta[idx].2;
        if hash != expected_hash.as_slice() {
            return Err(EnvelopeError::ContentHashMismatch);
        }

        let rel_path = RelPath::new(&item_wire.rel_path)
            .map_err(|e| EnvelopeError::ManifestMalformed(e.to_string()))?;
        envelope_items.push(EnvelopeItem::new(
            rel_path,
            item_wire.size,
            ContentHash::from_bytes(hash),
        ));
        contents.push(slice.to_vec());
    }

    Ok(OpenedEnvelope {
        transfer_id,
        sender: sender_identity,
        created_at: UnixTime::from_secs(created_secs),
        tier,
        items: envelope_items,
        contents,
    })
}

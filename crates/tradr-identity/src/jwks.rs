//! Parses a provider's JWKS document (RFC 7517) into the `Jwk` slice
//! `verify_id_token` selects from by `kid`. No I/O: fetching and caching
//! the document's bytes is WI-M0-011e. docs/05 makes an unknown `kid` a
//! rejection, not a lookup, so a broken usable entry rejects the whole
//! document here rather than being dropped from it silently.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

use crate::id_token::{Jwk, SignatureAlgorithm};

/// RFC 7518's floor for RS256: a modulus shorter than this is factorable
/// and must never be accepted, not even partially.
const MIN_MODULUS_BYTES: usize = 256;

/// Why a JWKS document could not be turned into a usable key set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwksError {
    /// The document itself, or a usable entry's key material, is not
    /// shaped the way this build requires.
    Malformed(String),
    /// Two usable entries published the same `kid`. `verify_id_token`
    /// selects the first match, so a duplicate would give one id two
    /// meanings.
    DuplicateKeyId(String),
    /// A usable entry's modulus is below the 2048-bit floor RFC 7518
    /// requires for RS256.
    WeakKey { kid: String, modulus_bytes: usize },
    /// No entry in the document was both usable and valid.
    NoUsableKeys,
}

impl fmt::Display for JwksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "malformed jwks document: {reason}"),
            Self::DuplicateKeyId(kid) => write!(f, "duplicate key id: {kid}"),
            Self::WeakKey { kid, modulus_bytes } => write!(
                f,
                "key {kid} has a {modulus_bytes}-byte modulus, below the 2048-bit floor for RS256"
            ),
            Self::NoUsableKeys => write!(f, "jwks document has no usable keys"),
        }
    }
}

impl std::error::Error for JwksError {}

/// Parses `document` into the keys `verify_id_token` may select among.
/// Walks `keys` in document order; see the module doc for why a usable
/// entry's own corruption rejects the whole document rather than being
/// dropped.
pub fn parse_jwks(document: &[u8]) -> Result<Vec<Jwk>, JwksError> {
    let root: Value = serde_json::from_slice(document)
        .map_err(|e| JwksError::Malformed(format!("document is not valid JSON: {e}")))?;
    let entries = root
        .as_object()
        .and_then(|obj| obj.get("keys"))
        .ok_or_else(|| JwksError::Malformed("document has no keys member".to_string()))?
        .as_array()
        .ok_or_else(|| JwksError::Malformed("keys member is not an array".to_string()))?;

    let mut keys: Vec<Jwk> = Vec::new();
    for entry in entries {
        let object = entry
            .as_object()
            .ok_or_else(|| JwksError::Malformed("a keys entry is not a JSON object".to_string()))?;

        let Some(usable) = usable_entry(object) else {
            continue;
        };

        let modulus = decode_key_material(object, "n")?;
        let exponent = decode_key_material(object, "e")?;

        let modulus_bytes = modulus.iter().skip_while(|&&b| b == 0).count();
        if modulus_bytes < MIN_MODULUS_BYTES {
            return Err(JwksError::WeakKey {
                kid: usable.kid,
                modulus_bytes,
            });
        }

        if keys.iter().any(|k| k.kid == usable.kid) {
            return Err(JwksError::DuplicateKeyId(usable.kid));
        }

        keys.push(Jwk {
            kid: usable.kid,
            algorithm: usable.algorithm,
            modulus,
            exponent,
        });
    }

    if keys.is_empty() {
        return Err(JwksError::NoUsableKeys);
    }

    Ok(keys)
}

/// A usable entry's identity, once its type, algorithm, and intended use
/// are confirmed. The key material is read separately, since a broken
/// usable entry rejects the document rather than being skipped like an
/// entry that fails this check.
struct UsableEntry {
    kid: String,
    algorithm: SignatureAlgorithm,
}

/// Decides whether this build can use `object` at all. Returns `None` for
/// anything outside what this build represents (a different key type, a
/// different algorithm, a non-signing use, or no `kid` to be selected by)
/// so the caller can skip it without treating it as an error.
fn usable_entry(object: &Map<String, Value>) -> Option<UsableEntry> {
    if object.get("kty").and_then(Value::as_str) != Some("RSA") {
        return None;
    }
    if object.get("alg").and_then(Value::as_str) != Some("RS256") {
        return None;
    }
    if let Some(use_value) = object.get("use")
        && use_value.as_str() != Some("sig")
    {
        return None;
    }
    let kid = object.get("kid").and_then(Value::as_str)?.to_string();
    Some(UsableEntry {
        kid,
        algorithm: SignatureAlgorithm::Rs256,
    })
}

/// Decodes an entry's `field` (`n` or `e`) as unpadded base64url. A usable
/// entry that fails here is corrupt, not merely unrepresentable, so this
/// makes the whole document `Malformed` rather than dropping the entry.
fn decode_key_material(object: &Map<String, Value>, field: &str) -> Result<Vec<u8>, JwksError> {
    let raw = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| JwksError::Malformed(format!("entry has no {field}")))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|e| JwksError::Malformed(format!("{field} is not base64url: {e}")))?;
    if bytes.is_empty() {
        return Err(JwksError::Malformed(format!(
            "{field} decodes to zero bytes"
        )));
    }
    Ok(bytes)
}

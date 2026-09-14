//! Holds the shell-free half of the paste-a-bundle Attestation exchange:
//! the bundle this device shows, and docs/05's seven steps run against
//! a peer's copy of it. Writes no cryptography of its own --
//! `tradr_identity::verify_attestation` already runs every step.

use serde::{Deserialize, Serialize};

use tradr_core::{PublicIdentity, PublicKeyPoint};
use tradr_identity::{
    AccountId, AttestationPolicy, JwksCache, ProviderProfile, SystemClock, Verification,
    verify_attestation, verify_id_token,
};
use tradr_oidc::fetch_jwks;

/// How old an `id_token`'s `iat` may be before verification rejects it
/// (docs/05, "Handling expiry"). The single definition every path applies:
/// this crate's `peer_trust` and `sign_in`, and the plugin's `link_commands`.
pub const STALENESS_LIMIT_SECS: u64 = 30 * 24 * 60 * 60;
/// How far ahead of this device's clock an `id_token`'s `iat` may be before
/// verification rejects it (docs/05 step 5).
pub const FUTURE_SKEW_LIMIT_SECS: u64 = 300;

/// What a peer needs to verify this device, and what this device parses
/// out of a peer's pasted copy of the same shape: the `id_token` an
/// OIDC provider signed, and the two public keys it binds, as lowercase
/// hex of their 65-byte SEC-1 points.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBundle {
    id_token: String,
    identity_pub: String,
    agreement_pub: String,
}

/// The outcome of verifying a peer's Attestation.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedPeer {
    tier: String,
    account: String,
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Decodes a lowercase-hex-encoded 65-byte SEC-1 point. Named after the
// field it came from so a malformed bundle's error says which half is
// wrong, and rejects a non-ASCII string outright rather than slicing into
// one and panicking on a non-char boundary.
fn decode_point(field: &str, hex: &str) -> Result<PublicKeyPoint, String> {
    if !hex.is_ascii() || !hex.len().is_multiple_of(2) {
        return Err(format!("{field} must be an even-length ascii hex string"));
    }
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty(), "length was checked above");
    let mut bytes = Vec::with_capacity(pairs.len());
    for &[hi, lo] in pairs {
        let hi = (hi as char)
            .to_digit(16)
            .ok_or_else(|| format!("{field} contains a non-hex character"))?;
        let lo = (lo as char)
            .to_digit(16)
            .ok_or_else(|| format!("{field} contains a non-hex character"))?;
        bytes.push(((hi << 4) | lo) as u8);
    }
    PublicKeyPoint::from_bytes(&bytes).map_err(|e| format!("{field}: {e}"))
}

/// Returns what a peer needs to verify this device: the `id_token` this
/// device's own sign-in obtained, and its two public keys as lowercase
/// hex.
pub fn bundle_for(identity: &PublicIdentity, id_token: String) -> AttestationBundle {
    AttestationBundle {
        id_token,
        identity_pub: encode_hex(identity.identity_pub().as_bytes()),
        agreement_pub: encode_hex(identity.agreement_pub().as_bytes()),
    }
}

/// Parses a peer's pasted Attestation bundle and runs docs/05's seven
/// steps against it, fetching a `JwksNeeded` uri at most once.
pub async fn verify_peer_bundle(
    bundle: &str,
    profile: &ProviderProfile,
    own_account: &AccountId,
    linked_accounts: &[AccountId],
) -> Result<VerifiedPeer, String> {
    let parsed: AttestationBundle =
        serde_json::from_str(bundle).map_err(|e| format!("malformed attestation bundle: {e}"))?;
    let identity_pub = decode_point("identity_pub", &parsed.identity_pub)?;
    let agreement_pub = decode_point("agreement_pub", &parsed.agreement_pub)?;

    let mut cache = JwksCache::new(&profile.jwks_uri);
    let policy = AttestationPolicy {
        profiles: std::slice::from_ref(profile),
        own_account,
        linked_accounts,
        staleness_limit_secs: STALENESS_LIMIT_SECS,
        future_skew_limit_secs: FUTURE_SKEW_LIMIT_SECS,
        ephemeral_receive: false,
    };

    let mut outcome = verify_attestation(
        &policy,
        &mut cache,
        &parsed.id_token,
        &identity_pub,
        &agreement_pub,
        &SystemClock,
    )
    .map_err(|e| e.to_string())?;

    if let Verification::JwksNeeded { jwks_uri } = outcome {
        let document = fetch_jwks(&jwks_uri).await.map_err(|e| e.to_string())?;
        cache.install(&document).map_err(|e| e.to_string())?;
        outcome = verify_attestation(
            &policy,
            &mut cache,
            &parsed.id_token,
            &identity_pub,
            &agreement_pub,
            &SystemClock,
        )
        .map_err(|e| e.to_string())?;
    }

    let tier = match outcome {
        Verification::Verified(tier) => tier,
        Verification::JwksNeeded { .. } => {
            return Err(
                "the provider's keys changed again right after a fetch; refusing a second one"
                    .to_string(),
            );
        }
    };

    // verify_attestation reports only the tier; the account it classified
    // against comes from re-reading the same already-verified token
    // through the same already-warmed cache.
    let claims =
        verify_id_token(profile, cache.keys(), &parsed.id_token).map_err(|e| e.to_string())?;

    Ok(VerifiedPeer {
        tier: format!("{tier:?}"),
        account: format!("{} on {}", claims.sub, claims.iss),
    })
}

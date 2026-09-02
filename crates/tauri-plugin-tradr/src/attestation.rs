//! The two-device exchange (WI-M0-016): shows this device's own
//! Attestation for a peer to copy, and runs docs/05's seven steps against
//! a peer's pasted copy of the same shape. Writes no cryptography of its
//! own -- `tradr_identity::verify_attestation` already runs every step;
//! nothing outside a test had ever called it before this module.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;

use tradr_core::PublicKeyPoint;
use tradr_identity::{
    AttestationPolicy, JwksCache, Platform, SystemClock, Verification, google, oauth_client,
    verify_attestation, verify_id_token,
};
use tradr_oidc::fetch_jwks;

use crate::identity::IdentityState;
use crate::link_registry::LinkRegistryState;
use crate::sign_in::{OAuthConfig, SignInState};

/// How old an `id_token`'s `iat` may be before verification rejects it
/// (docs/05, "Handling expiry"). Mirrors `sign_in`'s own limit; shared with
/// `crate::peer_trust` so a live connection applies the same policy.
pub(crate) const STALENESS_LIMIT_SECS: u64 = 30 * 24 * 60 * 60;
/// How far ahead of this device's clock an `id_token`'s `iat` may be before
/// verification rejects it (docs/05 step 5).
pub(crate) const FUTURE_SKEW_LIMIT_SECS: u64 = 300;

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
/// hex. Errors when no sign-in has completed, since there is no
/// `id_token` to hand over before then.
#[tauri::command]
pub fn attestation_bundle(
    identity_state: State<'_, IdentityState>,
    sign_in_state: State<'_, Arc<SignInState>>,
) -> Result<AttestationBundle, String> {
    let id_token = sign_in_state
        .id_token()
        .ok_or_else(|| "sign in before showing this device's Attestation".to_string())?;
    let identity = identity_state.public_identity()?;

    Ok(AttestationBundle {
        id_token,
        identity_pub: encode_hex(identity.identity_pub().as_bytes()),
        agreement_pub: encode_hex(identity.agreement_pub().as_bytes()),
    })
}

/// Parses a peer's pasted Attestation bundle and runs docs/05's seven
/// steps against it, fetching a `JwksNeeded` uri at most once. Requires a
/// completed sign-in of this device's own, since classifying a peer's
/// account needs one to classify against.
#[tauri::command]
pub async fn verify_peer_attestation(
    bundle: String,
    oauth: State<'_, OAuthConfig>,
    sign_in_state: State<'_, Arc<SignInState>>,
    link_registry: State<'_, LinkRegistryState>,
) -> Result<VerifiedPeer, String> {
    let parsed: AttestationBundle =
        serde_json::from_str(&bundle).map_err(|e| format!("malformed attestation bundle: {e}"))?;
    let identity_pub = decode_point("identity_pub", &parsed.identity_pub)?;
    let agreement_pub = decode_point("agreement_pub", &parsed.agreement_pub)?;

    let own_account = sign_in_state
        .own_account()
        .ok_or_else(|| "sign in on this device before verifying a peer".to_string())?;
    let linked_accounts = link_registry.linked_accounts().await?;

    let client = oauth_client(Platform::Desktop, oauth.client_ids, oauth.client_secret)
        .map_err(|e| e.to_string())?;
    let profile = google(client);
    let mut cache = JwksCache::new(&profile.jwks_uri);
    let policy = AttestationPolicy {
        profiles: std::slice::from_ref(&profile),
        own_account: &own_account,
        linked_accounts: &linked_accounts,
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
        verify_id_token(&profile, cache.keys(), &parsed.id_token).map_err(|e| e.to_string())?;

    Ok(VerifiedPeer {
        tier: format!("{tier:?}"),
        account: format!("{} on {}", claims.sub, claims.iss),
    })
}

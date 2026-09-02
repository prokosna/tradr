//! Builds a fresh `Invite` (docs/11-account-linking.md, "What the Invite
//! carries, and how it travels"). Encoding it to the base64url blob a QR
//! carries is a separate call the composition root makes through
//! `tradr-proto`; this module never touches the wire type.

use tradr_core::{
    Clock, DisplayName, HalfSecret, Invite, InviteId, PublicKeyPoint, Rng, RngError, UnixTime,
};

/// How long a freshly created invite stays open (docs/11, "What an
/// invite's expiry decides, and what it does not").
pub const INVITE_TTL_SECS: i64 = 300;

/// Builds a fresh `Invite` offering to link, expiring `INVITE_TTL_SECS`
/// from `clock.now()`. Draws 32 bytes in one `fill_bytes` call and splits
/// them: the first 16 become the `InviteId`, the last 16 the `HalfSecret`
/// -- one call is one failure point rather than two.
pub fn create_invite(
    rng: &dyn Rng,
    clock: &dyn Clock,
    identity_pub: PublicKeyPoint,
    agreement_pub: PublicKeyPoint,
    attestation_token: String,
    display_name: Option<DisplayName>,
) -> Result<Invite, RngError> {
    let mut drawn = [0u8; 32];
    rng.fill_bytes(&mut drawn)?;

    let invite_id =
        InviteId::from_bytes(&drawn[..16]).expect("a 16-byte slice always fits InviteId");
    let half_secret =
        HalfSecret::from_bytes(&drawn[16..]).expect("a 16-byte slice always fits HalfSecret");

    let expires_at = UnixTime::from_secs(clock.now().as_secs().saturating_add(INVITE_TTL_SECS));

    let mut invite = Invite::new(
        invite_id,
        identity_pub,
        agreement_pub,
        attestation_token,
        half_secret,
        expires_at,
    );
    if let Some(display_name) = display_name {
        invite = invite.with_display_name(display_name);
    }
    Ok(invite)
}

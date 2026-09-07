//! Implementation of the KeyBindingVerifier port (docs/04-protocol.md, "What each
//! side checks, and in what order"; docs/05-security.md; ADR-0020).

use std::sync::Arc;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey};
use tradr_core::{
    Clock, DeviceId, DomainTag, KeyBinding, KeyBindingRefused, KeyBindingVerifier, PublicKeyPoint,
    Signature, UnixTime,
};

pub(crate) fn parse_verifying_key(
    point: &PublicKeyPoint,
) -> Result<VerifyingKey, KeyBindingRefused> {
    VerifyingKey::from_sec1_bytes(point.as_bytes())
        .map_err(|_| KeyBindingRefused::MalformedIdentityKey)
}

pub(crate) fn signature_verifies(
    key: &VerifyingKey,
    domain: DomainTag,
    message: &[u8],
    signature: &Signature,
) -> bool {
    let Ok(payload) = domain.payload(message) else {
        return false;
    };
    let Ok(raw) = EcdsaSignature::from_slice(signature.as_bytes()) else {
        return false;
    };
    key.verify(payload.as_ref(), &raw).is_ok()
}

/// Verifies a `KeyBinding` against an authenticated agreement key, yielding
/// the `DeviceId` that derives from the identity key and never from the agreement key.
pub fn verify_key_binding(
    identity_pub: &PublicKeyPoint,
    binding: &KeyBinding,
    authenticated_agreement_pub: &PublicKeyPoint,
    now: UnixTime,
) -> Result<DeviceId, KeyBindingRefused> {
    if binding.agreement_pub() != authenticated_agreement_pub {
        return Err(KeyBindingRefused::NotForThisAgreementKey);
    }

    let key = parse_verifying_key(identity_pub)?;
    if !signature_verifies(
        &key,
        DomainTag::KeyBind,
        binding.agreement_pub().as_bytes(),
        binding.signature(),
    ) {
        return Err(KeyBindingRefused::SignatureInvalid);
    }

    if binding.not_after() < now {
        return Err(KeyBindingRefused::Expired {
            not_after: binding.not_after(),
            now,
        });
    }

    let digest: [u8; 32] = blake3::hash(identity_pub.as_bytes()).into();
    Ok(DeviceId::from_identity_digest(&digest))
}

/// A `KeyBindingVerifier` backed by a `Clock`.
pub struct ClockKeyBindingVerifier {
    clock: Arc<dyn Clock + Send + Sync>,
}

impl ClockKeyBindingVerifier {
    /// Backs verification with `clock`, read per call so a binding that expires
    /// mid-process stops verifying.
    pub fn new(clock: Arc<dyn Clock + Send + Sync>) -> Self {
        Self { clock }
    }
}

impl KeyBindingVerifier for ClockKeyBindingVerifier {
    fn device_id_for_agreement_key(
        &self,
        identity_pub: &PublicKeyPoint,
        binding: &KeyBinding,
        authenticated_agreement_pub: &PublicKeyPoint,
    ) -> Result<DeviceId, KeyBindingRefused> {
        verify_key_binding(
            identity_pub,
            binding,
            authenticated_agreement_pub,
            self.clock.now(),
        )
    }
}

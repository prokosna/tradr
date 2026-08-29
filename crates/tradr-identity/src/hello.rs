//! The Hello exchange (docs/04-protocol.md, "The Hello exchange";
//! docs/05-security.md, "An Attestation proves an account, never which
//! device is speaking"). Four steps, four types, consumed by value, so
//! replaying or skipping one fails to compile. Verifies no Attestation:
//! that is `verify_attestation`'s, called between `on_peer_hello` and `on_verified`.

use std::fmt;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey};

use tradr_core::{
    Capabilities, Clock, DeviceId, DomainTag, HelloNonce, KeyBinding, KeyStore, KeyStoreError,
    NoCommonVersion, PeerHello, PeerHelloAck, PublicIdentity, PublicKeyPoint, Rng, RngError,
    TrustTier, UnixTime, VersionRange, negotiate_version,
};

/// The smallest `max_frame_size` a peer's `HelloAck` may advertise
/// (docs/04, "What step 4 checks besides the signature"): the `ble-gatt`
/// bound, below which no legal frame fits.
pub const MIN_NEGOTIABLE_FRAME_SIZE: u32 = 512;

// Parses `point` as a P-256 verifying key, refusing whatever a peer's
// claimed identity key does not actually encode. Centralised here so
// every check against a peer's identity key fails the same way.
fn parse_verifying_key(point: &PublicKeyPoint) -> Result<VerifyingKey, HelloRefused> {
    VerifyingKey::from_sec1_bytes(point.as_bytes()).map_err(|_| HelloRefused::MalformedIdentityKey)
}

// Whether `signature`, under `domain` over `message`, verifies against
// `key`. The only failure mode this reports is "does not verify" --
// callers attach the domain-specific refusal.
fn signature_verifies(
    key: &VerifyingKey,
    domain: DomainTag,
    message: &[u8],
    signature: &tradr_core::Signature,
) -> bool {
    let Ok(payload) = domain.payload(message) else {
        return false;
    };
    let Ok(raw) = EcdsaSignature::from_slice(signature.as_bytes()) else {
        return false;
    };
    key.verify(payload.as_ref(), &raw).is_ok()
}

/// Step 1: our own `Hello`, and the state needed to check the peer's.
///
/// Built by `open`. Consumes itself into `AwaitingVerification` through
/// `on_peer_hello`, so a caller cannot present a second peer `Hello` to the
/// same exchange.
#[derive(Debug)]
pub struct AwaitingPeerHello {
    our_versions: VersionRange,
    our_nonce: HelloNonce,
}

/// Builds our own `Hello`, carrying a fresh nonce drawn through `rng`
/// (docs/04, "The Hello exchange" step 1), and the state that checks
/// whatever `Hello` the peer sends back.
pub fn open(
    rng: &dyn Rng,
    versions: VersionRange,
    identity: &PublicIdentity,
    attestation_token: String,
    key_binding: KeyBinding,
    capabilities: Capabilities,
) -> Result<(AwaitingPeerHello, PeerHello), RngError> {
    let nonce = HelloNonce::generate(rng)?;
    let our_hello = PeerHello::new(
        versions,
        identity.identity_pub().clone(),
        identity.agreement_pub().clone(),
        attestation_token,
        key_binding,
        nonce,
        capabilities,
    );
    let state = AwaitingPeerHello {
        our_versions: versions,
        our_nonce: nonce,
    };
    Ok((state, our_hello))
}

impl AwaitingPeerHello {
    /// Runs checks 1 through 3 against `peer` (docs/04's numbered list),
    /// then stops: check 4, the Attestation, is the caller's, and this
    /// returns exactly what it needs -- the `AttestationRequest` -- and
    /// verifies nothing about it itself.
    pub fn on_peer_hello(
        self,
        peer: PeerHello,
        authenticated: DeviceId,
        clock: &dyn Clock,
    ) -> Result<(AwaitingVerification, AttestationRequest), HelloRefused> {
        // Check 1: version overlap, an integer comparison, first because
        // it costs nothing.
        let negotiated_version = negotiate_version(self.our_versions, peer.versions())
            .map_err(HelloRefused::NoCommonVersion)?;

        // Check 2: the key join. One hash, before any signature work, and
        // before an AttestationRequest is ever produced.
        let digest: [u8; 32] = blake3::hash(peer.identity_pub().as_bytes()).into();
        let claimed = DeviceId::from_identity_digest(&digest);
        if claimed != authenticated {
            return Err(HelloRefused::KeyDoesNotMatchChannel {
                authenticated,
                claimed,
            });
        }

        // Check 3: the KeyBinding, in the order docs/04 states it -- the
        // covered key, then the signature, then expiry.
        let binding = peer.key_binding();
        if binding.agreement_pub() != peer.agreement_pub() {
            return Err(HelloRefused::KeyBindingNotForThisAgreementKey);
        }

        let peer_identity_key = parse_verifying_key(peer.identity_pub())?;
        if !signature_verifies(
            &peer_identity_key,
            DomainTag::KeyBind,
            binding.agreement_pub().as_bytes(),
            binding.signature(),
        ) {
            return Err(HelloRefused::KeyBindingSignatureInvalid);
        }

        let now = clock.now();
        if binding.not_after() < now {
            return Err(HelloRefused::KeyBindingExpired {
                not_after: binding.not_after(),
                now,
            });
        }

        let request = AttestationRequest {
            token: peer.attestation_token().to_string(),
            identity_pub: peer.identity_pub().clone(),
            agreement_pub: peer.agreement_pub().clone(),
        };

        let state = AwaitingVerification {
            peer_device_id: claimed,
            peer_identity_pub: peer.identity_pub().clone(),
            peer_nonce: peer.nonce(),
            our_nonce: self.our_nonce,
            negotiated_version,
        };

        Ok((state, request))
    }
}

/// Everything `verify_attestation` needs, and nothing it verifies itself
/// (docs/04, "No step performs I/O"): the caller runs docs/05's seven
/// steps against `token()` and comes back with a `TrustTier`.
pub struct AttestationRequest {
    token: String,
    identity_pub: PublicKeyPoint,
    agreement_pub: PublicKeyPoint,
}

impl AttestationRequest {
    /// The peer's provider-signed id token, unverified.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The identity key `verify_attestation`'s nonce check binds against.
    pub fn identity_pub(&self) -> &PublicKeyPoint {
        &self.identity_pub
    }

    /// The agreement key `verify_attestation`'s nonce check binds against.
    pub fn agreement_pub(&self) -> &PublicKeyPoint {
        &self.agreement_pub
    }
}

// Hand-written rather than derived (rule F4): `token` is a bearer
// credential, mirroring how `tradr_core::PeerHello`'s Debug redacts the
// same field.
impl fmt::Debug for AttestationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttestationRequest")
            .field("token", &"[redacted]")
            .field("identity_pub", &self.identity_pub)
            .field("agreement_pub", &self.agreement_pub)
            .finish()
    }
}

/// Step 2: the Attestation has been requested, and this awaits the
/// verdict a caller reaches by running `verify_attestation`.
#[derive(Debug)]
pub struct AwaitingVerification {
    peer_device_id: DeviceId,
    peer_identity_pub: PublicKeyPoint,
    peer_nonce: HelloNonce,
    our_nonce: HelloNonce,
    negotiated_version: u32,
}

impl AwaitingVerification {
    /// Step 3: signs the peer's nonce and produces our `HelloAck`, even
    /// for `tier` of `Rejected` (DCR-051) -- the domain tag is what makes
    /// signing attacker-chosen bytes safe, and `assigned_tier` in the same
    /// message already tells the peer the verdict.
    pub fn on_verified(
        self,
        tier: TrustTier,
        key_store: &dyn KeyStore,
        max_frame_size: u32,
    ) -> Result<(AwaitingPeerAck, PeerHelloAck), KeyStoreError> {
        let nonce_signature = key_store.sign(DomainTag::Hello, self.peer_nonce.as_bytes())?;
        let our_ack = PeerHelloAck::new(
            self.negotiated_version,
            max_frame_size,
            nonce_signature,
            tier,
        );

        let state = AwaitingPeerAck {
            peer_device_id: self.peer_device_id,
            peer_identity_pub: self.peer_identity_pub,
            our_nonce: self.our_nonce,
            negotiated_version: self.negotiated_version,
            tier,
        };

        Ok((state, our_ack))
    }
}

/// Step 4: awaits the peer's `HelloAck`, holding the tier we computed --
/// never the peer's -- so `Session::tier` cannot become an input the peer
/// controls (DCR-051's first rule).
#[derive(Debug)]
pub struct AwaitingPeerAck {
    peer_device_id: DeviceId,
    peer_identity_pub: PublicKeyPoint,
    our_nonce: HelloNonce,
    negotiated_version: u32,
    tier: TrustTier,
}

impl AwaitingPeerAck {
    /// Checks the peer's `HelloAck` and, if it holds up, settles the
    /// session. Check 5 (the nonce signature) first, since it is where the
    /// numbered list puts it; then the two DCR-052 claims.
    pub fn on_peer_hello_ack(self, ack: PeerHelloAck) -> Result<Session, HelloRefused> {
        let peer_identity_key = parse_verifying_key(&self.peer_identity_pub)?;
        if !signature_verifies(
            &peer_identity_key,
            DomainTag::Hello,
            self.our_nonce.as_bytes(),
            ack.nonce_signature(),
        ) {
            return Err(HelloRefused::NonceSignatureInvalid);
        }

        if ack.negotiated_version() != self.negotiated_version {
            return Err(HelloRefused::VersionDisagreement {
                ours: self.negotiated_version,
                theirs: ack.negotiated_version(),
            });
        }

        if ack.max_frame_size() < MIN_NEGOTIABLE_FRAME_SIZE {
            return Err(HelloRefused::FrameSizeTooSmall {
                advertised: ack.max_frame_size(),
                minimum: MIN_NEGOTIABLE_FRAME_SIZE,
            });
        }

        Ok(Session {
            peer: self.peer_device_id,
            tier: self.tier,
            negotiated_version: self.negotiated_version,
            peer_max_frame_size: ack.max_frame_size(),
        })
    }
}

/// A completed Hello exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    peer: DeviceId,
    tier: TrustTier,
    negotiated_version: u32,
    peer_max_frame_size: u32,
}

impl Session {
    /// The peer's `DeviceId`, the value the key join proved.
    pub fn peer(&self) -> DeviceId {
        self.peer
    }

    /// The tier this side computed, never the peer's own claim about
    /// itself (DCR-051).
    pub fn tier(&self) -> TrustTier {
        self.tier
    }

    /// The version both sides settled on.
    pub fn negotiated_version(&self) -> u32 {
        self.negotiated_version
    }

    /// The largest frame the peer will accept: our send bound (DCR-049).
    pub fn peer_max_frame_size(&self) -> u32 {
        self.peer_max_frame_size
    }
}

/// Why a Hello exchange refused to proceed (docs/04, "The Hello exchange").
#[derive(Debug)]
pub enum HelloRefused {
    /// Check 1: no version both sides support.
    NoCommonVersion(NoCommonVersion),
    /// Check 2: the peer's claimed identity key does not hash to the
    /// `DeviceId` the channel authenticated.
    KeyDoesNotMatchChannel {
        /// The `DeviceId` the channel actually authenticated.
        authenticated: DeviceId,
        /// The `DeviceId` the peer's `Hello` claims.
        claimed: DeviceId,
    },
    /// Check 3: the `KeyBinding`'s `agreement_pub` does not match the
    /// `Hello`'s own agreement key.
    KeyBindingNotForThisAgreementKey,
    /// Check 3: the `KeyBinding`'s signature does not verify.
    KeyBindingSignatureInvalid,
    /// Check 3: the `KeyBinding`'s `not_after` has passed.
    KeyBindingExpired {
        /// The time after which the binding was no longer valid.
        not_after: UnixTime,
        /// The time it was checked against.
        now: UnixTime,
    },
    /// A peer's claimed identity key is not a valid P-256 point.
    MalformedIdentityKey,
    /// Check 5: the peer's `HelloAck` signature over our nonce does not
    /// verify.
    NonceSignatureInvalid,
    /// The peer's `HelloAck` names a `negotiated_version` other than the
    /// one both sides had everything needed to compute (DCR-052).
    VersionDisagreement {
        /// The version this side negotiated.
        ours: u32,
        /// The version the peer's `HelloAck` claimed.
        theirs: u32,
    },
    /// The peer's `HelloAck` advertises a `max_frame_size` below
    /// `MIN_NEGOTIABLE_FRAME_SIZE` (DCR-052).
    FrameSizeTooSmall {
        /// The value the peer advertised.
        advertised: u32,
        /// The smallest value this protocol defines.
        minimum: u32,
    },
}

impl fmt::Display for HelloRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCommonVersion(e) => write!(f, "{e}"),
            Self::KeyDoesNotMatchChannel {
                authenticated,
                claimed,
            } => write!(
                f,
                "hello claims device {claimed}, but the channel authenticated {authenticated}"
            ),
            Self::KeyBindingNotForThisAgreementKey => {
                write!(f, "key binding does not cover the hello's agreement key")
            }
            Self::KeyBindingSignatureInvalid => {
                write!(f, "key binding signature does not verify")
            }
            Self::KeyBindingExpired { not_after, now } => write!(
                f,
                "key binding expired at {}, now is {}",
                not_after.as_secs(),
                now.as_secs()
            ),
            Self::MalformedIdentityKey => {
                write!(f, "peer's claimed identity key is not a valid point")
            }
            Self::NonceSignatureInvalid => {
                write!(f, "peer's hello-ack nonce signature does not verify")
            }
            Self::VersionDisagreement { ours, theirs } => write!(
                f,
                "peer's hello-ack names version {theirs}, we negotiated {ours}"
            ),
            Self::FrameSizeTooSmall {
                advertised,
                minimum,
            } => write!(
                f,
                "peer's hello-ack advertises max_frame_size {advertised}, minimum is {minimum}"
            ),
        }
    }
}

impl std::error::Error for HelloRefused {}

//! Layer 0 vocabulary for the Hello exchange (docs/04-protocol.md, "The
//! Hello exchange", DCR-051). Every type here is a claim, never a decision:
//! nothing verifies a signature, hashes a key, or derives a `DeviceId`. The
//! exchange runs in `tradr-identity`, the wire conversion in `tradr-proto`
//! (decision 23) -- neither may name the other, so this names nothing beyond `std` and this crate's own types (rule B1).

use std::fmt;

use crate::clock::UnixTime;
use crate::discovery::{Capabilities, DisplayName};
use crate::key_store::{PublicKeyPoint, Signature};
use crate::rng::{Rng, RngError};
use crate::trust_tier::TrustTier;

/// The lowest and highest protocol version one side of the Hello exchange
/// supports (docs/04, "The Hello exchange").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRange {
    min: u32,
    max: u32,
}

/// An error constructing a `VersionRange`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionRangeError {
    /// `min` was greater than `max`.
    Inverted {
        /// The `min` that was given.
        min: u32,
        /// The `max` that was given.
        max: u32,
    },
    /// `min` was zero. Protobuf omits a zero-valued scalar, so a `Hello`
    /// carrying no version fields at all decodes as `{ min: 0, max: 0 }`.
    /// If `0` were a valid version, a peer that sent nothing would
    /// negotiate one instead of being refused for sending nothing.
    ZeroIsNotAVersion,
}

impl fmt::Display for VersionRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inverted { min, max } => {
                write!(f, "version range is inverted: min {min} > max {max}")
            }
            Self::ZeroIsNotAVersion => write!(f, "version 0 is not a valid version"),
        }
    }
}

impl std::error::Error for VersionRangeError {}

impl VersionRange {
    /// Builds a `VersionRange`, refusing `min > max` and refusing
    /// `min == 0`. The zero refusal is not tidiness: protobuf omits a
    /// zero-valued scalar, so a `Hello` carrying no version fields at all
    /// decodes as `{ min: 0, max: 0 }`. Treating `0` as a version would let
    /// a peer that sent nothing negotiate one.
    pub fn new(min: u32, max: u32) -> Result<Self, VersionRangeError> {
        if min == 0 {
            return Err(VersionRangeError::ZeroIsNotAVersion);
        }
        if min > max {
            return Err(VersionRangeError::Inverted { min, max });
        }
        Ok(Self { min, max })
    }

    /// The lowest version supported.
    pub fn min(self) -> u32 {
        self.min
    }

    /// The highest version supported.
    pub fn max(self) -> u32 {
        self.max
    }
}

/// The version a Hello exchange settles on, or the reason it could not
/// (docs/04, "The Hello exchange" step 1): `negotiated = min(ours.max,
/// theirs.max)`, refused when that falls below `max(ours.min, theirs.min)`.
/// Symmetric in `ours` and `theirs`, since docs/04 says neither side is the
/// client and both must reach the same verdict.
pub fn negotiate_version(ours: VersionRange, theirs: VersionRange) -> Result<u32, NoCommonVersion> {
    let negotiated = ours.max.min(theirs.max);
    let floor = ours.min.max(theirs.min);
    if negotiated < floor {
        Err(NoCommonVersion { ours, theirs })
    } else {
        Ok(negotiated)
    }
}

/// The two ranges a Hello exchange could not negotiate a common version
/// from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoCommonVersion {
    ours: VersionRange,
    theirs: VersionRange,
}

impl NoCommonVersion {
    /// The range we offered.
    pub fn ours(self) -> VersionRange {
        self.ours
    }

    /// The range the peer offered.
    pub fn theirs(self) -> VersionRange {
        self.theirs
    }
}

impl fmt::Display for NoCommonVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "no common version: ours [{}, {}], theirs [{}, {}]",
            self.ours.min, self.ours.max, self.theirs.min, self.theirs.max
        )
    }
}

impl std::error::Error for NoCommonVersion {}

/// The number of bytes a `HelloNonce` occupies.
pub const HELLO_NONCE_LEN: usize = 16;

/// A nonce carried in a `Hello`, fresh per connection (docs/04, "The Hello
/// exchange"): the peer signs it back in its `HelloAck`, defeating replay
/// against a later session. Fixed at `HELLO_NONCE_LEN` bytes so "exactly
/// 16 bytes" holds by construction rather than by a check that can be
/// forgotten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HelloNonce([u8; HELLO_NONCE_LEN]);

impl HelloNonce {
    /// Wraps a nonce an implementation already obtained, e.g. by decoding
    /// a `Hello.nonce` field.
    pub fn from_bytes(bytes: [u8; HELLO_NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; HELLO_NONCE_LEN] {
        &self.0
    }

    /// Draws a fresh nonce through the `Rng` trait (rule B7), as docs/04
    /// requires: one drawn per connection, never reused.
    pub fn generate(rng: &dyn Rng) -> Result<Self, RngError> {
        let mut bytes = [0u8; HELLO_NONCE_LEN];
        rng.fill_bytes(&mut bytes)?;
        Ok(Self(bytes))
    }
}

/// A peer's proof that it holds the agreement key it claims (docs/04, "The
/// Hello exchange" step 3): a P-256 signature over `tradr-keybind-v1 ||
/// agreement_pub` against `identity_pub`, valid until `not_after`. Performs
/// no verification -- checking the signature is `008c`'s job and needs a
/// P-256 implementation this crate may not have (rule B1); this only carries the claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBinding {
    agreement_pub: PublicKeyPoint,
    signature: Signature,
    not_after: UnixTime,
}

impl KeyBinding {
    /// Builds a `KeyBinding` from its claimed fields, unverified.
    pub fn new(agreement_pub: PublicKeyPoint, signature: Signature, not_after: UnixTime) -> Self {
        Self {
            agreement_pub,
            signature,
            not_after,
        }
    }

    /// The agreement key this binding claims to cover.
    pub fn agreement_pub(&self) -> &PublicKeyPoint {
        &self.agreement_pub
    }

    /// The claimed signature, unverified.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// The time after which this binding is no longer valid.
    pub fn not_after(&self) -> UnixTime {
        self.not_after
    }
}

/// What a peer sent in its `Hello` (docs/04, "The Hello exchange"): a claim,
/// never a decision -- no verification, no `DeviceId` derivation; that is
/// `008c`'s job. `platform` is deliberately absent: no check in "The Hello
/// exchange" reads it, `tradr-discovery` already owns `Platform`, and
/// `ci/layer-deps.sh` forbids `tradr-identity` naming that crate, so duplicating it into Layer 0 would be what rule F3 forbids; `008d` maps it when a UI needs it.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerHello {
    versions: VersionRange,
    identity_pub: PublicKeyPoint,
    agreement_pub: PublicKeyPoint,
    attestation_token: String,
    key_binding: KeyBinding,
    nonce: HelloNonce,
    capabilities: Capabilities,
    display_name: Option<DisplayName>,
}

impl PeerHello {
    /// Builds a `PeerHello` from everything mandatory. `display_name` is
    /// the only optional field, added with `with_display_name`.
    pub fn new(
        versions: VersionRange,
        identity_pub: PublicKeyPoint,
        agreement_pub: PublicKeyPoint,
        attestation_token: String,
        key_binding: KeyBinding,
        nonce: HelloNonce,
        capabilities: Capabilities,
    ) -> Self {
        Self {
            versions,
            identity_pub,
            agreement_pub,
            attestation_token,
            key_binding,
            nonce,
            capabilities,
            display_name: None,
        }
    }

    /// Records the name the peer published about itself.
    pub fn with_display_name(mut self, display_name: DisplayName) -> Self {
        self.display_name = Some(display_name);
        self
    }

    /// The version range the peer claims to support.
    pub fn versions(&self) -> VersionRange {
        self.versions
    }

    /// The identity key the peer claims.
    pub fn identity_pub(&self) -> &PublicKeyPoint {
        &self.identity_pub
    }

    /// The agreement key the peer claims.
    pub fn agreement_pub(&self) -> &PublicKeyPoint {
        &self.agreement_pub
    }

    /// The provider-signed id token the peer's Attestation carries,
    /// unverified.
    pub fn attestation_token(&self) -> &str {
        &self.attestation_token
    }

    /// The peer's claimed binding between its identity and agreement keys,
    /// unverified.
    pub fn key_binding(&self) -> &KeyBinding {
        &self.key_binding
    }

    /// The fresh nonce the peer sent, to be signed back in our `HelloAck`.
    pub fn nonce(&self) -> HelloNonce {
        self.nonce
    }

    /// The capability bitmask the peer claims.
    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    /// The name the peer published about itself, if any.
    pub fn display_name(&self) -> Option<&DisplayName> {
        self.display_name.as_ref()
    }
}

// Hand-written rather than derived (rule F4): attestation_token is a
// bearer credential, so this must never place its value into a {:?}.
impl fmt::Debug for PeerHello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerHello")
            .field("versions", &self.versions)
            .field("identity_pub", &self.identity_pub)
            .field("agreement_pub", &self.agreement_pub)
            .field("attestation_token", &"[redacted]")
            .field("key_binding", &self.key_binding)
            .field("nonce", &self.nonce)
            .field("capabilities", &self.capabilities)
            .field("display_name", &self.display_name)
            .finish()
    }
}

/// What a peer sent back in its `HelloAck` (docs/04, "The Hello exchange"
/// step 4). `visible_shares` is deliberately absent: Shares arrive in M3
/// and no Layer 0 type describes one yet. `assigned_tier` is the tier
/// **the sender granted the receiver** (DCR-051): arriving from a peer, it
/// is what *they* granted *us* -- display material, never an input to the tier we ourselves grant them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHelloAck {
    negotiated_version: u32,
    max_frame_size: u32,
    nonce_signature: Signature,
    assigned_tier: TrustTier,
}

impl PeerHelloAck {
    /// Builds a `PeerHelloAck` from everything it carries.
    pub fn new(
        negotiated_version: u32,
        max_frame_size: u32,
        nonce_signature: Signature,
        assigned_tier: TrustTier,
    ) -> Self {
        Self {
            negotiated_version,
            max_frame_size,
            nonce_signature,
            assigned_tier,
        }
    }

    /// The version the peer says was negotiated.
    pub fn negotiated_version(&self) -> u32 {
        self.negotiated_version
    }

    /// The largest frame the peer will accept.
    pub fn max_frame_size(&self) -> u32 {
        self.max_frame_size
    }

    /// The peer's signature over our nonce, unverified.
    pub fn nonce_signature(&self) -> &Signature {
        &self.nonce_signature
    }

    /// The tier the peer granted us. Display material only: never an input
    /// to the tier we grant the peer.
    pub fn assigned_tier(&self) -> TrustTier {
        self.assigned_tier
    }
}

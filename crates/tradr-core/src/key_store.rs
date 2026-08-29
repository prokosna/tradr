//! Layer 1's key-custody abstraction (ADR-0011, ADR-0012). No
//! implementation lives here; that belongs to Layer 3. `KeyStore` exposes
//! operations rather than key bytes: a key inside StrongBox, a TPM, or
//! the Secure Enclave cannot be read out, so a trait handing back key
//! material could only ever be software.

use std::borrow::Cow;
use std::fmt;

use crate::DeviceId;

/// The number of bytes a P-256 point occupies in uncompressed SEC-1 form:
/// a `0x04` tag byte followed by a 32-byte X and a 32-byte Y coordinate
/// (docs/05-security.md, "Hardware backing and the curve"; ADR-0012).
pub const PUBLIC_KEY_POINT_LEN: usize = 65;

/// A P-256 public key point in uncompressed SEC-1 form, fixed at
/// `PUBLIC_KEY_POINT_LEN` bytes so a wrong-length value cannot enter the
/// type. Used for both the identity key and the agreement key: docs/05
/// pins one encoding for both, since disagreeing about it yields
/// different Attestation nonces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyPoint([u8; PUBLIC_KEY_POINT_LEN]);

/// An error constructing a `PublicKeyPoint` from bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyPointError {
    /// The input was not exactly `PUBLIC_KEY_POINT_LEN` bytes long.
    WrongLength(usize),
}

impl fmt::Display for PublicKeyPointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength(len) => write!(
                f,
                "public key point must be {PUBLIC_KEY_POINT_LEN} bytes, got {len}"
            ),
        }
    }
}

impl std::error::Error for PublicKeyPointError {}

impl PublicKeyPoint {
    /// Builds a `PublicKeyPoint` from exactly `PUBLIC_KEY_POINT_LEN` bytes.
    /// Does not itself check the leading tag byte or curve membership;
    /// that is a cryptographic check Layer 1 does not perform.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PublicKeyPointError> {
        let array: [u8; PUBLIC_KEY_POINT_LEN] = bytes
            .try_into()
            .map_err(|_| PublicKeyPointError::WrongLength(bytes.len()))?;
        Ok(Self(array))
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_POINT_LEN] {
        &self.0
    }
}

/// A device's public identity: its identity and agreement public keys,
/// plus the `DeviceId` derived from the identity key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    identity_pub: PublicKeyPoint,
    agreement_pub: PublicKeyPoint,
    device_id: DeviceId,
}

impl PublicIdentity {
    /// Builds a `PublicIdentity` from its two public keys and the
    /// `DeviceId` computed from the identity key.
    pub fn new(
        identity_pub: PublicKeyPoint,
        agreement_pub: PublicKeyPoint,
        device_id: DeviceId,
    ) -> Self {
        Self {
            identity_pub,
            agreement_pub,
            device_id,
        }
    }

    /// The device's identity public key, used for signing.
    pub fn identity_pub(&self) -> &PublicKeyPoint {
        &self.identity_pub
    }

    /// The device's agreement public key, used for `agree`.
    pub fn agreement_pub(&self) -> &PublicKeyPoint {
        &self.agreement_pub
    }

    /// The `DeviceId` derived from `identity_pub`.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
}

/// How a `DomainTag` separates its signed bytes from every other
/// context's (docs/05-security.md, "Two contexts admit no prefix, and the
/// structure is checked rather than argued"). Most contexts choose their
/// own message and get a tag prepended; two sign a structure someone else
/// fixed and instead require the message to already begin with theirs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Separation {
    /// Prepended to the message before signing.
    Prepended(&'static [u8]),
    /// The message must already begin with these bytes; signing is
    /// refused when it does not.
    Required(&'static [u8]),
}

/// The closed set of contexts an identity-key signature can be over
/// (docs/05-security.md, "Every signature carries a domain tag"). Closed
/// rather than a free string: otherwise a Brokr can hand a device an
/// opaque challenge that is actually another protocol's message and
/// collect a signature it can replay elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainTag {
    /// Binds the agreement key to the identity key: `KeyBinding.signature`.
    KeyBind,
    /// Proves current key possession during a handshake:
    /// `HelloAck.nonce_signature`, over the peer's `Hello.nonce`.
    Hello,
    /// Answers a Brokr's registration challenge:
    /// `BrokrRegister.challenge_signature`.
    BrokrChallenge,
    /// Declares a device revoked.
    Revoke,
    /// Signs the self-signed TLS certificate's `TBSCertificate`: X.509
    /// fixes that structure, so no tag can be prepended to it.
    CertificateTbs,
    /// Signs TLS 1.3's `CertificateVerify` content, whose preamble RFC
    /// 8446 fixes, covering both the client and server spellings.
    TlsCertificateVerify,
}

// RFC 8446 4.4.3's CertificateVerify preamble: sixty-four 0x20 bytes then
// "TLS 1.3, ". Built by a const-evaluated loop so the space count is
// provably right rather than typed out and hand-counted.
const TLS_CERTIFICATE_VERIFY_SPACES: usize = 64;
const TLS_CERTIFICATE_VERIFY_SUFFIX: &[u8] = b"TLS 1.3, ";
const TLS_CERTIFICATE_VERIFY_PREFIX_LEN: usize =
    TLS_CERTIFICATE_VERIFY_SPACES + TLS_CERTIFICATE_VERIFY_SUFFIX.len();
const TLS_CERTIFICATE_VERIFY_PREFIX: [u8; TLS_CERTIFICATE_VERIFY_PREFIX_LEN] = {
    let mut bytes = [0x20u8; TLS_CERTIFICATE_VERIFY_PREFIX_LEN];
    let mut i = 0;
    while i < TLS_CERTIFICATE_VERIFY_SUFFIX.len() {
        bytes[TLS_CERTIFICATE_VERIFY_SPACES + i] = TLS_CERTIFICATE_VERIFY_SUFFIX[i];
        i += 1;
    }
    bytes
};

impl DomainTag {
    /// All six contexts, for tests and callers that must check a
    /// property over the whole closed set rather than over an
    /// enumeration they wrote out by hand.
    pub const ALL: &'static [DomainTag] = &[
        Self::KeyBind,
        Self::Hello,
        Self::BrokrChallenge,
        Self::Revoke,
        Self::CertificateTbs,
        Self::TlsCertificateVerify,
    ];

    /// The separation this tag imposes on a message before signing.
    pub fn separation(self) -> Separation {
        match self {
            Self::KeyBind => Separation::Prepended(b"tradr-keybind-v1"),
            Self::Hello => Separation::Prepended(b"tradr-hello-v1"),
            Self::BrokrChallenge => Separation::Prepended(b"tradr-brokr-v1"),
            Self::Revoke => Separation::Prepended(b"tradr-revoke-v1"),
            Self::CertificateTbs => Separation::Required(&[0x30]),
            Self::TlsCertificateVerify => Separation::Required(&TLS_CERTIFICATE_VERIFY_PREFIX),
        }
    }

    /// Builds the exact bytes `KeyStore::sign` must sign for `message`
    /// under this tag: `tag || message`, owned, for `Prepended`;
    /// `message` itself, borrowed, when `Required`'s prefix is already
    /// present. Refuses a message lacking that prefix, so the policy
    /// lives here once rather than in every `KeyStore` implementation.
    pub fn payload(self, message: &[u8]) -> Result<Cow<'_, [u8]>, MissingSeparation> {
        match self.separation() {
            Separation::Prepended(tag) => {
                let mut bytes = Vec::with_capacity(tag.len() + message.len());
                bytes.extend_from_slice(tag);
                bytes.extend_from_slice(message);
                Ok(Cow::Owned(bytes))
            }
            Separation::Required(required) => {
                if message.starts_with(required) {
                    Ok(Cow::Borrowed(message))
                } else {
                    Err(MissingSeparation(self))
                }
            }
        }
    }
}

/// A `DomainTag::payload` call refused a message that did not carry the
/// tag's required separation. Names the tag that refused; says nothing
/// about the message, so a refusal cannot leak into a log what it
/// refused (rule F4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingSeparation(DomainTag);

impl fmt::Display for MissingSeparation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "message does not carry the separation {:?} requires",
            self.0
        )
    }
}

impl std::error::Error for MissingSeparation {}

/// A signature produced by `KeyStore::sign`, opaque to Layer 1: this crate
/// neither encodes nor verifies it, only carries the bytes an
/// implementation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Wraps a signature's raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the signature's raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The output of `KeyStore::agree`. Excludes `Clone`, `Debug` that prints
/// the bytes, and `Display` entirely, so the cheapest way to keep a shared
/// secret out of a log (rule F4) is that the type cannot be printed or
/// copied.
pub struct SharedSecret(Vec<u8>);

impl SharedSecret {
    /// Wraps raw shared key material an `agree` implementation produced.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes for a KDF to consume. The sole sanctioned
    /// use of the value.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SharedSecret").field(&"<redacted>").finish()
    }
}

/// Why a `KeyStore` fell back to software rather than a secure element
/// (docs/05-security.md, "Key storage").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareReason {
    /// This platform has no secure element category at all (Linux).
    PlatformHasNoSecureElement,
    /// The platform supports a TPM, but none is present on this machine.
    NoTpmPresent,
    /// A secure element exists, but its Keymint version predates support
    /// for this operation (Android).
    KeymintTooOld,
    /// No Secret Service session is available, so storage fell back past
    /// it to the kernel keyring or a `0600` file (headless Linux).
    NoSecretService,
}

/// Where a `KeyStore`'s private keys are held, and why when not hardware.
/// Closed rather than a string so the UI renders a fixed set of cases
/// (docs/05-security.md, "Key storage") instead of an implementation's own
/// wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backing {
    /// The key never leaves a secure element: StrongBox or the TEE, a
    /// TPM, or the Secure Enclave.
    Hardware,
    /// The key is stored in software, and why hardware backing was not
    /// used.
    Software(SoftwareReason),
}

/// Where a `SecretStore` actually reached, as opposed to what a caller
/// asked for (docs/05-security.md, "Key storage"). `backing()` must
/// report this: a Secret Service that is merely unreachable and a
/// `0600` file are different sentences, though both are software. Two
/// rungs, not three (DCR-033).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageLevel {
    /// The platform's Secret Service, reached over D-Bus.
    SecretService,
    /// A `0600` file, reached because no Secret Service was available.
    File,
}

/// An error from a `SecretStore` operation.
#[derive(Debug)]
pub enum SecretStoreError {
    /// The underlying storage backend failed; its own error is preserved.
    Backend(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for SecretStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "secret store backend error: {e}"),
        }
    }
}

impl std::error::Error for SecretStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Backend(e) => Some(e.as_ref()),
        }
    }
}

/// Durable storage for one secret at a time, keyed by an opaque slot name.
/// Declared here, not in Layer 3, so the load-or-generate policy around a
/// `KeyStore` can be tested with no keyring, no D-Bus and no filesystem
/// (WI-M0-007b); the real Linux backends implementing it are WI-M0-007c.
pub trait SecretStore {
    /// Writes `secret` under `slot`, replacing any value already there.
    fn store(&self, slot: &str, secret: &[u8]) -> Result<(), SecretStoreError>;

    /// Reads the value under `slot`, or `None` if the slot is empty. A
    /// backend that cannot be reached returns `Err`, never `Ok(None)`: the
    /// two must not be confused by a caller deciding whether to generate a
    /// replacement.
    fn load(&self, slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError>;

    /// The storage level this instance actually reached, for `backing()`
    /// to report.
    fn level(&self) -> StorageLevel;
}

/// An error from a `KeyStore` operation.
#[derive(Debug)]
pub enum KeyStoreError {
    /// The underlying platform key store failed; its own error is
    /// preserved.
    Backend(Box<dyn std::error::Error + Send + Sync>),
    /// `sign` was asked for a signature over a message whose `DomainTag`
    /// required a separation the message did not carry.
    DomainSeparation(MissingSeparation),
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "key store backend error: {e}"),
            Self::DomainSeparation(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for KeyStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Backend(e) => Some(e.as_ref()),
            Self::DomainSeparation(e) => Some(e),
        }
    }
}

/// Access to a device's private keys through operations only (ADR-0011).
/// No method returns key material, and none may be added that could:
/// that is the entire point of the ADR.
pub trait KeyStore: Send + Sync {
    /// The device's public identity: its two public keys and `DeviceId`.
    fn public_identity(&self) -> Result<PublicIdentity, KeyStoreError>;

    /// Signs `message` under `domain`, whose `separation` decides how the
    /// message is combined with the tag before signing (`DomainTag::
    /// payload`) so the result cannot be replayed as a signature over a
    /// different context. Fails when `message` does not carry a
    /// `Required` separation's prefix.
    fn sign(&self, domain: DomainTag, message: &[u8]) -> Result<Signature, KeyStoreError>;

    /// Performs ECDH against a peer's agreement public key, returning the
    /// raw shared secret for a KDF to consume. Covers Noise's static-key
    /// Diffie-Hellman.
    fn agree(&self, peer_public: &PublicKeyPoint) -> Result<SharedSecret, KeyStoreError>;

    /// Reports whether the private keys are hardware-backed, and why not
    /// when they are not.
    fn backing(&self) -> Backing;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tag_separations_match_docs_05_literally() {
        assert_eq!(
            DomainTag::KeyBind.separation(),
            Separation::Prepended(b"tradr-keybind-v1")
        );
        assert_eq!(
            DomainTag::Hello.separation(),
            Separation::Prepended(b"tradr-hello-v1")
        );
        assert_eq!(
            DomainTag::BrokrChallenge.separation(),
            Separation::Prepended(b"tradr-brokr-v1")
        );
        assert_eq!(
            DomainTag::Revoke.separation(),
            Separation::Prepended(b"tradr-revoke-v1")
        );
    }

    #[test]
    fn no_domain_tag_separation_is_a_prefix_of_another() {
        let tags = [
            DomainTag::KeyBind,
            DomainTag::Hello,
            DomainTag::BrokrChallenge,
            DomainTag::Revoke,
        ];

        for a in tags {
            for b in tags {
                if a == b {
                    continue;
                }
                let (Separation::Prepended(pa) | Separation::Required(pa)) = a.separation();
                let (Separation::Prepended(pb) | Separation::Required(pb)) = b.separation();
                let shorter_len = pa.len().min(pb.len());
                assert_ne!(
                    &pa[..shorter_len],
                    &pb[..shorter_len],
                    "{a:?}'s separation and {b:?}'s separation share a common prefix"
                );
            }
        }
    }

    #[test]
    fn public_key_point_rejects_a_sixty_four_byte_slice() {
        let bytes = [0u8; 64];

        assert_eq!(
            PublicKeyPoint::from_bytes(&bytes),
            Err(PublicKeyPointError::WrongLength(64))
        );
    }

    #[test]
    fn public_key_point_accepts_sixty_five_bytes() {
        let bytes = [7u8; PUBLIC_KEY_POINT_LEN];

        let point = PublicKeyPoint::from_bytes(&bytes).expect("65 bytes must construct");

        assert_eq!(point.as_bytes(), &bytes);
    }

    // A minimal fake KeyStore, present only to prove the trait is
    // object-safe and callable through a Box<dyn KeyStore>.
    struct FakeKeyStore;

    impl KeyStore for FakeKeyStore {
        fn public_identity(&self) -> Result<PublicIdentity, KeyStoreError> {
            let identity_pub = PublicKeyPoint::from_bytes(&[1u8; PUBLIC_KEY_POINT_LEN]).unwrap();
            let agreement_pub = PublicKeyPoint::from_bytes(&[2u8; PUBLIC_KEY_POINT_LEN]).unwrap();
            let device_id = DeviceId::from_bytes(&[9u8; 16]).unwrap();
            Ok(PublicIdentity::new(identity_pub, agreement_pub, device_id))
        }

        fn sign(&self, domain: DomainTag, message: &[u8]) -> Result<Signature, KeyStoreError> {
            let payload = domain
                .payload(message)
                .map_err(KeyStoreError::DomainSeparation)?;
            Ok(Signature::from_bytes(payload.into_owned()))
        }

        fn agree(&self, peer_public: &PublicKeyPoint) -> Result<SharedSecret, KeyStoreError> {
            Ok(SharedSecret::from_bytes(peer_public.as_bytes().to_vec()))
        }

        fn backing(&self) -> Backing {
            Backing::Software(SoftwareReason::PlatformHasNoSecureElement)
        }
    }

    #[test]
    fn a_boxed_key_store_compiles_and_can_be_called() {
        let store: Box<dyn KeyStore> = Box::new(FakeKeyStore);

        let identity = store.public_identity().expect("fake never fails");
        let signature = store
            .sign(DomainTag::Hello, b"nonce")
            .expect("fake never fails");
        let peer = PublicKeyPoint::from_bytes(&[3u8; PUBLIC_KEY_POINT_LEN]).unwrap();
        let secret = store.agree(&peer).expect("fake never fails");

        assert_eq!(
            identity.device_id(),
            DeviceId::from_bytes(&[9u8; 16]).unwrap()
        );
        assert_eq!(signature.as_bytes(), b"tradr-hello-v1nonce");
        assert_eq!(secret.as_bytes(), &[3u8; PUBLIC_KEY_POINT_LEN]);
        assert_eq!(
            store.backing(),
            Backing::Software(SoftwareReason::PlatformHasNoSecureElement)
        );
    }
}

use std::sync::Arc;

use tradr_core::{KeyStore, PublicKeyPoint, Rng};

use super::resolver::{LocalErrorSlot, TradrResolver};
use super::{MAX_PLAINTEXT_LEN, NoiseError};

// A placeholder key satisfies snow's builder check while the KeyStore-backed Dh ignores it.
const PLACEHOLDER_PRIVATE_KEY: [u8; 32] = [0u8; 32];

const PATTERN: &str = "Noise_IK_P256_ChaChaPoly_BLAKE2s";

/// The initiator side of a Noise_IK handshake before the first message is sent.
pub struct Initiator {
    state: snow::HandshakeState,
    peer_agreement_pub: PublicKeyPoint,
    error_slot: LocalErrorSlot,
}

impl Initiator {
    /// Starts a Noise_IK initiator for the peer's static agreement key.
    /// Takes `key_store` because static Diffie-Hellman never leaves it (ADR-0011),
    /// and `rng` because it is the only randomness snow has per DCR-091 with
    /// the use-getrandom feature deliberately absent.
    pub fn new(
        key_store: Arc<dyn KeyStore>,
        rng: Arc<dyn Rng + Send + Sync>,
        peer_agreement_pub: &PublicKeyPoint,
    ) -> Result<Self, NoiseError> {
        let identity = key_store.public_identity().map_err(NoiseError::KeyStore)?;
        let agreement_pub = identity.agreement_pub().clone();
        let error_slot = LocalErrorSlot::new();
        let resolver = TradrResolver::new(
            Arc::clone(&key_store),
            agreement_pub,
            Arc::clone(&rng),
            error_slot.clone(),
        );
        // Noise_IK_P256_ChaChaPoly_BLAKE2s is statically valid Noise specification syntax.
        let params: snow::params::NoiseParams =
            PATTERN.parse().expect("valid static Noise pattern");
        let builder = snow::Builder::with_resolver(params, Box::new(resolver));
        let builder = builder
            .local_private_key(&PLACEHOLDER_PRIVATE_KEY)
            .map_err(|_| error_slot.take_or_refused())?;
        let builder = builder
            .remote_public_key(peer_agreement_pub.as_bytes())
            .map_err(|_| error_slot.take_or_refused())?;
        let state = builder
            .build_initiator()
            .map_err(|_| error_slot.take_or_refused())?;
        Ok(Self {
            state,
            peer_agreement_pub: peer_agreement_pub.clone(),
            error_slot,
        })
    }

    /// Writes the first handshake message and transitions to awaiting the response.
    pub fn write_first(mut self) -> Result<(AwaitingResponse, Vec<u8>), NoiseError> {
        let mut message = vec![0u8; 65535];
        let len = match self.state.write_message(&[], &mut message) {
            Ok(len) => len,
            Err(_) => return Err(self.error_slot.take_or_refused()),
        };
        message.truncate(len);
        let next = AwaitingResponse {
            state: self.state,
            peer_agreement_pub: self.peer_agreement_pub,
            error_slot: self.error_slot,
        };
        Ok((next, message))
    }
}

/// The initiator side waiting for the responder's handshake reply.
pub struct AwaitingResponse {
    state: snow::HandshakeState,
    peer_agreement_pub: PublicKeyPoint,
    error_slot: LocalErrorSlot,
}

impl AwaitingResponse {
    /// Reads the responder's reply message and transitions to an established session.
    pub fn read_second(mut self, message: &[u8]) -> Result<NoiseSession, NoiseError> {
        let mut payload = vec![0u8; 65535];
        if self.state.read_message(message, &mut payload).is_err() {
            return Err(self.error_slot.take_or_refused());
        }
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|_| self.error_slot.take_or_refused())?;
        Ok(NoiseSession {
            transport,
            peer_agreement_pub: self.peer_agreement_pub,
            error_slot: self.error_slot,
        })
    }
}

/// The responder side of a Noise_IK handshake before the first message is received.
pub struct Responder {
    state: snow::HandshakeState,
    error_slot: LocalErrorSlot,
}

impl Responder {
    /// Starts a Noise_IK responder awaiting an initiator handshake message.
    /// Takes `key_store` because static Diffie-Hellman never leaves it (ADR-0011),
    /// and `rng` because it is the only randomness snow has per DCR-091 with
    /// the use-getrandom feature deliberately absent.
    pub fn new(
        key_store: Arc<dyn KeyStore>,
        rng: Arc<dyn Rng + Send + Sync>,
    ) -> Result<Self, NoiseError> {
        let identity = key_store.public_identity().map_err(NoiseError::KeyStore)?;
        let agreement_pub = identity.agreement_pub().clone();
        let error_slot = LocalErrorSlot::new();
        let resolver = TradrResolver::new(
            Arc::clone(&key_store),
            agreement_pub,
            Arc::clone(&rng),
            error_slot.clone(),
        );
        // Noise_IK_P256_ChaChaPoly_BLAKE2s is statically valid Noise specification syntax.
        let params: snow::params::NoiseParams =
            PATTERN.parse().expect("valid static Noise pattern");
        let builder = snow::Builder::with_resolver(params, Box::new(resolver));
        let builder = builder
            .local_private_key(&PLACEHOLDER_PRIVATE_KEY)
            .map_err(|_| error_slot.take_or_refused())?;
        let state = builder
            .build_responder()
            .map_err(|_| error_slot.take_or_refused())?;
        Ok(Self { state, error_slot })
    }

    /// Reads the initiator's first message and transitions to awaiting reply.
    pub fn read_first(mut self, message: &[u8]) -> Result<AwaitingReply, NoiseError> {
        let mut payload = vec![0u8; 65535];
        if self.state.read_message(message, &mut payload).is_err() {
            return Err(self.error_slot.take_or_refused());
        }
        Ok(AwaitingReply {
            state: self.state,
            error_slot: self.error_slot,
        })
    }
}

/// The responder side after reading the first message, ready to write the reply.
pub struct AwaitingReply {
    state: snow::HandshakeState,
    error_slot: LocalErrorSlot,
}

impl AwaitingReply {
    /// Writes the second handshake message and transitions to an established session.
    pub fn write_second(mut self) -> Result<(NoiseSession, Vec<u8>), NoiseError> {
        let mut message = vec![0u8; 65535];
        let len = match self.state.write_message(&[], &mut message) {
            Ok(len) => len,
            Err(_) => return Err(self.error_slot.take_or_refused()),
        };
        message.truncate(len);
        let remote_static = self.state.get_remote_static().ok_or(NoiseError::Refused)?;
        let peer_agreement_pub =
            PublicKeyPoint::from_bytes(remote_static).map_err(|_| NoiseError::Refused)?;
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|_| self.error_slot.take_or_refused())?;
        let session = NoiseSession {
            transport,
            peer_agreement_pub,
            error_slot: self.error_slot,
        };
        Ok((session, message))
    }
}

/// An established Noise session over an underlying byte stream.
pub struct NoiseSession {
    transport: snow::TransportState,
    peer_agreement_pub: PublicKeyPoint,
    error_slot: LocalErrorSlot,
}

impl NoiseSession {
    /// Returns the peer's static agreement public key.
    /// This is an agreement key, not an identity key: no DeviceId follows from it
    /// because DeviceId is BLAKE3(identity_pub)[0..16] over the identity key.
    /// See docs/05-security.md, "Why there are two encryption layers".
    pub fn peer_agreement_pub(&self) -> &PublicKeyPoint {
        &self.peer_agreement_pub
    }

    /// Encrypts `plaintext` into a transport ciphertext.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(NoiseError::PayloadTooLarge(plaintext.len()));
        }
        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let len = match self.transport.write_message(plaintext, &mut ciphertext) {
            Ok(len) => len,
            Err(_) => return Err(self.error_slot.take_or_refused()),
        };
        ciphertext.truncate(len);
        Ok(ciphertext)
    }

    /// Authenticates and decrypts `ciphertext` into plaintext by verifying its tag.
    /// NoiseError::Refused from this method means authentication failed, which is
    /// not a thing a caller retries.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = match self.transport.read_message(ciphertext, &mut plaintext) {
            Ok(len) => len,
            Err(_) => return Err(self.error_slot.take_or_refused()),
        };
        plaintext.truncate(len);
        Ok(plaintext)
    }
}

use std::sync::Arc;

use tradr_core::{
    DeviceId, KeyBinding, KeyBindingVerifier, KeyStore, PublicKeyPoint, Rng, Signature, UnixTime,
};

use super::resolver::{LocalErrorSlot, TradrResolver};
use super::{IDENTITY_JOIN_LEN, MAX_PLAINTEXT_LEN, NoiseError};

// A placeholder key satisfies snow's builder check while the KeyStore-backed Dh ignores it.
const PLACEHOLDER_PRIVATE_KEY: [u8; 32] = [0u8; 32];

const PATTERN: &str = "Noise_XX_P256_ChaChaPoly_BLAKE2s";

fn encode_identity_join(
    identity_pub: &PublicKeyPoint,
    binding: &KeyBinding,
) -> Result<Vec<u8>, NoiseError> {
    let sig_bytes = binding.signature().as_bytes();
    if sig_bytes.len() != 64 {
        return Err(NoiseError::LocalKeyBinding);
    }
    let mut join = Vec::with_capacity(IDENTITY_JOIN_LEN);
    join.extend_from_slice(identity_pub.as_bytes());
    join.extend_from_slice(sig_bytes);
    join.extend_from_slice(&binding.not_after().as_secs().to_be_bytes());
    Ok(join)
}

fn verify_identity_join(
    verifier: &dyn KeyBindingVerifier,
    payload: &[u8],
    peer_agreement_pub: &PublicKeyPoint,
) -> Result<DeviceId, NoiseError> {
    if payload.len() != IDENTITY_JOIN_LEN {
        return Err(NoiseError::Refused);
    }
    let identity_pub = match PublicKeyPoint::from_bytes(&payload[..65]) {
        Ok(point) => point,
        Err(_) => return Err(NoiseError::Refused),
    };
    let signature = Signature::from_bytes(payload[65..129].to_vec());
    let mut not_after_bytes = [0u8; 8];
    not_after_bytes.copy_from_slice(&payload[129..137]);
    let not_after = UnixTime::from_secs(i64::from_be_bytes(not_after_bytes));
    let binding = KeyBinding::new(peer_agreement_pub.clone(), signature, not_after);
    verifier
        .device_id_for_agreement_key(&identity_pub, &binding, peer_agreement_pub)
        .map_err(NoiseError::PeerKeyBinding)
}

/// The initiator side of a Noise_XX handshake before the first message is sent.
pub struct Initiator {
    state: snow::HandshakeState,
    our_join: Vec<u8>,
    verifier: Arc<dyn KeyBindingVerifier>,
    error_slot: LocalErrorSlot,
}

impl Initiator {
    /// Starts a Noise_XX initiator.
    /// Takes `key_store` because static Diffie-Hellman never leaves it (ADR-0011),
    /// and `rng` because it is the only randomness snow has per DCR-091 with
    /// the use-getrandom feature deliberately absent.
    pub fn new(
        key_store: Arc<dyn KeyStore>,
        rng: Arc<dyn Rng + Send + Sync>,
        verifier: Arc<dyn KeyBindingVerifier>,
        our_binding: KeyBinding,
    ) -> Result<Self, NoiseError> {
        let identity = key_store.public_identity().map_err(NoiseError::KeyStore)?;
        if our_binding.agreement_pub() != identity.agreement_pub() {
            return Err(NoiseError::LocalKeyBinding);
        }
        let our_join = encode_identity_join(identity.identity_pub(), &our_binding)?;
        let agreement_pub = identity.agreement_pub().clone();
        let error_slot = LocalErrorSlot::new();
        let resolver = TradrResolver::new(
            Arc::clone(&key_store),
            agreement_pub,
            Arc::clone(&rng),
            error_slot.clone(),
        );
        // Noise_XX_P256_ChaChaPoly_BLAKE2s is statically valid Noise specification syntax.
        let params: snow::params::NoiseParams =
            PATTERN.parse().expect("valid static Noise pattern");
        let builder = snow::Builder::with_resolver(params, Box::new(resolver));
        let builder = builder
            .local_private_key(&PLACEHOLDER_PRIVATE_KEY)
            .map_err(|_| error_slot.take_or_refused())?;
        let state = builder
            .build_initiator()
            .map_err(|_| error_slot.take_or_refused())?;
        Ok(Self {
            state,
            our_join,
            verifier,
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
            our_join: self.our_join,
            verifier: self.verifier,
            error_slot: self.error_slot,
        };
        Ok((next, message))
    }
}

/// The initiator side waiting for the responder's handshake reply.
pub struct AwaitingResponse {
    state: snow::HandshakeState,
    our_join: Vec<u8>,
    verifier: Arc<dyn KeyBindingVerifier>,
    error_slot: LocalErrorSlot,
}

impl AwaitingResponse {
    /// Reads the responder's reply message and transitions to ready to confirm.
    pub fn read_second(mut self, message: &[u8]) -> Result<ReadyToConfirm, NoiseError> {
        let mut payload = vec![0u8; 65535];
        let len = match self.state.read_message(message, &mut payload) {
            Ok(len) => len,
            Err(_) => return Err(self.error_slot.take_or_refused()),
        };
        payload.truncate(len);
        let remote_static = match self.state.get_remote_static() {
            Some(bytes) => bytes,
            None => return Err(self.error_slot.take_or_refused()),
        };
        let peer_agreement_pub = match PublicKeyPoint::from_bytes(remote_static) {
            Ok(point) => point,
            Err(_) => return Err(NoiseError::Refused),
        };
        let peer = verify_identity_join(&*self.verifier, &payload, &peer_agreement_pub)?;
        Ok(ReadyToConfirm {
            state: self.state,
            our_join: self.our_join,
            peer,
            peer_agreement_pub,
            error_slot: self.error_slot,
        })
    }
}

/// The initiator side after reading the responder's reply, ready to write the third message.
pub struct ReadyToConfirm {
    state: snow::HandshakeState,
    our_join: Vec<u8>,
    peer: DeviceId,
    peer_agreement_pub: PublicKeyPoint,
    error_slot: LocalErrorSlot,
}

impl ReadyToConfirm {
    /// Writes the third handshake message and transitions to an established session.
    pub fn write_third(mut self) -> Result<(NoiseSession, Vec<u8>), NoiseError> {
        let mut message = vec![0u8; 65535];
        let len = match self.state.write_message(&self.our_join, &mut message) {
            Ok(len) => len,
            Err(_) => return Err(self.error_slot.take_or_refused()),
        };
        message.truncate(len);
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|_| self.error_slot.take_or_refused())?;
        let session = NoiseSession {
            transport,
            peer: self.peer,
            peer_agreement_pub: self.peer_agreement_pub,
            error_slot: self.error_slot,
        };
        Ok((session, message))
    }
}

/// The responder side of a Noise_XX handshake before the first message is received.
pub struct Responder {
    state: snow::HandshakeState,
    our_join: Vec<u8>,
    verifier: Arc<dyn KeyBindingVerifier>,
    error_slot: LocalErrorSlot,
}

impl Responder {
    /// Starts a Noise_XX responder awaiting an initiator handshake message.
    /// Takes `key_store` because static Diffie-Hellman never leaves it (ADR-0011),
    /// and `rng` because it is the only randomness snow has per DCR-091 with
    /// the use-getrandom feature deliberately absent.
    pub fn new(
        key_store: Arc<dyn KeyStore>,
        rng: Arc<dyn Rng + Send + Sync>,
        verifier: Arc<dyn KeyBindingVerifier>,
        our_binding: KeyBinding,
    ) -> Result<Self, NoiseError> {
        let identity = key_store.public_identity().map_err(NoiseError::KeyStore)?;
        if our_binding.agreement_pub() != identity.agreement_pub() {
            return Err(NoiseError::LocalKeyBinding);
        }
        let our_join = encode_identity_join(identity.identity_pub(), &our_binding)?;
        let agreement_pub = identity.agreement_pub().clone();
        let error_slot = LocalErrorSlot::new();
        let resolver = TradrResolver::new(
            Arc::clone(&key_store),
            agreement_pub,
            Arc::clone(&rng),
            error_slot.clone(),
        );
        // Noise_XX_P256_ChaChaPoly_BLAKE2s is statically valid Noise specification syntax.
        let params: snow::params::NoiseParams =
            PATTERN.parse().expect("valid static Noise pattern");
        let builder = snow::Builder::with_resolver(params, Box::new(resolver));
        let builder = builder
            .local_private_key(&PLACEHOLDER_PRIVATE_KEY)
            .map_err(|_| error_slot.take_or_refused())?;
        let state = builder
            .build_responder()
            .map_err(|_| error_slot.take_or_refused())?;
        Ok(Self {
            state,
            our_join,
            verifier,
            error_slot,
        })
    }

    /// Reads the initiator's first message and transitions to awaiting reply.
    pub fn read_first(mut self, message: &[u8]) -> Result<AwaitingReply, NoiseError> {
        let mut payload = vec![0u8; 65535];
        if self.state.read_message(message, &mut payload).is_err() {
            return Err(self.error_slot.take_or_refused());
        }
        Ok(AwaitingReply {
            state: self.state,
            our_join: self.our_join,
            verifier: self.verifier,
            error_slot: self.error_slot,
        })
    }
}

/// The responder side after reading the first message, ready to write the reply.
pub struct AwaitingReply {
    state: snow::HandshakeState,
    our_join: Vec<u8>,
    verifier: Arc<dyn KeyBindingVerifier>,
    error_slot: LocalErrorSlot,
}

impl AwaitingReply {
    /// Writes the second handshake message and transitions to awaiting confirmation.
    pub fn write_second(mut self) -> Result<(AwaitingConfirmation, Vec<u8>), NoiseError> {
        let mut message = vec![0u8; 65535];
        let len = match self.state.write_message(&self.our_join, &mut message) {
            Ok(len) => len,
            Err(_) => return Err(self.error_slot.take_or_refused()),
        };
        message.truncate(len);
        Ok((
            AwaitingConfirmation {
                state: self.state,
                verifier: self.verifier,
                error_slot: self.error_slot,
            },
            message,
        ))
    }
}

/// The responder side after writing the reply, awaiting the initiator's confirmation.
pub struct AwaitingConfirmation {
    state: snow::HandshakeState,
    verifier: Arc<dyn KeyBindingVerifier>,
    error_slot: LocalErrorSlot,
}

impl AwaitingConfirmation {
    /// Reads the initiator's third handshake message and transitions to an established session.
    pub fn read_third(mut self, message: &[u8]) -> Result<NoiseSession, NoiseError> {
        let mut payload = vec![0u8; 65535];
        let len = match self.state.read_message(message, &mut payload) {
            Ok(len) => len,
            Err(_) => return Err(self.error_slot.take_or_refused()),
        };
        payload.truncate(len);
        let remote_static = match self.state.get_remote_static() {
            Some(bytes) => bytes,
            None => return Err(self.error_slot.take_or_refused()),
        };
        let peer_agreement_pub = match PublicKeyPoint::from_bytes(remote_static) {
            Ok(point) => point,
            Err(_) => return Err(NoiseError::Refused),
        };
        let peer = verify_identity_join(&*self.verifier, &payload, &peer_agreement_pub)?;
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|_| self.error_slot.take_or_refused())?;
        Ok(NoiseSession {
            transport,
            peer,
            peer_agreement_pub,
            error_slot: self.error_slot,
        })
    }
}

/// An established Noise session over an underlying byte stream.
pub struct NoiseSession {
    transport: snow::TransportState,
    peer: DeviceId,
    peer_agreement_pub: PublicKeyPoint,
    error_slot: LocalErrorSlot,
}

impl NoiseSession {
    /// Returns the peer's Device ID authenticated by the identity join.
    pub fn peer(&self) -> DeviceId {
        self.peer
    }

    /// Returns the peer's static agreement public key.
    ///
    /// This is an agreement key, not an identity key: no `DeviceId` follows from it
    /// because `peer()` derives from the identity key, never from this key.
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
    ///
    /// `NoiseError::Refused` from this method means authentication failed, which is
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

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as P256Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use tradr_core::{
    Backing, BoxFuture, DeviceId, DomainTag, KeyBinding, KeyBindingRefused, KeyBindingVerifier,
    KeyStore, KeyStoreError, PublicIdentity, PublicKeyPoint, Rng, RngError, SharedSecret,
    Signature, SoftwareReason, TransportError, TransportId, UnixTime,
};
use tradr_proto::mux::StreamOpener;
use tradr_transport::noise::{
    BLE_GATT_MAX_FRAME_SIZE, Initiator, LinkSink, LinkSource, NoiseChannel, NoiseChannelConfig,
    NoiseSession, Responder,
};

pub const NOW: i64 = 1_800_000_000;
pub const LATER: i64 = NOW + 30 * 24 * 3600;

pub struct CountingKeyStore {
    identity: p256::SecretKey,
    agreement: p256::SecretKey,
    agreements: AtomicUsize,
    refuse_agreement: bool,
}

impl CountingKeyStore {
    pub fn new(seed: u8) -> Self {
        Self {
            identity: secret_key(seed),
            agreement: secret_key(seed.wrapping_add(128)),
            agreements: AtomicUsize::new(0),
            refuse_agreement: false,
        }
    }

    pub fn agreements(&self) -> usize {
        self.agreements.load(Ordering::SeqCst)
    }

    pub fn identity_pub(&self) -> PublicKeyPoint {
        point(&self.identity)
    }

    pub fn agreement_pub(&self) -> PublicKeyPoint {
        point(&self.agreement)
    }

    pub fn device_id(&self) -> DeviceId {
        DeviceId::from_identity_digest(blake3::hash(self.identity_pub().as_bytes()).as_bytes())
    }

    pub fn binding(&self) -> KeyBinding {
        self.binding_over(&self.agreement_pub(), LATER)
    }

    pub fn binding_over(&self, covered: &PublicKeyPoint, not_after: i64) -> KeyBinding {
        KeyBinding::new(
            covered.clone(),
            keybind_signature(&self.identity, covered),
            UnixTime::from_secs(not_after),
        )
    }
}

pub fn secret_key(seed: u8) -> p256::SecretKey {
    let mut bytes = [seed; 32];
    bytes[0] = seed | 1;
    p256::SecretKey::from_bytes(&bytes.into()).expect("a non-zero scalar under the order")
}

pub fn point(secret: &p256::SecretKey) -> PublicKeyPoint {
    let encoded = secret.public_key().to_encoded_point(false);
    PublicKeyPoint::from_bytes(encoded.as_bytes()).expect("an uncompressed P-256 point is 65 bytes")
}

pub fn keybind_signature(identity: &p256::SecretKey, covered: &PublicKeyPoint) -> Signature {
    let signing = SigningKey::from(identity);
    let mut payload = b"tradr-keybind-v1".to_vec();
    payload.extend_from_slice(covered.as_bytes());
    let raw: P256Signature = signing.sign(&payload);
    let normalized = raw.normalize_s().unwrap_or(raw);
    Signature::from_bytes(normalized.to_bytes().to_vec())
}

impl KeyStore for CountingKeyStore {
    fn public_identity(&self) -> Result<PublicIdentity, KeyStoreError> {
        Ok(PublicIdentity::new(
            self.identity_pub(),
            self.agreement_pub(),
            self.device_id(),
        ))
    }

    fn sign(&self, _domain: DomainTag, _message: &[u8]) -> Result<Signature, KeyStoreError> {
        Ok(Signature::from_bytes(Vec::new()))
    }

    fn agree(&self, peer_public: &PublicKeyPoint) -> Result<SharedSecret, KeyStoreError> {
        self.agreements.fetch_add(1, Ordering::SeqCst);
        if self.refuse_agreement {
            return Err(KeyStoreError::Backend(
                "this key store refuses to agree".into(),
            ));
        }
        let peer = p256::PublicKey::from_sec1_bytes(peer_public.as_bytes())
            .map_err(|_| KeyStoreError::Backend("peer point is not on P-256".into()))?;
        let shared =
            p256::ecdh::diffie_hellman(self.agreement.to_nonzero_scalar(), peer.as_affine());
        Ok(SharedSecret::from_bytes(shared.raw_secret_bytes().to_vec()))
    }

    fn backing(&self) -> Backing {
        Backing::Software(SoftwareReason::PlatformHasNoSecureElement)
    }
}

pub struct CounterRng {
    next: Mutex<u64>,
}

impl CounterRng {
    pub fn new() -> Self {
        Self {
            next: Mutex::new(1),
        }
    }
}

impl Rng for CounterRng {
    fn fill_bytes(&self, buf: &mut [u8]) -> Result<(), RngError> {
        let mut next = self.next.lock().expect("no test poisons this lock");
        for byte in buf.iter_mut() {
            *next = next.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *byte = (*next >> 33) as u8;
        }
        Ok(())
    }
}

pub struct TestVerifier {
    now: i64,
}

impl KeyBindingVerifier for TestVerifier {
    fn device_id_for_agreement_key(
        &self,
        identity_pub: &PublicKeyPoint,
        binding: &KeyBinding,
        authenticated_agreement_pub: &PublicKeyPoint,
    ) -> Result<DeviceId, KeyBindingRefused> {
        if binding.agreement_pub() != authenticated_agreement_pub {
            return Err(KeyBindingRefused::NotForThisAgreementKey);
        }
        let key = VerifyingKey::from_sec1_bytes(identity_pub.as_bytes())
            .map_err(|_| KeyBindingRefused::MalformedIdentityKey)?;
        let mut payload = b"tradr-keybind-v1".to_vec();
        payload.extend_from_slice(binding.agreement_pub().as_bytes());
        let raw = P256Signature::from_slice(binding.signature().as_bytes())
            .map_err(|_| KeyBindingRefused::SignatureInvalid)?;
        key.verify(&payload, &raw)
            .map_err(|_| KeyBindingRefused::SignatureInvalid)?;
        let now = UnixTime::from_secs(self.now);
        if binding.not_after() < now {
            return Err(KeyBindingRefused::Expired {
                not_after: binding.not_after(),
                now,
            });
        }
        Ok(DeviceId::from_identity_digest(
            blake3::hash(identity_pub.as_bytes()).as_bytes(),
        ))
    }
}

pub fn verifier_at(now: i64) -> Arc<dyn KeyBindingVerifier> {
    Arc::new(TestVerifier { now })
}

pub struct Pair {
    pub initiator_store: Arc<CountingKeyStore>,
    pub responder_store: Arc<CountingKeyStore>,
    pub rng: Arc<CounterRng>,
    pub verifier: Arc<dyn KeyBindingVerifier>,
}

impl Pair {
    pub fn new() -> Self {
        Self {
            initiator_store: Arc::new(CountingKeyStore::new(3)),
            responder_store: Arc::new(CountingKeyStore::new(5)),
            rng: Arc::new(CounterRng::new()),
            verifier: verifier_at(NOW),
        }
    }

    pub fn initiator(&self) -> Initiator {
        Initiator::new(
            Arc::clone(&self.initiator_store) as Arc<dyn KeyStore>,
            Arc::clone(&self.rng) as Arc<dyn Rng + Send + Sync>,
            Arc::clone(&self.verifier),
            self.initiator_store.binding(),
        )
        .expect("initiator builds")
    }

    pub fn responder(&self) -> Responder {
        Responder::new(
            Arc::clone(&self.responder_store) as Arc<dyn KeyStore>,
            Arc::clone(&self.rng) as Arc<dyn Rng + Send + Sync>,
            Arc::clone(&self.verifier),
            self.responder_store.binding(),
        )
        .expect("responder builds")
    }
}

pub fn handshaken_pair() -> (NoiseSession, NoiseSession) {
    let pair = Pair::new();
    let (awaiting_response, first) = pair
        .initiator()
        .write_first()
        .expect("first message written");
    let (awaiting_confirmation, second) = pair
        .responder()
        .read_first(&first)
        .expect("first message read")
        .write_second()
        .expect("second message written");
    let (initiator, third) = awaiting_response
        .read_second(&second)
        .expect("second message read")
        .write_third()
        .expect("third message written");
    let responder = awaiting_confirmation
        .read_third(&third)
        .expect("third message read");
    (initiator, responder)
}

pub struct MemorySink {
    sender: tokio::sync::Mutex<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>,
    yield_before_send: bool,
}

impl MemorySink {
    pub fn dummy() -> Arc<Self> {
        Arc::new(Self {
            sender: tokio::sync::Mutex::new(None),
            yield_before_send: false,
        })
    }
}

impl LinkSink for MemorySink {
    fn send_record<'a>(&'a self, record: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            if self.yield_before_send {
                tokio::task::yield_now().await;
            }
            let sender = {
                let guard = self.sender.lock().await;
                guard.clone()
            };
            match sender {
                Some(tx) => tx
                    .send(record.to_vec())
                    .await
                    .map_err(|_| TransportError::Closed),
                None => Err(TransportError::Closed),
            }
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move {
            let mut guard = self.sender.lock().await;
            drop(guard.take());
            Ok(())
        })
    }
}

pub struct MemorySource {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl LinkSource for MemorySource {
    fn recv_record(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        Box::pin(async move { Ok(self.receiver.recv().await) })
    }
}

/// One full-duplex endpoint: an outgoing sink and an incoming source, cross-wired to its peer
/// endpoint by `memory_link_pair` rather than looped back to itself.
pub type MemoryEndpoint = (Arc<MemorySink>, Box<MemorySource>);

pub fn memory_channel(capacity: usize, yield_before_send: bool) -> MemoryEndpoint {
    let (tx, rx) = tokio::sync::mpsc::channel(capacity);
    (
        Arc::new(MemorySink {
            sender: tokio::sync::Mutex::new(Some(tx)),
            yield_before_send,
        }),
        Box::new(MemorySource { receiver: rx }),
    )
}

pub fn memory_link_pair(
    capacity: usize,
    yield_before_send: bool,
) -> (MemoryEndpoint, MemoryEndpoint) {
    let (tx_a, rx_b) = memory_channel(capacity, yield_before_send);
    let (tx_b, rx_a) = memory_channel(capacity, yield_before_send);
    ((tx_a, rx_a), (tx_b, rx_b))
}

pub fn connected_channels(yield_before_send: bool) -> (NoiseChannel, NoiseChannel) {
    connected_channels_with_limit(BLE_GATT_MAX_FRAME_SIZE, yield_before_send)
}

pub fn connected_channels_with_limit(
    record_limit: u32,
    yield_before_send: bool,
) -> (NoiseChannel, NoiseChannel) {
    let (initiator_session, responder_session) = handshaken_pair();
    let ((sink_a, source_a), (sink_b, source_b)) = memory_link_pair(64, yield_before_send);

    let config_a = NoiseChannelConfig {
        transport: TransportId::new("ble-gatt"),
        opener: StreamOpener::Dialler,
        max_frame_size: record_limit,
        record_limit,
        rtt: Duration::from_millis(50),
    };
    let config_b = NoiseChannelConfig {
        transport: TransportId::new("ble-gatt"),
        opener: StreamOpener::Listener,
        max_frame_size: record_limit,
        record_limit,
        rtt: Duration::from_millis(50),
    };

    let chan_a = NoiseChannel::new(initiator_session, sink_a, source_a, config_a)
        .expect("initiator channel builds");
    let chan_b = NoiseChannel::new(responder_session, sink_b, source_b, config_b)
        .expect("responder channel builds");

    (chan_a, chan_b)
}

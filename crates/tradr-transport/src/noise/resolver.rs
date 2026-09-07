use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use tradr_core::{KeyStore, PublicKeyPoint, Rng};

use crate::noise::NoiseError;

// snow::Error::Dh and snow::Error::Rng carry nothing of the error underneath
// them, so the cause is kept where it happens or it is gone.
#[derive(Clone, Default)]
pub(crate) struct LocalErrorSlot(Arc<Mutex<Option<NoiseError>>>);

impl LocalErrorSlot {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    pub(crate) fn record(&self, error: NoiseError) {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.is_none() {
            *guard = Some(error);
        }
    }

    pub(crate) fn take_or_refused(&self) -> NoiseError {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.take().unwrap_or(NoiseError::Refused)
    }
}

pub(crate) struct TradrResolver {
    key_store: Arc<dyn KeyStore>,
    agreement_pub: PublicKeyPoint,
    rng: Arc<dyn Rng + Send + Sync>,
    error_slot: LocalErrorSlot,
    dh_called: AtomicBool,
    default_resolver: DefaultResolver,
}

impl TradrResolver {
    pub(crate) fn new(
        key_store: Arc<dyn KeyStore>,
        agreement_pub: PublicKeyPoint,
        rng: Arc<dyn Rng + Send + Sync>,
        error_slot: LocalErrorSlot,
    ) -> Self {
        Self {
            key_store,
            agreement_pub,
            rng,
            error_slot,
            dh_called: AtomicBool::new(false),
            default_resolver: DefaultResolver,
        }
    }
}

impl CryptoResolver for TradrResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(InjectedRng {
            rng: Arc::clone(&self.rng),
            error_slot: self.error_slot.clone(),
        }))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        if !self.dh_called.swap(true, Ordering::SeqCst) {
            if *choice == DHChoice::P256 {
                Some(Box::new(KeyStoreDh::new(
                    Arc::clone(&self.key_store),
                    self.agreement_pub.clone(),
                    self.error_slot.clone(),
                )))
            } else {
                None
            }
        } else {
            self.default_resolver.resolve_dh(choice)
        }
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        self.default_resolver.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        self.default_resolver.resolve_cipher(choice)
    }
}

struct KeyStoreDh {
    key_store: Arc<dyn KeyStore>,
    agreement_pub: PublicKeyPoint,
    error_slot: LocalErrorSlot,
}

impl KeyStoreDh {
    fn new(
        key_store: Arc<dyn KeyStore>,
        agreement_pub: PublicKeyPoint,
        error_slot: LocalErrorSlot,
    ) -> Self {
        Self {
            key_store,
            agreement_pub,
            error_slot,
        }
    }
}

impl Dh for KeyStoreDh {
    fn name(&self) -> &'static str {
        "P256"
    }

    fn pub_len(&self) -> usize {
        65
    }

    fn priv_len(&self) -> usize {
        32
    }

    fn dh_len(&self) -> usize {
        32
    }

    fn set(&mut self, _privkey: &[u8]) {}

    fn generate(&mut self, _rng: &mut dyn Random) -> Result<(), snow::Error> {
        Err(snow::Error::Dh)
    }

    fn pubkey(&self) -> &[u8] {
        self.agreement_pub.as_bytes()
    }

    fn privkey(&self) -> &[u8] {
        &[]
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
        let peer_point = match PublicKeyPoint::from_bytes(pubkey) {
            Ok(point) => point,
            Err(_) => return Err(snow::Error::Dh),
        };
        match self.key_store.agree(&peer_point) {
            Ok(shared_secret) => {
                let bytes = shared_secret.as_bytes();
                if bytes.len() != 32 || out.len() < 32 {
                    return Err(snow::Error::Dh);
                }
                out[..32].copy_from_slice(bytes);
                Ok(())
            }
            Err(err) => {
                self.error_slot.record(NoiseError::KeyStore(err));
                Err(snow::Error::Dh)
            }
        }
    }
}

struct InjectedRng {
    rng: Arc<dyn Rng + Send + Sync>,
    error_slot: LocalErrorSlot,
}

impl Random for InjectedRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        if let Err(err) = self.rng.fill_bytes(dest) {
            self.error_slot.record(NoiseError::Rng(err));
            return Err(snow::Error::Rng);
        }
        Ok(())
    }
}

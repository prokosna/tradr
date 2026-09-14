use std::sync::atomic::{AtomicU16, Ordering};
use tradr_core::Capabilities;
use tradr_discovery::DeclaredCapabilities;

/// The capability set this device currently declares (docs/03, "Capability flags").
pub struct LocalCapabilities {
    bits: AtomicU16,
}

impl LocalCapabilities {
    /// Starts from the set the composition root knows at build time.
    pub fn new(initial: Capabilities) -> Self {
        Self {
            bits: AtomicU16::new(initial.bits()),
        }
    }

    /// The set to declare in the advertisement or `Hello` being composed now.
    pub fn get(&self) -> Capabilities {
        Capabilities::from_bits(self.bits.load(Ordering::SeqCst))
    }

    /// Adds every bit in `bits`, called by the half that has just started.
    pub fn declare(&self, bits: Capabilities) {
        self.bits.fetch_or(bits.bits(), Ordering::SeqCst);
    }

    /// Clears every bit in `bits`, called by the half that has just stopped.
    pub fn withdraw(&self, bits: Capabilities) {
        self.bits.fetch_and(!bits.bits(), Ordering::SeqCst);
    }
}

impl DeclaredCapabilities for LocalCapabilities {
    fn capabilities(&self) -> Capabilities {
        self.get()
    }
}

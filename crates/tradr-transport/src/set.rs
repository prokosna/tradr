//! Keyed set of available transports for candidate dispatch (docs/03, DCR-108).

use std::collections::BTreeMap;
use std::sync::Arc;

use tradr_core::{Candidate, Transport, TransportId};

/// Keyed collection of transports available to dial candidates on this device.
pub struct TransportSet {
    transports: BTreeMap<TransportId, Arc<dyn Transport>>,
}

impl TransportSet {
    /// Builds a transport set where later entries overwrite earlier ones with the same transport identifier.
    pub fn new(transports: Vec<Arc<dyn Transport>>) -> Self {
        let mut map = BTreeMap::new();
        for transport in transports {
            map.insert(transport.id(), transport);
        }
        Self { transports: map }
    }

    /// Selects the transport capable of dialling the candidate.
    pub fn dialler(&self, candidate: &Candidate) -> Option<&dyn Transport> {
        self.transports
            .get(&candidate.transport())
            .map(|t| t.as_ref())
    }

    /// Picks the diallable candidate with the highest class weight, preserving arrival order on ties.
    pub fn best_candidate(&self, candidates: &[Candidate]) -> Option<Candidate> {
        let mut best: Option<(i32, Candidate)> = None;
        for candidate in candidates {
            if self.dialler(candidate).is_none() {
                continue;
            }
            let weight = crate::selection::class_weight(candidate.transport());
            match &best {
                None => best = Some((weight, candidate.clone())),
                Some((best_weight, _)) => {
                    if weight > *best_weight {
                        best = Some((weight, candidate.clone()));
                    }
                }
            }
        }
        best.map(|(_, c)| c)
    }
}

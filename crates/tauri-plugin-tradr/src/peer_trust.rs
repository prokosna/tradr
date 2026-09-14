//! Builds this device's PeerTrust from this build's OAuth configuration
//! and holds the outcome as managed state.

use std::sync::Arc;

use tradr_app::peer_trust::{HttpsJwksFetch, PeerTrust};
use tradr_app::sign_in::{OAuthConfig, provider_profile};

/// The outcome of building this device's `PeerTrust`, kept as managed
/// state so a clone with no configured OAuth client ids reports the error
/// on first use rather than panicking at startup.
pub struct PeerTrustState(Result<Arc<PeerTrust>, String>);

impl PeerTrustState {
    /// The device's `PeerTrust`, built once at startup.
    pub fn peer_trust(&self) -> Result<Arc<PeerTrust>, String> {
        self.0.clone()
    }
}

// Builds the Google profile the same way attestation.rs already does for
// the paste-a-bundle flow, so a live connection classifies against the
// identical provider set.
fn build_peer_trust(oauth: &OAuthConfig) -> Result<Arc<PeerTrust>, String> {
    let profile = provider_profile(oauth)?;
    Ok(Arc::new(PeerTrust::new(profile, Arc::new(HttpsJwksFetch))))
}

/// Builds the `PeerTrustState` to be managed by the app, from this
/// build's OAuth configuration.
pub(crate) fn init_peer_trust_state(oauth: &OAuthConfig) -> PeerTrustState {
    PeerTrustState(build_peer_trust(oauth))
}

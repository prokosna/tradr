//! Runs the foreground receive command: opens device identity, signs in,
//! binds QUIC, advertises on mDNS, and serves incoming transfers.

use std::path::PathBuf;
use std::sync::Arc;

pub use tradr_core::RelPath;
use tradr_core::{BoxFuture, Capabilities, Clock, RootId, Transport, TrustTier};
use tradr_identity::hello::AttestationRequest;
use tradr_identity::{LinkRegistry, OsRng, SystemClock, attestation_nonce};
use tradr_integrity::BaoVerifier;
use tradr_vfs::NativeVfs;

use crate::capabilities::LocalCapabilities;
use crate::peer_trust::{HttpsJwksFetch, PeerTrust};
use crate::sign_in::{OAuthConfig, SignInState, finish_sign_in, obtain_id_token_desktop};
use crate::{identity, listener, network, paths, sign_in};

// A fixed root identifier is safe because the command exposes only a single receive directory.
fn receive_root_id() -> RootId {
    RootId::new(1)
}

/// Runs the foreground receive command, listening for incoming transfers over QUIC.
#[allow(clippy::type_complexity)]
pub async fn run_receive(
    receive_dir: PathBuf,
    oauth: &OAuthConfig,
    on_arrival: Arc<dyn Fn(&[RelPath]) + Send + Sync>,
) -> Result<(), String> {
    let dir = paths::app_data_dir()?;
    let keys_dir = paths::device_keys_dir(&dir);
    let ladder = identity::platform_ladder(keys_dir);
    let identity = identity::open_device_identity(&ladder, &OsRng)?;
    let public_identity = identity.public_identity();

    let profile = sign_in::provider_profile(oauth)?;

    let peer_trust = Arc::new(PeerTrust::new(profile.clone(), Arc::new(HttpsJwksFetch)));

    let links_path = dir.join("links.json");
    let registry = LinkRegistry::load(&links_path)
        .map_err(|e| format!("link registry at {}: {e}", links_path.display()))?;
    let link_registry = Arc::new(std::sync::Mutex::new(registry));

    let sign_in_state = Arc::new(SignInState::empty());

    let nonce = attestation_nonce(profile.nonce_binding, &public_identity);
    eprintln!("receive: opening browser for sign-in...");
    let id_token = obtain_id_token_desktop(&profile, &nonce).await?;
    finish_sign_in(
        &profile,
        &public_identity,
        id_token,
        &peer_trust,
        &sign_in_state,
        &SystemClock,
    )
    .await?;

    let transport = network::bind_quic_transport(identity.key_store())?;
    let bound_port = transport
        .local_addr()
        .map_err(|e| format!("failed to get quic local address: {e}"))?
        .port();

    let daemon = network::mdns_daemon()?;
    let capabilities = Arc::new(LocalCapabilities::new(Capabilities::DIRECT_QUIC));
    let txt_record = network::device_txt_record(
        &public_identity,
        capabilities.get(),
        network::local_display_name(),
    )?;
    network::register_advertisement(&daemon, bound_port, &txt_record, &OsRng)?;
    eprintln!("receive: listening on quic port {bound_port}");

    std::fs::create_dir_all(&receive_dir).map_err(|e| {
        format!(
            "could not create receive directory {}: {e}",
            receive_dir.display()
        )
    })?;
    let vfs = Arc::new(NativeVfs::new());
    vfs.register_root(receive_root_id(), receive_dir.clone(), false)
        .map_err(|e| {
            format!(
                "could not register receive root {}: {e}",
                receive_dir.display()
            )
        })?;

    let verifier: Arc<
        dyn Fn(AttestationRequest) -> BoxFuture<'static, Result<TrustTier, String>> + Send + Sync,
    > = {
        let peer_trust = Arc::clone(&peer_trust);
        let sign_in_state = Arc::clone(&sign_in_state);
        let link_registry = Arc::clone(&link_registry);
        let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SystemClock);
        Arc::new(move |req: AttestationRequest| {
            sign_in::peer_verifier(
                Arc::clone(&peer_trust),
                Arc::clone(&sign_in_state),
                Arc::clone(&link_registry),
                Arc::clone(&clock),
            )(req)
        })
    };

    let incoming = transport
        .listen()
        .await
        .map_err(|e| format!("failed to listen on quic transport: {e}"))?;
    let verifier_call = {
        let verifier = Arc::clone(&verifier);
        move |req| verifier(req)
    };
    listener::run_listener(
        incoming,
        vfs,
        identity.key_store(),
        public_identity,
        sign_in_state,
        receive_root_id(),
        capabilities,
        listener::ListenerServices {
            rng: &OsRng,
            clock: &SystemClock,
            verifier: &BaoVerifier,
        },
        verifier_call,
        None,
        Some(on_arrival),
    )
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}

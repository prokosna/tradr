//! Tests for desktop peer discovery and send session compositions (WI-M8-028).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tradr_app::network::bind_quic_dialler;
use tradr_app::send_session::PeerDiscovery;
use tradr_core::{DeviceId, PeerExpectation, Transport};
use tradr_discovery::{MdnsSource, STATIC_PEER_SOURCE_ID, StaticPeerRegistry};
use tradr_identity::{OsRng, SoftwareKeyStore};
use tradr_secrets::FileStore;
use tradr_transport::quic::QuicTransport;
use tradr_transport::selection::TransferSize;
use tradr_transport::set::TransportSet;

fn setup_key_store(dir: &std::path::Path) -> Arc<SoftwareKeyStore> {
    let rung = FileStore::new(dir.join("keys"));
    let store = SoftwareKeyStore::open(&rung, "device-key", &OsRng).expect("open key store");
    Arc::new(store)
}

#[tokio::test]
async fn await_peer_resolves_a_static_peer_entry_inside_the_window() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let registry_dir = tempfile::tempdir().expect("registry tempdir");
        let registry_path = registry_dir.path().join("static-peers.json");
        let (mut registry, static_source) =
            StaticPeerRegistry::load(&registry_path).expect("load empty registry");

        let rx_dir = tempfile::tempdir().expect("rx tempdir");
        let rx_store = setup_key_store(rx_dir.path());
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
        let rx_transport = QuicTransport::new(rx_store, bind_addr).expect("rx transport");
        let rx_addr = rx_transport.local_addr().expect("local addr");

        let static_id = registry
            .add(Some("test peer"), &[rx_addr.to_string()], &OsRng)
            .expect("add static peer");

        let (_tx, rx) = flume::unbounded();
        let mdns = MdnsSource::new(rx);

        let self_id = DeviceId::from_bytes(&[0x01; 16]).expect("device id");
        let mut discovery = PeerDiscovery::from_sources(mdns, static_source, registry, self_id);

        let tx_dir = tempfile::tempdir().expect("tx tempdir");
        let tx_store = setup_key_store(tx_dir.path());
        let dialler = bind_quic_dialler(tx_store).expect("dialler transport");
        let transports = TransportSet::new(vec![dialler as Arc<dyn Transport>]);

        let peer_id = format!("{STATIC_PEER_SOURCE_ID}/{static_id}");
        let resolved = discovery
            .await_peer(
                &peer_id,
                &transports,
                TransferSize::Bytes(0),
                Duration::from_millis(200),
            )
            .await
            .expect("await_peer must resolve static peer");

        assert_eq!(resolved.expectation, PeerExpectation::Unpinned);
        assert_eq!(resolved.pin_target, Some(static_id));
        assert_eq!(resolved.candidate.address(), rx_addr.to_string());
    })
    .await
    .expect("test did not hang");
}

#[tokio::test]
async fn await_peer_answers_not_found_when_selector_is_unreported() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let registry_dir = tempfile::tempdir().expect("registry tempdir");
        let registry_path = registry_dir.path().join("static-peers.json");
        let (registry, static_source) =
            StaticPeerRegistry::load(&registry_path).expect("load empty registry");

        let (_tx, rx) = flume::unbounded();
        let mdns = MdnsSource::new(rx);

        let self_id = DeviceId::from_bytes(&[0x01; 16]).expect("device id");
        let mut discovery = PeerDiscovery::from_sources(mdns, static_source, registry, self_id);

        let tx_dir = tempfile::tempdir().expect("tx tempdir");
        let tx_store = setup_key_store(tx_dir.path());
        let dialler = bind_quic_dialler(tx_store).expect("dialler transport");
        let transports = TransportSet::new(vec![dialler as Arc<dyn Transport>]);

        let unknown_id = "nonexistent-peer-id";
        let result = discovery
            .await_peer(
                unknown_id,
                &transports,
                TransferSize::Bytes(0),
                Duration::from_millis(50),
            )
            .await;

        let err = result.expect_err("unknown selector must fail");
        assert_eq!(err, format!("peer with id {unknown_id} not found"));
        assert!(!err.to_lowercase().contains("timed out"));
    })
    .await
    .expect("test did not hang");
}

#[tokio::test]
async fn await_peer_answers_candidate_refusal_when_candidate_cannot_be_dialed() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let registry_dir = tempfile::tempdir().expect("registry tempdir");
        let registry_path = registry_dir.path().join("static-peers.json");
        let (mut registry, static_source) =
            StaticPeerRegistry::load(&registry_path).expect("load empty registry");

        let static_id = registry
            .add(
                Some("undialable peer"),
                &["127.0.0.1:21820".to_string()],
                &OsRng,
            )
            .expect("add static peer");

        let (_tx, rx) = flume::unbounded();
        let mdns = MdnsSource::new(rx);

        let self_id = DeviceId::from_bytes(&[0x01; 16]).expect("device id");
        let mut discovery = PeerDiscovery::from_sources(mdns, static_source, registry, self_id);

        let empty_transports = TransportSet::new(vec![]);

        let peer_id = format!("{STATIC_PEER_SOURCE_ID}/{static_id}");
        let result = discovery
            .await_peer(
                &peer_id,
                &empty_transports,
                TransferSize::Bytes(0),
                Duration::from_millis(50),
            )
            .await;

        let err = result.expect_err("undialable candidate must fail");
        assert_eq!(
            err,
            format!("no candidate for peer {peer_id} that this device can dial")
        );
        assert_ne!(err, format!("peer with id {peer_id} not found"));
    })
    .await
    .expect("test did not hang");
}

#[tokio::test]
async fn collect_answers_static_peer_entry_with_observation_id_key() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let registry_dir = tempfile::tempdir().expect("registry tempdir");
        let registry_path = registry_dir.path().join("static-peers.json");
        let (mut registry, static_source) =
            StaticPeerRegistry::load(&registry_path).expect("load empty registry");

        let static_id = registry
            .add(
                Some("pinned later"),
                &["127.0.0.1:21820".to_string()],
                &OsRng,
            )
            .expect("add static peer");

        let (_tx, rx) = flume::unbounded();
        let mdns = MdnsSource::new(rx);

        let self_id = DeviceId::from_bytes(&[0x01; 16]).expect("device id");
        let mut discovery = PeerDiscovery::from_sources(mdns, static_source, registry, self_id);

        let peers = discovery
            .collect(Duration::from_millis(50))
            .await
            .expect("collect must succeed");

        assert_eq!(peers.len(), 1);
        let expected_key = format!("{STATIC_PEER_SOURCE_ID}/{static_id}");
        assert_eq!(peers[0].key, expected_key);
        assert_eq!(peers[0].device_id, "");
        assert_eq!(peers[0].display_name.as_deref(), Some("pinned later"));
        assert_eq!(peers[0].addresses, vec!["127.0.0.1:21820"]);
        assert_eq!(peers[0].sources, vec!["static-peer"]);
    })
    .await
    .expect("test did not hang");
}

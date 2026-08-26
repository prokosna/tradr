//! `tradr_core::SendStream` and `RecvStream` over `quinn`'s. Constructed
//! only from within this crate: `WI-M1-004d`'s `SecureChannel` is the
//! first caller. Neither type names a `quinn` type in a public signature.

use tradr_core::{BoxFuture, RecvStream, SendStream, TransportError};

use super::error::{map_read_error, map_write_error};

// `tradr_core::SendStream` over `quinn::SendStream`.
pub(crate) struct QuicSendStream {
    inner: quinn::SendStream,
}

impl QuicSendStream {
    pub(crate) fn new(inner: quinn::SendStream) -> Self {
        Self { inner }
    }
}

impl SendStream for QuicSendStream {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move { self.inner.write_all(buf).await.map_err(map_write_error) })
    }

    fn finish<'a>(&'a mut self) -> BoxFuture<'a, Result<(), TransportError>> {
        // quinn's `finish` is synchronous (fact #3); the future exists
        // only to satisfy Layer 1's signature.
        Box::pin(async move { self.inner.finish().map_err(|_| TransportError::Closed) })
    }
}

// `tradr_core::RecvStream` over `quinn::RecvStream`.
pub(crate) struct QuicRecvStream {
    inner: quinn::RecvStream,
}

impl QuicRecvStream {
    pub(crate) fn new(inner: quinn::RecvStream) -> Self {
        Self { inner }
    }
}

impl RecvStream for QuicRecvStream {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize, TransportError>> {
        Box::pin(async move {
            match self.inner.read(buf).await {
                Ok(Some(n)) => Ok(n),
                // quinn's `Ok(None)` is Layer 1's `Ok(0)` (fact #2): both
                // mean the peer has finished writing.
                Ok(None) => Ok(0),
                Err(e) => Err(map_read_error(e)),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::{PublicKey, SecretKey};
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use tradr_core::{
        Backing, DeviceId, DomainTag, KeyStore, KeyStoreError, PeerExpectation, PublicIdentity,
        PublicKeyPoint, SharedSecret, Signature, SoftwareReason,
    };

    use super::*;
    use crate::tls;

    // Copied from `tests/mutual_tls.rs` (a Supervisor-authored Critical
    // Module file this Work Item may not edit): a `KeyStore` over fixed
    // P-256 scalars, so a config can be built without `tradr-identity`,
    // which `ci/layer-deps.sh` forbids this crate to depend on.
    #[derive(Debug)]
    struct TestKeyStore {
        identity_key: SigningKey,
        agreement_key: SecretKey,
    }

    impl TestKeyStore {
        fn with_scalars(identity: [u8; 32], agreement: [u8; 32]) -> Self {
            Self {
                identity_key: SigningKey::from_slice(&identity)
                    .expect("a fixed valid P-256 scalar"),
                agreement_key: SecretKey::from_slice(&agreement)
                    .expect("a fixed valid P-256 scalar"),
            }
        }

        fn identity_point(&self) -> PublicKeyPoint {
            let point = self.identity_key.verifying_key().to_encoded_point(false);
            PublicKeyPoint::from_bytes(point.as_bytes()).expect("p256 writes 65 bytes uncompressed")
        }
    }

    impl KeyStore for TestKeyStore {
        fn public_identity(&self) -> Result<PublicIdentity, KeyStoreError> {
            let agreement_point = self.agreement_key.public_key().to_encoded_point(false);
            let agreement_pub = PublicKeyPoint::from_bytes(agreement_point.as_bytes())
                .expect("p256 writes 65 bytes uncompressed");
            Ok(PublicIdentity::new(
                self.identity_point(),
                agreement_pub,
                DeviceId::from_identity_digest(
                    blake3::hash(self.identity_point().as_bytes()).as_bytes(),
                ),
            ))
        }

        fn sign(&self, domain: DomainTag, message: &[u8]) -> Result<Signature, KeyStoreError> {
            use p256::ecdsa::signature::Signer;
            let payload = domain
                .payload(message)
                .map_err(KeyStoreError::DomainSeparation)?;
            let raw: p256::ecdsa::Signature = self
                .identity_key
                .try_sign(payload.as_ref())
                .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;
            let normalized = raw.normalize_s().unwrap_or(raw);
            Ok(Signature::from_bytes(normalized.to_bytes().to_vec()))
        }

        fn agree(&self, peer_public: &PublicKeyPoint) -> Result<SharedSecret, KeyStoreError> {
            let peer = PublicKey::from_sec1_bytes(peer_public.as_bytes())
                .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;
            let shared = p256::ecdh::diffie_hellman(
                self.agreement_key.to_nonzero_scalar(),
                peer.as_affine(),
            );
            Ok(SharedSecret::from_bytes(shared.raw_secret_bytes().to_vec()))
        }

        fn backing(&self) -> Backing {
            Backing::Software(SoftwareReason::PlatformHasNoSecureElement)
        }
    }

    fn device(seed: u8) -> Arc<TestKeyStore> {
        Arc::new(TestKeyStore::with_scalars(
            [seed; 32],
            [seed.wrapping_add(0x40); 32],
        ))
    }

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    const SERVER_NAME: &str = "tradr.invalid";

    // Binds and configures a listening endpoint before any dial is
    // attempted, so "not listening yet" is impossible by construction.
    fn server_endpoint(key_store: Arc<dyn KeyStore>) -> (quinn::Endpoint, SocketAddr) {
        let rustls_config = tls::server_config(key_store).expect("a working store configures");
        let quic_crypto =
            QuicServerConfig::try_from(rustls_config).expect("TLS 1.3 only is compatible");
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let endpoint = quinn::Endpoint::server(server_config, bind).expect("loopback binds");
        let addr = endpoint
            .local_addr()
            .expect("a bound endpoint reports its address");
        (endpoint, addr)
    }

    fn client_endpoint() -> quinn::Endpoint {
        let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        quinn::Endpoint::client(bind).expect("loopback binds")
    }

    // Drives both sides of a real loopback handshake to completion. Each
    // endpoint's driver task is spawned onto the tokio runtime already,
    // so awaiting both sides concurrently is enough; nothing here sleeps.
    async fn connected_pair(
        dialler: Arc<TestKeyStore>,
        listener: Arc<TestKeyStore>,
    ) -> (quinn::Connection, quinn::Connection) {
        let (server, addr) = server_endpoint(listener);
        let client = client_endpoint();

        let rustls_client = tls::client_config(dialler, PeerExpectation::Unpinned)
            .expect("a working store configures");
        let quic_client_crypto =
            QuicClientConfig::try_from(rustls_client).expect("TLS 1.3 only is compatible");
        let client_config = quinn::ClientConfig::new(Arc::new(quic_client_crypto));

        let connecting = client
            .connect_with(client_config, addr, SERVER_NAME)
            .expect("a valid config dials");

        let dial = async { connecting.await.expect("handshake completes") };
        let accept = async {
            let incoming = server.accept().await.expect("the dial arrives");
            incoming
                .accept()
                .expect("a well-formed Initial")
                .await
                .expect("handshake completes")
        };

        tokio::join!(dial, accept)
    }

    #[tokio::test]
    async fn a_bidirectional_stream_carries_bytes_both_ways() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (client_conn, server_conn) = connected_pair(device(0x11), device(0x22)).await;

            let (client_send, client_recv) = client_conn
                .open_bi()
                .await
                .expect("credit is available up front");
            let mut client_send = QuicSendStream::new(client_send);
            let mut client_recv = QuicRecvStream::new(client_recv);
            client_send
                .write_all(b"ping")
                .await
                .expect("the peer is listening");

            let (server_send, server_recv) = server_conn
                .accept_bi()
                .await
                .expect("the client opened one");
            let mut server_send = QuicSendStream::new(server_send);
            let mut server_recv = QuicRecvStream::new(server_recv);

            let mut received = [0u8; 4];
            let mut read = 0;
            while read < received.len() {
                let n = server_recv
                    .read(&mut received[read..])
                    .await
                    .expect("the client is still writing");
                assert_ne!(n, 0, "the client closed before sending everything");
                read += n;
            }
            assert_eq!(&received, b"ping");

            server_send
                .write_all(b"pong")
                .await
                .expect("the client is still reading");

            let mut received = [0u8; 4];
            let mut read = 0;
            while read < received.len() {
                let n = client_recv
                    .read(&mut received[read..])
                    .await
                    .expect("the server is still writing");
                assert_ne!(n, 0, "the server closed before sending everything");
                read += n;
            }
            assert_eq!(&received, b"pong");
        })
        .await
        .expect("a loopback handshake completes well inside the bound");
    }

    #[tokio::test]
    async fn a_reader_sees_a_clean_end_of_stream_as_ok_zero() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (client_conn, server_conn) = connected_pair(device(0x11), device(0x22)).await;

            let mut send =
                QuicSendStream::new(client_conn.open_uni().await.expect("credit is available"));
            send.write_all(b"done")
                .await
                .expect("the peer is listening");
            send.finish().await.expect("closing the send half succeeds");

            // Only awaited once the stream's data is already in flight
            // (rule E3): the server's driver has something to accept.
            let mut recv = QuicRecvStream::new(
                server_conn
                    .accept_uni()
                    .await
                    .expect("the client opened one"),
            );

            let mut received = [0u8; 4];
            let mut read = 0;
            while read < received.len() {
                let n = recv
                    .read(&mut received[read..])
                    .await
                    .expect("data before the end");
                read += n;
            }

            let after_end = recv
                .read(&mut received)
                .await
                .expect("a clean end of stream is not an error");
            assert_eq!(after_end, 0, "quinn's Ok(None) must surface as Ok(0)");
        })
        .await
        .expect("a loopback handshake completes well inside the bound");
    }

    #[tokio::test]
    async fn writing_after_the_peer_closes_the_connection_yields_closed() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let (client_conn, server_conn) = connected_pair(device(0x11), device(0x22)).await;

            let mut send =
                QuicSendStream::new(client_conn.open_uni().await.expect("credit is available"));

            server_conn.close(0u32.into(), b"done with you");
            client_conn.closed().await;

            let result = send.write_all(b"still writing").await;
            assert_eq!(result, Err(TransportError::Closed));
        })
        .await
        .expect("a loopback handshake completes well inside the bound");
    }
}

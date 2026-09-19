//! `Transport` and `Incoming` over `quinn` (docs/03's `direct-quic`). The
//! only file in the crate that builds or holds a `quinn::Endpoint`.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use socket2::{Domain, Protocol, Socket, Type};
use tradr_core::{
    BoxFuture, Candidate, Incoming, KeyStore, PeerExpectation, SecureChannel, Transport,
    TransportError, TransportId,
};

use super::channel::QuicChannel;
use super::error::{map_connect_error, map_connection_error};
use crate::tls::{self, TlsError};

// The name docs/03's transport table gives `direct-quic`.
const TRANSPORT_ID: TransportId = TransportId::new("direct-quic");

// The name a QUIC dialler has to supply and this design never reads:
// identity lives in the SubjectPublicKeyInfo (DCR-038), so the verifier
// this crate installs ignores it and nothing may depend on its value.
const SERVER_NAME: &str = "tradr.invalid";

/// An error building a `QuicTransport`. Never names a `quinn` type: Change
/// Drill D3 confines a `quinn` swap to this directory alone, and a type
/// in this signature would reach outside it.
#[derive(Debug)]
pub enum QuicTransportError {
    /// The `KeyStore` or certificate could not build a TLS config.
    Tls(TlsError),
    /// The local UDP socket could not be bound, or the TLS config could
    /// not be converted into quinn's own representation.
    Io(std::io::Error),
}

impl fmt::Display for QuicTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls(e) => write!(f, "tls configuration error: {e}"),
            Self::Io(e) => write!(f, "quic transport io error: {e}"),
        }
    }
}

impl std::error::Error for QuicTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Tls(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}

fn dual_stack_udp_socket(bind: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    // IPV6_V6ONLY defaults disagree across platforms, so dual-stack is explicitly enabled here (docs/03, DCR-138).
    socket.set_only_v6(false)?;
    socket.bind(&socket2::SockAddr::from(bind))?;
    Ok(socket.into())
}

/// `direct-quic`: a `quinn::Endpoint` that both dials and listens, backed
/// by the device's `KeyStore`.
pub struct QuicTransport {
    key_store: Arc<dyn KeyStore>,
    endpoint: quinn::Endpoint,
}

impl QuicTransport {
    /// Binds `bind` and configures the endpoint from `key_store`'s
    /// certificate, so it can both accept and dial from the moment it
    /// returns.
    pub fn new(key_store: Arc<dyn KeyStore>, bind: SocketAddr) -> Result<Self, QuicTransportError> {
        let rustls_config =
            tls::server_config(key_store.clone()).map_err(QuicTransportError::Tls)?;
        // Unreachable in practice: `rustls_config` is always restricted to
        // TLS 1.3 (see `tls::server_config`), which is exactly what this
        // conversion requires. Handled rather than `expect`ed (rule F5).
        let quic_crypto = QuicServerConfig::try_from(rustls_config).map_err(|_| {
            QuicTransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid TLS config",
            ))
        })?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        let endpoint = match bind {
            SocketAddr::V6(_) => {
                let std_socket = dual_stack_udp_socket(bind).map_err(QuicTransportError::Io)?;
                let runtime = quinn::default_runtime().ok_or_else(|| {
                    QuicTransportError::Io(std::io::Error::other("no async runtime found"))
                })?;
                quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(server_config),
                    std_socket,
                    runtime,
                )
                .map_err(QuicTransportError::Io)?
            }
            SocketAddr::V4(_) => {
                quinn::Endpoint::server(server_config, bind).map_err(QuicTransportError::Io)?
            }
        };
        Ok(Self {
            key_store,
            endpoint,
        })
    }

    /// Returns the local socket address this transport's endpoint is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.endpoint.local_addr()
    }
}

impl Transport for QuicTransport {
    fn id(&self) -> TransportId {
        TRANSPORT_ID
    }

    fn connect<'a>(
        &'a self,
        candidate: &'a Candidate,
        expect: &'a PeerExpectation,
    ) -> BoxFuture<'a, Result<Box<dyn SecureChannel>, TransportError>> {
        Box::pin(async move {
            let addr: SocketAddr = match candidate.address().parse() {
                Ok(addr) => addr,
                Err(_) => resolve(&self.endpoint, candidate.address()).await?,
            };

            // Building this config only fails on a local `KeyStore` or
            // crypto-conversion problem, decided before any packet leaves
            // (docs/03, "`Unreachable` is a local verdict").
            let rustls_client = tls::client_config(self.key_store.clone(), expect.clone())
                .map_err(|_| TransportError::Unreachable)?;
            let quic_client_crypto = QuicClientConfig::try_from(rustls_client)
                .map_err(|_| TransportError::Unreachable)?;
            let client_config = quinn::ClientConfig::new(Arc::new(quic_client_crypto));

            let connecting = self
                .endpoint
                .connect_with(client_config, addr, SERVER_NAME)
                .map_err(map_connect_error)?;
            let connection = connecting.await.map_err(map_connection_error)?;

            let channel = QuicChannel::new(connection, TRANSPORT_ID)?;
            Ok(Box::new(channel) as Box<dyn SecureChannel>)
        })
    }

    fn listen(&self) -> BoxFuture<'_, Result<Box<dyn Incoming>, TransportError>> {
        let endpoint = self.endpoint.clone();
        Box::pin(async move { Ok(Box::new(QuicIncoming { endpoint }) as Box<dyn Incoming>) })
    }
}

// Resolves a candidate that failed to parse as a literal `SocketAddr`
// (docs/03, "How `direct-quic` turns a candidate into an address"): the
// system resolver, filtered to the family this endpoint's own bound
// address can dial, taking the first survivor in the resolver's order.
// Nothing is cached here; the system resolver already owns that cache.
async fn resolve(endpoint: &quinn::Endpoint, address: &str) -> Result<SocketAddr, TransportError> {
    let resolved = tokio::net::lookup_host(address)
        .await
        .map_err(|_| TransportError::Unreachable)?;
    let local = endpoint
        .local_addr()
        .map_err(|_| TransportError::Unreachable)?;
    first_dialable(local, resolved).ok_or(TransportError::Unreachable)
}

// docs/03, "How `direct-quic` turns a candidate into an address": an
// IPv6-bound local address dials either family, an IPv4-bound one dials
// IPv4 only. Pure and synchronous, unlike `resolve`, so the family rule
// is falsifiable by a test that never touches a resolver or a socket.
fn first_dialable(
    local: SocketAddr,
    mut resolved: impl Iterator<Item = SocketAddr>,
) -> Option<SocketAddr> {
    let dials_both_families = matches!(local, SocketAddr::V6(_));
    resolved.find(|addr| dials_both_families || addr.is_ipv4())
}

// The listening half of a `QuicTransport`: a clone of its `Endpoint`,
// used only to accept.
struct QuicIncoming {
    endpoint: quinn::Endpoint,
}

impl Incoming for QuicIncoming {
    fn accept(&mut self) -> BoxFuture<'_, Result<Box<dyn SecureChannel>, TransportError>> {
        Box::pin(async move {
            loop {
                // A closed endpoint yields `None` here rather than an error
                // (docs/03), so that is the one case mapped by hand.
                let incoming = self.endpoint.accept().await.ok_or(TransportError::Closed)?;
                let remote_address = incoming.remote_address();
                let connection = match incoming.await {
                    Ok(connection) => connection,
                    Err(err) => {
                        eprintln!("direct-quic handshake failed for {remote_address}: {err}");
                        continue;
                    }
                };
                match QuicChannel::new(connection, TRANSPORT_ID) {
                    Ok(channel) => return Ok(Box::new(channel) as Box<dyn SecureChannel>),
                    Err(err) => {
                        eprintln!(
                            "direct-quic channel creation failed for {remote_address}: {err}"
                        );
                        continue;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("a fixed literal address in a test")
    }

    fn v4_local() -> SocketAddr {
        addr("0.0.0.0:0")
    }

    fn v6_local() -> SocketAddr {
        addr("[::]:0")
    }

    #[test]
    fn an_ipv4_bound_endpoint_skips_a_leading_ipv6_answer() {
        let resolved = vec![addr("[2001:db8::1]:9"), addr("192.0.2.1:9")];

        assert_eq!(
            first_dialable(v4_local(), resolved.into_iter()),
            Some(addr("192.0.2.1:9"))
        );
    }

    #[test]
    fn an_ipv4_bound_endpoint_given_only_ipv6_answers_dials_nothing() {
        let resolved = vec![addr("[2001:db8::1]:9"), addr("[2001:db8::2]:9")];

        assert_eq!(first_dialable(v4_local(), resolved.into_iter()), None);
    }

    #[test]
    fn an_ipv6_bound_endpoint_takes_the_leading_ipv6_answer() {
        let resolved = vec![addr("[2001:db8::1]:9"), addr("192.0.2.1:9")];

        assert_eq!(
            first_dialable(v6_local(), resolved.into_iter()),
            Some(addr("[2001:db8::1]:9"))
        );
    }

    #[test]
    fn an_ipv6_bound_endpoint_takes_a_leading_ipv4_answer_too() {
        let resolved = vec![addr("192.0.2.1:9"), addr("[2001:db8::1]:9")];

        assert_eq!(
            first_dialable(v6_local(), resolved.into_iter()),
            Some(addr("192.0.2.1:9"))
        );
    }

    #[test]
    fn an_empty_answer_dials_nothing() {
        assert_eq!(first_dialable(v4_local(), std::iter::empty()), None);
    }

    #[test]
    fn the_resolvers_order_is_kept_and_never_sorted() {
        let resolved = vec![addr("192.0.2.1:9"), addr("192.0.2.2:9")];

        assert_eq!(
            first_dialable(v4_local(), resolved.into_iter()),
            Some(addr("192.0.2.1:9"))
        );
    }

    use std::time::Duration;

    use crate::test_support::device;

    #[test]
    fn dual_stack_socket_has_v6only_disabled() {
        let bind: SocketAddr = "[::]:0".parse().expect("valid address literal");
        let socket = dual_stack_udp_socket(bind).expect("dual-stack socket binds");
        assert!(matches!(
            socket2::SockRef::from(&socket).only_v6(),
            Ok(false)
        ));
    }

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn binds_ipv6_endpoint_through_production_path() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let key_store = device(0x11);
            let bind: SocketAddr = "[::]:0".parse().expect("valid address literal");
            let transport = QuicTransport::new(key_store, bind).expect("production bind succeeds");
            let local = transport.local_addr().expect("reports local address");
            assert!(local.is_ipv6());
        })
        .await
        .expect("production bind completes within timeout");
    }

    #[tokio::test]
    async fn endpoint_bound_to_ipv6_wildcard_accepts_ipv4_loopback_connection() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let server_store = device(0x22);
            let server_bind: SocketAddr = "[::]:0".parse().expect("valid address literal");
            let server_transport =
                QuicTransport::new(server_store, server_bind).expect("server binds");
            let server_port = server_transport.local_addr().expect("local addr").port();
            let mut incoming = server_transport.listen().await.expect("listen succeeds");

            let client_store = device(0x11);
            let client_bind: SocketAddr = "127.0.0.1:0".parse().expect("valid address literal");
            let client_transport =
                QuicTransport::new(client_store, client_bind).expect("client binds");

            let candidate = Candidate::new(TRANSPORT_ID, &format!("127.0.0.1:{server_port}"))
                .expect("valid candidate");
            let dial = client_transport.connect(&candidate, &PeerExpectation::Unpinned);
            let accept = incoming.accept();

            let (dial_res, accept_res) = tokio::join!(dial, accept);
            assert!(dial_res.is_ok(), "dial must succeed: {:?}", dial_res.err());
            assert!(
                accept_res.is_ok(),
                "accept must succeed: {:?}",
                accept_res.err()
            );
        })
        .await
        .expect("handshake completed within timeout");
    }

    #[tokio::test]
    async fn endpoint_bound_to_ipv6_wildcard_accepts_ipv6_loopback_connection() {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let server_store = device(0x22);
            let server_bind: SocketAddr = "[::]:0".parse().expect("valid address literal");
            let server_transport =
                QuicTransport::new(server_store, server_bind).expect("server binds");
            let server_port = server_transport.local_addr().expect("local addr").port();
            let mut incoming = server_transport.listen().await.expect("listen succeeds");

            let client_store = device(0x11);
            let client_bind: SocketAddr = "[::1]:0".parse().expect("valid address literal");
            let client_transport =
                QuicTransport::new(client_store, client_bind).expect("client binds");

            let candidate = Candidate::new(TRANSPORT_ID, &format!("[::1]:{server_port}"))
                .expect("valid candidate");
            let dial = client_transport.connect(&candidate, &PeerExpectation::Unpinned);
            let accept = incoming.accept();

            let (dial_res, accept_res) = tokio::join!(dial, accept);
            assert!(dial_res.is_ok(), "dial must succeed: {:?}", dial_res.err());
            assert!(
                accept_res.is_ok(),
                "accept must succeed: {:?}",
                accept_res.err()
            );
        })
        .await
        .expect("handshake completed within timeout");
    }
}

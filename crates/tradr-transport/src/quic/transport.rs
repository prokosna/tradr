//! `Transport` and `Incoming` over `quinn` (docs/03's `direct-quic`). The
//! only file in the crate that builds or holds a `quinn::Endpoint`.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
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
        let endpoint =
            quinn::Endpoint::server(server_config, bind).map_err(QuicTransportError::Io)?;
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
            // DF-21: DNS resolution is out of scope, so anything besides a
            // literal socket address is unreachable by this transport.
            let addr: SocketAddr = candidate
                .address()
                .parse()
                .map_err(|_| TransportError::Unreachable)?;

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

// The listening half of a `QuicTransport`: a clone of its `Endpoint`,
// used only to accept.
struct QuicIncoming {
    endpoint: quinn::Endpoint,
}

impl Incoming for QuicIncoming {
    fn accept(&mut self) -> BoxFuture<'_, Result<Box<dyn SecureChannel>, TransportError>> {
        Box::pin(async move {
            // A closed endpoint yields `None` here rather than an error
            // (docs/03), so that is the one case mapped by hand.
            let incoming = self.endpoint.accept().await.ok_or(TransportError::Closed)?;
            let connection = incoming.await.map_err(map_connection_error)?;
            let channel = QuicChannel::new(connection, TRANSPORT_ID)?;
            Ok(Box::new(channel) as Box<dyn SecureChannel>)
        })
    }
}

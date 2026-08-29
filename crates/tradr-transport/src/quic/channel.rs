//! `tradr_core::SecureChannel` over a `quinn::Connection` (WI-M1-004d).
//! `direct-quic` gets its security from QUIC's own TLS 1.3 (docs/03, "A
//! transport delivers an already-secure channel"), so this wraps an
//! already-authenticated connection rather than layering anything on it.

use std::time::Duration;

use rustls::pki_types::CertificateDer;
use tradr_core::{
    BoxFuture, DeviceId, RecvStream, SecureChannel, SendStream, TransportError, TransportId,
};

use super::error::map_connection_error;
use super::stream::{QuicRecvStream, QuicSendStream};
use crate::tls;

// docs/04-protocol.md, "Framing": the default `max_frame_size` negotiated
// in `Hello`. Not `Connection::max_datagram_size()`, which reports a
// wholly different, path-MTU-bound quantity (about 1024 * 1024 on loopback).
const MAX_FRAME_SIZE_BYTES: u32 = 1024 * 1024;

// `tradr_core::SecureChannel` over `quinn::Connection`.
pub(crate) struct QuicChannel {
    connection: quinn::Connection,
    transport: TransportId,
    peer: DeviceId,
}

impl QuicChannel {
    // Derives the peer's `DeviceId` once, here, so `SecureChannel::peer`'s
    // promise that it cannot fail holds: a connection this cannot derive
    // it from never becomes a `QuicChannel`.
    pub(crate) fn new(
        connection: quinn::Connection,
        transport: TransportId,
    ) -> Result<Self, TransportError> {
        let identity = connection
            .peer_identity()
            .ok_or(TransportError::AuthenticationFailed)?;
        let certificates = identity
            .downcast::<Vec<CertificateDer<'static>>>()
            .map_err(|_| TransportError::AuthenticationFailed)?;
        let certificate = certificates
            .first()
            .ok_or(TransportError::AuthenticationFailed)?;
        let peer =
            tls::peer_device_id(certificate).map_err(|_| TransportError::AuthenticationFailed)?;
        Ok(Self {
            connection,
            transport,
            peer,
        })
    }
}

impl SecureChannel for QuicChannel {
    fn peer(&self) -> DeviceId {
        self.peer
    }

    fn transport(&self) -> TransportId {
        self.transport
    }

    fn rtt(&self) -> Duration {
        self.connection.rtt()
    }

    fn max_frame_size(&self) -> u32 {
        MAX_FRAME_SIZE_BYTES
    }

    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Box<dyn SendStream>, Box<dyn RecvStream>), TransportError>> {
        Box::pin(async move {
            let (send, recv) = self
                .connection
                .open_bi()
                .await
                .map_err(map_connection_error)?;
            Ok((
                Box::new(QuicSendStream::new(send)) as Box<dyn SendStream>,
                Box::new(QuicRecvStream::new(recv)) as Box<dyn RecvStream>,
            ))
        })
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<Box<dyn SendStream>, TransportError>> {
        Box::pin(async move {
            let send = self
                .connection
                .open_uni()
                .await
                .map_err(map_connection_error)?;
            Ok(Box::new(QuicSendStream::new(send)) as Box<dyn SendStream>)
        })
    }

    fn accept_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Box<dyn SendStream>, Box<dyn RecvStream>), TransportError>> {
        Box::pin(async move {
            let (send, recv) = self
                .connection
                .accept_bi()
                .await
                .map_err(map_connection_error)?;
            Ok((
                Box::new(QuicSendStream::new(send)) as Box<dyn SendStream>,
                Box::new(QuicRecvStream::new(recv)) as Box<dyn RecvStream>,
            ))
        })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<Box<dyn RecvStream>, TransportError>> {
        Box::pin(async move {
            let recv = self
                .connection
                .accept_uni()
                .await
                .map_err(map_connection_error)?;
            Ok(Box::new(QuicRecvStream::new(recv)) as Box<dyn RecvStream>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move {
            self.connection.close(0u32.into(), b"");
            Ok(())
        })
    }
}

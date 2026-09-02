//! Drives the 4-step Hello exchange over bidirectional transport streams
//! (docs/04-protocol.md, "The Hello exchange"). Bridges tradr-identity's state
//! machine, tradr-proto's framing codec, and tradr-core's stream traits.

use std::future::Future;

use tradr_core::{
    Capabilities, Clock, DeviceId, KeyBinding, KeyStore, KeyStoreError, PeerHello, PublicIdentity,
    RecvStream, Rng, RngError, SendStream, TransportError, TrustTier, VersionRange,
};
use tradr_identity::hello::{AttestationRequest, AwaitingPeerHello, HelloRefused, Session, open};
use tradr_proto::framing::{Frame, FrameDecoder};
use tradr_proto::hello::{
    HelloFrameError, decode_hello_ack_frame, decode_hello_frame, encode_hello_ack_frame,
    encode_hello_frame,
};

/// Errors that can occur during the 4-step Hello handshake.
#[derive(Debug)]
pub enum HandshakeError {
    /// Random number generator failure while generating a nonce.
    Rng(RngError),
    /// Protocol framing, encoding, or decoding error.
    Proto(HelloFrameError),
    /// Transport error while performing stream I/O.
    Transport(TransportError),
    /// The stream reached end-of-file before the handshake completed.
    UnexpectedEof,
    /// Protocol validation refused the peer's message.
    Refused(HelloRefused),
    /// Attestation verification rejected the token.
    Attestation(String),
    /// Key store failure while signing the peer's nonce.
    KeyStore(KeyStoreError),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rng(e) => write!(f, "rng error: {e}"),
            Self::Proto(e) => write!(f, "proto error: {e}"),
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::UnexpectedEof => write!(f, "unexpected eof during handshake"),
            Self::Refused(e) => write!(f, "handshake refused: {e}"),
            Self::Attestation(msg) => write!(f, "attestation verification failed: {msg}"),
            Self::KeyStore(e) => write!(f, "key store error: {e}"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rng(e) => Some(e),
            Self::Proto(e) => Some(e),
            Self::Transport(e) => Some(e),
            Self::UnexpectedEof => None,
            Self::Refused(e) => Some(e),
            Self::Attestation(_) => None,
            Self::KeyStore(e) => Some(e),
        }
    }
}

// Feeds incoming stream bytes into the decoder until a complete frame is available.
async fn read_frame(
    recv_stream: &mut dyn RecvStream,
    decoder: &mut FrameDecoder,
) -> Result<Frame, HandshakeError> {
    let mut buf = [0u8; 4096];
    loop {
        if let Some(frame) = decoder
            .next_frame()
            .map_err(HelloFrameError::Framing)
            .map_err(HandshakeError::Proto)?
        {
            return Ok(frame);
        }
        let n = recv_stream
            .read(&mut buf)
            .await
            .map_err(HandshakeError::Transport)?;
        if n == 0 {
            if let Some(frame) = decoder
                .next_frame()
                .map_err(HelloFrameError::Framing)
                .map_err(HandshakeError::Proto)?
            {
                return Ok(frame);
            }
            return Err(HandshakeError::UnexpectedEof);
        }
        decoder.feed(&buf[..n]);
    }
}

/// Parameters for driving the Hello handshake over a transport stream.
pub struct HandshakeParams<'a> {
    /// The peer's DeviceId authenticated at the transport layer.
    pub authenticated_peer: DeviceId,
    /// Our channel's maximum frame size.
    pub our_channel_max_frame_size: u32,
    /// Our public identity (identity_pub and agreement_pub).
    pub our_identity: &'a PublicIdentity,
    /// Our OIDC provider-signed ID token.
    pub our_attestation_token: String,
    /// Our key binding linking agreement key to identity key.
    pub our_key_binding: KeyBinding,
    /// Supported protocol version range.
    pub our_versions: VersionRange,
    /// Supported transport and plane capabilities.
    pub our_capabilities: Capabilities,
}

/// Drives the 4-step Hello handshake across a pair of send and receive streams.
pub async fn perform_handshake<F, Fut>(
    send_stream: &mut dyn SendStream,
    recv_stream: &mut dyn RecvStream,
    params: HandshakeParams<'_>,
    key_store: &(dyn KeyStore + Sync),
    rng: &(dyn Rng + Sync),
    clock: &(dyn Clock + Sync),
    verify_attestation: F,
) -> Result<Session, HandshakeError>
where
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    let (awaiting_peer_hello, our_hello) = open(
        rng,
        params.our_versions,
        params.our_identity,
        params.our_attestation_token,
        params.our_key_binding,
        params.our_capabilities,
    )
    .map_err(HandshakeError::Rng)?;

    let frame_bytes = encode_hello_frame(&our_hello, params.our_channel_max_frame_size)
        .map_err(HandshakeError::Proto)?;
    send_stream
        .write_all(&frame_bytes)
        .await
        .map_err(HandshakeError::Transport)?;

    let mut decoder = FrameDecoder::new(params.our_channel_max_frame_size);
    let frame = read_frame(recv_stream, &mut decoder).await?;
    let peer_hello = decode_hello_frame(&frame).map_err(HandshakeError::Proto)?;

    continue_after_peer_hello(
        send_stream,
        recv_stream,
        &mut decoder,
        awaiting_peer_hello,
        peer_hello,
        params.authenticated_peer,
        params.our_channel_max_frame_size,
        key_store,
        clock,
        verify_attestation,
    )
    .await
}

/// Drives the Hello handshake for a caller that has already read and
/// decoded the peer's `Hello` -- `listener.rs`'s branch on the first
/// Control frame (docs/04, "Deciding which of the two a stream is").
/// Writes our own `Hello` first, then runs the same steps
/// `perform_handshake` runs from `on_peer_hello` onward.
#[allow(clippy::too_many_arguments)]
pub async fn perform_handshake_after_peer_hello<F, Fut>(
    send_stream: &mut dyn SendStream,
    recv_stream: &mut dyn RecvStream,
    peer_hello: PeerHello,
    params: HandshakeParams<'_>,
    key_store: &(dyn KeyStore + Sync),
    rng: &(dyn Rng + Sync),
    clock: &(dyn Clock + Sync),
    verify_attestation: F,
) -> Result<Session, HandshakeError>
where
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    let (awaiting_peer_hello, our_hello) = open(
        rng,
        params.our_versions,
        params.our_identity,
        params.our_attestation_token,
        params.our_key_binding,
        params.our_capabilities,
    )
    .map_err(HandshakeError::Rng)?;

    let frame_bytes = encode_hello_frame(&our_hello, params.our_channel_max_frame_size)
        .map_err(HandshakeError::Proto)?;
    send_stream
        .write_all(&frame_bytes)
        .await
        .map_err(HandshakeError::Transport)?;

    // listener.rs's `read_frame` consumed exactly the peer's Hello frame
    // and buffers nothing past it, so this decoder starts empty rather
    // than carrying over one that might hold bytes read for `Hello`.
    let mut decoder = FrameDecoder::new(params.our_channel_max_frame_size);

    continue_after_peer_hello(
        send_stream,
        recv_stream,
        &mut decoder,
        awaiting_peer_hello,
        peer_hello,
        params.authenticated_peer,
        params.our_channel_max_frame_size,
        key_store,
        clock,
        verify_attestation,
    )
    .await
}

// Everything from `on_peer_hello` onward, shared so it runs once rather
// than twice. `perform_handshake` passes the decoder it already read the
// peer's `Hello` through, since it may hold bytes past that frame;
// `perform_handshake_after_peer_hello` passes a fresh one.
#[allow(clippy::too_many_arguments)]
async fn continue_after_peer_hello<F, Fut>(
    send_stream: &mut dyn SendStream,
    recv_stream: &mut dyn RecvStream,
    decoder: &mut FrameDecoder,
    awaiting_peer_hello: AwaitingPeerHello,
    peer_hello: PeerHello,
    authenticated_peer: DeviceId,
    our_channel_max_frame_size: u32,
    key_store: &(dyn KeyStore + Sync),
    clock: &(dyn Clock + Sync),
    verify_attestation: F,
) -> Result<Session, HandshakeError>
where
    F: FnOnce(AttestationRequest) -> Fut,
    Fut: Future<Output = Result<TrustTier, String>>,
{
    let (awaiting_verification, attestation_req) = awaiting_peer_hello
        .on_peer_hello(peer_hello, authenticated_peer, clock)
        .map_err(HandshakeError::Refused)?;

    let tier = verify_attestation(attestation_req)
        .await
        .map_err(HandshakeError::Attestation)?;

    let (awaiting_peer_ack, our_ack) = awaiting_verification
        .on_verified(tier, key_store, our_channel_max_frame_size)
        .map_err(HandshakeError::KeyStore)?;

    let frame_bytes = encode_hello_ack_frame(&our_ack, our_channel_max_frame_size)
        .map_err(HandshakeError::Proto)?;
    send_stream
        .write_all(&frame_bytes)
        .await
        .map_err(HandshakeError::Transport)?;

    let ack_frame = read_frame(recv_stream, decoder).await?;
    let peer_ack = decode_hello_ack_frame(&ack_frame).map_err(HandshakeError::Proto)?;

    awaiting_peer_ack
        .on_peer_hello_ack(peer_ack)
        .map_err(HandshakeError::Refused)
}

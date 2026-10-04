//! Drives the 4-step Hello exchange over bidirectional transport streams
//! (docs/04-protocol.md, "The Hello exchange"). Bridges tradr-identity's state
//! machine, tradr-proto's framing codec, and tradr-core's stream traits.

use std::future::Future;

use crate::known_store::KnownDeviceRecorder;
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

// Reading exact byte count prevents stream offset misalignment on subsequent frames.
async fn read_exact(recv: &mut dyn RecvStream, mut buf: &mut [u8]) -> Result<(), HandshakeError> {
    while !buf.is_empty() {
        let n = recv.read(buf).await.map_err(HandshakeError::Transport)?;
        if n == 0 {
            return Err(HandshakeError::UnexpectedEof);
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

// Length prefix is fed first to bound allocation before payload read (DCR-162).
async fn read_frame(
    recv_stream: &mut dyn RecvStream,
    decoder: &mut FrameDecoder,
) -> Result<Frame, HandshakeError> {
    let mut len_bytes = [0u8; 4];
    read_exact(recv_stream, &mut len_bytes).await?;
    decoder.feed(&len_bytes);
    decoder
        .next_frame()
        .map_err(HelloFrameError::Framing)
        .map_err(HandshakeError::Proto)?;
    let announced = u32::from_be_bytes(len_bytes);
    let mut payload = vec![0u8; announced as usize];
    read_exact(recv_stream, &mut payload).await?;
    decoder.feed(&payload);
    decoder
        .next_frame()
        .map_err(HelloFrameError::Framing)
        .map_err(HandshakeError::Proto)?
        .ok_or(HandshakeError::UnexpectedEof)
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
    /// Optional recorder for storing devices met through a verified handshake.
    pub known_devices: Option<&'a dyn KnownDeviceRecorder>,
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
    let known_devices = params.known_devices;
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

    let session = continue_after_peer_hello(
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
    .await?;

    if let Some(recorder) = known_devices {
        recorder.record(session.peer_identity(), session.tier(), clock.now());
    }

    Ok(session)
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
    let known_devices = params.known_devices;
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

    let session = continue_after_peer_hello(
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
    .await?;

    if let Some(recorder) = known_devices {
        recorder.record(session.peer_identity(), session.tier(), clock.now());
    }

    Ok(session)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_recv::CountingRecvStream;
    use tradr_proto::framing::{FrameError, encode_frame};

    #[tokio::test]
    async fn read_frame_stops_at_frame_boundary_leaving_subsequent_frame_in_stream() {
        let max_frame_size = 1024u32;
        let type1 = 0x01u8;
        let payload1 = b"first-frame-payload";
        let frame1_bytes = encode_frame(type1, payload1, max_frame_size).expect("encode frame 1");

        let type2 = 0x02u8;
        let payload2 = b"second-frame-longer-payload-bytes";
        let frame2_bytes = encode_frame(type2, payload2, max_frame_size).expect("encode frame 2");

        let mut stream_bytes = Vec::new();
        stream_bytes.extend_from_slice(&frame1_bytes);
        stream_bytes.extend_from_slice(&frame2_bytes);

        let mut stream = CountingRecvStream::new(stream_bytes);
        let mut decoder = FrameDecoder::new(max_frame_size);

        let frame = read_frame(&mut stream, &mut decoder)
            .await
            .expect("read first frame");
        assert_eq!(frame.type_code(), type1);
        assert_eq!(frame.payload(), payload1);

        let mut remaining_buf = vec![0u8; 4096];
        let n = stream
            .read(&mut remaining_buf)
            .await
            .expect("read remaining stream");
        assert_eq!(&remaining_buf[..n], &frame2_bytes[..]);
    }

    #[tokio::test]
    async fn read_frame_refuses_oversized_announcement_before_payload() {
        let max_frame_size = 64u32;
        let announced = max_frame_size + 1;
        let mut bytes = announced.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 16]);
        let mut stream = CountingRecvStream::new(bytes);
        let mut decoder = FrameDecoder::new(max_frame_size);

        let result = read_frame(&mut stream, &mut decoder).await;
        match result {
            Err(HandshakeError::Proto(HelloFrameError::Framing(FrameError::Oversized {
                announced: actual_announced,
                limit: actual_limit,
            }))) => {
                assert_eq!(actual_announced, announced as u64);
                assert_eq!(actual_limit, max_frame_size);
            }
            other => panic!("expected oversized frame error, got {other:?}"),
        }
        // Distinguishes prefix refusal from decoder-side refusal after payload read.
        assert_eq!(stream.read_count(), 1);
    }

    #[tokio::test]
    async fn read_frame_refuses_zero_length_announcement() {
        let max_frame_size = 64u32;
        let announced = 0u32;
        let mut bytes = announced.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0x01, 0x02]);
        let mut stream = CountingRecvStream::new(bytes);
        let mut decoder = FrameDecoder::new(max_frame_size);

        let result = read_frame(&mut stream, &mut decoder).await;
        match result {
            Err(HandshakeError::Proto(HelloFrameError::Framing(FrameError::Empty))) => {}
            other => panic!("expected empty frame error, got {other:?}"),
        }
        // Distinguishes prefix refusal from decoder-side refusal after payload read.
        assert_eq!(stream.read_count(), 1);
    }

    #[tokio::test]
    async fn read_frame_returns_unexpected_eof_on_truncated_payload() {
        let max_frame_size = 64u32;
        let announced = 10u32;
        let mut bytes = announced.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0x01, 0x02, 0x03]);
        let mut stream = CountingRecvStream::new(bytes);
        let mut decoder = FrameDecoder::new(max_frame_size);

        let result = read_frame(&mut stream, &mut decoder).await;
        match result {
            Err(HandshakeError::UnexpectedEof) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }
}

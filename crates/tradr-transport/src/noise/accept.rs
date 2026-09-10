//! Handshake driver for Noise responder over a framed link (docs/03, WI-M7-007i).

use std::time::Duration;

use tradr_core::{Clock, TransportError};

use super::handshake::{NoiseSession, Responder};
use super::link::{LinkSink, LinkSource};
use super::map_noise_error;

/// Completes a three-message Noise_XX handshake as the accepting responder,
/// returning the session beside the round trip the handshake itself took.
pub async fn handshake_as_responder(
    responder: Responder,
    sink: &dyn LinkSink,
    source: &mut dyn LinkSource,
    clock: &(dyn Clock + Sync),
) -> Result<(NoiseSession, Duration), TransportError> {
    let msg1 = match source.recv_record().await? {
        Some(record) => record,
        None => return Err(TransportError::Closed),
    };
    let start = clock.monotonic_now();
    let awaiting_reply = responder.read_first(&msg1).map_err(map_noise_error)?;
    let (awaiting_confirmation, msg2) = awaiting_reply.write_second().map_err(map_noise_error)?;
    sink.send_record(&msg2).await?;
    let msg3 = match source.recv_record().await? {
        Some(record) => record,
        None => return Err(TransportError::Closed),
    };
    let rtt = clock.monotonic_now().duration_since(start);
    let session = awaiting_confirmation
        .read_third(&msg3)
        .map_err(map_noise_error)?;
    Ok((session, rtt))
}

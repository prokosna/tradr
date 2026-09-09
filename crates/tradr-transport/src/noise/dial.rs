//! Handshake driver for Noise initiator over a framed link (docs/03, ADR-0020).

use tradr_core::TransportError;

use super::NoiseError;
use super::handshake::{Initiator, NoiseSession};
use super::link::{LinkSink, LinkSource};

fn map_noise_error(err: NoiseError) -> TransportError {
    match err {
        NoiseError::Refused | NoiseError::PeerKeyBinding(_) | NoiseError::LocalKeyBinding => {
            TransportError::AuthenticationFailed
        }
        NoiseError::KeyStore(_) | NoiseError::Rng(_) | NoiseError::PayloadTooLarge(_) => {
            TransportError::Io(std::io::ErrorKind::Other)
        }
    }
}

/// Completes a three-message Noise_XX handshake as the dialling initiator.
pub async fn handshake_as_initiator(
    initiator: Initiator,
    sink: &dyn LinkSink,
    source: &mut dyn LinkSource,
) -> Result<NoiseSession, TransportError> {
    let (awaiting, msg1) = initiator.write_first().map_err(map_noise_error)?;
    sink.send_record(&msg1).await?;
    let msg2 = match source.recv_record().await? {
        Some(record) => record,
        None => return Err(TransportError::Closed),
    };
    let ready = awaiting.read_second(&msg2).map_err(map_noise_error)?;
    let (session, msg3) = ready.write_third().map_err(map_noise_error)?;
    sink.send_record(&msg3).await?;
    Ok(session)
}

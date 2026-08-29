//! The one place a `quinn` failure becomes a `TransportError` (DCR-045,
//! docs/03-discovery-and-transport.md, "What a transport can know about a
//! refusal, and what it must not invent"). No other file in this crate
//! matches on a `quinn` error type.

use tradr_core::TransportError;

// RFC 9000's crypto range: a CRYPTO_ERROR carries a TLS alert number in
// its low byte, and neither side of a QUIC handshake can tell a pin
// mismatch from a forged signature once it arrives as this one code.
fn is_crypto_range(code: u64) -> bool {
    (0x100..=0x1ff).contains(&code)
}

// Maps a lost or refused connection. A crypto-range code arrives through
// two different variants depending on which side reports it -- the
// dialling side sees `TransportError`, the listening side sees the same
// code inside `ConnectionClosed` -- so both are checked here rather than
// at the two call sites that would otherwise repeat the range test.
pub(crate) fn map_connection_error(error: quinn::ConnectionError) -> TransportError {
    match error {
        quinn::ConnectionError::TransportError(e) if is_crypto_range(u64::from(e.code)) => {
            TransportError::AuthenticationFailed
        }
        quinn::ConnectionError::TransportError(_) => {
            TransportError::Io(std::io::ErrorKind::InvalidData)
        }
        quinn::ConnectionError::ConnectionClosed(c) if is_crypto_range(u64::from(c.error_code)) => {
            TransportError::AuthenticationFailed
        }
        quinn::ConnectionError::ConnectionClosed(_) => TransportError::Rejected,
        quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::Reset
        | quinn::ConnectionError::LocallyClosed => TransportError::Closed,
        quinn::ConnectionError::TimedOut => TransportError::TimedOut,
        quinn::ConnectionError::VersionMismatch | quinn::ConnectionError::CidsExhausted => {
            TransportError::Unreachable
        }
    }
}

// Maps a dial that never left the local endpoint. DCR-045: this is
// always a local verdict, decided before a packet is sent, for every
// `ConnectError` variant quinn reports.
pub(crate) fn map_connect_error(_error: quinn::ConnectError) -> TransportError {
    TransportError::Unreachable
}

// Maps a failed write. `ConnectionLost` delegates to the connection
// mapping rather than repeating it; every other variant means only this
// stream is unusable, which is `Closed` regardless of which of the three
// ways quinn reports that.
pub(crate) fn map_write_error(error: quinn::WriteError) -> TransportError {
    match error {
        quinn::WriteError::ConnectionLost(e) => map_connection_error(e),
        quinn::WriteError::Stopped(_)
        | quinn::WriteError::ClosedStream
        | quinn::WriteError::ZeroRttRejected => TransportError::Closed,
    }
}

// Maps a failed read. Mirrors `map_write_error`; see its comment.
pub(crate) fn map_read_error(error: quinn::ReadError) -> TransportError {
    match error {
        quinn::ReadError::ConnectionLost(e) => map_connection_error(e),
        quinn::ReadError::Reset(_)
        | quinn::ReadError::ClosedStream
        | quinn::ReadError::IllegalOrderedRead
        | quinn::ReadError::ZeroRttRejected => TransportError::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Builds the case DCR-045 describes without a handshake: a
    // `TransportError` (the dialling side's view) carrying a crypto code.
    fn dialler_view(code: quinn::TransportErrorCode) -> quinn::ConnectionError {
        quinn::ConnectionError::TransportError(code.into())
    }

    // The listening side's view of the identical event: the same code
    // inside a `ConnectionClosed` frame.
    fn listener_view(code: quinn::TransportErrorCode) -> quinn::ConnectionError {
        quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
            error_code: code,
            frame_type: None,
            reason: Vec::new().into(),
        })
    }

    #[test]
    fn a_crypto_range_code_authenticates_as_failed_from_either_side() {
        assert_eq!(
            map_connection_error(dialler_view(quinn::TransportErrorCode::crypto(31))),
            TransportError::AuthenticationFailed
        );
        assert_eq!(
            map_connection_error(listener_view(quinn::TransportErrorCode::crypto(42))),
            TransportError::AuthenticationFailed
        );
    }

    #[test]
    fn a_non_crypto_close_is_not_authentication_failed() {
        assert_eq!(
            map_connection_error(listener_view(quinn::TransportErrorCode::PROTOCOL_VIOLATION)),
            TransportError::Rejected
        );
        assert_eq!(
            map_connection_error(dialler_view(quinn::TransportErrorCode::PROTOCOL_VIOLATION)),
            TransportError::Io(std::io::ErrorKind::InvalidData)
        );
    }

    #[test]
    fn a_connect_error_is_always_unreachable_since_no_packet_left() {
        assert_eq!(
            map_connect_error(quinn::ConnectError::CidsExhausted),
            TransportError::Unreachable
        );
        assert_eq!(
            map_connect_error(quinn::ConnectError::UnsupportedVersion),
            TransportError::Unreachable
        );
    }

    #[test]
    fn the_crypto_range_is_pinned_at_both_boundaries() {
        assert!(!is_crypto_range(0xff), "one below the range starts");
        assert!(is_crypto_range(0x100), "the range's first code");
        assert!(is_crypto_range(0x1ff), "the range's last code");
        assert!(!is_crypto_range(0x200), "one past the range's last code");
    }

    #[test]
    fn a_write_lost_to_a_crypto_range_close_authenticates_as_failed() {
        let lost =
            quinn::WriteError::ConnectionLost(dialler_view(quinn::TransportErrorCode::crypto(31)));
        assert_eq!(map_write_error(lost), TransportError::AuthenticationFailed);
    }

    #[test]
    fn a_read_lost_to_a_crypto_range_close_authenticates_as_failed() {
        let lost =
            quinn::ReadError::ConnectionLost(dialler_view(quinn::TransportErrorCode::crypto(31)));
        assert_eq!(map_read_error(lost), TransportError::AuthenticationFailed);
    }
}

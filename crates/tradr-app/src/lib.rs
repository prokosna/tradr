#![forbid(unsafe_code)]
//! Shell-free application logic independent of any UI or frontend shell.
//! This crate must never name Tauri to keep the application core portable (D9).

pub mod attestation;
pub mod broadcast_secrets;
pub mod browse;
pub mod capabilities;
pub mod handshake;
pub mod identity;
pub mod link_exchange;
pub mod link_invite;
pub mod listener;
pub mod paths;
pub mod peer_trust;
pub mod peers;
pub mod send;
pub mod share;
pub mod sign_in;
pub mod transfer;

#[cfg(test)]
pub(crate) mod test_recv {
    use tradr_core::{BoxFuture, RecvStream, TransportError};

    pub(crate) struct CountingRecvStream {
        bytes: Vec<u8>,
        offset: usize,
        read_count: usize,
    }

    impl CountingRecvStream {
        pub(crate) fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                offset: 0,
                read_count: 0,
            }
        }

        pub(crate) fn read_count(&self) -> usize {
            self.read_count
        }
    }

    impl RecvStream for CountingRecvStream {
        fn read<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> BoxFuture<'a, Result<usize, TransportError>> {
            self.read_count += 1;
            let available = &self.bytes[self.offset..];
            let to_read = available.len().min(buf.len());
            buf[..to_read].copy_from_slice(&available[..to_read]);
            self.offset += to_read;
            Box::pin(async move { Ok(to_read) })
        }
    }
}

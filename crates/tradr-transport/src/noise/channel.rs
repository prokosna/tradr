//! `tradr_core::SecureChannel` over an established Noise session (WI-M7-007f).

use std::sync::Arc;
use std::time::Duration;

use tradr_core::{
    BoxFuture, DeviceId, RecvStream, SecureChannel, SendStream, TransportError, TransportId,
};
use tradr_proto::framing::FrameDecoder;
use tradr_proto::mux::{StreamId, StreamOpener, mux_frame_from_wire};

use super::NoiseSession;
use super::link::{LinkSink, LinkSource};
use crate::mux::{Multiplexer, MuxFault, ReadOutcome};

/// The plane's fixed `max_frame_size` over `ble-gatt` (docs/04); bounds a plane's own frames, never the mux frame the link carries.
pub const BLE_GATT_MAX_FRAME_SIZE: u32 = 512;

/// Parameters defining link limits and stream opener role.
#[derive(Debug, Clone, Copy)]
pub struct NoiseChannelConfig {
    /// Identifies the underlying transport.
    pub transport: TransportId,
    /// Identifies whether this side dials or listens for stream allocation.
    pub opener: StreamOpener,
    /// Maximum frame size negotiated for stream payloads.
    pub max_frame_size: u32,
    /// Maximum record size accepted or transmitted on the link.
    pub record_limit: u32,
    /// `ble-gatt` has no continuous round trip estimate, so this reports what establishing the link cost instead of inventing a moving one (docs/03).
    pub rtt: Duration,
}

struct ChannelState {
    session: tokio::sync::Mutex<NoiseSession>,
    transmit: tokio::sync::Mutex<()>,
    mux: std::sync::Mutex<Multiplexer>,
    progress: tokio::sync::Notify,
    close_reason: std::sync::Mutex<Option<TransportError>>,
    sink: Arc<dyn LinkSink>,
}

impl ChannelState {
    fn set_close_reason(&self, error: TransportError) {
        let mut guard = match self.close_reason.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.is_none() {
            *guard = Some(error);
        }
    }

    fn close_reason(&self) -> Option<TransportError> {
        match self.close_reason.lock() {
            Ok(g) => *g,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    fn close_with(&self, error: TransportError) {
        self.set_close_reason(error);
        self.progress.notify_waiters();
    }

    // DCR-097: a record's place in the sequence is its nonce, so encrypting and sending stay one critical section under `transmit`.
    async fn transmit(&self, frames: &[Vec<u8>]) -> Result<(), TransportError> {
        let _transmit = self.transmit.lock().await;
        if let Some(err) = self.close_reason() {
            return Err(err);
        }
        for frame in frames {
            let record = {
                let mut session = self.session.lock().await;
                session.encrypt(frame)
            };
            let record = match record {
                Ok(r) => r,
                Err(_) => {
                    self.close_with(TransportError::Closed);
                    return Err(TransportError::Closed);
                }
            };
            if let Err(e) = self.sink.send_record(&record).await {
                self.close_with(e);
                return Err(e);
            }
        }
        Ok(())
    }
}

struct StreamReleaser {
    stream_id: StreamId,
    state: Arc<ChannelState>,
}

impl Drop for StreamReleaser {
    fn drop(&mut self) {
        let mut mux = match self.state.mux.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        mux.retire(self.stream_id);
        drop(mux);
        self.state.progress.notify_waiters();
    }
}

// Shares one `StreamReleaser` between both halves so the stream retires only once both are dropped.
fn bidirectional_handles(
    state: &Arc<ChannelState>,
    stream_id: StreamId,
) -> (Box<dyn SendStream>, Box<dyn RecvStream>) {
    let releaser = Arc::new(StreamReleaser {
        stream_id,
        state: Arc::clone(state),
    });
    let send = Box::new(NoiseSendStream {
        stream_id,
        state: Arc::clone(state),
        _releaser: Arc::clone(&releaser),
    }) as Box<dyn SendStream>;
    let recv = Box::new(NoiseRecvStream {
        stream_id,
        state: Arc::clone(state),
        _releaser: releaser,
    }) as Box<dyn RecvStream>;
    (send, recv)
}

// Holds the sole `StreamReleaser` for a send-only stream.
fn send_handle(state: &Arc<ChannelState>, stream_id: StreamId) -> Box<dyn SendStream> {
    let releaser = Arc::new(StreamReleaser {
        stream_id,
        state: Arc::clone(state),
    });
    Box::new(NoiseSendStream {
        stream_id,
        state: Arc::clone(state),
        _releaser: releaser,
    })
}

// Holds the sole `StreamReleaser` for a receive-only stream.
fn recv_handle(state: &Arc<ChannelState>, stream_id: StreamId) -> Box<dyn RecvStream> {
    let releaser = Arc::new(StreamReleaser {
        stream_id,
        state: Arc::clone(state),
    });
    Box::new(NoiseRecvStream {
        stream_id,
        state: Arc::clone(state),
        _releaser: releaser,
    })
}

struct NoiseSendStream {
    stream_id: StreamId,
    state: Arc<ChannelState>,
    _releaser: Arc<StreamReleaser>,
}

impl SendStream for NoiseSendStream {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            if let Some(err) = self.state.close_reason() {
                return Err(err);
            }
            let frames = {
                let mut mux = match self.state.mux.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                mux.write(self.stream_id, buf)
            };
            let frames = match frames {
                Ok(f) => f,
                Err(fault) => {
                    if let Some(err) = self.state.close_reason() {
                        return Err(err);
                    }
                    return Err(map_mux_fault(fault));
                }
            };
            self.state.transmit(&frames).await
        })
    }

    fn finish<'a>(&'a mut self) -> BoxFuture<'a, Result<(), TransportError>> {
        Box::pin(async move {
            if let Some(err) = self.state.close_reason() {
                return Err(err);
            }
            let frame = {
                let mut mux = match self.state.mux.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                mux.finish(self.stream_id)
            };
            let frame = match frame {
                Ok(f) => f,
                Err(fault) => {
                    if let Some(err) = self.state.close_reason() {
                        return Err(err);
                    }
                    return Err(map_mux_fault(fault));
                }
            };
            self.state.transmit(std::slice::from_ref(&frame)).await
        })
    }
}

struct NoiseRecvStream {
    stream_id: StreamId,
    state: Arc<ChannelState>,
    _releaser: Arc<StreamReleaser>,
}

impl RecvStream for NoiseRecvStream {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize, TransportError>> {
        Box::pin(async move {
            loop {
                let notified = self.state.progress.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                let outcome = {
                    let mut mux = match self.state.mux.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    mux.read(self.stream_id, buf)
                };

                match outcome {
                    Ok(ReadOutcome::Read(n)) => return Ok(n),
                    Ok(ReadOutcome::Finished) => return Ok(0),
                    Ok(ReadOutcome::Pending) => {
                        if let Some(err) = self.state.close_reason() {
                            return Err(err);
                        }
                        notified.await;
                    }
                    Err(fault) => {
                        if let Some(err) = self.state.close_reason() {
                            return Err(err);
                        }
                        return Err(map_mux_fault(fault));
                    }
                }
            }
        })
    }
}

fn map_mux_fault(fault: MuxFault) -> TransportError {
    match fault {
        MuxFault::Refused(_)
        | MuxFault::NoSuchStream(_)
        | MuxFault::NotReadable(_)
        | MuxFault::NotWritable(_)
        | MuxFault::AlreadyFinished(_)
        | MuxFault::StreamIdsExhausted => TransportError::Closed,
        MuxFault::RecordLimitTooSmall(_) => TransportError::Io(std::io::ErrorKind::InvalidInput),
        MuxFault::Encode(_) => TransportError::Io(std::io::ErrorKind::InvalidData),
    }
}

async fn run_reader(state: Arc<ChannelState>, mut source: Box<dyn LinkSource>, record_limit: u32) {
    let mut decoder = FrameDecoder::new(record_limit);
    loop {
        let record = match source.recv_record().await {
            Ok(Some(record)) => record,
            Ok(None) => {
                state.close_with(TransportError::Closed);
                break;
            }
            Err(err) => {
                state.close_with(err);
                break;
            }
        };

        let plaintext = {
            let mut session = state.session.lock().await;
            session.decrypt(&record)
        };
        let plaintext = match plaintext {
            Ok(pt) => pt,
            Err(_) => {
                state.close_with(TransportError::AuthenticationFailed);
                break;
            }
        };

        decoder.feed(&plaintext);
        let mut fatal = false;
        loop {
            match decoder.next_frame() {
                Ok(Some(frame)) => match mux_frame_from_wire(&frame) {
                    Ok(mux_frame) => {
                        let mut mux = match state.mux.lock() {
                            Ok(g) => g,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        if mux.on_frame(&mux_frame).is_err() {
                            state.close_with(TransportError::Closed);
                            fatal = true;
                            break;
                        }
                    }
                    Err(_) => {
                        state.close_with(TransportError::Closed);
                        fatal = true;
                        break;
                    }
                },
                Ok(None) => break,
                Err(_) => {
                    state.close_with(TransportError::Closed);
                    fatal = true;
                    break;
                }
            }
        }

        state.progress.notify_waiters();
        if fatal {
            break;
        }
    }
    state.progress.notify_waiters();
}

/// Multiplexed secure channel over an authenticated Noise session.
pub struct NoiseChannel {
    peer: DeviceId,
    config: NoiseChannelConfig,
    state: Arc<ChannelState>,
    reader_task: tokio::task::JoinHandle<()>,
}

impl NoiseChannel {
    /// Binds a session and link into a multiplexed secure channel.
    pub fn new(
        session: NoiseSession,
        sink: Arc<dyn LinkSink>,
        source: Box<dyn LinkSource>,
        config: NoiseChannelConfig,
    ) -> Result<Self, TransportError> {
        let peer = session.peer();
        let mux = Multiplexer::new(config.opener, config.max_frame_size, config.record_limit)
            .map_err(map_mux_fault)?;

        let state = Arc::new(ChannelState {
            session: tokio::sync::Mutex::new(session),
            transmit: tokio::sync::Mutex::new(()),
            mux: std::sync::Mutex::new(mux),
            progress: tokio::sync::Notify::new(),
            close_reason: std::sync::Mutex::new(None),
            sink,
        });

        let reader_state = Arc::clone(&state);
        let record_limit = config.record_limit;
        let reader_task = tokio::spawn(async move {
            run_reader(reader_state, source, record_limit).await;
        });

        Ok(Self {
            peer,
            config,
            state,
            reader_task,
        })
    }
}

impl Drop for NoiseChannel {
    fn drop(&mut self) {
        // A surviving stream handle outlives the channel and awaits the reader forever unless this wakes it.
        self.state.close_with(TransportError::Closed);
        self.reader_task.abort();
    }
}

impl SecureChannel for NoiseChannel {
    fn peer(&self) -> DeviceId {
        self.peer
    }

    fn transport(&self) -> TransportId {
        self.config.transport
    }

    fn rtt(&self) -> Duration {
        self.config.rtt
    }

    fn max_frame_size(&self) -> u32 {
        self.config.max_frame_size
    }

    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Box<dyn SendStream>, Box<dyn RecvStream>), TransportError>> {
        Box::pin(async move {
            if let Some(err) = self.state.close_reason() {
                return Err(err);
            }
            let stream_id = {
                let mut mux = match self.state.mux.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                mux.open_bidirectional()
            };
            let stream_id = match stream_id {
                Ok(id) => id,
                Err(fault) => {
                    if let Some(err) = self.state.close_reason() {
                        return Err(err);
                    }
                    return Err(map_mux_fault(fault));
                }
            };
            Ok(bidirectional_handles(&self.state, stream_id))
        })
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<Box<dyn SendStream>, TransportError>> {
        Box::pin(async move {
            if let Some(err) = self.state.close_reason() {
                return Err(err);
            }
            let stream_id = {
                let mut mux = match self.state.mux.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                mux.open_unidirectional()
            };
            let stream_id = match stream_id {
                Ok(id) => id,
                Err(fault) => {
                    if let Some(err) = self.state.close_reason() {
                        return Err(err);
                    }
                    return Err(map_mux_fault(fault));
                }
            };
            Ok(send_handle(&self.state, stream_id))
        })
    }

    fn accept_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Box<dyn SendStream>, Box<dyn RecvStream>), TransportError>> {
        Box::pin(async move {
            loop {
                let notified = self.state.progress.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                let stream_id = {
                    let mut mux = match self.state.mux.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    mux.accept_bidirectional()
                };

                if let Some(stream_id) = stream_id {
                    return Ok(bidirectional_handles(&self.state, stream_id));
                }

                if let Some(err) = self.state.close_reason() {
                    return Err(err);
                }

                notified.await;
            }
        })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<Box<dyn RecvStream>, TransportError>> {
        Box::pin(async move {
            loop {
                let notified = self.state.progress.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                let stream_id = {
                    let mut mux = match self.state.mux.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    mux.accept_unidirectional()
                };

                if let Some(stream_id) = stream_id {
                    return Ok(recv_handle(&self.state, stream_id));
                }

                if let Some(err) = self.state.close_reason() {
                    return Err(err);
                }

                notified.await;
            }
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), TransportError>> {
        Box::pin(async move {
            self.state.close_with(TransportError::Closed);
            self.state.sink.close().await
        })
    }
}

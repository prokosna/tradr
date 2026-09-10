//! Inbound GATT link acceptance over Noise_XX (docs/03, DCR-102).

use std::sync::Arc;

use tradr_core::{Clock, TransportError};
use tradr_proto::mux::StreamOpener;

use super::BLE_GATT_TRANSPORT_ID;
use crate::noise::{
    BLE_GATT_MAX_FRAME_SIZE, BLE_GATT_MAX_RECORD, ByteSink, ByteSource, LinkSink, NoiseChannel,
    NoiseChannelConfig, RecordSink, RecordSource, Responder, handshake_as_responder,
};

/// Accepts an inbound GATT link, executes the responder Noise handshake, and constructs an authenticated channel.
pub async fn accept_link<Snk, Src>(
    sink: Snk,
    source: Src,
    responder: Responder,
    clock: &(dyn Clock + Sync),
) -> Result<NoiseChannel, TransportError>
where
    Snk: ByteSink + 'static,
    Src: ByteSource + 'static,
{
    let sink: Arc<dyn LinkSink> = Arc::new(RecordSink::new(sink, BLE_GATT_MAX_RECORD));
    let mut source = RecordSource::new(source, BLE_GATT_MAX_RECORD);
    let (session, rtt) = handshake_as_responder(responder, &*sink, &mut source, clock).await?;
    let config = NoiseChannelConfig {
        transport: BLE_GATT_TRANSPORT_ID,
        opener: StreamOpener::Listener,
        max_frame_size: BLE_GATT_MAX_FRAME_SIZE,
        record_limit: BLE_GATT_MAX_FRAME_SIZE,
        rtt,
    };
    NoiseChannel::new(session, sink, Box::new(source), config)
}

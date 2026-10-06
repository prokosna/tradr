//! DTOs and projections for Known Devices and Deferred Deliveries (docs/13).

use serde::{Deserialize, Serialize};
use tradr_core::{DeviceId, TrustTier};
use tradr_identity::KnownDevice;

use super::api::OutboxState;
use super::outbox::DeliveryStatus;

/// A known device exposed to the interface for deferred delivery targeting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownDeviceDto {
    /// Device identifier as lowercase hex.
    pub device_id: String,
    /// Display name published by the device, if known.
    pub display_name: Option<String>,
    /// Trust tier ("same-account" or "linked").
    pub tier: String,
    /// Unix timestamp in seconds when the device was last seen directly.
    pub last_seen: i64,
}

/// A sent deferred delivery status exposed to the interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryDto {
    /// The delivery identifier assigned by the Brokr.
    pub id: String,
    /// Recipient device identifier as lowercase hex.
    pub recipient_device_id: String,
    /// Recipient display name from known devices, or None if unknown.
    pub recipient_name: Option<String>,
    /// Filenames carried in the delivery.
    pub names: Vec<String>,
    /// Unix timestamp in seconds when the delivery was sent locally.
    pub sent_at: i64,
    /// Delivery state ("waiting", "delivered", or "expired").
    pub state: String,
    /// Millisecond timestamp when collected by the recipient, if delivered.
    pub collected_at: Option<i64>,
}

/// Maps a slice of known devices to DTOs, omitting this device itself.
pub fn known_device_dtos(known: &[KnownDevice], self_id: DeviceId) -> Vec<KnownDeviceDto> {
    known
        .iter()
        .filter(|d| d.device_id() != self_id)
        .map(|d| KnownDeviceDto {
            device_id: d.device_id().to_string(),
            display_name: d.display_name().map(|name| name.as_str().to_string()),
            tier: tier_string(d.tier()).to_string(),
            last_seen: d.last_seen().as_secs(),
        })
        .collect()
}

fn tier_string(tier: TrustTier) -> &'static str {
    match tier {
        TrustTier::SameAccount => "same-account",
        TrustTier::Linked => "linked",
        TrustTier::NearbyEphemeral => "nearby-ephemeral",
        TrustTier::Rejected => "rejected",
    }
}

fn outbox_state_string(state: OutboxState) -> &'static str {
    match state {
        OutboxState::Waiting => "waiting",
        OutboxState::Delivered => "delivered",
        OutboxState::Expired => "expired",
    }
}

/// Builds a DeliveryDto from a delivery status and known devices.
pub fn delivery_dto(status: &DeliveryStatus, known: &[KnownDevice]) -> DeliveryDto {
    let recipient_name = known
        .iter()
        .find(|d| d.device_id() == status.recipient_device_id)
        .and_then(|d| d.display_name().map(|name| name.as_str().to_string()));
    DeliveryDto {
        id: status.id.clone(),
        recipient_device_id: status.recipient_device_id.to_string(),
        recipient_name,
        names: status.names.clone(),
        sent_at: status.sent_at.as_secs(),
        state: outbox_state_string(status.state).to_string(),
        collected_at: status.collected_at,
    }
}

/// Builds DeliveryDto records from delivery statuses and known devices.
pub fn delivery_dtos(statuses: &[DeliveryStatus], known: &[KnownDevice]) -> Vec<DeliveryDto> {
    statuses.iter().map(|s| delivery_dto(s, known)).collect()
}

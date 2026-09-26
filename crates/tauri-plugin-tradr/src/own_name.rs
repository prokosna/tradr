use tradr_core::DisplayName;

/// Holds this device's display name decided once at plugin start (DCR-160).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnDisplayName(pub Option<DisplayName>);

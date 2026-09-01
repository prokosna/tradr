//! The type byte registry (docs/04-protocol.md, "The type byte"): which
//! plane a code belongs to, which codes that plane has assigned, and what
//! a receiver does with a code it did not expect. `framing.rs` carries the
//! byte verbatim and knows none of this; this module is the registry, and
//! the two never import each other (DCR-049).

use core::fmt;

/// The three streams a frame can arrive on ("The three planes"). Each owns
/// a fixed range of the type byte, checked before any code inside it is
/// looked up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Plane {
    /// `0x01`-`0x1f`. Handshake, capability negotiation, offer and accept,
    /// progress and completion.
    Control,
    /// `0x20`-`0x3f`. Chunk payloads.
    Data,
    /// `0x40`-`0x5f`. Listing, stat, and reading or writing Share Roots.
    Browse,
}

impl Plane {
    /// All three planes, for tests and callers that must check a property
    /// over the whole closed set rather than over an enumeration they
    /// wrote out by hand (the precedent is `DomainTag::ALL` in
    /// `tradr-core`).
    pub const ALL: &'static [Plane] = &[Self::Control, Self::Data, Self::Browse];

    // The inclusive (low, high) bounds of this plane's range on the type
    // byte.
    fn range(self) -> (u8, u8) {
        match self {
            Self::Control => (0x01, 0x1f),
            Self::Data => (0x20, 0x3f),
            Self::Browse => (0x40, 0x5f),
        }
    }
}

impl fmt::Display for Plane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Control => "Control",
            Self::Data => "Data",
            Self::Browse => "Browse",
        };
        write!(f, "{name}")
    }
}

/// Every message the type byte can name, one variant per assigned code in
/// docs/04's table. Maps a code to a *name*, never to a generated protobuf
/// type: wiring a code to the message it decodes as is `WI-M1-008c`'s job,
/// in a different file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    // Control: 0x01-0x1f, 14 assigned.
    Hello,
    HelloAck,
    TransferOffer,
    TransferAccept,
    TransferReject,
    TransferComplete,
    TransferAbort,
    PathChanged,
    KeepAlive,
    ItemComplete,
    TransferProgress,
    LinkReply,
    LinkApprove,
    LinkDecline,
    // Data: 0x20-0x3f, 4 assigned.
    ChunkRequest,
    ChunkRerequest,
    ChunkData,
    FlowControl,
    // Browse: 0x40-0x5f, 13 assigned.
    ListDir,
    DirListing,
    Stat,
    StatResult,
    ReadFile,
    ReadFileBegin,
    WriteFile,
    Mkdir,
    Delete,
    Rename,
    Ack,
    Watch,
    FsEvent,
}

impl MessageType {
    /// Every assigned variant, for tests and callers that must check a
    /// property over the whole closed set. A test in this module fails
    /// if a variant is added here without being added to `ALL`.
    pub const ALL: &'static [MessageType] = &[
        Self::Hello,
        Self::HelloAck,
        Self::TransferOffer,
        Self::TransferAccept,
        Self::TransferReject,
        Self::TransferComplete,
        Self::TransferAbort,
        Self::PathChanged,
        Self::KeepAlive,
        Self::ItemComplete,
        Self::TransferProgress,
        Self::LinkReply,
        Self::LinkApprove,
        Self::LinkDecline,
        Self::ChunkRequest,
        Self::ChunkRerequest,
        Self::ChunkData,
        Self::FlowControl,
        Self::ListDir,
        Self::DirListing,
        Self::Stat,
        Self::StatResult,
        Self::ReadFile,
        Self::ReadFileBegin,
        Self::WriteFile,
        Self::Mkdir,
        Self::Delete,
        Self::Rename,
        Self::Ack,
        Self::Watch,
        Self::FsEvent,
    ];

    /// The type byte docs/04 assigns this message.
    pub fn code(self) -> u8 {
        match self {
            Self::Hello => 0x01,
            Self::HelloAck => 0x02,
            Self::TransferOffer => 0x03,
            Self::TransferAccept => 0x04,
            Self::TransferReject => 0x05,
            Self::TransferComplete => 0x06,
            Self::TransferAbort => 0x07,
            Self::PathChanged => 0x08,
            Self::KeepAlive => 0x09,
            Self::ItemComplete => 0x0a,
            Self::TransferProgress => 0x0b,
            Self::LinkReply => 0x0c,
            Self::LinkApprove => 0x0d,
            Self::LinkDecline => 0x0e,
            Self::ChunkRequest => 0x20,
            Self::ChunkRerequest => 0x21,
            Self::ChunkData => 0x22,
            Self::FlowControl => 0x23,
            Self::ListDir => 0x40,
            Self::DirListing => 0x41,
            Self::Stat => 0x42,
            Self::StatResult => 0x43,
            Self::ReadFile => 0x44,
            Self::ReadFileBegin => 0x45,
            Self::WriteFile => 0x46,
            Self::Mkdir => 0x47,
            Self::Delete => 0x48,
            Self::Rename => 0x49,
            Self::Ack => 0x4a,
            Self::Watch => 0x4b,
            Self::FsEvent => 0x4c,
        }
    }

    /// The plane this message travels on.
    pub fn plane(self) -> Plane {
        match self {
            Self::Hello
            | Self::HelloAck
            | Self::TransferOffer
            | Self::TransferAccept
            | Self::TransferReject
            | Self::TransferComplete
            | Self::TransferAbort
            | Self::PathChanged
            | Self::KeepAlive
            | Self::ItemComplete
            | Self::TransferProgress
            | Self::LinkReply
            | Self::LinkApprove
            | Self::LinkDecline => Plane::Control,
            Self::ChunkRequest | Self::ChunkRerequest | Self::ChunkData | Self::FlowControl => {
                Plane::Data
            }
            Self::ListDir
            | Self::DirListing
            | Self::Stat
            | Self::StatResult
            | Self::ReadFile
            | Self::ReadFileBegin
            | Self::WriteFile
            | Self::Mkdir
            | Self::Delete
            | Self::Rename
            | Self::Ack
            | Self::Watch
            | Self::FsEvent => Plane::Browse,
        }
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}(0x{:02x})", self.code())
    }
}

/// Why `classify` refused a code, never merely skipped it. This is the
/// caller's signal to close the stream: this module performs no I/O and
/// holds no state, so acting on the refusal is left to whoever owns the
/// connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `0x00`: what padding, a truncated write and an uninitialised buffer
    /// all produce, so the one code that must never mean a message.
    Zero,
    /// The code falls inside a plane's range other than the one it
    /// arrived on, whether or not that plane has assigned it. `range_owner`
    /// is the plane owning the *range*, not the message: `0x0f` is
    /// unassigned and still belongs to Control.
    WrongPlane { range_owner: Plane },
    /// `0x60`-`0x7f`, reserved for the in-band multiplexing variant no
    /// QUIC path sends, and `0x80`-`0xff`, unassigned. The only codes in
    /// no plane's range.
    OutsideEveryPlane,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => write!(f, "0x00 is never a valid type byte"),
            Self::WrongPlane { range_owner } => {
                write!(
                    f,
                    "code belongs to {range_owner}'s range, not the plane it arrived on"
                )
            }
            Self::OutsideEveryPlane => write!(f, "code falls inside no plane's range"),
        }
    }
}

impl std::error::Error for Refusal {}

/// What a receiver does with a code, once the plane it arrived on is
/// known. Exactly three outcomes: docs/04's "unknown message types are
/// ignored" covers only `Ignorable`, and reaches only an unassigned code
/// inside the receiving plane's own range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// A code this version assigned, on the plane it belongs to. Dispatch
    /// it.
    Known(MessageType),
    /// An unassigned code inside `arriving_on`'s own range. Skip it; a
    /// future version may have given it meaning.
    Ignorable,
    /// Everything else. Close the stream.
    Refused(Refusal),
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(message_type) => write!(f, "known({message_type})"),
            Self::Ignorable => write!(f, "ignorable"),
            Self::Refused(refusal) => write!(f, "refused({refusal})"),
        }
    }
}

/// Classifies `code` as it arrives on `arriving_on`. A pure function of
/// its two arguments: no I/O, no state, and the frame's extent must
/// already be known (the framing layer's job) before this is meaningful,
/// since an unassigned code is only ever skippable within one already
/// known to be a whole frame.
pub fn classify(code: u8, arriving_on: Plane) -> Classification {
    if code == 0x00 {
        return Classification::Refused(Refusal::Zero);
    }

    let range_owner = Plane::ALL.iter().copied().find(|plane| {
        let (low, high) = plane.range();
        (low..=high).contains(&code)
    });

    let range_owner = match range_owner {
        Some(owner) => owner,
        None => return Classification::Refused(Refusal::OutsideEveryPlane),
    };

    if range_owner != arriving_on {
        return Classification::Refused(Refusal::WrongPlane { range_owner });
    }

    match MessageType::ALL
        .iter()
        .copied()
        .find(|message_type| message_type.code() == code)
    {
        Some(message_type) => Classification::Known(message_type),
        None => Classification::Ignorable,
    }
}

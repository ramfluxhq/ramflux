// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact downstream JSON admission measurements, including authority metadata.
use crate::NodeCoreError;
use serde::Serialize;
use std::io;

pub const ENTRY_FRAME_BYTE_CAP: usize = 1_048_576;
const WIDEST_INCARNATION: &str = "ffffffffffffffffffffffffffffffff";
#[derive(Serialize)]
struct WireEntry<'a> {
    inbox_seq: u64,
    target_delivery_id: &'a str,
    envelope: &'a ramflux_protocol::Envelope,
}
#[derive(Serialize)]
struct Record<'a> {
    entry: WireEntry<'a>,
    retain_until: i64,
}
#[derive(Serialize)]
struct LegacyDeliver<'a> {
    frame_type: &'static str,
    entry: WireEntry<'a>,
}
#[derive(Serialize)]
struct CapableDeliver<'a> {
    frame_type: &'static str,
    incarnation_id: &'static str,
    entry: WireEntry<'a>,
    retain_until: i64,
}
#[derive(Serialize)]
struct EntryReply<'a> {
    frame_type: &'static str,
    incarnation_id: &'static str,
    record: Record<'a>,
}
struct Count(usize);
impl io::Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("frame size overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(crate) fn serialized_size(value: &impl Serialize) -> Result<usize, NodeCoreError> {
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value)
        .map_err(|e| NodeCoreError::ItestJson(e.to_string()))?;
    Ok(count.0)
}
fn wire(envelope: &ramflux_protocol::Envelope) -> WireEntry<'_> {
    WireEntry { inbox_seq: u64::MAX, target_delivery_id: &envelope.target_delivery_id, envelope }
}
/// Largest downstream JSON frame with maximum-width sequence, deadline and incarnation.
/// # Errors
/// Returns a serialization error if the envelope cannot be encoded.
pub fn single_entry_frame_size(
    envelope: &ramflux_protocol::Envelope,
) -> Result<usize, NodeCoreError> {
    let legacy = serialized_size(&LegacyDeliver { frame_type: "deliver", entry: wire(envelope) })?;
    let capable = serialized_size(&CapableDeliver {
        frame_type: "deliver",
        incarnation_id: WIDEST_INCARNATION,
        entry: wire(envelope),
        retain_until: i64::MIN,
    })?;
    let entry = serialized_size(&EntryReply {
        frame_type: "entry",
        incarnation_id: WIDEST_INCARNATION,
        record: Record { entry: wire(envelope), retain_until: i64::MIN },
    })?;
    Ok(legacy.max(capable).max(entry))
}
/// Refuse a new delivery that cannot fit every downstream single-entry shape.
/// # Errors
/// Returns typed `payload_too_large` or a serialization error, before allocation/replay.
pub fn check_entry_bound(envelope: &ramflux_protocol::Envelope) -> Result<(), NodeCoreError> {
    if single_entry_frame_size(envelope)? > ENTRY_FRAME_BYTE_CAP {
        return Err(NodeCoreError::PayloadTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

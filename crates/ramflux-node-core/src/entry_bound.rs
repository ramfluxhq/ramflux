// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact downstream JSON admission measurements, including authority metadata.
use crate::NodeCoreError;
use serde::Serialize;
use std::io;

pub const ENTRY_FRAME_BYTE_CAP: usize = 1_048_576;
const _: () =
    assert!(ENTRY_FRAME_BYTE_CAP == ramflux_protocol::message::outer::MAX_COMPLETE_FRAME_BYTES);
// Exact fixed JSON bytes around the WireEntry slot. Empty slots below contribute
// no entry bytes; the independent wire oracle checks all three complete shapes.
const LEGACY_OVERHEAD: usize = r#"{"frame_type":"deliver","entry":}"#.len();
const CAPABLE_OVERHEAD: usize = r#"{"frame_type":"deliver","incarnation_id":"ffffffffffffffffffffffffffffffff","entry":,"retain_until":-9223372036854775808}"#.len();
const ENTRY_OVERHEAD: usize = r#"{"frame_type":"entry","incarnation_id":"ffffffffffffffffffffffffffffffff","record":{"entry":,"retain_until":-9223372036854775808}}"#.len();
#[derive(Serialize)]
struct WireEntry<'a> {
    inbox_seq: u64,
    target_delivery_id: &'a str,
    envelope: &'a ramflux_protocol::Envelope,
}
struct Count(usize);
impl io::Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        #[cfg(test)]
        SIZED_BYTES.with(|count| count.set(count.get() + bytes.len()));
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
    serialized_size(&wire(envelope))?
        .checked_add(LEGACY_OVERHEAD.max(CAPABLE_OVERHEAD).max(ENTRY_OVERHEAD))
        .ok_or_else(|| NodeCoreError::ItestJson("frame size overflow".into()))
}
/// Refuse a new delivery that cannot fit every downstream single-entry shape.
/// # Errors
/// Returns typed `payload_too_large` or a serialization error, before allocation/replay.
pub fn check_entry_bound(envelope: &ramflux_protocol::Envelope) -> Result<(), NodeCoreError> {
    if single_entry_frame_size(envelope)? > ENTRY_FRAME_BYTE_CAP {
        return Err(NodeCoreError::PayloadTooLarge);
    }
    ramflux_protocol::message::outer::refuse_named_fields_while_gate_off(envelope)
        .map_err(map_outer_profile)?;
    if ramflux_protocol::schema_profile::schema_v1_live() {
        check_candidate_entry_bound(envelope)?;
    }
    Ok(())
}

fn check_candidate_entry_bound(envelope: &ramflux_protocol::Envelope) -> Result<(), NodeCoreError> {
    ramflux_protocol::message::outer::refuse_live_bridge(envelope).map_err(map_outer_profile)?;
    ramflux_protocol::message::outer::parse_live_named_delivery_mode(envelope)
        .map_err(map_outer_profile)?;
    let tag = ramflux_protocol::message::outer::live_collapse_tag_bytes(envelope)
        .map_err(map_outer_profile)?;
    if tag.len() != 32 {
        return Err(map_outer_profile(
            ramflux_protocol::message::outer::OuterProfileError::CollapseTag,
        ));
    }
    ramflux_protocol::message::outer::require_live_report_commitment(envelope)
        .map_err(map_outer_profile)?;
    let payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        envelope.encrypted_payload.as_bytes(),
    );
    if envelope.payload_hash != payload_hash {
        return Err(NodeCoreError::InvalidConfiguration("envelope payload hash mismatch".into()));
    }
    let sizes = ramflux_protocol::message::outer::IngressSizes::measure_wire(envelope, 0, &[], &[])
        .map_err(map_outer_profile)?;
    ramflux_protocol::message::outer::check_ingress_caps(sizes).map_err(map_outer_profile)
}

fn map_outer_profile(error: ramflux_protocol::message::outer::OuterProfileError) -> NodeCoreError {
    use ramflux_protocol::message::outer::OuterProfileError;
    match error {
        OuterProfileError::PayloadTooLarge => NodeCoreError::PayloadTooLarge,
        OuterProfileError::Bridge
        | OuterProfileError::DualField
        | OuterProfileError::UnknownMode
        | OuterProfileError::MissingMode
        | OuterProfileError::NamedFieldsWhileGateOff
        | OuterProfileError::CollapseTag => NodeCoreError::DeliveryModeRefused,
        _ => NodeCoreError::InvalidConfiguration(error.to_string()),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
thread_local! { pub(crate) static SIZED_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

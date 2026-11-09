// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent byte walker for pairing-relay retained structures. Production-compiled,
//! allocation-free. Sums `capacity()`/`len()` of owned buffers plus [`ENTRY_OVERHEAD`].
use super::limits::ENTRY_OVERHEAD;
use super::store::{ClaimEntry, ClosedSlot, Direction, IssuedSlot, LiveSlot, Slot, SlotBody};
use ramflux_protocol::custody::pairing::Commit;
use ramflux_protocol::custody::pairing::native::{CreateTicket, Invitation};
use ramflux_protocol::custody::pairing::relay::RelayFrame;
use ramflux_protocol::custody::{DeviceRef, Envelope};
use std::collections::{HashMap, VecDeque};
use std::mem::size_of;

pub(super) fn table_bytes<K, V>(map: &HashMap<K, V>) -> usize {
    map.capacity().saturating_mul(ENTRY_OVERHEAD)
}

pub(super) fn heap_str(value: &String) -> usize {
    value.capacity()
}

pub(super) fn hour_payload(times: &VecDeque<u64>) -> usize {
    times.capacity().saturating_mul(size_of::<u64>())
}

pub(super) fn claim_payload(entry: &ClaimEntry) -> usize {
    entry
        .prefixes
        .capacity()
        .saturating_mul(size_of::<String>())
        .saturating_add(entry.prefixes.iter().map(heap_str).sum())
}

pub(super) fn closed_payload(closed: &ClosedSlot) -> usize {
    heap_str(&closed.reason).saturating_add(ENTRY_OVERHEAD)
}

pub(super) fn slot_payload(slot: &Slot) -> usize {
    match &slot.body {
        SlotBody::Issued(issued) => size_of::<IssuedSlot>().saturating_add(issued_heap(issued)),
        SlotBody::Live(live) => size_of::<LiveSlot>().saturating_add(live_heap(live)),
    }
}

pub(super) fn frame_heap(frame: &RelayFrame) -> usize {
    match frame {
        RelayFrame::Commit { value } => commit_heap(value),
        RelayFrame::RevealChunk { object_id, bytes, .. }
        | RelayFrame::OfferChunk { object_id, bytes, .. } => {
            heap_str(object_id).saturating_add(heap_str(bytes))
        }
        RelayFrame::Confirm { role, transcript_hash, mac } => {
            heap_str(role).saturating_add(heap_str(transcript_hash)).saturating_add(heap_str(mac))
        }
        RelayFrame::Channel { ciphertext, .. } => heap_str(ciphertext),
    }
}

pub(super) fn frame_list_heap(frames: &[(u64, RelayFrame)]) -> usize {
    frames.iter().map(|(_, frame)| frame_heap(frame)).sum()
}

pub(super) fn direction_payload(direction: &Direction) -> usize {
    direction
        .frames
        .capacity()
        .saturating_mul(ENTRY_OVERHEAD)
        .saturating_add(frame_list_heap(&direction.frames))
        .saturating_add(direction.poll_times.capacity().saturating_mul(size_of::<u64>()))
        .saturating_add(direction.last_send.as_ref().map_or(0, |(_, digest)| heap_str(digest)))
}

fn issued_heap(issued: &IssuedSlot) -> usize {
    envelope_ticket_heap(&issued.ticket)
        .saturating_add(heap_str(&issued.spec_hash))
        .saturating_add(device_ref_heap(&issued.primary_ref))
}

fn live_heap(live: &LiveSlot) -> usize {
    envelope_ticket_heap(&live.ticket)
        .saturating_add(envelope_invitation_heap(&live.descriptor))
        .saturating_add(direction_payload(&live.initiator))
        .saturating_add(direction_payload(&live.responder))
        .saturating_add(live.closed_reason.as_ref().map_or(0, heap_str))
}

fn envelope_ticket_heap(envelope: &Envelope<CreateTicket>) -> usize {
    heap_str(&envelope.signature).saturating_add(ticket_heap(&envelope.body))
}

fn envelope_invitation_heap(envelope: &Envelope<Invitation>) -> usize {
    heap_str(&envelope.signature).saturating_add(invitation_heap(&envelope.body))
}

fn ticket_heap(ticket: &CreateTicket) -> usize {
    heap_str(&ticket.schema)
        .saturating_add(heap_str(&ticket.node_key))
        .saturating_add(heap_str(&ticket.boot_id))
        .saturating_add(heap_str(&ticket.create_id))
        .saturating_add(heap_str(&ticket.account_anchor))
        .saturating_add(device_ref_heap(&ticket.primary_ref))
        .saturating_add(heap_str(&ticket.spec_hash))
}

fn invitation_heap(invitation: &Invitation) -> usize {
    heap_str(&invitation.schema)
        .saturating_add(heap_str(&invitation.invitation_id))
        .saturating_add(heap_str(&invitation.request_id))
        .saturating_add(heap_str(&invitation.node_key))
        .saturating_add(heap_str(&invitation.public_origin))
        .saturating_add(heap_str(&invitation.account_anchor))
        .saturating_add(device_ref_heap(&invitation.primary_ref))
        .saturating_add(heap_str(&invitation.base_record_hash))
        .saturating_add(heap_str(&invitation.purpose))
        .saturating_add(heap_str(&invitation.recipient_mode))
        .saturating_add(invitation.destination_ref.as_ref().map_or(0, device_ref_heap))
        .saturating_add(string_vec_heap(
            invitation.capabilities.capacity(),
            &invitation.capabilities,
        ))
        .saturating_add(data_selection_heap(
            invitation.data_selection.capacity(),
            &invitation.data_selection,
        ))
        .saturating_add(invitation.transfer_id.as_ref().map_or(0, heap_str))
}

fn device_ref_heap(device: &DeviceRef) -> usize {
    heap_str(&device.account_anchor).saturating_add(heap_str(&device.device_id))
}

fn string_vec_heap(capacity: usize, values: &[String]) -> usize {
    capacity.saturating_mul(size_of::<String>()).saturating_add(values.iter().map(heap_str).sum())
}

fn data_selection_heap(
    capacity: usize,
    rows: &[ramflux_protocol::custody::pairing::DataSelection],
) -> usize {
    capacity
        .saturating_mul(size_of::<ramflux_protocol::custody::pairing::DataSelection>())
        .saturating_add(
            rows.iter()
                .map(|row| heap_str(&row.key_id).saturating_add(heap_str(&row.purpose)))
                .sum(),
        )
}

fn commit_heap(commit: &Commit) -> usize {
    heap_str(&commit.schema)
        .saturating_add(heap_str(&commit.invitation_id))
        .saturating_add(heap_str(&commit.role))
        .saturating_add(heap_str(&commit.commitment))
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent byte walker for pairing-relay retained structures. Production-compiled,
//! allocation-free. Sums `capacity()`/`len()` of owned buffers plus per-table overhead.
//! Exhaustive destructures so a new owned field is a compile error.
use super::limits::ENTRY_OVERHEAD;
use super::store::{ClaimEntry, ClosedSlot, Direction, IssuedSlot, LiveSlot, Slot, SlotBody};
use ramflux_protocol::custody::pairing::Commit;
use ramflux_protocol::custody::pairing::native::{CreateTicket, Invitation};
use ramflux_protocol::custody::pairing::relay::RelayFrame;
use ramflux_protocol::custody::{DeviceRef, Envelope};
use std::collections::{HashMap, VecDeque};
use std::mem::size_of;

pub(super) const fn entry_overhead<T>() -> usize {
    let size = size_of::<T>();
    if size > ENTRY_OVERHEAD { size } else { ENTRY_OVERHEAD }
}

pub(super) fn table_bytes<K, V>(map: &HashMap<K, V>) -> usize {
    map.capacity().saturating_mul(entry_overhead::<(K, V)>())
}

pub(super) fn heap_str(value: &String) -> usize {
    value.capacity()
}

pub(super) fn hour_payload(times: &VecDeque<u64>) -> usize {
    times.capacity().saturating_mul(size_of::<u64>())
}

pub(super) fn claim_payload(entry: &ClaimEntry) -> usize {
    let ClaimEntry { prefixes, expires_ms } = entry;
    let _ = expires_ms;
    prefixes
        .capacity()
        .saturating_mul(entry_overhead::<String>())
        .saturating_add(prefixes.iter().map(heap_str).sum())
}

pub(super) fn closed_payload(closed: &ClosedSlot) -> usize {
    let ClosedSlot {
        reason,
        issuer_seq,
        primary_hash,
        recipient_hash,
        expires_at,
        monotonic_deadline,
    } = closed;
    let _ = (issuer_seq, primary_hash, recipient_hash, expires_at, monotonic_deadline);
    heap_str(reason).saturating_add(entry_overhead::<ClosedSlot>())
}

pub(super) fn slot_payload(slot: &Slot) -> usize {
    let Slot { allocation, account, expires_at, monotonic_deadline, body } = slot;
    let _ = (allocation, account, expires_at, monotonic_deadline);
    slot_body_payload(body)
}

pub(super) fn slot_body_payload(body: &SlotBody) -> usize {
    match body {
        SlotBody::Issued(issued) => size_of::<IssuedSlot>().saturating_add(issued_heap(issued)),
        SlotBody::Live(live) => size_of::<LiveSlot>().saturating_add(live_heap(live)),
    }
}

pub(super) fn frame_heap(frame: &RelayFrame) -> usize {
    match frame {
        RelayFrame::Commit { value } => commit_heap(value),
        RelayFrame::RevealChunk { object_id, index, count, total_bytes, bytes }
        | RelayFrame::OfferChunk { object_id, index, count, total_bytes, bytes } => {
            let _ = (index, count, total_bytes);
            heap_str(object_id).saturating_add(heap_str(bytes))
        }
        RelayFrame::Confirm { role, transcript_hash, mac } => {
            heap_str(role).saturating_add(heap_str(transcript_hash)).saturating_add(heap_str(mac))
        }
        RelayFrame::Channel { counter, ciphertext } => {
            let _ = counter;
            heap_str(ciphertext)
        }
    }
}

pub(super) fn frame_list_heap(frames: &[(u64, RelayFrame)]) -> usize {
    frames.iter().map(|(_, frame)| frame_heap(frame)).sum()
}

pub(super) fn direction_payload(direction: &Direction) -> usize {
    let Direction { frames, next_send_seq, last_send, acked_seq, poll_times } = direction;
    let _ = (next_send_seq, acked_seq);
    frames
        .capacity()
        .saturating_mul(entry_overhead::<(u64, RelayFrame)>())
        .saturating_add(frame_list_heap(frames))
        .saturating_add(poll_times.capacity().saturating_mul(size_of::<u64>()))
        .saturating_add(last_send.as_ref().map_or(0, |(_, digest)| heap_str(digest)))
}

fn issued_heap(issued: &IssuedSlot) -> usize {
    let IssuedSlot { ticket, spec_hash, primary_ref } = issued;
    envelope_ticket_heap(ticket)
        .saturating_add(heap_str(spec_hash))
        .saturating_add(device_ref_heap(primary_ref))
}

fn live_heap(live: &LiveSlot) -> usize {
    let LiveSlot {
        data_lease,
        ticket,
        descriptor,
        primary_token,
        recipient_token,
        claim_nonce,
        initiator,
        responder,
        closed_reason,
        last_activity_ms,
    } = live;
    let _ = (primary_token, recipient_token, claim_nonce, last_activity_ms);
    envelope_ticket_heap(ticket)
        .saturating_add(envelope_invitation_heap(descriptor))
        .saturating_add(direction_payload(initiator))
        .saturating_add(direction_payload(responder))
        .saturating_add(closed_reason.as_ref().map_or(0, heap_str))
        .saturating_add(data_lease.as_ref().map_or(0, |lease| lease_cache_heap(lease)))
}

fn envelope_ticket_heap(envelope: &Envelope<CreateTicket>) -> usize {
    let Envelope { body, signature } = envelope;
    heap_str(signature).saturating_add(ticket_heap(body))
}

fn envelope_invitation_heap(envelope: &Envelope<Invitation>) -> usize {
    let Envelope { body, signature } = envelope;
    heap_str(signature).saturating_add(invitation_heap(body))
}

fn ticket_heap(ticket: &CreateTicket) -> usize {
    let CreateTicket {
        schema,
        version,
        node_key,
        boot_id,
        create_id,
        issuer_seq,
        account_anchor,
        primary_ref,
        spec_hash,
        issued_at,
        expires_at,
    } = ticket;
    let _ = (version, issuer_seq, issued_at, expires_at);
    heap_str(schema)
        .saturating_add(heap_str(node_key))
        .saturating_add(heap_str(boot_id))
        .saturating_add(heap_str(create_id))
        .saturating_add(heap_str(account_anchor))
        .saturating_add(device_ref_heap(primary_ref))
        .saturating_add(heap_str(spec_hash))
}

fn invitation_heap(invitation: &Invitation) -> usize {
    let Invitation {
        schema,
        version,
        invitation_id,
        issuer_seq,
        request_id,
        node_key,
        public_origin,
        account_anchor,
        primary_ref,
        base_record_hash,
        base_epoch,
        purpose,
        recipient_mode,
        destination_ref,
        capabilities,
        lease_not_before,
        lease_expires_at,
        data_selection,
        transfer_id,
        created_at,
        expires_at,
    } = invitation;
    let _ = (
        version,
        issuer_seq,
        base_epoch,
        lease_not_before,
        lease_expires_at,
        created_at,
        expires_at,
    );
    heap_str(schema)
        .saturating_add(heap_str(invitation_id))
        .saturating_add(heap_str(request_id))
        .saturating_add(heap_str(node_key))
        .saturating_add(heap_str(public_origin))
        .saturating_add(heap_str(account_anchor))
        .saturating_add(device_ref_heap(primary_ref))
        .saturating_add(heap_str(base_record_hash))
        .saturating_add(heap_str(purpose))
        .saturating_add(heap_str(recipient_mode))
        .saturating_add(destination_ref.as_ref().map_or(0, device_ref_heap))
        .saturating_add(string_vec_heap(capabilities.capacity(), capabilities))
        .saturating_add(data_selection_heap(data_selection.capacity(), data_selection))
        .saturating_add(transfer_id.as_ref().map_or(0, heap_str))
}

fn device_ref_heap(device: &DeviceRef) -> usize {
    let DeviceRef { account_anchor, device_id, device_epoch } = device;
    let _ = device_epoch;
    heap_str(account_anchor).saturating_add(heap_str(device_id))
}

fn string_vec_heap(capacity: usize, values: &[String]) -> usize {
    capacity
        .saturating_mul(entry_overhead::<String>())
        .saturating_add(values.iter().map(heap_str).sum())
}

fn data_selection_heap(
    capacity: usize,
    rows: &[ramflux_protocol::custody::pairing::DataSelection],
) -> usize {
    capacity
        .saturating_mul(entry_overhead::<ramflux_protocol::custody::pairing::DataSelection>())
        .saturating_add(rows.iter().map(selection_heap).sum())
}

fn selection_heap(row: &ramflux_protocol::custody::pairing::DataSelection) -> usize {
    let ramflux_protocol::custody::pairing::DataSelection { key_id, purpose } = row;
    heap_str(key_id).saturating_add(heap_str(purpose))
}

fn commit_heap(commit: &Commit) -> usize {
    let Commit { schema, version, invitation_id, role, commitment } = commit;
    let _ = version;
    heap_str(schema)
        .saturating_add(heap_str(invitation_id))
        .saturating_add(heap_str(role))
        .saturating_add(heap_str(commitment))
}

pub(super) fn lease_cache_heap(cache: &super::store::LeaseCache) -> usize {
    use ramflux_protocol::custody::pairing::full_transfer::lease::{
        BranchKeys, DataGrant, DataLease,
    };
    let super::store::LeaseCache { request_hash, lease } = cache;
    let _ = request_hash;
    let Envelope { body, signature } = lease;
    let DataLease { schema, version, lease_id, grant, issued_at, expires_at } = body;
    let _ = (version, issued_at, expires_at);
    let DataGrant {
        schema: grant_schema,
        version: grant_version,
        transfer_id,
        node_id,
        source_ref,
        destination_ref,
        branch_keys,
        opaque_commitment,
        expires_at: grant_expiry,
    } = grant;
    let _ = (grant_version, grant_expiry);
    let BranchKeys { source, destination } = branch_keys;
    size_of::<super::store::LeaseCache>()
        + [
            schema,
            lease_id,
            grant_schema,
            transfer_id,
            node_id,
            opaque_commitment,
            source,
            destination,
            signature,
        ]
        .into_iter()
        .map(heap_str)
        .sum::<usize>()
        + device_ref_heap(source_ref)
        + device_ref_heap(destination_ref)
}

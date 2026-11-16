// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Select one entry and import. A missing entry shows the message and refuses the body.

use ramflux_crypto::large_attachment::{
    DeviceTarget, KeySlotBinding, KeySlotParties, open_file_key, open_segment,
};
use ramflux_protocol::large_attachment::{
    AttachmentRegistrationReceipt, SEGMENT_BYTES, SegmentLayout,
};

use super::codes::{CODE_LAYOUT_INVALID, CODE_NOT_GRANTEE, CODE_SEAL_FAILED, Refusal};
use super::meta::Row;
use super::owner_wire::decode_hex;
use super::plane::{self, Plane, ReadCall};
use super::seal_job::segment_name_of;
use super::store::Store;

pub(crate) struct Importer<'a> {
    pub account_anchor: &'a str,
    pub device_id: &'a str,
    pub device_epoch: u64,
    pub secret: &'a [u8; 32],
}

pub(crate) struct SourcePin<'a> {
    pub source: &'a str,
    pub generation: u64,
    pub public_key: &'a [u8; 32],
    pub now: u64,
}

/// # Errors
/// Returns `not_grantee` when this device has no entry. No relay read is performed.
pub(crate) fn select<'a>(
    media: &'a ramflux_protocol::message::MediaRef,
    importer: &Importer<'_>,
) -> Result<&'a ramflux_protocol::message::MediaKeySlot, Refusal> {
    media
        .key_slots
        .iter()
        .find(|slot| matches_slot(slot, importer))
        .ok_or(Refusal::new(CODE_NOT_GRANTEE))
}

/// # Errors
/// Returns `not_grantee` before `plane.read`, or `seal_failed` when the body will not open.
pub(crate) fn import_entry(
    plane: &dyn Plane,
    media: &ramflux_protocol::message::MediaRef,
    importer: &Importer<'_>,
    pin: &SourcePin<'_>,
) -> Result<Vec<u8>, Refusal> {
    let slot = select(media, importer)?;
    let object_id = decode_hex(&media.object_id)?;
    let manifest = media.large_manifest.as_ref().ok_or(Refusal::new(CODE_LAYOUT_INVALID))?;
    if !manifest.read_capability.is_empty() {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    let relay_hash = hash32(&manifest.manifest_id)?;
    let (grant, _) = AttachmentRegistrationReceipt::decode_capability(
        &slot.read_capability,
        pin.source,
        pin.generation,
        pin.public_key,
        pin.now,
    )
    .map_err(|_| Refusal::new(CODE_NOT_GRANTEE))?;
    let grant_id = hash32(&slot.grant_id)?;
    let device = DeviceTarget {
        account_anchor: importer.account_anchor.to_owned(),
        device_id: importer.device_id.to_owned(),
        device_epoch: importer.device_epoch,
    };
    let key = open_file_key(
        slot.format,
        &slot.encrypted_key,
        importer.secret,
        &KeySlotBinding {
            object_id,
            relay_hash,
            account_anchor: importer.account_anchor.to_owned(),
            device_id: importer.device_id.to_owned(),
            device_epoch: importer.device_epoch,
            grant_id,
            reference_id: grant.grant().reference_id,
        },
        &KeySlotParties { caller: &device, slot_recipient: &device, grant_grantee: &device },
    )
    .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let layout = SegmentLayout {
        plaintext_length: manifest.plaintext_length,
        network_chunk_bytes: manifest.network_chunk_bytes,
    };
    read_plain(plane, &slot.read_capability, object_id, relay_hash, layout, &key)
}

/// The sender opens a file this account sealed. No entry is required.
/// # Errors
/// Returns `seal_failed` when the local segments do not open.
pub(crate) fn import_owned(store: &Store, row: &Row) -> Result<Vec<u8>, Refusal> {
    let (key, object_id) = store.open_secret(row)?;
    let length = row.plaintext_length.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let layout = SegmentLayout { plaintext_length: length, network_chunk_bytes: 524_288 };
    let (count, _) = layout.dimensions().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    let mut plain = Vec::new();
    for index in 0..count {
        let name = segment_name_of(index);
        let cipher = store.read_named(&row.prepare_id, &name)?;
        let opened = open_segment(&key, &object_id, layout, u64::from(index), &cipher)
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        plain.extend_from_slice(opened.as_staging_bytes());
    }
    Ok(plain)
}

fn read_plain(
    plane: &dyn Plane,
    capability: &[u8],
    object_id: [u8; 32],
    relay_hash: [u8; 32],
    layout: SegmentLayout,
    key: &[u8; 32],
) -> Result<Vec<u8>, Refusal> {
    let (count, _) = layout.dimensions().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    let mut plain = Vec::new();
    for index in 0..count {
        let len = layout
            .segment_plaintext_length(u64::from(index))
            .map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?
            + 16;
        if len > u64::from(SEGMENT_BYTES) {
            return Err(Refusal::new(CODE_LAYOUT_INVALID));
        }
        let call = ReadCall {
            capability,
            object_id: &object_id,
            manifest_hash: &relay_hash,
            index: u64::from(index),
            offset: 0,
            length: len,
        };
        plane::read_bounded(&call)?;
        let cipher = plane.read(&call)?;
        let opened = open_segment(key, &object_id, layout, u64::from(index), &cipher)
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        plain.extend_from_slice(opened.as_staging_bytes());
    }
    Ok(plain)
}

fn matches_slot(slot: &ramflux_protocol::message::MediaKeySlot, importer: &Importer<'_>) -> bool {
    slot.recipient.as_ref().is_some_and(|recipient| {
        recipient.account_anchor == importer.account_anchor
            && recipient.device_id == importer.device_id
            && recipient.device_epoch == importer.device_epoch
    })
}

fn hash32(bytes: &[u8]) -> Result<[u8; 32], Refusal> {
    bytes.try_into().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))
}

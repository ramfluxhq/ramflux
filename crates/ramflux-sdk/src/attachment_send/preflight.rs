// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Size the real roster before Reserve. Sixty-four is only a count ceiling.

use prost::Message as _;
use ramflux_protocol::large_attachment::{
    MAX_MANIFEST_BYTES, MediaKeySlot, MediaManifest, MediaRef, QualifiedDevice, SEGMENT_BYTES,
    SegmentLayout,
};
use ramflux_protocol::message::outer::{MAX_INNER_BYTES, MAX_UNPADDED_PLAINTEXT_BYTES};

use super::codes::{CODE_LAYOUT_INVALID, CODE_MANIFEST_TOO_LARGE, Refusal};
use super::targets::MediaDevice;

const NETWORK_CHUNK: u32 = 524_288;
const FRAME: usize = 36;

/// One file in the ordered prepare list.
pub(crate) struct FileBound<'a> {
    pub mime: &'a str,
    pub name: &'a str,
    pub plaintext_length: u64,
}

/// # Errors
/// Returns `manifest_too_large` or `layout_invalid` before any reservation.
#[derive(Clone, Copy)]
pub(crate) struct IdentityLen<'a> {
    pub account: &'a str,
    pub device: &'a str,
    pub home: &'a str,
}

/// # Errors
/// Returns `manifest_too_large` or `layout_invalid` before any reservation.
pub(crate) fn measure(
    files: &[FileBound<'_>],
    targets: &[MediaDevice],
    caption: &str,
    owner: IdentityLen<'_>,
    source: &str,
) -> Result<(), Refusal> {
    if files.is_empty() || files.len() > super::meta::MAX_ATTACHMENTS {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    let slots = slots(targets, &owner, source)?;
    let mut media = Vec::with_capacity(files.len());
    for file in files {
        let reference = one_ref(file, &slots)?;
        media.push(to_prost(&reference));
    }
    let inner = ramflux_protocol::message::Message {
        text: caption.to_owned(),
        media,
        ..Default::default()
    };
    let encoded = inner.encode_to_vec();
    if encoded.len() > MAX_INNER_BYTES
        || encoded.len().saturating_add(FRAME) > MAX_UNPADDED_PLAINTEXT_BYTES
    {
        return Err(Refusal::new(CODE_MANIFEST_TOO_LARGE));
    }
    Ok(())
}

/// A manifest-level read capability is not this layout.
/// # Errors
/// Returns `layout_invalid` when the bytes are not empty.
pub(crate) fn manifest_capability(bytes: &[u8]) -> Result<(), Refusal> {
    if bytes.is_empty() { Ok(()) } else { Err(Refusal::new(CODE_LAYOUT_INVALID)) }
}

fn slots(
    targets: &[MediaDevice],
    owner: &IdentityLen<'_>,
    source: &str,
) -> Result<Vec<MediaKeySlot>, Refusal> {
    let owner_len = qualified_len(owner.account, owner.device, owner.home)?;
    let mut slots = Vec::with_capacity(targets.len());
    for target in targets {
        let length = capability_len(target, owner_len, source)?;
        if length > 8192 {
            return Err(Refusal::new(CODE_LAYOUT_INVALID));
        }
        slots.push(MediaKeySlot {
            recipient: QualifiedDevice {
                account_anchor: target.account_anchor.clone(),
                device_id: target.device_id.clone(),
                device_epoch: target.device_epoch,
            },
            encrypted_key: vec![1_u8; 80],
            format: 1,
            grant_id: vec![1_u8; 32],
            read_capability: vec![1_u8; length],
        });
    }
    Ok(slots)
}

pub(super) fn capability_len(
    target: &MediaDevice,
    owner_len: usize,
    source: &str,
) -> Result<usize, Refusal> {
    let grant = qualified_len(&target.account_anchor, &target.device_id, &target.home_node_id)?
        .saturating_add(owner_len)
        .saturating_add(8 + 128 + 8 + 4 + 8 + 8);
    let signed = 4 + 4 + grant + 4 + 64;
    let receipt = 4 + 4 + 32 + 8 + 4 + source.len() + 8 + 8;
    let container = 4 + receipt + 4 + 64;
    Ok(signed + 4 + container)
}

pub(super) fn qualified_len(account: &str, device: &str, home: &str) -> Result<usize, Refusal> {
    for part in [account, device, home] {
        if part.is_empty() || part.len() > 256 {
            return Err(Refusal::new(CODE_LAYOUT_INVALID));
        }
    }
    Ok(4 + account.len() + 4 + device.len() + 8 + 32 + 4 + home.len())
}

fn one_ref(file: &FileBound<'_>, slots: &[MediaKeySlot]) -> Result<MediaRef, Refusal> {
    let layout = SegmentLayout {
        plaintext_length: file.plaintext_length,
        network_chunk_bytes: NETWORK_CHUNK,
    };
    let (count, cipher) = layout.dimensions().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    let digests = vec![[2_u8; 32]; usize::try_from(count).unwrap_or(0)];
    let large = MediaManifest {
        manifest_id: [3_u8; 32],
        plaintext_digest: [4_u8; 32],
        plaintext_length: file.plaintext_length,
        ciphertext_length: cipher,
        encrypted_segment_bytes: SEGMENT_BYTES,
        network_chunk_bytes: NETWORK_CHUNK,
        segment_digests: digests,
        key_slots: slots.to_vec(),
        relay_origin: "node".into(),
        read_capability: Vec::new(),
        expires_at: 1,
        retention_class: "relay_retained.v1".into(),
    };
    let digest = large.hash().map_err(|_| Refusal::new(CODE_MANIFEST_TOO_LARGE))?;
    let reference = MediaRef {
        mime_type: file.mime.to_owned(),
        file_name: Some(file.name.to_owned()),
        inline_thumbnail: None,
        object_id: "00".repeat(32),
        manifest_digest: digest,
        size: file.plaintext_length,
        key_slots: slots.to_vec(),
        large_manifest: large,
    };
    match reference.canonical_bytes() {
        Ok(bytes) if bytes.len() <= MAX_MANIFEST_BYTES => Ok(reference),
        Ok(_) => Err(Refusal::new(CODE_MANIFEST_TOO_LARGE)),
        Err(error) if error.0.contains("cap") => Err(Refusal::new(CODE_MANIFEST_TOO_LARGE)),
        Err(_) => Err(Refusal::new(CODE_LAYOUT_INVALID)),
    }
}

pub(crate) fn to_prost(reference: &MediaRef) -> ramflux_protocol::message::MediaRef {
    ramflux_protocol::message::MediaRef {
        object_id: reference.object_id.clone(),
        manifest_digest: reference.manifest_digest.to_vec(),
        mime_type: reference.mime_type.clone(),
        size: reference.size,
        key_slots: reference.key_slots.iter().map(prost_slot).collect(),
        file_name: reference.file_name.clone(),
        inline_thumbnail: None,
        large_manifest: Some(prost_manifest(&reference.large_manifest)),
    }
}

fn prost_slot(slot: &MediaKeySlot) -> ramflux_protocol::message::MediaKeySlot {
    ramflux_protocol::message::MediaKeySlot {
        recipient: Some(ramflux_protocol::message::QualifiedDevice {
            account_anchor: slot.recipient.account_anchor.clone(),
            device_id: slot.recipient.device_id.clone(),
            device_epoch: slot.recipient.device_epoch,
        }),
        encrypted_key: slot.encrypted_key.clone(),
        format: slot.format,
        grant_id: slot.grant_id.clone(),
        read_capability: slot.read_capability.clone(),
    }
}

fn prost_manifest(inner: &MediaManifest) -> ramflux_protocol::message::MediaManifest {
    ramflux_protocol::message::MediaManifest {
        manifest_id: inner.manifest_id.to_vec(),
        plaintext_digest: inner.plaintext_digest.to_vec(),
        plaintext_length: inner.plaintext_length,
        ciphertext_length: inner.ciphertext_length,
        encrypted_segment_bytes: inner.encrypted_segment_bytes,
        network_chunk_bytes: inner.network_chunk_bytes,
        segment_digests: inner.segment_digests.iter().map(|item| item.to_vec()).collect(),
        key_slots: inner.key_slots.iter().map(prost_slot).collect(),
        relay_origin: inner.relay_origin.clone(),
        read_capability: inner.read_capability.clone(),
        expires_at: inner.expires_at,
        retention_class: inner.retention_class.clone(),
    }
}

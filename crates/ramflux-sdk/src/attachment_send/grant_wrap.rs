// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One owner-signed grant per target, then one HPKE wrap. The manifest capability stays empty.

use ed25519_dalek::{Signer, SigningKey};
use prost::Message as _;
use ramflux_crypto::large_attachment::{KeySlotBinding, wrap_file_key};
use ramflux_protocol::large_attachment::{
    MediaKeySlot, MediaManifest, MediaRef, QualifiedDevice, QualifiedOwner, SEGMENT_BYTES,
    ScopedAttachmentGrant, SegmentLayout, digest,
};
use ramflux_protocol::message::outer::{MAX_INNER_BYTES, MAX_UNPADDED_PLAINTEXT_BYTES};

use super::codes::{CODE_LAYOUT_INVALID, CODE_MANIFEST_TOO_LARGE, CODE_SEAL_FAILED, Refusal};
use super::meta::Row;
use super::owner_wire::encode_hex;
use super::plane::{self, Plane, RegisterCall};
use super::preflight;
use super::store::Store;
use super::targets::MediaDevice;

const NETWORK_CHUNK: u32 = 524_288;
const READER_RIGHTS: u32 = 15;

pub(crate) struct WrapInput<'a> {
    pub store: &'a Store,
    pub plane: &'a dyn Plane,
    pub row: &'a Row,
    pub owner: &'a QualifiedOwner,
    pub owner_key: &'a SigningKey,
    pub targets: &'a [MediaDevice],
    pub manifest: &'a [u8],
    pub relay_hash: [u8; 32],
    pub source: &'a str,
    pub now: u64,
    pub caption: &'a str,
}

#[derive(Debug)]
pub(crate) struct Wrapped {
    pub media: ramflux_protocol::message::MediaRef,
}

/// # Errors
/// Returns a stable refusal when a grant, the Inner, or the group frame does not fit.
pub(crate) fn wrap(input: &WrapInput<'_>) -> Result<Wrapped, Refusal> {
    if let Ok(stored) = input.store.read_named(&input.row.prepare_id, "media.bin") {
        let media = ramflux_protocol::message::MediaRef::decode(stored.as_slice())
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        input.store.read_named(&input.row.prepare_id, "inner.bin")?;
        return Ok(Wrapped { media });
    }
    let slots = slots(input)?;
    let reference = media_ref(input, slots)?;
    let prost_media = preflight::to_prost(&reference);
    let inner = ramflux_protocol::message::Message {
        text: input.caption.to_owned(),
        media: vec![prost_media.clone()],
        ..Default::default()
    }
    .encode_to_vec();
    if inner.len() > MAX_INNER_BYTES
        || inner.len().saturating_add(36) > MAX_UNPADDED_PLAINTEXT_BYTES
    {
        return Err(Refusal::new(CODE_MANIFEST_TOO_LARGE));
    }
    input.store.write_named(&input.row.prepare_id, "media.bin", &prost_media.encode_to_vec())?;
    input.store.write_named(&input.row.prepare_id, "inner.bin", &inner)?;
    Ok(Wrapped { media: prost_media })
}

fn slots(input: &WrapInput<'_>) -> Result<Vec<MediaKeySlot>, Refusal> {
    let (file_key, object_id) = input.store.open_secret(input.row)?;
    let mut slots = Vec::with_capacity(input.targets.len());
    for target in input.targets {
        slots.push(one_slot(input, target, &file_key, object_id)?);
    }
    Ok(slots)
}

fn one_slot(
    input: &WrapInput<'_>,
    target: &MediaDevice,
    file_key: &[u8; 32],
    object_id: [u8; 32],
) -> Result<MediaKeySlot, Refusal> {
    let grant_id = fresh_id()?;
    let reference_id = reference(object_id, grant_id)?;
    let grant = ScopedAttachmentGrant {
        grant_id,
        reference_id,
        object_id,
        manifest_hash: input.relay_hash,
        owner: input.owner.clone(),
        grantee: grantee(target),
        epoch: 1,
        rights: READER_RIGHTS,
        issued_at: input.now,
        expires_at: input.now.saturating_add(3600),
    };
    let signature = input
        .owner_key
        .sign(&grant.signing_bytes().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?)
        .to_bytes();
    let signed = grant.signed_bytes(&signature).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    let upload = input.row.upload_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let call = RegisterCall { upload_id: &upload, manifest: input.manifest, grant: &signed };
    plane::register_ready(&call)?;
    let capability = input.plane.register(&call)?;
    if capability.len() > 8192 {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    let binding = KeySlotBinding {
        object_id,
        relay_hash: input.relay_hash,
        account_anchor: target.account_anchor.clone(),
        device_id: target.device_id.clone(),
        device_epoch: target.device_epoch,
        grant_id,
        reference_id,
    };
    let encrypted = wrap_file_key(file_key, &target.hpke_public, &binding)
        .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    Ok(MediaKeySlot {
        recipient: QualifiedDevice {
            account_anchor: target.account_anchor.clone(),
            device_id: target.device_id.clone(),
            device_epoch: target.device_epoch,
        },
        encrypted_key: encrypted,
        format: 1,
        grant_id: grant_id.to_vec(),
        read_capability: capability,
    })
}

fn media_ref(input: &WrapInput<'_>, slots: Vec<MediaKeySlot>) -> Result<MediaRef, Refusal> {
    preflight::manifest_capability(&[])?;
    let length = input.row.plaintext_length.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let layout = SegmentLayout { plaintext_length: length, network_chunk_bytes: NETWORK_CHUNK };
    let (_, cipher) = layout.dimensions().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    let digest_bytes = input.row.plaintext_digest.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let large = MediaManifest {
        manifest_id: input.relay_hash,
        plaintext_digest: digest_bytes,
        plaintext_length: length,
        ciphertext_length: cipher,
        encrypted_segment_bytes: SEGMENT_BYTES,
        network_chunk_bytes: NETWORK_CHUNK,
        segment_digests: input.row.segment_digests.clone(),
        key_slots: slots.clone(),
        relay_origin: input.source.to_owned(),
        read_capability: Vec::new(),
        expires_at: input.row.hard_deadline,
        retention_class: "relay_retained.v1".into(),
    };
    let manifest_digest = large.hash().map_err(|_| Refusal::new(CODE_MANIFEST_TOO_LARGE))?;
    let reference = MediaRef {
        mime_type: input.row.mime.clone(),
        file_name: Some(input.row.file_name.clone()),
        inline_thumbnail: None,
        object_id: encode_hex(&input.row.object_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?),
        manifest_digest,
        size: length,
        key_slots: slots,
        large_manifest: large,
    };
    reference.canonical_bytes().map_err(|_| Refusal::new(CODE_MANIFEST_TOO_LARGE))?;
    Ok(reference)
}

fn grantee(target: &MediaDevice) -> QualifiedOwner {
    QualifiedOwner {
        account_anchor: target.account_anchor.clone(),
        device_id: target.device_id.clone(),
        device_epoch: target.device_epoch,
        signing_public_key: target.signing_public,
        home_node_id: target.home_node_id.clone(),
    }
}

fn reference(object_id: [u8; 32], grant_id: [u8; 32]) -> Result<[u8; 32], Refusal> {
    let mut material = [0_u8; 64];
    material[..32].copy_from_slice(&object_id);
    material[32..].copy_from_slice(&grant_id);
    digest("ramflux.attachment.reference.v1", &material)
        .map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))
}

fn fresh_id() -> Result<[u8; 32], Refusal> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    Ok(bytes)
}

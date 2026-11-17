// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One owner-signed grant per target, then one HPKE wrap. The manifest capability stays empty.
//! Every step is durable and idempotent: the grant ids and signed bytes are written before the
//! first registration, a retry registers the same id, and a finished wrap is never redone.

use ed25519_dalek::{Signer, SigningKey};
use prost::Message as _;
use ramflux_crypto::large_attachment::{KeySlotBinding, wrap_file_key};
use ramflux_protocol::large_attachment::{
    MediaKeySlot, MediaManifest, MediaRef, QualifiedDevice, QualifiedOwner, SEGMENT_BYTES,
    ScopedAttachmentGrant, SegmentLayout, digest,
};
use ramflux_protocol::message::outer::{MAX_INNER_BYTES, MAX_UNPADDED_PLAINTEXT_BYTES};

use super::codes::{
    CODE_EXPIRED, CODE_LAYOUT_INVALID, CODE_MANIFEST_TOO_LARGE, CODE_SEAL_FAILED, Refusal,
};
use super::meta::{GrantRecord, Row};
use super::plane::{self, Plane, RegisterCall};
use super::preflight;
use super::store::Store;
use super::targets::MediaDevice;

const NETWORK_CHUNK: u32 = 524_288;
const READER_RIGHTS: u32 = 15;
const GRANTS: &str = "grants.json";
const MEDIA: &str = "media.bin";
const INNER: &str = "inner.bin";

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
    /// Grants of devices that stopped being targets before the Inner was built. They are in
    /// no entry and the caller retires them.
    pub excluded: Vec<GrantRecord>,
}

/// # Errors
/// Returns a stable refusal when a grant, the Inner, or the group frame does not fit.
pub(crate) fn wrap(input: &WrapInput<'_>) -> Result<Wrapped, Refusal> {
    let mut grants = load(input.store, &input.row.prepare_id)?;
    if let Ok(stored) = input.store.read_named(&input.row.prepare_id, MEDIA) {
        input.store.read_named(&input.row.prepare_id, INNER)?;
        let media = ramflux_protocol::message::MediaRef::decode(stored.as_slice())
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let excluded = grants.into_iter().filter(|grant| grant.excluded).collect();
        return Ok(Wrapped { media, excluded });
    }
    let (file_key, object_id) = input.store.open_secret(input.row)?;
    plan(input, &mut grants, object_id)?;
    save(input.store, &input.row.prepare_id, &grants)?;
    for index in 0..grants.len() {
        if grants[index].excluded {
            continue;
        }
        if grants[index].capability.is_none() {
            register(input, &mut grants[index])?;
            save(input.store, &input.row.prepare_id, &grants)?;
        }
        if grants[index].slot.is_none() {
            let target = input
                .targets
                .iter()
                .find(|target| same_device(&grants[index], target))
                .ok_or(Refusal::new(CODE_SEAL_FAILED))?;
            let slot = one_slot(input, target, &grants[index], &file_key, object_id)?;
            grants[index].slot = Some(prost_slot(&slot).encode_to_vec());
            save(input.store, &input.row.prepare_id, &grants)?;
        }
    }
    let slots = ordered_slots(input.targets, &grants)?;
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
    input.store.write_named(&input.row.prepare_id, MEDIA, &prost_media.encode_to_vec())?;
    input.store.write_named(&input.row.prepare_id, INNER, &inner)?;
    let excluded = grants.into_iter().filter(|grant| grant.excluded).collect();
    Ok(Wrapped { media: prost_media, excluded })
}

/// The grants this prepare has recorded, registered or not.
/// # Errors
/// Returns `seal_failed` when the file is unreadable.
pub(crate) fn load(store: &Store, prepare_id: &str) -> Result<Vec<GrantRecord>, Refusal> {
    match store.read_named(prepare_id, GRANTS) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| Refusal::new(CODE_SEAL_FAILED)),
        Err(_) => Ok(Vec::new()),
    }
}

/// # Errors
/// Returns `seal_failed` when the file cannot be written durably.
pub(crate) fn save(store: &Store, prepare_id: &str, grants: &[GrantRecord]) -> Result<(), Refusal> {
    let bytes = serde_json::to_vec(grants).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    store.write_named(prepare_id, GRANTS, &bytes)
}

/// Decodes the retained media reference of a finished wrap, if any.
/// # Errors
/// Returns `seal_failed` when the stored bytes do not decode.
pub(crate) fn stored_media(
    store: &Store,
    prepare_id: &str,
) -> Result<Option<ramflux_protocol::message::MediaRef>, Refusal> {
    match store.read_named(prepare_id, MEDIA) {
        Ok(bytes) => ramflux_protocol::message::MediaRef::decode(bytes.as_slice())
            .map(Some)
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED)),
        Err(_) => Ok(None),
    }
}

/// Marks a recorded grant as no longer part of the roster. The grant is kept so it can be retired.
fn plan(
    input: &WrapInput<'_>,
    grants: &mut Vec<GrantRecord>,
    object_id: [u8; 32],
) -> Result<(), Refusal> {
    for grant in grants.iter_mut() {
        grant.excluded = !input.targets.iter().any(|target| same_device(grant, target));
    }
    for target in input.targets {
        if grants.iter().any(|grant| same_device(grant, target)) {
            continue;
        }
        grants.push(new_grant(input, target, object_id)?);
    }
    Ok(())
}

fn new_grant(
    input: &WrapInput<'_>,
    target: &MediaDevice,
    object_id: [u8; 32],
) -> Result<GrantRecord, Refusal> {
    let expires_at = input.row.hard_deadline;
    if expires_at <= input.now.saturating_add(60) {
        return Err(Refusal::new(CODE_EXPIRED));
    }
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
        expires_at,
    };
    let signature = input
        .owner_key
        .sign(&grant.signing_bytes().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?)
        .to_bytes();
    let signed_grant =
        grant.signed_bytes(&signature).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    Ok(GrantRecord {
        account_anchor: target.account_anchor.clone(),
        device_id: target.device_id.clone(),
        device_epoch: target.device_epoch,
        grant_id,
        reference_id,
        signed_grant,
        capability: None,
        slot: None,
        excluded: false,
    })
}

fn register(input: &WrapInput<'_>, grant: &mut GrantRecord) -> Result<(), Refusal> {
    let upload = input.row.upload_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let call =
        RegisterCall { upload_id: &upload, manifest: input.manifest, grant: &grant.signed_grant };
    plane::register_ready(&call)?;
    let capability = input.plane.register(&call)?;
    if capability.is_empty() || capability.len() > 8192 {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    grant.capability = Some(capability);
    Ok(())
}

fn one_slot(
    input: &WrapInput<'_>,
    target: &MediaDevice,
    grant: &GrantRecord,
    file_key: &[u8; 32],
    object_id: [u8; 32],
) -> Result<MediaKeySlot, Refusal> {
    let capability = grant.capability.clone().ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let binding = KeySlotBinding {
        object_id,
        relay_hash: input.relay_hash,
        account_anchor: target.account_anchor.clone(),
        device_id: target.device_id.clone(),
        device_epoch: target.device_epoch,
        grant_id: grant.grant_id,
        reference_id: grant.reference_id,
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
        grant_id: grant.grant_id.to_vec(),
        read_capability: capability,
    })
}

fn ordered_slots(
    targets: &[MediaDevice],
    grants: &[GrantRecord],
) -> Result<Vec<MediaKeySlot>, Refusal> {
    let mut slots = Vec::with_capacity(targets.len());
    for target in targets {
        let record = grants
            .iter()
            .find(|grant| !grant.excluded && same_device(grant, target))
            .ok_or(Refusal::new(CODE_SEAL_FAILED))?;
        let bytes = record.slot.as_deref().ok_or(Refusal::new(CODE_SEAL_FAILED))?;
        let slot = ramflux_protocol::message::MediaKeySlot::decode(bytes)
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        slots.push(from_prost_slot(&slot)?);
    }
    Ok(slots)
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

fn from_prost_slot(
    slot: &ramflux_protocol::message::MediaKeySlot,
) -> Result<MediaKeySlot, Refusal> {
    let recipient = slot.recipient.as_ref().ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    Ok(MediaKeySlot {
        recipient: QualifiedDevice {
            account_anchor: recipient.account_anchor.clone(),
            device_id: recipient.device_id.clone(),
            device_epoch: recipient.device_epoch,
        },
        encrypted_key: slot.encrypted_key.clone(),
        format: slot.format,
        grant_id: slot.grant_id.clone(),
        read_capability: slot.read_capability.clone(),
    })
}

fn same_device(grant: &GrantRecord, target: &MediaDevice) -> bool {
    grant.account_anchor == target.account_anchor
        && grant.device_id == target.device_id
        && grant.device_epoch == target.device_epoch
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
        object_id: ramflux_protocol::encode_base64url(
            input.row.object_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?,
        ),
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

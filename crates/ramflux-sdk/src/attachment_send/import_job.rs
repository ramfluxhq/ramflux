// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Select one entry, check it against the reference, and stream the plaintext out. Nothing
//! reaches the staging file unless its segment digest matches the manifest, and nothing is
//! marked ready unless the whole plaintext hashes to the manifest digest and length.
//! A missing entry shows the message and refuses the body before any relay read.

use std::io::Write;

use prost::Message as _;
use ramflux_crypto::large_attachment::{
    DeviceTarget, KeySlotBinding, KeySlotParties, open_file_key, open_segment, segment_digest,
};
use ramflux_protocol::large_attachment::{
    AttachmentRegistrationReceipt, MediaManifest, MediaRef, SEGMENT_BYTES, SegmentLayout, digest,
};

use super::budget;
use super::codes::{
    CODE_CANCELLED, CODE_LAYOUT_INVALID, CODE_NOT_GRANTEE, CODE_SEAL_FAILED, Refusal,
};
use super::meta::Row;
use super::plane::{Plane, ReadCall};
use super::seal_job::segment_name_of;
use super::store::Store;

pub(crate) const NETWORK_CHUNK: u32 = 524_288;
const READER_RIGHTS: u32 = 15;

/// The calling device. `secret` is its X25519 agreement secret.
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

/// A reference that passed every identity check, with the file key opened.
pub(crate) struct Opened {
    key: zeroize::Zeroizing<[u8; 32]>,
    object_id: [u8; 32],
    relay_hash: [u8; 32],
    layout: SegmentLayout,
    capability: Vec<u8>,
    manifest: MediaManifest,
}

impl Opened {
    pub(super) fn recovery_key(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(*self.key)
    }
}

/// Decodes the canonical reference. This runs the codec's binding rules: entries equal the
/// manifest's, the manifest digest and size match, entries are unique, and no manifest-level
/// capability is present.
/// # Errors
/// Returns `layout_invalid` for any non-canonical or inconsistent reference.
pub(crate) fn canonical(media: &ramflux_protocol::message::MediaRef) -> Result<MediaRef, Refusal> {
    MediaRef::decode(&media.encode_to_vec())
        .map_err(|_| Refusal::because_of(CODE_LAYOUT_INVALID, "the reference is not canonical"))
}

/// Finds this device's one entry. Zero matches is `not_grantee`; the caller reads nothing.
/// # Errors
/// Returns `not_grantee` or `layout_invalid`.
pub(crate) fn select<'a>(
    reference: &'a MediaRef,
    importer: &Importer<'_>,
) -> Result<&'a ramflux_protocol::large_attachment::MediaKeySlot, Refusal> {
    let mut found = reference.key_slots.iter().filter(|slot| {
        slot.recipient.account_anchor == importer.account_anchor
            && slot.recipient.device_id == importer.device_id
            && slot.recipient.device_epoch == importer.device_epoch
    });
    let slot = found.next().ok_or(Refusal::new(CODE_NOT_GRANTEE))?;
    if found.next().is_some() {
        return Err(Refusal::because_of(CODE_LAYOUT_INVALID, "two entries name this device"));
    }
    Ok(slot)
}

/// Verifies the entry against the reference and opens the file key.
/// # Errors
/// Returns `not_grantee` before any relay read, `layout_invalid` for an identity mismatch,
/// and `seal_failed` when the key slot does not open.
pub(crate) fn open_entry(
    media: &ramflux_protocol::message::MediaRef,
    importer: &Importer<'_>,
    pin: &SourcePin<'_>,
) -> Result<Opened, Refusal> {
    let reference = canonical(media)?;
    let slot = select(&reference, importer)?;
    let manifest = reference.large_manifest.clone();
    let object_id: [u8; 32] = ramflux_protocol::decode_base64url(&reference.object_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Refusal::new(CODE_LAYOUT_INVALID))?;
    let (grant, _receipt) = AttachmentRegistrationReceipt::decode_capability(
        &slot.read_capability,
        pin.source,
        pin.generation,
        pin.public_key,
        pin.now,
    )
    .map_err(|_| Refusal::new(CODE_NOT_GRANTEE))?;
    let g = grant.grant();
    let grant_id: [u8; 32] =
        slot.grant_id.as_slice().try_into().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    let expected_reference = reference_id(object_id, grant_id)?;
    let device = DeviceTarget {
        account_anchor: importer.account_anchor.to_owned(),
        device_id: importer.device_id.to_owned(),
        device_epoch: importer.device_epoch,
    };
    let grantee = DeviceTarget {
        account_anchor: g.grantee.account_anchor.clone(),
        device_id: g.grantee.device_id.clone(),
        device_epoch: g.grantee.device_epoch,
    };
    let recipient = DeviceTarget {
        account_anchor: slot.recipient.account_anchor.clone(),
        device_id: slot.recipient.device_id.clone(),
        device_epoch: slot.recipient.device_epoch,
    };
    if g.grant_id != grant_id
        || g.object_id != object_id
        || g.manifest_hash != manifest.manifest_id
        || g.reference_id != expected_reference
        || g.rights != READER_RIGHTS
        || grantee != device
        || recipient != device
    {
        let why = if g.grant_id != grant_id {
            "grant id differs from the entry"
        } else if g.object_id != object_id {
            "grant object differs from the reference"
        } else if g.manifest_hash != manifest.manifest_id {
            "grant manifest differs from the reference"
        } else if g.reference_id != expected_reference {
            "grant reference id is not derived from object and grant"
        } else if g.rights != READER_RIGHTS {
            "grant rights are not the reader set"
        } else if grantee != device {
            "grant grantee is not this device"
        } else {
            "entry recipient is not this device"
        };
        return Err(Refusal::because_of(CODE_LAYOUT_INVALID, why));
    }
    if manifest.network_chunk_bytes != NETWORK_CHUNK
        || manifest.encrypted_segment_bytes != SEGMENT_BYTES
    {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    let key = open_file_key(
        slot.format,
        &slot.encrypted_key,
        importer.secret,
        &KeySlotBinding {
            object_id,
            relay_hash: manifest.manifest_id,
            account_anchor: importer.account_anchor.to_owned(),
            device_id: importer.device_id.to_owned(),
            device_epoch: importer.device_epoch,
            grant_id,
            reference_id: g.reference_id,
        },
        &KeySlotParties { caller: &device, slot_recipient: &recipient, grant_grantee: &grantee },
    )
    .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    Ok(Opened {
        key: zeroize::Zeroizing::new(*key),
        object_id,
        relay_hash: manifest.manifest_id,
        layout: manifest.layout(),
        capability: slot.read_capability.clone(),
        manifest,
    })
}

/// The durable cache of one remote download: `verified[i]` says segment `i` is on disk and
/// digest-checked. `checkpoint` receives the bitmap after every newly written segment.
pub(crate) struct SegmentCache<'a> {
    pub(crate) dir: &'a std::path::Path,
    pub(crate) verified: Vec<bool>,
    pub(crate) checkpoint: &'a dyn Fn(&[bool]) -> Result<(), Refusal>,
    /// Announces a corrupt or missing cached segment before its refetch. The bit stays set until
    /// the fresh bytes are durable, so the counts never drop.
    pub(crate) integrity: &'a dyn Fn(u32) -> Result<(), Refusal>,
    /// Holds the worker while the download is paused. No relay read happens meanwhile.
    pub(crate) paused: &'a dyn Fn() -> bool,
}

/// How long a paused download sleeps between checks of its flag and the cancel fence.
const PAUSE_POLL: std::time::Duration = std::time::Duration::from_millis(250);

fn hold_while_paused(paused: &dyn Fn() -> bool, fenced: &dyn Fn() -> bool) -> Result<(), Refusal> {
    while paused() {
        if fenced() {
            return Err(Refusal::new(CODE_CANCELLED));
        }
        std::thread::sleep(PAUSE_POLL);
    }
    Ok(())
}

/// Streams the ciphertext from the relay in network-chunk ranges. Verified cached segments are
/// read from the cache (refetched if they no longer match); every other segment is fetched,
/// checked, persisted, and only then marked in the bitmap. Memory stays at one segment of
/// ciphertext plus one of plaintext.
/// # Errors
/// Returns `seal_failed` for any digest, length or open failure, and `cancelled` when
/// `fenced` reports the handle was fenced.
pub(crate) fn stream_remote(
    plane: &dyn Plane,
    opened: &Opened,
    sink: &mut dyn Write,
    fenced: &dyn Fn() -> bool,
    meter: &budget::Meter,
    mut cache: Option<&mut SegmentCache<'_>>,
) -> Result<(), Refusal> {
    let (count, _) = opened.layout.dimensions().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    if opened.manifest.segment_digests.len() != count as usize {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    if cache.as_ref().is_some_and(|cache| cache.verified.len() != count as usize) {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    let mut plain_digest = blake3::Hasher::new();
    let mut written = 0_u64;
    let paused = cache.as_ref().map(|cache| cache.paused);
    let gate = || match paused {
        Some(paused) => hold_while_paused(paused, fenced),
        None => Ok(()),
    };
    for index in 0..count {
        if fenced() {
            return Err(Refusal::new(CODE_CANCELLED));
        }
        let _held = budget::memory_metered(2 * u64::from(SEGMENT_BYTES), meter)?;
        let expected = opened.manifest.segment_digests[index as usize];
        if let Some(paused) = cache.as_ref().map(|cache| cache.paused) {
            hold_while_paused(paused, fenced)?;
        }
        let mut corrupt = false;
        let cached = match cache.as_ref() {
            Some(cache) if cache.verified[index as usize] => {
                let hit = super::import_cache::read(cache.dir, index, expected);
                corrupt = hit.is_none();
                hit
            }
            _ => None,
        };
        if corrupt && let Some(cache) = cache.as_ref() {
            (cache.integrity)(index)?;
        }
        let cipher = if let Some(bytes) = cached {
            bytes
        } else {
            let fresh = fetch_segment(plane, opened, index, &gate)?;
            if segment_digest(&fresh).map_err(|_| Refusal::new(CODE_SEAL_FAILED))? != expected {
                return Err(Refusal::new(CODE_SEAL_FAILED));
            }
            if let Some(cache) = cache.as_mut() {
                super::import_cache::write(cache.dir, index, &fresh)?;
                cache.verified[index as usize] = true;
                (cache.checkpoint)(&cache.verified)?;
            }
            fresh
        };
        let plain =
            open_segment(&opened.key, &opened.object_id, opened.layout, u64::from(index), &cipher)
                .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let bytes = plain.as_staging_bytes();
        plain_digest.update(bytes);
        sink.write_all(bytes).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        written = written.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    }
    finish_checks(written, *plain_digest.finalize().as_bytes(), &opened.manifest)
}

fn finish_checks(written: u64, plain: [u8; 32], manifest: &MediaManifest) -> Result<(), Refusal> {
    if written != manifest.plaintext_length || plain != manifest.plaintext_digest {
        return Err(Refusal::new(CODE_SEAL_FAILED));
    }
    Ok(())
}

/// Fetches one encrypted segment in network chunks. `gate` runs before every relay read, so a
/// paused download issues no further GET; it may block or refuse.
pub(super) fn fetch_segment(
    plane: &dyn Plane,
    opened: &Opened,
    index: u32,
    gate: &dyn Fn() -> Result<(), Refusal>,
) -> Result<Vec<u8>, Refusal> {
    let total = opened
        .layout
        .segment_plaintext_length(u64::from(index))
        .map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?
        + 16;
    if total > u64::from(SEGMENT_BYTES) {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    let mut cipher = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
    let mut offset = 0_u64;
    while offset < total {
        let length = (total - offset).min(u64::from(NETWORK_CHUNK));
        let call = ReadCall {
            capability: &opened.capability,
            object_id: &opened.object_id,
            manifest_hash: &opened.relay_hash,
            index: u64::from(index),
            offset,
            length,
        };
        gate()?;
        super::plane::read_bounded(&call)?;
        let part = plane.read(&call)?;
        if u64::try_from(part.len()).ok() != Some(length) {
            return Err(Refusal::new(CODE_SEAL_FAILED));
        }
        cipher.extend_from_slice(&part);
        offset += length;
    }
    Ok(cipher)
}

/// The sender opens a file this account sealed from its own account-sealed key and the local
/// segments. No entry is required, and the same segment and plaintext digests are checked.
/// # Errors
/// Returns `seal_failed` when the local segments do not open or do not match.
pub(crate) fn stream_owned(
    store: &Store,
    row: &Row,
    sink: &mut dyn Write,
    fenced: &dyn Fn() -> bool,
    meter: &budget::Meter,
) -> Result<(), Refusal> {
    let (key, object_id) = store.open_secret(row)?;
    let length = row.plaintext_length.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let expected = row.plaintext_digest.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let layout = SegmentLayout { plaintext_length: length, network_chunk_bytes: NETWORK_CHUNK };
    let (count, _) = layout.dimensions().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    if row.segment_digests.len() != count as usize {
        return Err(Refusal::new(CODE_SEAL_FAILED));
    }
    let mut plain_digest = blake3::Hasher::new();
    let mut written = 0_u64;
    for index in 0..count {
        if fenced() {
            return Err(Refusal::new(CODE_CANCELLED));
        }
        let _held = budget::memory_metered(2 * u64::from(SEGMENT_BYTES), meter)?;
        let cipher = store.read_named(&row.prepare_id, &segment_name_of(index))?;
        if segment_digest(&cipher).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?
            != row.segment_digests[index as usize]
        {
            return Err(Refusal::new(CODE_SEAL_FAILED));
        }
        let plain = open_segment(&key, &object_id, layout, u64::from(index), &cipher)
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let bytes = plain.as_staging_bytes();
        plain_digest.update(bytes);
        sink.write_all(bytes).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        written = written.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    }
    if written != length || *plain_digest.finalize().as_bytes() != expected {
        return Err(Refusal::new(CODE_SEAL_FAILED));
    }
    Ok(())
}

fn reference_id(object_id: [u8; 32], grant_id: [u8; 32]) -> Result<[u8; 32], Refusal> {
    let mut material = [0_u8; 64];
    material[..32].copy_from_slice(&object_id);
    material[32..].copy_from_slice(&grant_id);
    digest("ramflux.attachment.reference.v1", &material)
        .map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))
}

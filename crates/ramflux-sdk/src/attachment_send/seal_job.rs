// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Seal a persisted key into segment files. `SegmentSealer::new` is not used.

use ed25519_dalek::{Signer, SigningKey};
use ramflux_crypto::large_attachment::{SegmentSealer, segment_digest};
use ramflux_protocol::large_attachment::{
    ContentManifest, PLAINTEXT_SEGMENT_BYTES, QualifiedOwner, SegmentLayout,
};

use super::chunks;
use super::codes::{CODE_LAYOUT_INVALID, CODE_SEAL_FAILED, Refusal};
use super::meta::Row;
use super::store::Store;

const NETWORK_CHUNK: u32 = 524_288;

pub(crate) struct SealedFile {
    pub bytes: Vec<u8>,
    pub hash: [u8; 32],
    pub object_id: [u8; 32],
    pub digests: Vec<[u8; 32]>,
}

/// # Errors
/// Returns `seal_failed` when the persisted key will not seal this plaintext.
pub(crate) fn seal_persisted(
    store: &Store,
    row: &Row,
    owner: &QualifiedOwner,
    key: &SigningKey,
) -> Result<SealedFile, Refusal> {
    let length = row.plaintext_length.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let object_id = row.object_id.ok_or(Refusal::new(CODE_SEAL_FAILED))?;
    let layout = SegmentLayout { plaintext_length: length, network_chunk_bytes: NETWORK_CHUNK };
    let (count, _) = layout.dimensions().map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    let (file_key, opened) = store.open_secret(row)?;
    if opened != object_id {
        return Err(Refusal::new(CODE_SEAL_FAILED));
    }
    let mut sealer = SegmentSealer::from_persisted(*file_key, object_id, layout)
        .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let digests = write_segments(store, &row.prepare_id, &mut sealer, layout, count)?;
    let manifest = ContentManifest {
        object_id,
        owner: owner.clone(),
        layout,
        segment_digests: digests.clone(),
    };
    let signature =
        key.sign(&manifest.signing_bytes().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?).to_bytes();
    let bytes = manifest.signed_bytes(&signature).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let hash = manifest.hash().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    store.write_named(&row.prepare_id, "manifest.bin", &bytes)?;
    Ok(SealedFile { bytes, hash, object_id, digests })
}

fn write_segments(
    store: &Store,
    prepare_id: &str,
    sealer: &mut SegmentSealer,
    layout: SegmentLayout,
    count: u32,
) -> Result<Vec<[u8; 32]>, Refusal> {
    let mut digests = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for index in 0..count {
        let cipher = seal_index(store, prepare_id, sealer, layout, index)?;
        let name = segment_name(index)?;
        store.write_named(prepare_id, &name, &cipher)?;
        digests.push(segment_digest(&cipher).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?);
    }
    Ok(digests)
}

fn seal_index(
    store: &Store,
    prepare_id: &str,
    sealer: &mut SegmentSealer,
    layout: SegmentLayout,
    index: u32,
) -> Result<Vec<u8>, Refusal> {
    let len = layout
        .segment_plaintext_length(u64::from(index))
        .map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
    let offset = u64::from(index).saturating_mul(PLAINTEXT_SEGMENT_BYTES);
    let plain = if len == 0 {
        Vec::new()
    } else {
        let size = usize::try_from(len).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        chunks::read_range(&store.plain_path(prepare_id), offset, size)?
    };
    sealer.seal(u64::from(index), &plain).map_err(|_| Refusal::new(CODE_SEAL_FAILED))
}

fn segment_name(index: u32) -> Result<String, Refusal> {
    let name = format!("segment-{index}.bin");
    if name.len() > 64 {
        return Err(Refusal::new(CODE_SEAL_FAILED));
    }
    Ok(name)
}

#[must_use]
pub(crate) fn segment_name_of(index: u32) -> String {
    format!("segment-{index}.bin")
}

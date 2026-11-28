// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Attachment seal and host put/get/delete. Ciphertext is padded onto `attach_size_ok`.

use ramflux_crypto::large_attachment::{SegmentSealer, open_segment};
use ramflux_crypto::large_group::{
    ATTACH_MAX_BYTES, ATTACH_PAD, ATTACH_PER_POST_MAX, TokenBucket, attach_put_body,
    attach_size_ok, op_bind,
};
use ramflux_protocol::large_attachment::{PLAINTEXT_SEGMENT_BYTES, SEGMENT_BYTES, SegmentLayout};

use super::host::{CHUNK_BYTES, attach_put_chunk, chunk_count, fail};
use super::session::{reply_bytes, status_code};
use super::store::{AttachSecret, GroupRow, Store};
use super::tokens::take;
use crate::SdkError;

pub(crate) struct SealedAttach {
    pub secret: AttachSecret,
    pub cipher: Vec<u8>,
}

pub(crate) fn padded_plain_len(raw: u64) -> Option<u64> {
    if raw == 0 {
        return None;
    }
    let full = raw / PLAINTEXT_SEGMENT_BYTES;
    let rem = raw % PLAINTEXT_SEGMENT_BYTES;
    if rem == 0 {
        let cipher = full.saturating_mul(u64::from(SEGMENT_BYTES));
        return attach_size_ok(cipher).then_some(raw);
    }
    let need = rem.saturating_add(16);
    let up = need.div_ceil(ATTACH_PAD).saturating_mul(ATTACH_PAD);
    if up <= u64::from(SEGMENT_BYTES) {
        let padded_rem = up.saturating_sub(16);
        let total = full.saturating_mul(PLAINTEXT_SEGMENT_BYTES).saturating_add(padded_rem);
        let cipher = full.saturating_mul(u64::from(SEGMENT_BYTES)).saturating_add(up);
        return (cipher <= ATTACH_MAX_BYTES && attach_size_ok(cipher)).then_some(total);
    }
    let segments = full.saturating_add(1);
    let total = segments.saturating_mul(PLAINTEXT_SEGMENT_BYTES);
    let cipher = segments.saturating_mul(u64::from(SEGMENT_BYTES));
    (cipher <= ATTACH_MAX_BYTES && attach_size_ok(cipher)).then_some(total)
}

pub(crate) fn seal(post_id: &str, plain: &[u8]) -> Result<SealedAttach, SdkError> {
    let raw = u64::try_from(plain.len()).map_err(|_| fail("attachment_too_large", "length"))?;
    let padded = padded_plain_len(raw).ok_or_else(|| fail("attachment_too_large", "pad"))?;
    if padded > ATTACH_MAX_BYTES {
        return Err(fail("attachment_too_large", "ciphertext"));
    }
    let layout = SegmentLayout { plaintext_length: padded, network_chunk_bytes: 524_288 };
    let (segments, cipher_len) =
        layout.dimensions().map_err(|error| fail("attachment_too_large", error.to_string()))?;
    if !attach_size_ok(cipher_len) {
        return Err(fail("attachment_too_large", "sealed length is not a 64 KiB multiple"));
    }
    let mut sealer =
        SegmentSealer::new(layout).map_err(|error| fail("internal", error.to_string()))?;
    let mut padded_bytes = plain.to_vec();
    let padded_len = usize::try_from(padded).map_err(|_| fail("internal", "pad"))?;
    padded_bytes.resize(padded_len, 0);
    let mut cipher = Vec::new();
    let mut offset = 0usize;
    for index in 0..u64::from(segments) {
        let len = layout
            .segment_plaintext_length(index)
            .map_err(|error| fail("internal", error.to_string()))?;
        let len_us = usize::try_from(len).map_err(|_| fail("internal", "segment length"))?;
        let end = offset.saturating_add(len_us);
        let piece =
            padded_bytes.get(offset..end).ok_or_else(|| fail("internal", "segment bounds"))?;
        let segment =
            sealer.seal(index, piece).map_err(|error| fail("internal", error.to_string()))?;
        cipher.extend_from_slice(&segment);
        offset = end;
    }
    let blob_ref = *blake3::hash(&cipher).as_bytes();
    let del_secret = super::host::random_bytes::<32>()?;
    let del_hash = *blake3::hash(&del_secret).as_bytes();
    let key = *sealer.file_key();
    let object_id = *sealer.object_id();
    Ok(SealedAttach {
        secret: AttachSecret {
            blob_ref,
            key,
            object_id,
            del_secret,
            del_hash,
            plain_len: raw,
            cipher_len,
            post_id: post_id.to_owned(),
        },
        cipher,
    })
}

pub(crate) async fn upload(
    store: &Store,
    group: &GroupRow,
    data_root: &std::path::Path,
    sealed: &SealedAttach,
    now_ms: u64,
    seed: &[u8; 32],
) -> Result<(), SdkError> {
    let total_bytes =
        u64::try_from(sealed.cipher.len()).map_err(|_| fail("attachment_too_large", "cipher"))?;
    let total = chunk_count(total_bytes)?;
    let mut secrets = take(store, group, data_root, TokenBucket::Attach, 1, now_ms, seed).await?;
    let token = secrets.pop().ok_or_else(|| fail("rate_limited", "attach"))?;
    let bind_body =
        attach_put_body(&sealed.secret.blob_ref, total, total_bytes, &sealed.secret.del_hash);
    let bound = token.bind(&op_bind("attach.put", &group.group_id, &bind_body)).to_bytes();
    let chunk_len = u64::try_from(CHUNK_BYTES).map_err(|_| fail("internal", "chunk"))?;
    for idx in 0..total {
        let start = usize::try_from(u64::from(idx).saturating_mul(chunk_len))
            .map_err(|_| fail("internal", "chunk start"))?;
        let end = start.saturating_add(CHUNK_BYTES).min(sealed.cipher.len());
        let chunk = sealed.cipher.get(start..end).ok_or_else(|| fail("internal", "chunk"))?;
        let (del, auth): (&[u8], &[u8]) =
            if idx == 0 { (&sealed.secret.del_hash, &bound) } else { (&[], &[]) };
        let body =
            attach_put_chunk(&sealed.secret.blob_ref, idx, total, total_bytes, del, auth, chunk);
        let reply = super::session::member_op(
            &group.host_node_id,
            data_root,
            group.group_id,
            "attach.put",
            &body,
            || super::commit::open_frame(store, group, data_root, now_ms, seed),
        )
        .await?;
        if reply.status != "ok" {
            return Err(fail(status_code(&reply.status), reply.status));
        }
    }
    store.put_attach(&group.group_id, &sealed.secret)?;
    Ok(())
}

pub(crate) async fn download(
    store: &Store,
    group: &GroupRow,
    data_root: &std::path::Path,
    secret: &AttachSecret,
    now_ms: u64,
    seed: &[u8; 32],
) -> Result<Vec<u8>, SdkError> {
    let total = chunk_count(secret.cipher_len)?;
    let mut cipher = Vec::new();
    for idx in 0..total {
        let mut body = ramflux_crypto::large_group::LgWriter::default();
        body.fixed(&secret.blob_ref).u32(idx);
        let reply = super::session::member_op(
            &group.host_node_id,
            data_root,
            group.group_id,
            "attach.get",
            &body.finish(),
            || super::commit::open_frame(store, group, data_root, now_ms, seed),
        )
        .await?;
        if reply.status == "not_found" {
            return Err(fail("expired", "attachment"));
        }
        if reply.status != "ok" {
            return Err(fail(status_code(&reply.status), reply.status));
        }
        cipher.extend_from_slice(&reply_bytes(&reply)?);
    }
    let layout = SegmentLayout {
        plaintext_length: padded_plain_len(secret.plain_len)
            .ok_or_else(|| fail("internal", "pad"))?,
        network_chunk_bytes: 524_288,
    };
    let (segments, _) = layout.dimensions().map_err(|error| fail("internal", error.to_string()))?;
    let mut plain = Vec::new();
    let mut offset = 0usize;
    for index in 0..u64::from(segments) {
        let len = layout
            .segment_plaintext_length(index)
            .map_err(|error| fail("internal", error.to_string()))?;
        let cipher_len = usize::try_from(len.saturating_add(16))
            .map_err(|_| fail("internal", "cipher length"))?;
        let end = offset.saturating_add(cipher_len);
        let piece = cipher.get(offset..end).ok_or_else(|| fail("internal", "cipher bounds"))?;
        let opened = open_segment(&secret.key, &secret.object_id, layout, index, piece)
            .map_err(|error| fail("internal", error.to_string()))?;
        plain.extend_from_slice(opened.as_staging_bytes());
        offset = end;
    }
    let plain_len =
        usize::try_from(secret.plain_len).map_err(|_| fail("internal", "plain length"))?;
    plain.truncate(plain_len);
    Ok(plain)
}

pub(crate) async fn delete(
    store: &Store,
    group: &GroupRow,
    data_root: &std::path::Path,
    secret: &AttachSecret,
    now_ms: u64,
    seed: &[u8; 32],
) -> Result<(), SdkError> {
    let mut body = ramflux_crypto::large_group::LgWriter::default();
    body.fixed(&secret.blob_ref).fixed(&secret.del_secret);
    let reply = super::session::member_op(
        &group.host_node_id,
        data_root,
        group.group_id,
        "attach.delete",
        &body.finish(),
        || super::commit::open_frame(store, group, data_root, now_ms, seed),
    )
    .await?;
    if reply.status != "ok" && reply.status != "not_found" {
        return Err(fail(status_code(&reply.status), reply.status));
    }
    Ok(())
}

pub(crate) fn too_many(count: usize) -> Result<(), SdkError> {
    if count > ATTACH_PER_POST_MAX {
        Err(fail("too_many_attachments", "a post carries at most 10 attachments"))
    } else {
        Ok(())
    }
}

pub(crate) fn thumb_ok(thumb: &[u8]) -> Result<(), SdkError> {
    if thumb.len() > ramflux_crypto::large_group::ATTACH_THUMB_MAX {
        Err(fail("bad_request", "thumbnail exceeds 16 KiB"))
    } else {
        Ok(())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group host wire helpers. The four-line open binding is copied from the node; production code
//! does not call node-core.

#![allow(clippy::too_many_arguments)]

use ramflux_crypto::large_group::{LgReader, LgWriter};
use ramflux_protocol::domain::LG_OPEN_V1;

use crate::SdkError;

pub(crate) const OPEN_PER_DAY_PLACEHOLDER: u32 = 24;
pub(crate) const CHUNK_BYTES: usize = 512 * 1024;
pub(crate) const ROLE_MEMBER: u8 = 0;
pub(crate) const ROLE_ADMIN: u8 = 1;
pub(crate) const ROLE_OWNER: u8 = 2;
pub(crate) const GENESIS_SIG_DOMAIN: &[u8] = b"rf-lg-genesis-sig-v1";
pub(crate) const INVITE_PREFIX: &str = "rf-lg-invite-v1.";
pub(crate) const INVITE_LINK_MAX: usize = 512;
pub(crate) const JOIN_ATTEMPT_BUDGET: u8 = 3;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const INVITE_MAX_TTL_MS: u64 = 7 * DAY_MS;

pub(crate) fn fail(code: &'static str, detail: impl Into<String>) -> SdkError {
    SdkError::Mls { code, detail: detail.into() }
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn kv_err(error: ramflux_mls::MlsKvError) -> SdkError {
    fail("internal", error.to_string())
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn storage_err(error: impl ToString) -> SdkError {
    fail("internal", error.to_string())
}

/// `BLAKE3(rf-lg-open-v1 ‖ group_id ‖ nonce)`, the bytes an open token binds to.
#[must_use]
pub(crate) fn open_bind(gid: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut enc = LgWriter::new(LG_OPEN_V1.as_bytes());
    enc.fixed(gid).fixed(nonce);
    *blake3::hash(&enc.finish()).as_bytes()
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    ramflux_protocol::encode_base64url(bytes)
}

pub(crate) fn b64_fixed<const N: usize>(text: &str) -> Result<[u8; N], SdkError> {
    let bytes = ramflux_protocol::decode_base64url(text)
        .map_err(|_| fail("bad_request", "body is not base64url"))?;
    bytes.try_into().map_err(|got: Vec<u8>| {
        fail("bad_request", format!("expected {N} bytes, got {}", got.len()))
    })
}

pub(crate) fn b64_bytes(text: &str) -> Result<Vec<u8>, SdkError> {
    ramflux_protocol::decode_base64url(text)
        .map_err(|_| fail("bad_request", "body is not base64url"))
}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], SdkError> {
    ramflux_crypto::large_group::random_array::<N>().map_err(|error| fail("internal", error.to_string()))
}

pub(crate) fn put_var(enc: &mut LgWriter, bytes: &[u8]) {
    enc.var(bytes);
}

pub(crate) fn read_var<'a>(dec: &mut LgReader<'a>, max: usize) -> Result<&'a [u8], SdkError> {
    dec.var(max).map_err(|error| fail("bad_request", error.to_string()))
}

pub(crate) fn read_fixed<const N: usize>(dec: &mut LgReader<'_>) -> Result<[u8; N], SdkError> {
    dec.fixed::<N>().map_err(|error| fail("bad_request", error.to_string()))
}

pub(crate) fn finish_dec(dec: &LgReader<'_>) -> Result<(), SdkError> {
    dec.finish().map_err(|error| fail("bad_request", error.to_string()))
}

/// `blob.put` / `attach.put` body prefix shared by both ops.
pub(crate) fn put_chunk_prefix(
    blob_ref: &[u8; 32],
    idx: u32,
    total: u32,
    total_bytes: u64,
) -> LgWriter {
    let mut enc = LgWriter::default();
    enc.fixed(blob_ref).u32(idx).u32(total).u64(total_bytes);
    enc
}

pub(crate) fn attach_put_chunk(
    blob_ref: &[u8; 32],
    idx: u32,
    total: u32,
    total_bytes: u64,
    del_hash: &[u8],
    auth: &[u8],
    chunk: &[u8],
) -> Vec<u8> {
    let mut enc = put_chunk_prefix(blob_ref, idx, total, total_bytes);
    put_var(&mut enc, del_hash);
    put_var(&mut enc, auth);
    put_var(&mut enc, chunk);
    enc.finish()
}

pub(crate) fn blob_put_chunk(
    blob_ref: &[u8; 32],
    idx: u32,
    total: u32,
    total_bytes: u64,
    auth: &[u8],
    chunk: &[u8],
) -> Vec<u8> {
    let mut enc = put_chunk_prefix(blob_ref, idx, total, total_bytes);
    put_var(&mut enc, auth);
    put_var(&mut enc, chunk);
    enc.finish()
}

pub(crate) fn chunk_count(total_bytes: u64) -> Result<u32, SdkError> {
    let chunk = u64::try_from(CHUNK_BYTES).unwrap_or(u64::MAX);
    let total = total_bytes.div_ceil(chunk).max(1);
    u32::try_from(total).map_err(|_| fail("bad_request", "too many chunks"))
}

/// Roster plaintext. The last 64 bytes are `key_ack`.
pub(crate) fn roster_plain(
    p: &[u8; 32],
    credential: &[u8],
    device_chain: &[u8],
    ai_flag: u8,
    role: u8,
    mention_key: &[u8; 32],
    member_proof: &[u8],
    key_ack: &[u8; 64],
) -> Vec<u8> {
    let mut enc = LgWriter::default();
    enc.fixed(p);
    put_var(&mut enc, credential);
    put_var(&mut enc, device_chain);
    enc.u8(ai_flag).u8(role).fixed(mention_key);
    put_var(&mut enc, member_proof);
    let mut out = enc.finish();
    out.extend_from_slice(key_ack);
    out
}

pub(crate) fn split_key_ack(plain: &[u8]) -> Option<(&[u8], &[u8; 64])> {
    let ack: &[u8; 64] = plain.get(plain.len().saturating_sub(64)..)?.try_into().ok()?;
    let body = plain.get(..plain.len().saturating_sub(64))?;
    Some((body, ack))
}

pub(crate) struct ParsedRoster {
    pub p: [u8; 32],
    pub join_pk_id_ack: [u8; 64],
}

pub(crate) fn parse_roster_p(plain: &[u8]) -> Result<ParsedRoster, SdkError> {
    let (body, ack) = split_key_ack(plain).ok_or_else(|| fail("bad_request", "roster truncated"))?;
    let mut dec = LgReader::new(body);
    let p = read_fixed::<32>(&mut dec)?;
    Ok(ParsedRoster { p, join_pk_id_ack: *ack })
}

pub(crate) fn invite_link_bytes(
    host_node_id: &str,
    group_id: &[u8; 32],
    invite_id: &[u8; 16],
    invite_sk: &[u8; 32],
    expires_at: u64,
    join_pk: &[u8; 32],
) -> Vec<u8> {
    let mut enc = LgWriter::default();
    put_var(&mut enc, host_node_id.as_bytes());
    enc.fixed(group_id).fixed(invite_id).fixed(invite_sk).u64(expires_at).fixed(join_pk);
    enc.finish()
}

pub(crate) fn format_invite_link(payload: &[u8]) -> Result<String, SdkError> {
    let link = format!("{INVITE_PREFIX}{}", b64(payload));
    if !link.is_ascii() || link.len() > INVITE_LINK_MAX {
        return Err(fail("bad_request", "invite link exceeds 512 ASCII bytes"));
    }
    Ok(link)
}

pub(crate) struct InviteParts {
    pub host_node_id: String,
    pub group_id: [u8; 32],
    pub invite_id: [u8; 16],
    pub invite_sk: [u8; 32],
    pub expires_at: u64,
    pub join_pk: [u8; 32],
}

pub(crate) fn parse_invite_link(link: &str) -> Result<InviteParts, SdkError> {
    if !link.is_ascii() || link.len() > INVITE_LINK_MAX {
        return Err(fail("link_invalid", "invite link is not ASCII within 512 bytes"));
    }
    let payload = link
        .strip_prefix(INVITE_PREFIX)
        .ok_or_else(|| fail("link_invalid", "invite link prefix"))?;
    let bytes = b64_bytes(payload)?;
    let mut dec = LgReader::new(&bytes);
    let host = read_var(&mut dec, 256)?;
    let host_node_id = String::from_utf8(host.to_vec())
        .map_err(|_| fail("link_invalid", "host node id"))?;
    let parts = InviteParts {
        host_node_id,
        group_id: read_fixed(&mut dec)?,
        invite_id: read_fixed(&mut dec)?,
        invite_sk: read_fixed(&mut dec)?,
        expires_at: dec.u64().map_err(|error| fail("link_invalid", error.to_string()))?,
        join_pk: read_fixed(&mut dec)?,
    };
    finish_dec(&dec)?;
    Ok(parts)
}

pub(crate) fn invite_expiry_ok(now_ms: u64, ttl_ms: u64) -> Result<u64, SdkError> {
    if ttl_ms == 0 || ttl_ms > INVITE_MAX_TTL_MS {
        return Err(fail("bad_request", "invite lifetime must be within 7 days"));
    }
    Ok(now_ms.saturating_add(ttl_ms))
}

pub(crate) fn first_day(created_at_ms: u64, now_ms: u64) -> bool {
    now_ms < created_at_ms.saturating_add(DAY_MS)
}

pub(crate) fn join_attempt_allowed(used: u8) -> bool {
    used < JOIN_ATTEMPT_BUDGET
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_bind_matches_the_spec_bytes() {
        let gid = [0x11; 32];
        let nonce = [0x22; 32];
        let mut enc = LgWriter::new(LG_OPEN_V1.as_bytes());
        enc.fixed(&gid).fixed(&nonce);
        let spec = *blake3::hash(&enc.finish()).as_bytes();
        assert_eq!(open_bind(&gid, &nonce), spec);
    }

    #[test]
    fn invite_link_round_trip_holds_the_seed_and_rejects_over_512() {
        let sk = [0xAB; 32];
        let payload = invite_link_bytes("node-a", &[1; 32], &[2; 16], &sk, 90, &[3; 32]);
        let link = format_invite_link(&payload).expect("link fits");
        let parsed = parse_invite_link(&link).expect("parse");
        assert_eq!(parsed.invite_sk, sk);
        assert_eq!(parsed.host_node_id, "node-a");
        let huge = format!("{INVITE_PREFIX}{}", "A".repeat(INVITE_LINK_MAX));
        assert!(parse_invite_link(&huge).is_err());
        assert!(format_invite_link(&vec![0xFF; 400]).is_err());
    }

    #[test]
    fn join_attempt_budget_stops_at_three() {
        assert!(join_attempt_allowed(0));
        assert!(join_attempt_allowed(1));
        assert!(join_attempt_allowed(2));
        assert!(!join_attempt_allowed(3));
        assert!(!join_attempt_allowed(4));
    }

    #[test]
    fn roster_plain_ends_with_key_ack() {
        let ack = [0x5A; 64];
        let plain = roster_plain(&[1; 32], b"cred", b"chain", 0, ROLE_MEMBER, &[2; 32], &[], &ack);
        assert!(plain.len() >= 64);
        assert_eq!(&plain[plain.len() - 64..], &ack);
        let parsed = parse_roster_p(&plain).expect("roster");
        assert_eq!(parsed.p, [1; 32]);
        assert_eq!(parsed.join_pk_id_ack, ack);
    }

    #[test]
    fn attach_put_idx0_has_del_hash_and_later_chunks_do_not() {
        let blob_ref = [7; 32];
        let del_hash = [8; 32];
        let token = [9; 68];
        let chunk = [1, 2, 3, 4];
        let first = attach_put_chunk(&blob_ref, 0, 2, 8, &del_hash, &token, &chunk);
        let later = attach_put_chunk(&blob_ref, 1, 2, 8, &[], &[], &chunk);
        let (del0, auth0) = attach_fields(&first);
        let (del1, auth1) = attach_fields(&later);
        assert_eq!(del0, del_hash);
        assert_eq!(auth0, token);
        assert_eq!(del1, [] as [u8; 0]);
        assert_eq!(auth1, [] as [u8; 0]);
    }

    fn attach_fields(body: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut dec = LgReader::new(body);
        let _blob: [u8; 32] = dec.fixed().expect("blob");
        let _idx = dec.u32().expect("idx");
        let _total = dec.u32().expect("total");
        let _bytes = dec.u64().expect("bytes");
        let del = dec.var(32).expect("del").to_vec();
        let auth = dec.var(68).expect("auth").to_vec();
        (del, auth)
    }
}

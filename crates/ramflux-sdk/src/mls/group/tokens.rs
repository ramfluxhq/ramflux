// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Four token buckets. Open quota is stored and shown; it is not a local refusal.

use std::path::Path;

use ramflux_crypto::large_group::{
    LgReader, LgWriter, SignedReq, Token, TokenBucket, TokenSecret, begin_token_batch_sized,
    finish_token_batch,
};

use super::host::{OPEN_PER_DAY_PLACEHOLDER, fail, finish_dec, first_day, random_bytes, read_fixed};
use super::session::{ident_call, reply_bytes, status_code};
use super::store::{GroupRow, Store, TokenPart, Wallet};
use crate::SdkError;

const ATTACH_GAP_MS: u64 = 60_000;
const ATTACH_RESERVE: usize = 3;

pub(crate) fn bucket_name(bucket: TokenBucket) -> &'static str {
    match bucket {
        TokenBucket::Post => "post",
        TokenBucket::Commit => "commit",
        TokenBucket::Open => "open",
        TokenBucket::Attach => "attach",
    }
}

pub(crate) fn limited(bucket: TokenBucket, retry_after_s: Option<u64>) -> SdkError {
    match retry_after_s {
        Some(seconds) => fail("rate_limited", format!("{}:{seconds}", bucket_name(bucket))),
        None => fail("rate_limited", bucket_name(bucket)),
    }
}

fn list<'a>(wallet: &'a mut Wallet, bucket: TokenBucket) -> &'a mut Vec<TokenPart> {
    match bucket {
        TokenBucket::Post => &mut wallet.post,
        TokenBucket::Commit => &mut wallet.commit,
        TokenBucket::Open => &mut wallet.open,
        TokenBucket::Attach => &mut wallet.attach,
    }
}

fn spent(wallet: &Wallet, bucket: TokenBucket) -> u32 {
    match bucket {
        TokenBucket::Post => wallet.spent_post,
        TokenBucket::Commit => wallet.spent_commit,
        TokenBucket::Open => 0,
        TokenBucket::Attach => wallet.spent_attach,
    }
}

fn add_spent(wallet: &mut Wallet, bucket: TokenBucket, n: u32) {
    match bucket {
        TokenBucket::Post => wallet.spent_post = wallet.spent_post.saturating_add(n),
        TokenBucket::Commit => wallet.spent_commit = wallet.spent_commit.saturating_add(n),
        TokenBucket::Open => {}
        TokenBucket::Attach => wallet.spent_attach = wallet.spent_attach.saturating_add(n),
    }
}

fn limit_of(bucket: TokenBucket, group: &GroupRow, now_ms: u64) -> u32 {
    let quota = bucket.quota(OPEN_PER_DAY_PLACEHOLDER);
    if first_day(group.created_at_ms, now_ms) { quota.first_day } else { quota.per_day }
}

fn roll_day(wallet: &mut Wallet, now_ms: u64) {
    if wallet.day_start_ms == 0 {
        wallet.day_start_ms = now_ms;
        return;
    }
    if now_ms.saturating_sub(wallet.day_start_ms) >= 24 * 60 * 60 * 1000 {
        wallet.day_start_ms = now_ms;
        wallet.spent_post = 0;
        wallet.spent_commit = 0;
        wallet.spent_attach = 0;
    }
}

fn mature(part: &TokenPart, bucket: TokenBucket, now_ms: u64) -> bool {
    bucket != TokenBucket::Attach || now_ms.saturating_sub(part.issued_ms) >= ATTACH_GAP_MS
}

pub(crate) async fn take(
    store: &Store,
    group: &GroupRow,
    data_root: &Path,
    bucket: TokenBucket,
    count: usize,
    now_ms: u64,
    seed: &[u8; 32],
) -> Result<Vec<TokenSecret>, SdkError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let mut wallet = store.wallet(&group.group_id)?;
    roll_day(&mut wallet, now_ms);
    if wallet.te != group.te {
        wallet.te = group.te;
        wallet.post.clear();
        wallet.commit.clear();
        wallet.open.clear();
        wallet.attach.clear();
    }
    let cap = limit_of(bucket, group, now_ms);
    if bucket != TokenBucket::Open {
        let used = spent(&wallet, bucket);
        if used.saturating_add(u32::try_from(count).unwrap_or(u32::MAX)) > cap {
            return Err(limited(bucket, None));
        }
    }
    ensure(store, group, data_root, &mut wallet, bucket, count, now_ms, seed).await?;
    let mut out = Vec::with_capacity(count);
    let pool = list(&mut wallet, bucket);
    for _ in 0..count {
        let index = pool.iter().position(|part| mature(part, bucket, now_ms)).ok_or_else(|| {
            if bucket == TokenBucket::Attach {
                limited(bucket, Some(60))
            } else {
                limited(bucket, None)
            }
        })?;
        let part = pool.remove(index);
        out.push(TokenSecret::from_parts(part.te, bucket, part.input, part.output));
    }
    add_spent(&mut wallet, bucket, u32::try_from(count).unwrap_or(u32::MAX));
    store.put_wallet(&group.group_id, &wallet)?;
    Ok(out)
}

async fn ensure(
    store: &Store,
    group: &GroupRow,
    data_root: &Path,
    wallet: &mut Wallet,
    bucket: TokenBucket,
    count: usize,
    now_ms: u64,
    seed: &[u8; 32],
) -> Result<(), SdkError> {
    let have = list(wallet, bucket).len();
    if have >= count {
        return Ok(());
    }
    let need = count - have;
    if bucket == TokenBucket::Attach {
        if now_ms.saturating_sub(wallet.last_attach_issue_ms) < ATTACH_GAP_MS {
            return Ok(());
        }
        let room = ATTACH_RESERVE.saturating_sub(have);
        if room == 0 {
            return Ok(());
        }
        issue(group, data_root, wallet, bucket, need.min(room), now_ms, seed).await?;
        store.put_wallet(&group.group_id, wallet)?;
        return Ok(());
    }
    issue(group, data_root, wallet, bucket, need, now_ms, seed).await?;
    store.put_wallet(&group.group_id, wallet)?;
    Ok(())
}

async fn issue(
    group: &GroupRow,
    data_root: &Path,
    wallet: &mut Wallet,
    bucket: TokenBucket,
    count: usize,
    now_ms: u64,
    seed: &[u8; 32],
) -> Result<(), SdkError> {
    let count = count.min(bucket.batch_max());
    if count == 0 {
        return Ok(());
    }
    let request = begin_token_batch_sized(bucket, count).map_err(|error| fail("internal", error.to_string()))?;
    let request_id: [u8; 16] = random_bytes()?;
    let mut body = LgWriter::default();
    body.u32(group.te).u8(bucket.code()).fixed(&request_id).u32(u32::try_from(count).unwrap_or(0));
    for element in &request.blinded {
        body.fixed(element);
    }
    let signed = SignedReq::sign("tokens", &group.group_id, seed, body.finish());
    let reply = ident_call(&group.host_node_id, data_root, group.group_id, "tokens", &signed.encode()).await?;
    if reply.status != "ok" {
        let code = status_code(&reply.status);
        if code == "rate_limited" {
            return Err(limited(bucket, None));
        }
        return Err(fail(code, reply.status));
    }
    let bytes = reply_bytes(&reply)?;
    let proof_at = bytes.len().checked_sub(64).ok_or_else(|| fail("bad_request", "token reply"))?;
    if proof_at == 0 || !proof_at.is_multiple_of(32) {
        return Err(fail("bad_request", "token reply length"));
    }
    let mut dec = LgReader::new(&bytes);
    let mut evaluated = Vec::with_capacity(proof_at / 32);
    for _ in 0..proof_at / 32 {
        evaluated.push(read_fixed(&mut dec)?);
    }
    let proof = read_fixed::<64>(&mut dec)?;
    finish_dec(&dec)?;
    let secrets = finish_token_batch(
        &request,
        &evaluated,
        &proof,
        &group.token_root_pk,
        &group.group_id,
        group.te,
    )
    .map_err(|error| fail("internal", error.to_string()))?;
    if bucket == TokenBucket::Attach {
        wallet.last_attach_issue_ms = now_ms;
    }
    for secret in secrets {
        let (te, bucket, input, output) = secret.to_parts();
        list(wallet, bucket).push(TokenPart { te, bucket: bucket.code(), input, output, issued_ms: now_ms });
    }
    Ok(())
}

pub(crate) fn bind_one(secret: &TokenSecret, hash: &[u8; 32]) -> Token {
    secret.bind(hash)
}

pub(crate) fn quota_view(group: &GroupRow, wallet: &Wallet, now_ms: u64) -> QuotaView {
    QuotaView {
        post_limit: limit_of(TokenBucket::Post, group, now_ms),
        post_spent: wallet.spent_post,
        commit_limit: limit_of(TokenBucket::Commit, group, now_ms),
        commit_spent: wallet.spent_commit,
        attach_limit: limit_of(TokenBucket::Attach, group, now_ms),
        attach_spent: wallet.spent_attach,
        open_per_day: group.open_per_day,
        open_spent: group.open_spent,
        open_first_day: OPEN_PER_DAY_PLACEHOLDER.div_ceil(3),
    }
}

pub(crate) struct QuotaView {
    pub post_limit: u32,
    pub post_spent: u32,
    pub commit_limit: u32,
    pub commit_spent: u32,
    pub attach_limit: u32,
    pub attach_spent: u32,
    pub open_per_day: u32,
    pub open_spent: u32,
    pub open_first_day: u32,
}

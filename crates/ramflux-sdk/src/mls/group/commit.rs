// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Create, invites, member submit, and the roster-add commit.

#![allow(clippy::too_many_arguments)]

use ed25519_dalek::{Signer, SigningKey};
use ramflux_crypto::large_group::{
    ElectCandidate, EnvAuth, EnvHeader, EnvKind, Envelope, Genesis, LgReader, LgWriter, SignedReq,
    TAG_SLOTS, TIER_1000, Token, TokenBucket, TokenSecret, blob_put_body, election_delay_ms,
    election_order, op_bind, post_padded_len,
};
use ramflux_mls::{CommitMeta, GroupKind, Tier, key_package_signature_key};

use super::host::{
    CHUNK_BYTES, GENESIS_SIG_DOMAIN, OPEN_PER_DAY_PLACEHOLDER, b64, blob_put_chunk, chunk_count,
    fail, finish_dec, invite_expiry_ok, kv_err, put_var, random_bytes, read_fixed, read_var,
    storage_err,
};
use super::join::{open_sealed, parse_opened, roster_checks};
use super::session::{ident_call, member_op, reply_bytes, status_code};
use super::store::{GroupRow, OutboxRow, RetiredJoinSk, Store};
use super::tokens::take;
use super::{InviteRecord, Parts};
use crate::SdkError;
use crate::gateway::GatewayClientFrame;

pub(crate) struct Receipt {
    pub log_seq: u64,
    pub appended_at_ms: u64,
}

struct QueuedJoin {
    p: [u8; 32],
    join_pk_id: [u8; 32],
    key_package: Vec<u8>,
    sealed: Vec<u8>,
}

pub(crate) struct SealedCommit {
    pub envelope: Vec<u8>,
    pub welcome: Vec<u8>,
    pub epoch: u64,
}

pub(crate) fn load_group(store: &Store, id: &[u8; 32]) -> Result<GroupRow, SdkError> {
    store.group(id)?.ok_or_else(|| fail("not_found", b64(id)))
}

pub(crate) fn require_member(group: &GroupRow) -> Result<(), SdkError> {
    if group.removed || !group.member {
        Err(fail("not_member", b64(&group.group_id)))
    } else {
        Ok(())
    }
}

pub(crate) fn push_warning(group: &mut GroupRow, text: &str) {
    if !group.warnings.iter().any(|item| item == text) {
        group.warnings.push(text.to_owned());
    }
}

pub(crate) fn remember_outbox(
    store: &Store,
    group: &GroupRow,
    bytes: Vec<u8>,
    kind: &str,
) -> Result<(), SdkError> {
    store.put_outbox(&OutboxRow {
        group_id: group.group_id,
        epoch: group.epoch,
        bytes,
        kind: kind.to_owned(),
    })
}

pub(crate) async fn open_frame(
    store: &Store,
    group: &GroupRow,
    data_root: &std::path::Path,
    now_ms: u64,
    seed: &[u8; 32],
) -> Result<GatewayClientFrame, SdkError> {
    let mut row = store.group(&group.group_id)?.unwrap_or_else(|| group.clone());
    let nonce = random_bytes::<32>()?;
    let bind = super::host::open_bind(&row.group_id, &nonce);
    let mut secrets = take(store, &row, data_root, TokenBucket::Open, 1, now_ms, seed).await?;
    let secret = secrets.pop().ok_or_else(|| fail("rate_limited", "open"))?;
    let token = secret.bind(&bind);
    row.open_spent = row.open_spent.saturating_add(1);
    store.put_group(&row)?;
    Ok(GatewayClientFrame::GroupOpen {
        group_id: b64(&row.group_id),
        open_token: b64(&token.to_bytes()),
        nonce: b64(&nonce),
    })
}

#[allow(clippy::similar_names)]
pub(crate) async fn create(
    client: &crate::RamfluxClient,
    parts: &Parts<'_>,
    name: &str,
    approval: bool,
    now_ms: u64,
) -> Result<super::CreateResult, SdkError> {
    let endpoint = client
        .account_db()?
        .load_actor_state::<String>("account/node-id")
        .map_err(storage_err)?
        .filter(|value| !value.is_empty())
        .ok_or(SdkError::NoNodeSelected)?;
    let record = crate::node::fetch_client_record(&endpoint).await?;
    let zero = [0u8; 32];
    let prepared = ident_call(&endpoint, &parts.root, zero, "create.prepare", &[]).await?;
    if prepared.status != "ok" {
        return Err(fail(status_code(&prepared.status), prepared.status));
    }
    let prep = reply_bytes(&prepared)?;
    let mut dec = LgReader::new(&prep);
    let prep_id = read_fixed::<16>(&mut dec)?;
    let host_head_pk = read_fixed::<32>(&mut dec)?;
    let token_root_pk = read_fixed::<32>(&mut dec)?;
    finish_dec(&dec)?;
    let handle = crate::mls::process_crypto()?;
    let signer =
        ramflux_mls::signer::LeafSigner::generate(handle.crypto()).map_err(SdkError::from)?;
    let owner_p = *signer.public();
    let owner_seed = *signer.secret();
    let (join_pk, join_sk) = super::join::fresh_join_key()?;
    let nonce = random_bytes::<32>()?;
    let genesis = Genesis {
        host_node_id: record.node_id.clone(),
        host_head_pk,
        owner_p_pub: owner_p,
        token_root_pk,
        approval,
        join_pk_0: join_pk,
        tier: TIER_1000,
        created_at: now_ms,
        nonce,
    };
    genesis.check().map_err(|error| fail("internal", error.to_string()))?;
    let genesis_bytes = genesis.encode();
    let group_id = genesis.group_id();
    let mut message = LgWriter::new(GENESIS_SIG_DOMAIN);
    message.var(&genesis_bytes);
    let owner_sig = SigningKey::from_bytes(&owner_seed).sign(&message.finish()).to_bytes();
    let mut body = LgWriter::default();
    body.fixed(&prep_id);
    put_var(&mut body, &genesis_bytes);
    body.fixed(&owner_sig);
    let created = ident_call(&endpoint, &parts.root, zero, "create", &body.finish()).await?;
    if created.status != "ok" {
        return Err(fail(status_code(&created.status), created.status));
    }
    let got = reply_bytes(&created)?;
    let got_id =
        <[u8; 32]>::try_from(got.as_slice()).map_err(|_| fail("bad_request", "group id"))?;
    if got_id != group_id {
        return Err(fail("host_unusual", "group id"));
    }
    let mls_out = parts
        .mls
        .create_with(GroupKind::Group, Some(Tier::Members1000), None, Some(group_id))
        .map_err(SdkError::from)?
        .commit_plain()
        .map_err(kv_err)?;
    if mls_out.group_id.as_slice() != group_id.as_slice() {
        return Err(fail("internal", "mls group id"));
    }
    let row = GroupRow {
        group_id,
        name: name.to_owned(),
        host_node_id: record.node_id,
        approval,
        created_at_ms: now_ms,
        owner_seed,
        owner_p,
        join_pk,
        join_sk,
        mention_key: random_bytes()?,
        epoch: mls_out.epoch,
        log_seq: 0,
        applied_seq: 0,
        te: 0,
        floor_seq: 0,
        leaf_count: 1,
        own_leaf: 0,
        admin: true,
        read_log_seq: 0,
        genesis: genesis_bytes,
        token_root_pk,
        warnings: Vec::new(),
        open_per_day: OPEN_PER_DAY_PLACEHOLDER,
        open_spent: 0,
        member: true,
        removed: false,
        last_commit_ms: 0,
    };
    parts.store.put_group(&row)?;
    Ok(super::CreateResult { group_id, epoch: mls_out.epoch })
}

#[allow(clippy::similar_names)]
pub(crate) async fn invite_put(
    parts: &Parts<'_>,
    group_id: &[u8; 32],
    max_uses: u32,
    ttl_ms: u64,
    now_ms: u64,
) -> Result<InviteRecord, SdkError> {
    let group = load_group(parts.store, group_id)?;
    require_member(&group)?;
    if !(1..=100).contains(&max_uses) {
        return Err(fail("bad_request", "max_uses must be 1..=100"));
    }
    let expires_at = invite_expiry_ok(now_ms, ttl_ms)?;
    let invite_id = random_bytes::<16>()?;
    let mut rows = parts.store.invites(group_id)?;
    if rows.iter().any(|row| row.invite_id == invite_id) {
        return Err(fail("invite_invalid", "duplicate invite"));
    }
    let invite_sk = random_bytes::<32>()?;
    let invite_pk = SigningKey::from_bytes(&invite_sk).verifying_key().to_bytes();
    let mut spec = LgWriter::default();
    spec.fixed(&invite_id).fixed(&invite_pk).u32(max_uses).u64(expires_at);
    let signed = SignedReq::sign("invite.put", group_id, &group.owner_seed, spec.finish());
    let reply =
        ident_call(&group.host_node_id, &parts.root, *group_id, "invite.put", &signed.encode())
            .await?;
    if reply.status != "ok" {
        return Err(fail(status_code(&reply.status), reply.status));
    }
    let link_bytes = super::host::invite_link_bytes(
        &group.host_node_id,
        group_id,
        &invite_id,
        &invite_sk,
        expires_at,
        &group.join_pk,
    );
    let link = super::host::format_invite_link(&link_bytes)?;
    let record =
        InviteRecord { invite_id, link: link.clone(), max_uses, expires_at, revoked: false };
    rows.push(super::store::InviteRow {
        group_id: *group_id,
        invite_id,
        invite_sk,
        invite_pk,
        max_uses,
        expires_at,
        link,
        revoked: false,
    });
    parts.store.put_invites(group_id, &rows)?;
    Ok(record)
}

pub(crate) async fn invite_revoke(
    parts: &Parts<'_>,
    group_id: &[u8; 32],
    invite_id: &[u8; 16],
) -> Result<(), SdkError> {
    let group = load_group(parts.store, group_id)?;
    require_member(&group)?;
    let mut rows = parts.store.invites(group_id)?;
    let Some(index) = rows.iter().position(|row| row.invite_id == *invite_id) else {
        return Err(fail("invite_invalid", "unknown invite"));
    };
    if rows.get(index).is_some_and(|row| row.revoked) {
        return Ok(());
    }
    let signed = SignedReq::sign("invite.revoke", group_id, &group.owner_seed, invite_id.to_vec());
    let reply =
        ident_call(&group.host_node_id, &parts.root, *group_id, "invite.revoke", &signed.encode())
            .await?;
    if reply.status != "ok" {
        return Err(fail(status_code(&reply.status), reply.status));
    }
    if let Some(row) = rows.get_mut(index) {
        row.revoked = true;
    }
    parts.store.put_invites(group_id, &rows)?;
    Ok(())
}

pub(crate) fn invite_list(
    store: &Store,
    group_id: &[u8; 32],
) -> Result<Vec<InviteRecord>, SdkError> {
    let rows = store.invites(group_id)?;
    Ok(rows
        .into_iter()
        .map(|row| InviteRecord {
            invite_id: row.invite_id,
            link: row.link,
            max_uses: row.max_uses,
            expires_at: row.expires_at,
            revoked: row.revoked,
        })
        .collect())
}

pub(crate) async fn submit(
    parts: &Parts<'_>,
    group: &GroupRow,
    body: &[u8],
    bucket: &str,
    now_ms: u64,
) -> Result<Receipt, SdkError> {
    require_member(group)?;
    let reply = member_op(&group.host_node_id, &parts.root, group.group_id, "submit", body, || {
        open_frame(parts.store, group, &parts.root, now_ms, &group.owner_seed)
    })
    .await?;
    if reply.status != "ok" {
        let code = status_code(&reply.status);
        if code == "rate_limited" {
            let retry = reply.retry_at_ms.map(|at| at.saturating_sub(now_ms).div_ceil(1000));
            let detail = match retry {
                Some(secs) => format!("{bucket}:{secs}"),
                None => bucket.to_owned(),
            };
            return Err(fail("rate_limited", detail));
        }
        return Err(fail(code, reply.status));
    }
    parse_receipt(&reply_bytes(&reply)?)
}

fn parse_receipt(bytes: &[u8]) -> Result<Receipt, SdkError> {
    let mut dec = LgReader::new(bytes);
    let log_seq = dec.u64().map_err(|error| fail("bad_request", error.to_string()))?;
    let appended_at_ms = dec.u64().map_err(|error| fail("bad_request", error.to_string()))?;
    let _head = read_fixed::<32>(&mut dec)?;
    let _sig = read_fixed::<64>(&mut dec)?;
    finish_dec(&dec)?;
    Ok(Receipt { log_seq, appended_at_ms })
}

pub(crate) fn seal_application(
    parts: &Parts<'_>,
    group: &GroupRow,
    kind: EnvKind,
    post_id: [u8; 16],
    plaintext: &[u8],
    secret: &TokenSecret,
    del_hash: Option<[u8; 32]>,
) -> Result<Vec<u8>, SdkError> {
    let mut header = header_of(
        group,
        kind,
        post_id,
        EnvAuth::Token(Token { te: group.te, input: [0; 32], tag: [0; 32] }),
        Vec::new(),
        None,
        del_hash,
    );
    let aad = header.aad_bytes();
    let output = parts
        .mls
        .send(&group.group_id, plaintext, &aad)
        .map_err(SdkError::from)?
        .commit_plain()
        .map_err(kv_err)?;
    if output.epoch != header.epoch {
        return Err(fail("internal", "application epoch"));
    }
    let hash = header.bind_hash(&output.message);
    header.auth = EnvAuth::Token(secret.bind(&hash));
    header.check().map_err(|error| fail("internal", error.to_string()))?;
    Ok(Envelope { header, payload: output.message }.encode())
}

pub(crate) fn seal_commit(
    parts: &Parts<'_>,
    group: &GroupRow,
    added_p: [u8; 32],
    key_package: &[u8],
    secrets: &[TokenSecret; 4],
) -> Result<SealedCommit, SdkError> {
    let mut header = header_of(
        group,
        EnvKind::Commit,
        random_bytes()?,
        EnvAuth::CommitTokens(dummy_commits(group.te)),
        vec![added_p],
        None,
        None,
    );
    let aad = header.aad_bytes();
    let output = parts
        .mls
        .add_with(&group.group_id, &[key_package.to_vec()], CommitMeta { aad: &aad })
        .map_err(SdkError::from)?
        .commit_plain()
        .map_err(kv_err)?;
    if output.epoch != group.epoch {
        discard_quiet(parts, &group.group_id);
        return Err(fail("internal", "commit epoch"));
    }
    header.welcome_ref = Some(*blake3::hash(&output.welcome).as_bytes());
    let hash = header.bind_hash(&output.commit);
    let [first, second, third, fourth] = secrets;
    header.auth = EnvAuth::CommitTokens([
        first.bind(&hash),
        second.bind(&hash),
        third.bind(&hash),
        fourth.bind(&hash),
    ]);
    if let Err(error) = header.check() {
        discard_quiet(parts, &group.group_id);
        return Err(fail("internal", error.to_string()));
    }
    Ok(SealedCommit {
        envelope: Envelope { header, payload: output.commit }.encode(),
        welcome: output.welcome,
        epoch: output.epoch,
    })
}

pub(crate) fn merge_own(
    parts: &Parts<'_>,
    group: &mut GroupRow,
    now_ms: u64,
) -> Result<(), SdkError> {
    match parts.mls.merge_own(&group.group_id) {
        Ok(staged) => {
            let merged = staged.commit_plain().map_err(kv_err)?;
            group.epoch = merged.epoch;
            group.last_commit_ms = now_ms;
            Ok(())
        }
        Err(ramflux_mls::MlsError::NotFound(_)) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn discard_quiet(parts: &Parts<'_>, group_id: &[u8; 32]) {
    if let Ok(staged) = parts.mls.discard_own(group_id) {
        let _ = staged.commit_plain();
    }
}

pub(crate) async fn admit(
    parts: &Parts<'_>,
    group: &mut GroupRow,
    key_package: &[u8],
    added_p: [u8; 32],
    now_ms: u64,
) -> Result<u64, SdkError> {
    let plain = padded(roster_bytes(&added_p))?;
    let mut one =
        take(parts.store, group, &parts.root, TokenBucket::Commit, 1, now_ms, &group.owner_seed)
            .await?;
    let secret = one.pop().ok_or_else(|| fail("rate_limited", "commit"))?;
    let state_id = random_bytes::<16>()?;
    let state = seal_application(parts, group, EnvKind::State, state_id, &plain, &secret, None)?;
    remember_outbox(parts.store, group, state.clone(), "state")?;
    let _state_receipt = submit(parts, group, &state, "commit", now_ms).await?;
    parts.store.clear_outbox(&group.group_id)?;
    let secrets = four(
        take(parts.store, group, &parts.root, TokenBucket::Commit, 4, now_ms, &group.owner_seed)
            .await?,
    )?;
    let sealed = seal_commit(parts, group, added_p, key_package, &secrets)?;
    if let Err(error) = put_welcome(parts, group, &sealed.welcome, now_ms).await {
        discard_quiet(parts, &group.group_id);
        return Err(error);
    }
    remember_outbox(parts.store, group, sealed.envelope.clone(), "commit")?;
    let receipt = submit(parts, group, &sealed.envelope, "commit", now_ms).await?;
    merge_own(parts, group, now_ms)?;
    parts.store.clear_outbox(&group.group_id)?;
    group.last_commit_ms = now_ms;
    if let Ok(status) = parts.mls.status(&group.group_id) {
        group.leaf_count =
            u32::try_from(status.leaves).map_err(|_| fail("internal", "leaf count"))?;
        group.own_leaf = status.own_leaf;
        group.epoch = status.epoch;
    }
    parts.store.put_group_merged(group)?;
    Ok(receipt.log_seq)
}

pub(crate) async fn elect(
    parts: &Parts<'_>,
    group: &mut GroupRow,
    now_ms: u64,
) -> Result<(), SdkError> {
    if !group.admin {
        return Ok(());
    }
    if group.last_commit_ms != 0
        && now_ms.saturating_sub(group.last_commit_ms)
            < ramflux_crypto::large_group::MEMBER_COMMIT_GAP_MS
    {
        return Ok(());
    }
    let candidates = [ElectCandidate { leaf: group.own_leaf, admin: true }];
    let order = election_order(&group.group_id, group.epoch, &candidates)
        .map_err(|error| fail("internal", error.to_string()))?;
    let position = order.iter().position(|item| item.leaf == group.own_leaf).unwrap_or(0);
    if now_ms < group.created_at_ms.saturating_add(election_delay_ms(position)) {
        return Ok(());
    }
    let signed = SignedReq::sign("join.pending", &group.group_id, &group.owner_seed, Vec::new());
    let reply = ident_call(
        &group.host_node_id,
        &parts.root,
        group.group_id,
        "join.pending",
        &signed.encode(),
    )
    .await?;
    if reply.status != "ok" {
        return Ok(());
    }
    let queued = parse_pending(&reply_bytes(&reply)?)?;
    let retired = parts.store.retired(&group.group_id)?;
    for row in queued {
        if !join_key_known(group, &retired, &row.join_pk_id, now_ms) {
            push_warning(group, "host_unusual");
            continue;
        }
        let Ok(plain) = open_with_keys(group, &retired, &row.sealed, now_ms) else {
            push_warning(group, "host_unusual");
            continue;
        };
        let Ok(opened) = parse_opened(&plain) else {
            push_warning(group, "host_unusual");
            continue;
        };
        if opened.p != row.p || roster_checks(&group.group_id, &opened, &row.join_pk_id).is_err() {
            push_warning(group, "host_unusual");
            continue;
        }
        let Ok(added) = key_package_signature_key(&row.key_package) else {
            push_warning(group, "host_unusual");
            continue;
        };
        if added != opened.p {
            push_warning(group, "host_unusual");
            continue;
        }
        admit(parts, group, &row.key_package, added, now_ms).await?;
        return Ok(());
    }
    parts.store.put_group_merged(group)?;
    Ok(())
}

async fn put_welcome(
    parts: &Parts<'_>,
    group: &GroupRow,
    welcome: &[u8],
    now_ms: u64,
) -> Result<[u8; 32], SdkError> {
    let blob_ref = *blake3::hash(welcome).as_bytes();
    let total_bytes = u64::try_from(welcome.len()).map_err(|_| fail("bad_request", "welcome"))?;
    let total = chunk_count(total_bytes)?;
    let mut secrets =
        take(parts.store, group, &parts.root, TokenBucket::Commit, 1, now_ms, &group.owner_seed)
            .await?;
    let token = secrets.pop().ok_or_else(|| fail("rate_limited", "commit"))?;
    let bind = op_bind("blob.put", &group.group_id, &blob_put_body(&blob_ref, total, total_bytes));
    let bound = token.bind(&bind).to_bytes();
    let chunk_len = u64::try_from(CHUNK_BYTES).map_err(|_| fail("internal", "chunk"))?;
    for idx in 0..total {
        let start = usize::try_from(u64::from(idx).saturating_mul(chunk_len))
            .map_err(|_| fail("internal", "chunk"))?;
        let end = start.saturating_add(CHUNK_BYTES).min(welcome.len());
        let chunk = welcome.get(start..end).ok_or_else(|| fail("internal", "chunk"))?;
        let auth: &[u8] = if idx == 0 { &bound } else { &[] };
        let body = blob_put_chunk(&blob_ref, idx, total, total_bytes, auth, chunk);
        let reply =
            member_op(&group.host_node_id, &parts.root, group.group_id, "blob.put", &body, || {
                open_frame(parts.store, group, &parts.root, now_ms, &group.owner_seed)
            })
            .await?;
        if reply.status != "ok" {
            return Err(fail(status_code(&reply.status), reply.status));
        }
    }
    Ok(blob_ref)
}

fn four(mut secrets: Vec<TokenSecret>) -> Result<[TokenSecret; 4], SdkError> {
    if secrets.len() != 4 {
        return Err(fail("rate_limited", "commit"));
    }
    let d = secrets.pop().ok_or_else(|| fail("rate_limited", "commit"))?;
    let c = secrets.pop().ok_or_else(|| fail("rate_limited", "commit"))?;
    let b = secrets.pop().ok_or_else(|| fail("rate_limited", "commit"))?;
    let a = secrets.pop().ok_or_else(|| fail("rate_limited", "commit"))?;
    Ok([a, b, c, d])
}

fn dummy_token(te: u32, mark: u8) -> Token {
    let mut input = [0u8; 32];
    if let Some(slot) = input.first_mut() {
        *slot = mark;
    }
    Token { te, input, tag: [0; 32] }
}

fn dummy_commits(te: u32) -> [Token; 4] {
    [dummy_token(te, 1), dummy_token(te, 2), dummy_token(te, 3), dummy_token(te, 4)]
}

fn header_of(
    group: &GroupRow,
    kind: EnvKind,
    post_id: [u8; 16],
    auth: EnvAuth,
    added_p: Vec<[u8; 32]>,
    welcome_ref: Option<[u8; 32]>,
    del_hash: Option<[u8; 32]>,
) -> EnvHeader {
    EnvHeader {
        group_id: group.group_id,
        kind,
        epoch: group.epoch,
        post_id,
        bucket: kind.token_bucket(),
        tags: [[0u8; 16]; TAG_SLOTS],
        del_hash,
        blob_ref: None,
        welcome_ref,
        added_p,
        removed: Vec::new(),
        join_pk_new: None,
        auth,
    }
}

fn roster_bytes(p: &[u8; 32]) -> Vec<u8> {
    let mut enc = LgWriter::default();
    enc.u8(1).fixed(p);
    enc.finish()
}

pub(crate) fn padded(raw: Vec<u8>) -> Result<Vec<u8>, SdkError> {
    let len =
        post_padded_len(raw.len()).ok_or_else(|| fail("bad_request", "post exceeds 64 KiB"))?;
    let mut out = raw;
    out.resize(len, 0);
    Ok(out)
}

fn join_key_known(
    group: &GroupRow,
    retired: &[RetiredJoinSk],
    join_pk_id: &[u8; 32],
    now_ms: u64,
) -> bool {
    if *blake3::hash(&group.join_pk).as_bytes() == *join_pk_id {
        return true;
    }
    let day = 24 * 60 * 60 * 1000;
    retired.iter().any(|row| {
        now_ms.saturating_sub(row.retired_at_ms) <= day
            && *blake3::hash(&row.join_pk).as_bytes() == *join_pk_id
    })
}

fn open_with_keys(
    group: &GroupRow,
    retired: &[RetiredJoinSk],
    sealed: &[u8],
    now_ms: u64,
) -> Result<Vec<u8>, SdkError> {
    if let Ok(plain) = open_sealed(&group.join_sk, sealed) {
        return Ok(plain);
    }
    let day = 24 * 60 * 60 * 1000;
    for row in retired {
        if now_ms.saturating_sub(row.retired_at_ms) > day {
            continue;
        }
        if let Ok(plain) = open_sealed(&row.join_sk, sealed) {
            return Ok(plain);
        }
    }
    Err(fail("host_unusual", "join key"))
}

fn parse_pending(bytes: &[u8]) -> Result<Vec<QueuedJoin>, SdkError> {
    let mut dec = LgReader::new(bytes);
    let count = dec.u32().map_err(|error| fail("bad_request", error.to_string()))?;
    if count > 100 {
        return Err(fail("bad_request", "pending"));
    }
    let mut rows = Vec::new();
    for _ in 0..count {
        let p = read_fixed::<32>(&mut dec)?;
        let _queue = dec.u8().map_err(|error| fail("bad_request", error.to_string()))?;
        let _kind = dec.u8().map_err(|error| fail("bad_request", error.to_string()))?;
        let join_pk_id = read_fixed::<32>(&mut dec)?;
        let key_package = read_var(&mut dec, 16 * 1024)?.to_vec();
        let sealed = read_var(&mut dec, 16 * 1024)?.to_vec();
        rows.push(QueuedJoin { p, join_pk_id, key_package, sealed });
    }
    finish_dec(&dec)?;
    Ok(rows)
}

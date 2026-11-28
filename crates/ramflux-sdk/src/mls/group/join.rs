// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Invite, own-device and rejoin. `join_key_stale` is an internal re-seal, never a result.

use ed25519_dalek::{Signer, SigningKey};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType};
use ramflux_crypto::custody::{DeviceChainCapability, verify_device_chain};
use ramflux_crypto::large_group::{
    JoinKind, JoinRequest, LgReader, LgWriter, TokenBucket, invite_proof_message, join_bind,
    join_proof_sign, key_ack_sign, key_ack_verify,
};
use ramflux_crypto::X25519KeyPair;
use ramflux_mls::{GroupKind, Mls};
use ramflux_protocol::domain::LG_JOIN_V1;
use serde_json::{Value, json};

use super::host::{
    b64, b64_fixed, fail, finish_dec, join_attempt_allowed, put_var, read_fixed, read_var,
    roster_plain, split_key_ack,
};
use super::session::{ident_call, reply_bytes, status_code};
use super::store::{GroupRow, PendingRow, Store};
use super::tokens::take;
use crate::mls::kv_adapter::SqlMlsKv;
use crate::mls::process_crypto;
use crate::SdkError;

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const PENDING_CAP: usize = 100;
const RETRY_AFTER_S: u64 = 10;

fn hpke_config() -> HpkeConfig {
    HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128)
}

pub(crate) fn refused(reason: &str, params: Value) -> super::JoinOutcome {
    super::JoinOutcome::Refused { reason: reason.to_owned(), params }
}

pub(crate) fn pending_outcome(row: &PendingRow) -> super::JoinOutcome {
    super::JoinOutcome::Pending {
        request_id: row.request_id.clone(),
        reason: row.reason.clone(),
        expires_at: row.expires_at,
    }
}

fn map_host(status: &str, leaf_cap: u32) -> super::JoinOutcome {
    let code = status_code(status);
    let params = match code {
        "group_full" => json!({ "leaf_cap": leaf_cap }),
        "rate_limited" => json!({ "retry_after_s": RETRY_AFTER_S }),
        "internal" => json!({ "host_code": status }),
        _ => Value::Null,
    };
    let reason = if code == "join_key_stale" { "join_key_stale" } else { code };
    refused(reason, params)
}

struct IdentityMaterial {
    anchor: String,
    device_id: String,
    device_epoch: u64,
    signing_pk: [u8; 32],
    chain: Vec<u8>,
    ai_flag: u8,
}

fn identity_of(client: &crate::RamfluxClient) -> Result<IdentityMaterial, SdkError> {
    let identity = client
        .mls_device_identity()?
        .ok_or_else(|| fail("internal", "the account has no device identity"))?;
    let kind = ramflux_crypto::custody::device_chain_principal_kind(&identity.device_chain)
        .map_err(|error| fail("internal", error.to_string()))?;
    Ok(IdentityMaterial {
        anchor: identity.account_anchor,
        device_id: identity.device_id,
        device_epoch: identity.device_epoch,
        signing_pk: identity.device_signing_pk,
        chain: identity.device_chain,
        ai_flag: u8::from(kind != ramflux_protocol::PrincipalKind::Human),
    })
}

fn credential_bytes(id: &IdentityMaterial) -> Vec<u8> {
    let mut enc = LgWriter::default();
    put_var(&mut enc, id.anchor.as_bytes());
    put_var(&mut enc, id.device_id.as_bytes());
    enc.u64(id.device_epoch).fixed(&id.signing_pk);
    enc.finish()
}

fn seal(join_pk: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, SdkError> {
    let crypto = process_crypto()?;
    let sealed = OpenMlsCrypto::hpke_seal(
        crypto.crypto(),
        hpke_config(),
        join_pk,
        LG_JOIN_V1.as_bytes(),
        &[],
        plain,
    )
    .map_err(|error| fail("internal", format!("hpke seal {error:?}")))?;
    let mut enc = LgWriter::default();
    put_var(&mut enc, sealed.kem_output.as_slice());
    put_var(&mut enc, sealed.ciphertext.as_slice());
    Ok(enc.finish())
}

pub(crate) fn open_sealed(join_sk: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, SdkError> {
    let mut dec = LgReader::new(sealed);
    let kem = read_var(&mut dec, 1024)?.to_vec();
    let ct = read_var(&mut dec, 64 * 1024)?.to_vec();
    finish_dec(&dec)?;
    let input = HpkeCiphertext { kem_output: kem.into(), ciphertext: ct.into() };
    let crypto = process_crypto()?;
    OpenMlsCrypto::hpke_open(
        crypto.crypto(),
        hpke_config(),
        &input,
        join_sk,
        LG_JOIN_V1.as_bytes(),
        &[],
    )
    .map_err(|error| fail("bad_request", format!("hpke open {error:?}")))
}

pub(crate) struct OpenedRoster {
    pub p: [u8; 32],
    pub credential: Vec<u8>,
    pub device_chain: Vec<u8>,
    pub key_ack: [u8; 64],
}

pub(crate) fn parse_opened(plain: &[u8]) -> Result<OpenedRoster, SdkError> {
    let (body, ack) = split_key_ack(plain).ok_or_else(|| fail("bad_request", "roster truncated"))?;
    let mut dec = LgReader::new(body);
    let p = read_fixed::<32>(&mut dec)?;
    let credential = read_var(&mut dec, 16 * 1024)?.to_vec();
    let device_chain = read_var(&mut dec, 4 * 1024)?.to_vec();
    let _ai = dec.u8().map_err(|error| fail("bad_request", error.to_string()))?;
    let _role = dec.u8().map_err(|error| fail("bad_request", error.to_string()))?;
    let _mention = read_fixed::<32>(&mut dec)?;
    let _proof = read_var(&mut dec, 64)?;
    finish_dec(&dec)?;
    Ok(OpenedRoster { p, credential, device_chain, key_ack: *ack })
}

pub(crate) fn roster_checks(
    group_id: &[u8; 32],
    roster: &OpenedRoster,
    join_pk_id: &[u8; 32],
) -> Result<(), SdkError> {
    key_ack_verify(&roster.p, group_id, join_pk_id, &roster.key_ack)
        .map_err(|error| fail("host_unusual", error.to_string()))?;
    let mut dec = LgReader::new(&roster.credential);
    let anchor = read_var(&mut dec, 256)?;
    let device = read_var(&mut dec, 256)?;
    let epoch = dec.u64().map_err(|error| fail("bad_request", error.to_string()))?;
    let pk = read_fixed::<32>(&mut dec)?;
    let anchor = std::str::from_utf8(anchor).map_err(|_| fail("bad_request", "anchor"))?;
    let device = std::str::from_utf8(device).map_err(|_| fail("bad_request", "device"))?;
    verify_device_chain(
        &roster.device_chain,
        anchor,
        device,
        epoch,
        &pk,
        DeviceChainCapability::Group,
    )
    .map_err(|error| fail("host_unusual", error.to_string()))?;
    Ok(())
}

struct Minted {
    p: [u8; 32],
    seed: [u8; 32],
    key_package: Vec<u8>,
}

fn leaf_secret(store_kv: &ramflux_storage::MlsKvStore, public: &[u8]) -> Result<[u8; 32], SdkError> {
    let raw = store_kv
        .get(ramflux_mls::RF_LABEL_LEAF_SIG, public)
        .map_err(super::host::storage_err)?
        .ok_or_else(|| fail("internal", "leaf signing key is missing"))?;
    raw.as_slice().try_into().map_err(|_| fail("internal", "leaf secret length"))
}

pub(crate) fn fresh_join_key() -> Result<([u8; 32], [u8; 32]), SdkError> {
    let seed = super::host::random_bytes::<32>()?;
    let pair = X25519KeyPair::from_seed(seed);
    Ok((pair.public, seed))
}

fn invite_auth(invite_sk: &[u8; 32], gid: &[u8; 32], p: &[u8; 32], join_pk_id: &[u8; 32], invite_id: &[u8; 16]) -> Vec<u8> {
    let sig = SigningKey::from_bytes(invite_sk).sign(&invite_proof_message(gid, p, join_pk_id)).to_bytes();
    let mut auth = invite_id.to_vec();
    auth.extend_from_slice(&sig);
    auth
}

async fn post_join(
    endpoint: &str,
    root: &std::path::Path,
    group_id: [u8; 32],
    member: bool,
    body: &[u8],
    seed: Option<&[u8; 32]>,
    store: &Store,
    group: Option<&GroupRow>,
    now_ms: u64,
) -> Result<crate::gateway::GroupHostReply, SdkError> {
    if member {
        let group = group.ok_or_else(|| fail("not_member", "group"))?;
        let seed = seed.ok_or_else(|| fail("internal", "member seed"))?;
        return super::session::member_op(endpoint, root, group_id, "join", body, || {
            super::commit::open_frame(store, group, root, now_ms, seed)
        })
        .await;
    }
    ident_call(endpoint, root, group_id, "join", body).await
}

#[allow(clippy::too_many_arguments)]
async fn send_attempts(
    endpoint: &str,
    root: &std::path::Path,
    group_id: [u8; 32],
    member: bool,
    kind: JoinKind,
    minted: &Minted,
    auth_of: impl Fn(&[u8; 32]) -> Vec<u8>,
    mut join_pk: [u8; 32],
    plain_of: &dyn Fn(&[u8; 32]) -> Result<Vec<u8>, SdkError>,
    seed: Option<&[u8; 32]>,
    store: &Store,
    group: Option<&GroupRow>,
    now_ms: u64,
) -> Result<crate::gateway::GroupHostReply, SdkError> {
    let mut used = 0_u8;
    loop {
        if !join_attempt_allowed(used) {
            return Err(fail("rate_limited", format!("commit:{RETRY_AFTER_S}")));
        }
        used = used.saturating_add(1);
        let plain = plain_of(&join_pk)?;
        let sealed = seal(&join_pk, &plain)?;
        let join_pk_id = *blake3::hash(&join_pk).as_bytes();
        let mut request = JoinRequest {
            kind,
            key_package: minted.key_package.clone(),
            auth: Vec::new(),
            join_pk_id,
            sealed,
        };
        if kind.token_bucket().is_some() {
            let bind = join_bind(&request);
            let group = group.ok_or_else(|| fail("not_member", "group"))?;
            let owner = seed.ok_or_else(|| fail("internal", "seed"))?;
            let mut secrets = take(store, group, root, TokenBucket::Commit, 1, now_ms, owner).await?;
            let secret = secrets.pop().ok_or_else(|| fail("rate_limited", "commit"))?;
            request.auth = secret.bind(&bind).to_bytes().to_vec();
        } else {
            request.auth = auth_of(&join_pk_id);
        }
        let reply = post_join(
            endpoint,
            root,
            group_id,
            member,
            &request.encode(),
            seed,
            store,
            group,
            now_ms,
        )
        .await?;
        if reply.status == "join_key_stale" {
            if let Some(next) = reply.join_pk.as_deref() {
                join_pk = b64_fixed(next)?;
                continue;
            }
        }
        if reply.status == "join_rate_limited" || reply.status == "quota" {
            tokio::time::sleep(std::time::Duration::from_secs(RETRY_AFTER_S)).await;
            return Err(fail("rate_limited", format!("commit:{RETRY_AFTER_S}")));
        }
        return Ok(reply);
    }
}

fn save_pending(store: &Store, row: PendingRow) -> Result<super::JoinOutcome, SdkError> {
    let mut rows = store.pending()?;
    rows.retain(|item| item.request_id != row.request_id);
    if rows.len() >= PENDING_CAP {
        return Ok(refused("rate_limited", json!({ "retry_after_s": RETRY_AFTER_S })));
    }
    let outcome = pending_outcome(&row);
    rows.push(row);
    store.put_pending(&rows)?;
    Ok(outcome)
}

pub(crate) async fn join_invite(
    client: &crate::RamfluxClient,
    mls: &Mls<SqlMlsKv>,
    store: &Store,
    link: &str,
    now_ms: u64,
) -> Result<super::JoinOutcome, SdkError> {
    let parts = match super::host::parse_invite_link(link) {
        Ok(parts) => parts,
        Err(error) => return Ok(outcome_err(error, "link_invalid")),
    };
    if parts.expires_at <= now_ms {
        return Ok(refused("invite_expired", json!({ "expired_at": parts.expires_at })));
    }
    if let Some(group) = store.group(&parts.group_id)? {
        if group.member && !group.removed {
            return Ok(refused("already_member", json!({ "group_id": b64(&parts.group_id) })));
        }
    }
    let existing = store.pending()?.into_iter().find(|row| row.link == link && row.group_id == parts.group_id);
    if let Some(row) = existing {
        if row.expires_at <= now_ms {
            return Ok(refused("request_expired", json!({ "expired_at": row.expires_at })));
        }
        return Ok(pending_outcome(&row));
    }
    if store.pending()?.len() >= PENDING_CAP {
        return Ok(refused("rate_limited", json!({ "retry_after_s": RETRY_AFTER_S })));
    }
    let root = data_root(client)?;
    let minted = mint_with_store(mls, store)?;
    let id = identity_of(client)?;
    let cred = credential_bytes(&id);
    let chain = id.chain.clone();
    let ai = id.ai_flag;
    let mention = super::host::random_bytes::<32>()?;
    let p = minted.p;
    let seed = minted.seed;
    let gid = parts.group_id;
    let invite_sk = parts.invite_sk;
    let invite_id = parts.invite_id;
    let plain_of = move |join_pk: &[u8; 32]| {
        let join_pk_id = *blake3::hash(join_pk).as_bytes();
        let ack = key_ack_sign(&seed, &gid, &join_pk_id);
        Ok(roster_plain(&p, &cred, &chain, ai, super::host::ROLE_MEMBER, &mention, &[], &ack))
    };
    let reply = match send_attempts(
        &parts.host_node_id,
        &root,
        parts.group_id,
        false,
        JoinKind::Invite,
        &minted,
        |join_pk_id| invite_auth(&invite_sk, &gid, &p, join_pk_id, &invite_id),
        parts.join_pk,
        &plain_of,
        None,
        store,
        None,
        now_ms,
    )
    .await
    {
        Ok(reply) => reply,
        Err(error) => return Ok(outcome_err(error, "internal")),
    };
    if reply.status != "ok" {
        let mapped = map_host(&reply.status, ramflux_crypto::large_group::LEAF_CAP);
        if let super::JoinOutcome::Refused { reason, .. } = &mapped {
            if reason == "join_key_stale" {
                return Ok(refused("rate_limited", json!({ "retry_after_s": RETRY_AFTER_S })));
            }
        }
        return Ok(mapped);
    }
    let request_id = format!("{:016x}", u128::from_be_bytes(super::host::random_bytes::<16>()?));
    save_pending(
        store,
        PendingRow {
            request_id,
            group_id: parts.group_id,
            host_node_id: parts.host_node_id,
            reason: "approval".to_owned(),
            requested_at: now_ms,
            expires_at: parts.expires_at,
            p: minted.p,
            seed: minted.seed,
            key_package: minted.key_package,
            link: link.to_owned(),
        },
    )
}

fn mint_with_store(mls: &Mls<SqlMlsKv>, store: &Store) -> Result<Minted, SdkError> {
    let output = mls
        .key_package(GroupKind::Group, false)
        .map_err(SdkError::from)?
        .commit_plain()
        .map_err(super::host::kv_err)?;
    let seed = leaf_secret(kv_of(store), &output.leaf_sig_pk)?;
    Ok(Minted { p: output.leaf_sig_pk, seed, key_package: output.bytes })
}

fn kv_of(store: &Store) -> &ramflux_storage::MlsKvStore {
    store.kv_handle()
}

pub(crate) fn data_root(client: &crate::RamfluxClient) -> Result<std::path::PathBuf, SdkError> {
    let account = client
        .born_v3_account
        .as_ref()
        .ok_or_else(|| fail("internal", "no open account"))?;
    Ok(account.data_root()?.to_path_buf())
}

fn outcome_err(error: SdkError, fallback: &str) -> super::JoinOutcome {
    match error {
        SdkError::Mls { code, detail } if code == "rate_limited" => {
            let retry = detail.split(':').nth(1).and_then(|text| text.parse().ok()).unwrap_or(RETRY_AFTER_S);
            refused("rate_limited", json!({ "retry_after_s": retry }))
        }
        SdkError::Mls { code, .. } if code == "link_invalid" || code == "invite_expired" => {
            refused(code, Value::Null)
        }
        _ => refused(fallback, json!({ "host_code": error.to_string() })),
    }
}

pub(crate) async fn join_member_kind(
    client: &crate::RamfluxClient,
    mls: &Mls<SqlMlsKv>,
    store: &Store,
    group_id: &[u8; 32],
    kind: JoinKind,
    now_ms: u64,
) -> Result<super::JoinOutcome, SdkError> {
    let Some(group) = store.group(group_id)? else {
        return Ok(refused("not_member", json!({ "group_id": b64(group_id) })));
    };
    if group.removed {
        return Ok(refused("not_member", json!({ "group_id": b64(group_id) })));
    }
    let root = data_root(client)?;
    let status = mls.status(group_id).map_err(SdkError::from)?;
    let old_seed = leaf_secret(store.kv_handle(), &status.own_sig_pk)?;
    let minted = mint_with_store(mls, store)?;
    let id = identity_of(client)?;
    let cred = credential_bytes(&id);
    let chain = id.chain.clone();
    let proof = join_proof_sign(&old_seed, &minted.p).to_vec();
    let ai_flag = id.ai_flag;
    let mention = group.mention_key;
    let p = minted.p;
    let seed = minted.seed;
    let gid = *group_id;
    let plain_of = move |join_pk: &[u8; 32]| {
        let join_pk_id = *blake3::hash(join_pk).as_bytes();
        let ack = key_ack_sign(&seed, &gid, &join_pk_id);
        Ok(roster_plain(
            &p,
            &cred,
            &chain,
            ai_flag,
            super::host::ROLE_MEMBER,
            &mention,
            &proof,
            &ack,
        ))
    };
    let reply = match send_attempts(
        &group.host_node_id,
        &root,
        *group_id,
        true,
        kind,
        &minted,
        |_| Vec::new(),
        group.join_pk,
        &plain_of,
        Some(&group.owner_seed),
        store,
        Some(&group),
        now_ms,
    )
    .await
    {
        Ok(reply) => reply,
        Err(error) => return Ok(outcome_err(error, "internal")),
    };
    if reply.status != "ok" {
        return Ok(map_host(&reply.status, ramflux_crypto::large_group::LEAF_CAP));
    }
    save_pending(
        store,
        PendingRow {
            request_id: format!("{:016x}", u128::from_be_bytes(super::host::random_bytes::<16>()?)),
            group_id: *group_id,
            host_node_id: group.host_node_id.clone(),
            reason: "queued".to_owned(),
            requested_at: now_ms,
            expires_at: now_ms.saturating_add(DAY_MS),
            p: minted.p,
            seed: minted.seed,
            key_package: minted.key_package,
            link: String::new(),
        },
    )
}

pub(crate) async fn welcome_poll(
    client: &crate::RamfluxClient,
    mls: &Mls<SqlMlsKv>,
    store: &Store,
    group_id: &[u8; 32],
    now_ms: u64,
) -> Result<super::JoinOutcome, SdkError> {
    let Some(row) = store.pending()?.into_iter().find(|row| &row.group_id == group_id) else {
        if store.group(group_id)?.is_some_and(|group| group.member && !group.removed) {
            return Ok(super::JoinOutcome::Joined { group_id: *group_id });
        }
        return Ok(refused("not_found", Value::Null));
    };
    if row.expires_at <= now_ms {
        return Ok(refused("request_expired", json!({ "expired_at": row.expires_at })));
    }
    let root = data_root(client)?;
    let signed = ramflux_crypto::large_group::SignedReq::sign(
        "welcome.get",
        group_id,
        &row.seed,
        Vec::new(),
    );
    let reply = ident_call(&row.host_node_id, &root, *group_id, "welcome.get", &signed.encode()).await?;
    if reply.status == "not_found" || reply.status != "ok" {
        if reply.status == "not_found" {
            return Ok(pending_outcome(&row));
        }
        return Ok(map_host(&reply.status, ramflux_crypto::large_group::LEAF_CAP));
    }
    let bytes = reply_bytes(&reply)?;
    let mut dec = LgReader::new(&bytes);
    let _commit_seq = dec.u64().map_err(|error| fail("bad_request", error.to_string()))?;
    let blob_ref = read_fixed::<32>(&mut dec)?;
    let total = dec.u32().map_err(|error| fail("bad_request", error.to_string()))?;
    let _size = dec.u64().map_err(|error| fail("bad_request", error.to_string()))?;
    finish_dec(&dec)?;
    let mut group = store.group(group_id)?.unwrap_or_else(|| placeholder_group(&row, now_ms));
    let mut welcome = Vec::new();
    for idx in 0..total {
        let mut body = LgWriter::default();
        body.fixed(&blob_ref).u32(idx);
        let chunk = super::session::member_op(
            &row.host_node_id,
            &root,
            *group_id,
            "blob.get",
            &body.finish(),
            || super::commit::open_frame(store, &group, &root, now_ms, &row.seed),
        )
        .await?;
        if chunk.status != "ok" {
            return Ok(map_host(&chunk.status, ramflux_crypto::large_group::LEAF_CAP));
        }
        welcome.extend_from_slice(&reply_bytes(&chunk)?);
    }
    let read_body = ramflux_crypto::large_group::ReadRequest { from_seq: 0, limit: 1 }.encode();
    let read = super::session::member_op(&row.host_node_id, &root, *group_id, "read", &read_body, || {
        super::commit::open_frame(store, &group, &root, now_ms, &row.seed)
    })
    .await?;
    if read.status != "ok" {
        return Ok(map_host(&read.status, ramflux_crypto::large_group::LEAF_CAP));
    }
    let page = ramflux_crypto::large_group::ReadReply::decode(&reply_bytes(&read)?)
        .map_err(|error| fail("bad_request", error.to_string()))?;
    let joined = mls
        .join_group(&welcome, &page.genesis)
        .map_err(SdkError::from)?
        .commit_plain()
        .map_err(super::host::kv_err)?;
    group.member = true;
    group.removed = false;
    group.genesis = page.genesis;
    group.epoch = joined.epoch;
    group.te = page.te;
    group.leaf_count = u32::try_from(joined.leaves).unwrap_or(u32::MAX);
    group.own_leaf = mls.status(group_id).map(|status| status.own_leaf).unwrap_or(0);
    if let Ok(genesis) = ramflux_crypto::large_group::Genesis::decode(&group.genesis) {
        group.token_root_pk = genesis.token_root_pk;
        group.approval = genesis.approval;
        group.created_at_ms = genesis.created_at;
        group.join_pk = genesis.join_pk_0;
    }
    store.put_group_merged(&group)?;
    let mut pending = store.pending()?;
    pending.retain(|item| &item.group_id != group_id);
    store.put_pending(&pending)?;
    Ok(super::JoinOutcome::Joined { group_id: *group_id })
}

fn placeholder_group(row: &PendingRow, now_ms: u64) -> GroupRow {
    GroupRow {
        group_id: row.group_id,
        name: String::new(),
        host_node_id: row.host_node_id.clone(),
        approval: true,
        created_at_ms: now_ms,
        owner_seed: row.seed,
        owner_p: row.p,
        join_pk: [0; 32],
        join_sk: [0; 32],
        mention_key: [0; 32],
        epoch: 0,
        log_seq: 0,
        applied_seq: 0,
        te: 0,
        floor_seq: 0,
        leaf_count: 1,
        own_leaf: 0,
        admin: false,
        read_log_seq: 0,
        genesis: Vec::new(),
        token_root_pk: [0; 32],
        warnings: Vec::new(),
        open_per_day: super::host::OPEN_PER_DAY_PLACEHOLDER,
        open_spent: 0,
        member: false,
        removed: false,
        last_commit_ms: 0,
    }
}

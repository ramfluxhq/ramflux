// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Requests a client writes: create, invite, join, token refill, post, admin and the key delivery
//! (`W` for approval ON, `W'` for OFF). Every call goes through the identity-free gateway frame.

use ed25519_dalek::{Signer, SigningKey};
use ramflux_crypto::large_group::{
    BATCH_SIZE, EntryHeader, EntryKind, EpochKey, Genesis, JoinPolicy, KeyDelivery,
    LgReader as Dec, LgWriter as Enc, MEMBER_CAP, PostEntry, Seen, SignedKeyBody, SignedReq,
    SlotOpened, TAG_SLOTS, admin_chain_head, begin_token_batch, bucket_for, derive_k_content,
    derive_kc, entry_bind_hash, finish_token_batch, generate_recv_keypair, header_hash, late_reply,
    leaf_hash, merkle_root, open_slot, random_array, ratchet_epoch_key, seal_entry, seal_slot,
    settle_at_ms, w_body_hash,
};
use serde_json::{Value, json};

use super::state::{
    HeldToken, LgState, ROLE_ADMIN, ROLE_MEMBER, ROLE_OWNER, Runtime, now_ms, pub_of,
};
use super::{lg_err, lg_msg};
use crate::SdkError;
use crate::bus::connection_manager::SessionClient;

const GENESIS_SIG_DOMAIN: &[u8] = b"rf-lg-genesis-sig-v1";
const JOIN_DOMAIN: &[u8] = b"rf-lg-join-v1";
const MAX_WELCOME: usize = 100;
const REFILL_JITTER_MS: u32 = 120_000;
const HOLD_MAX: usize = 30;
const REFILL_BELOW: usize = 10;

/// The identity-free gateway call.
pub(crate) struct Host<'a>(pub &'a mut SessionClient);

impl Host<'_> {
    pub(crate) async fn call(&mut self, op: &str, body: Vec<u8>) -> Result<Vec<u8>, SdkError> {
        let (status, reply) = self.0.large_group_call(op.to_owned(), body).await?;
        if status == "ok" {
            return Ok(reply);
        }
        Err(SdkError::LocalBusRefused {
            code: "LargeGroupRefused".into(),
            message: format!("large-group host refused {op}: {status}"),
            body: Box::new(json!({"refusal": status, "op": op})),
        })
    }
}

fn sign_with(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

fn new_state(gid: [u8; 32], genesis: Vec<u8>, role: u8) -> Result<(LgState, [u8; 32]), SdkError> {
    let (recv_sk, recv_pk) = generate_recv_keypair().map_err(lg_err)?;
    let state = LgState {
        gid,
        genesis,
        p_seed: random_array().map_err(lg_err)?,
        recv_sk: *recv_sk,
        dev_seed: random_array().map_err(lg_err)?,
        role,
        join_sk: None,
        keyed: false,
        cur_epoch: 0,
        epoch_seq: 0,
        keys: Vec::new(),
        cursor: 0,
        last_head: [0; 32],
        last_sig: [0; 64],
        last_appended_ms: 0,
        te: 0,
        roll_a_ms: 0,
        roll_u_ms: 0,
        warnings: Vec::new(),
    };
    Ok((state, recv_pk))
}

/// Creates a group: host key preparation, owner-signed genesis, owner keys.
pub(crate) async fn create(
    host: &mut Host<'_>,
    host_node_id: &str,
    approval_on: bool,
) -> Result<LgState, SdkError> {
    let prepared = host.call("create_prepare", Vec::new()).await?;
    let mut dec = Dec::new(&prepared);
    let prep_id: [u8; 16] = dec.fixed().map_err(lg_err)?;
    let host_head_pk: [u8; 32] = dec.fixed().map_err(lg_err)?;
    let token_root_pk: [u8; 32] = dec.fixed().map_err(lg_err)?;
    let (join_sk, join_pk) = generate_recv_keypair().map_err(lg_err)?;
    let (mut state, _) = new_state([0; 32], Vec::new(), ROLE_OWNER)?;
    let genesis = Genesis {
        host_node_id: host_node_id.to_owned(),
        host_head_pk,
        owner_p_pub: pub_of(&state.p_seed),
        token_root_pk,
        join_policy: if approval_on { JoinPolicy::ApprovalOn } else { JoinPolicy::ApprovalOff },
        join_pk_0: join_pk,
        member_cap: MEMBER_CAP,
        created_at: now_ms(),
        nonce: random_array().map_err(lg_err)?,
    };
    let genesis_bytes = genesis.encode();
    let mut message = Enc::new(GENESIS_SIG_DOMAIN);
    message.var(&genesis_bytes);
    let sig = sign_with(&state.p_seed, &message.finish());
    let mut body = Enc::default();
    body.fixed(&prep_id).var(&genesis_bytes).fixed(&sig);
    host.call("create", body.finish()).await?;
    state.gid = genesis.group_id();
    state.genesis = genesis_bytes;
    state.join_sk = Some(*join_sk);
    state.keyed = true;
    state.keys.push((0, random_array().map_err(lg_err)?));
    Ok(state)
}

/// An admin or owner mints an invite and returns the link (`gid`, id, invite seed, genesis).
pub(crate) async fn invite(
    rt: &Runtime,
    host: &mut Host<'_>,
    max_uses: u32,
    ttl_ms: u64,
) -> Result<String, SdkError> {
    let invite_id: [u8; 16] = random_array().map_err(lg_err)?;
    let invite_seed: [u8; 32] = random_array().map_err(lg_err)?;
    let mut body = Enc::default();
    body.fixed(&invite_id).fixed(&pub_of(&invite_seed)).u8(ROLE_MEMBER).u32(max_uses);
    body.u64(now_ms().saturating_add(ttl_ms));
    let req = SignedReq::sign("invite", &rt.st.gid, &rt.st.p_seed, body.finish());
    host.call("invite", req.encode()).await?;
    let mut link = Enc::default();
    link.fixed(&rt.st.gid).fixed(&invite_id).fixed(&invite_seed).var(&rt.st.genesis);
    Ok(ramflux_protocol::encode_base64url(link.finish()))
}

/// Joins with an invite link. Returns the new client state and whether the host marked it active.
pub(crate) async fn join(host: &mut Host<'_>, link: &str) -> Result<(LgState, bool), SdkError> {
    let bytes = ramflux_protocol::decode_base64url(link).map_err(|_| lg_msg("invite link"))?;
    let mut dec = Dec::new(&bytes);
    let gid: [u8; 32] = dec.fixed().map_err(lg_err)?;
    let invite_id: [u8; 16] = dec.fixed().map_err(lg_err)?;
    let invite_seed: [u8; 32] = dec.fixed().map_err(lg_err)?;
    let genesis_bytes = dec.var(4096).map_err(lg_err)?.to_vec();
    dec.finish().map_err(lg_err)?;
    let genesis = Genesis::decode(&genesis_bytes).map_err(lg_err)?;
    if genesis.group_id() != gid {
        return Err(lg_msg("invite genesis does not hash to the group id"));
    }
    let (state, recv_pk) = new_state(gid, genesis_bytes, ROLE_MEMBER)?;
    let p = pub_of(&state.p_seed);
    let join_pk_id: [u8; 16] = blake3::hash(&genesis.join_pk_0).as_bytes()[..16]
        .try_into()
        .map_err(|_| lg_msg("join key id"))?;
    let mut proof = Enc::new(JOIN_DOMAIN);
    proof.fixed(&gid).fixed(&p).fixed(&join_pk_id);
    let invite_sig = sign_with(&invite_seed, &proof.finish());
    let blob = seal_slot(&genesis.join_pk_0, &p, &blob_plain(&recv_pk)?).map_err(lg_err)?;
    let mut body = Enc::default();
    body.fixed(&gid).fixed(&p).fixed(&invite_id).fixed(&invite_sig).fixed(&join_pk_id);
    body.var(&blob);
    let reply = host.call("join", body.finish()).await?;
    Ok((state, reply.first() == Some(&1)))
}

fn blob_plain(recv_pk: &[u8; 32]) -> Result<SlotOpened, SdkError> {
    let zero_body = SignedKeyBody {
        group_id: [0; 32],
        kind: 0,
        key_epoch: 0,
        prev_key_seq: 0,
        slot_root: [0; 32],
        slot_count: 0,
        kc: [0; 32],
        admin_chain_head: [0; 32],
        join_pk_new: None,
    };
    Ok(SlotOpened {
        key: EpochKey::from_bytes([0; 32]),
        body: zero_body,
        signature: [0; 64],
        signer_pub: [0; 32],
        signer_cert: recv_pk.to_vec(),
        roster_head: Vec::new(),
        admin_chain: Vec::new(),
    })
}

/// Admin promote (`1`) or demote (`2`) of a pseudonym.
pub(crate) async fn admin(
    rt: &Runtime,
    host: &mut Host<'_>,
    action: u8,
    target: [u8; 32],
) -> Result<(), SdkError> {
    let mut body = Enc::default();
    body.u8(action).fixed(&target);
    let req = SignedReq::sign("admin", &rt.st.gid, &rt.st.p_seed, body.finish());
    host.call("admin", req.encode()).await.map(|_| ())
}

fn rand_below(bound: u32) -> Result<u32, SdkError> {
    let raw = u32::from_be_bytes(random_array::<4>().map_err(lg_err)?);
    Ok(raw % bound.max(1))
}

/// Requests one fixed batch of 20 tokens and schedules each token's first spend time.
pub(crate) async fn refill(
    rt: &mut Runtime,
    host: &mut Host<'_>,
    force: bool,
) -> Result<Value, SdkError> {
    let now = now_ms();
    if !force && rt.tokens.len() >= REFILL_BELOW {
        return Ok(json!({"held": rt.tokens.len(), "requested": false}));
    }
    if !force && now < rt.refill_due_ms {
        return Err(lg_msg("refill not due yet (random 0-120 s after the trigger)"));
    }
    if !force && rt.tokens.len() + BATCH_SIZE > HOLD_MAX {
        return Ok(json!({"held": rt.tokens.len(), "requested": false}));
    }
    let request = begin_token_batch().map_err(lg_err)?;
    let te = rt.st.te;
    let req_id: [u8; 16] = random_array().map_err(lg_err)?;
    let mut body = Enc::default();
    body.u32(te).fixed(&req_id).u32(u32::try_from(BATCH_SIZE).unwrap_or(20));
    for blinded in &request.blinded {
        body.fixed(blinded);
    }
    let signed = SignedReq::sign("issue", &rt.st.gid, &rt.st.p_seed, body.finish());
    let reply = host.call("issue", signed.encode()).await?;
    let received = now_ms();
    let mut dec = Dec::new(&reply);
    let mut evaluated = Vec::with_capacity(BATCH_SIZE);
    for _ in 0..BATCH_SIZE {
        evaluated.push(dec.fixed::<32>().map_err(lg_err)?);
    }
    let proof: [u8; 64] = dec.fixed().map_err(lg_err)?;
    dec.finish().map_err(lg_err)?;
    let genesis = Genesis::decode(&rt.st.genesis).map_err(lg_err)?;
    let tokens = match finish_token_batch(
        &request,
        &evaluated,
        &proof,
        &genesis.token_root_pk,
        &rt.st.gid,
        te,
    ) {
        Ok(tokens) => tokens,
        Err(_) => {
            rt.st.warn("token batch proof failed: batch discarded");
            return Err(lg_msg("token batch discarded (proof verification failed)"));
        }
    };
    let (roll_a, roll_u) = rt.epochs.get(&te).copied().unwrap_or((0, 0));
    if te > 0 && late_reply(roll_a, received) && received > roll_a {
        rt.st.warn("group host is behaving unusually: token batch arrived after A+180s");
    }
    let settle = settle_at_ms(received, roll_a, roll_u);
    for secret in tokens {
        rt.tokens.push(HeldToken { secret, settle_at_ms: settle });
    }
    Ok(json!({"held": rt.tokens.len(), "requested": true, "settle_at_ms": settle, "te": te}))
}

/// Schedules the refill after a roll: 0-120 s after receipt.
pub(crate) fn schedule_refill(rt: &mut Runtime, received_ms: u64) -> Result<(), SdkError> {
    rt.refill_due_ms = received_ms.saturating_add(u64::from(rand_below(REFILL_JITTER_MS)?));
    Ok(())
}

fn take_token(rt: &mut Runtime) -> Result<ramflux_crypto::large_group::TokenSecret, SdkError> {
    let now = now_ms();
    let te = rt.st.te;
    rt.tokens.retain(|held| held.secret.te == te);
    let next_settle = rt.tokens.iter().map(|held| held.settle_at_ms).min();
    match rt.tokens.iter().position(|held| held.settle_at_ms <= now) {
        Some(index) => Ok(rt.tokens.remove(index).secret),
        None => Err(SdkError::LocalBusRefused {
            code: "LargeGroupRefused".into(),
            message: "no spendable token yet".into(),
            body: Box::new(json!({
                "refusal": if next_settle.is_some() { "token_settling" } else { "no_token" },
                "settle_at_ms": next_settle,
                "now_ms": now,
            })),
        }),
    }
}

fn seen_bytes(st: &LgState) -> Vec<u8> {
    if st.cursor == 0 {
        return Vec::new();
    }
    Seen { log_seq: st.cursor, head: st.last_head, host_sig: st.last_sig }.encode()
}

fn fresh_header(kind: u8, key_epoch: u64, bucket: usize) -> Result<EntryHeader, SdkError> {
    let mut tags = [[0_u8; 16]; TAG_SLOTS];
    for tag in &mut tags {
        *tag = random_array().map_err(lg_err)?;
    }
    let del_secret: [u8; 32] = random_array().map_err(lg_err)?;
    Ok(EntryHeader {
        kind,
        post_id: random_array().map_err(lg_err)?,
        key_epoch,
        bucket: u32::try_from(bucket).map_err(|_| lg_msg("bucket"))?,
        del_secret_hash: *blake3::hash(&del_secret).as_bytes(),
        tags,
    })
}

/// Posts a text entry under the current key with a settled token.
pub(crate) async fn post(
    rt: &mut Runtime,
    host: &mut Host<'_>,
    text: &str,
) -> Result<Value, SdkError> {
    let epoch = rt.st.cur_epoch;
    let key =
        rt.st.key_for(epoch).ok_or_else(|| lg_msg("key is provisional: verifying group key"))?;
    let seen = seen_bytes(&rt.st);
    let bucket = bucket_for(seen.len(), text.len()).map_err(lg_err)?;
    let header = fresh_header(EntryKind::POST, epoch, bucket)?;
    let k_content = derive_k_content(&key, &rt.st.gid, epoch).map_err(lg_err)?;
    let sealed =
        seal_entry(&k_content, &rt.st.gid, &header, &rt.st.dev_seed, &seen, text.as_bytes())
            .map_err(lg_err)?;
    let secret = take_token(rt)?;
    let bind = entry_bind_hash(&header_hash(&header), &sealed.ciphertext);
    let entry = PostEntry {
        header,
        ciphertext: sealed.ciphertext,
        token: secret.bind(&bind).to_bytes().to_vec(),
        key: None,
    };
    submit(rt, host, &entry).await
}

async fn submit(rt: &Runtime, host: &mut Host<'_>, entry: &PostEntry) -> Result<Value, SdkError> {
    let mut body = Enc::default();
    body.fixed(&rt.st.gid).var(&entry.encode());
    let reply = host.call("post", body.finish()).await?;
    let mut dec = Dec::new(&reply);
    let seq = dec.u64().map_err(lg_err)?;
    let appended = dec.u64().map_err(lg_err)?;
    Ok(json!({"seq": seq, "appended_at_ms": appended}))
}

/// Delivers the next key to pending joiners: `W` (approval ON, admin) or `W'` (OFF, member).
pub(crate) async fn welcome(rt: &mut Runtime, host: &mut Host<'_>) -> Result<Value, SdkError> {
    let genesis = Genesis::decode(&rt.st.genesis).map_err(lg_err)?;
    let approval_on = genesis.join_policy == JoinPolicy::ApprovalOn;
    if (approval_on && rt.st.role < ROLE_ADMIN) || !rt.st.keyed {
        return Err(lg_msg("only a keyed admin may approve joins in an approval-on group"));
    }
    let join_sk = rt.st.join_sk.ok_or_else(|| lg_msg("no join key held"))?;
    let listed = SignedReq::sign("pending", &rt.st.gid, &rt.st.p_seed, Vec::new());
    let reply = host.call("pending", listed.encode()).await?;
    let mut dec = Dec::new(&reply);
    let count = usize::try_from(dec.u32().map_err(lg_err)?).unwrap_or(0);
    let mut joiners: Vec<([u8; 32], [u8; 32])> = Vec::new();
    for _ in 0..count.min(MAX_WELCOME) {
        let p: [u8; 32] = dec.fixed().map_err(lg_err)?;
        let blob = dec.var(2048).map_err(lg_err)?;
        if let Ok(opened) = open_slot(&join_sk, &rt.st.gid, 0, 0, &p, blob)
            && let Ok(recv_pk) = <[u8; 32]>::try_from(opened.signer_cert.as_slice())
        {
            joiners.push((p, recv_pk));
        }
    }
    joiners.sort_by_key(|(p, _)| *p);
    joiners.dedup_by_key(|(p, _)| *p);
    if joiners.is_empty() {
        return Ok(json!({"welcomed": 0, "key_epoch": rt.st.cur_epoch}));
    }
    let kind = if approval_on { EntryKind::KEY_W } else { EntryKind::KEY_W_PRIME };
    let new_epoch = rt.st.cur_epoch.saturating_add(1);
    let prev = rt.st.epoch_seq;
    let gid = rt.st.gid;
    let ps: Vec<[u8; 32]> = joiners.iter().map(|(p, _)| *p).collect();
    let k_e = rt.st.key_for(rt.st.cur_epoch).ok_or_else(|| lg_msg("no current key"))?;
    let w_body = w_body_hash(&gid, kind, new_epoch, prev, &ps).map_err(lg_err)?;
    let next = ratchet_epoch_key(&k_e, &w_body).map_err(lg_err)?;
    let kc = derive_kc(&next, &gid, new_epoch).map_err(lg_err)?;
    let signer_seed = if approval_on { rt.st.p_seed } else { rt.st.dev_seed };
    let chain_blob = encode_chain(&rt.admin_chain)?;
    let roster = if approval_on { Vec::new() } else { roster_with_join_sk(&join_sk) };
    let head = admin_chain_head(&gid, &rt.admin_chain);
    let slot_body = SignedKeyBody {
        group_id: gid,
        kind,
        key_epoch: new_epoch,
        prev_key_seq: prev,
        slot_root: [0; 32],
        slot_count: u32::try_from(ps.len()).map_err(|_| lg_msg("joiners"))?,
        kc,
        admin_chain_head: head,
        join_pk_new: None,
    };
    let slot_sig = slot_body.sign(&signer_seed);
    let mut slots = Vec::with_capacity(joiners.len());
    for (p, recv_pk) in &joiners {
        let plain = SlotOpened {
            key: EpochKey::from_bytes(*next.expose()),
            body: slot_body.clone(),
            signature: slot_sig,
            signer_pub: pub_of(&signer_seed),
            signer_cert: Vec::new(),
            roster_head: roster.clone(),
            admin_chain: chain_blob.clone(),
        };
        slots.push(seal_slot(recv_pk, p, &plain).map_err(lg_err)?);
    }
    let leaves: Vec<[u8; 32]> = ps.iter().zip(&slots).map(|(p, ct)| leaf_hash(p, ct)).collect();
    let full_body = SignedKeyBody { slot_root: merkle_root(&leaves).map_err(lg_err)?, ..slot_body };
    let body_bytes = full_body.encode();
    let body_sig = full_body.sign(&signer_seed);
    let mut inner = Enc::default();
    inner.var(&body_bytes).fixed(&body_sig);
    let inner = inner.finish();
    let seen = seen_bytes(&rt.st);
    let bucket = bucket_for(seen.len(), inner.len()).map_err(lg_err)?;
    let header = fresh_header(kind, new_epoch, bucket)?;
    let k_content = derive_k_content(&k_e, &gid, rt.st.cur_epoch).map_err(lg_err)?;
    let sealed =
        seal_entry(&k_content, &gid, &header, &rt.st.dev_seed, &seen, &inner).map_err(lg_err)?;
    let (token, signer_p, sig) = if approval_on {
        (Vec::new(), Some(pub_of(&rt.st.p_seed)), Some(body_sig))
    } else {
        let secret = take_token(rt)?;
        let bind = entry_bind_hash(&header_hash(&header), &sealed.ciphertext);
        (secret.bind(&bind).to_bytes().to_vec(), None, None)
    };
    let kd = KeyDelivery { signer_p, body_bytes, body_sig: sig, joiners: ps.clone(), slots };
    let entry = PostEntry { header, ciphertext: sealed.ciphertext, token, key: Some(kd) };
    let sent = submit(rt, host, &entry).await?;
    let seq = sent.get("seq").and_then(Value::as_u64).unwrap_or(0);
    rt.st.keys.push((new_epoch, *next.expose()));
    rt.st.cur_epoch = new_epoch;
    rt.st.epoch_seq = seq;
    Ok(json!({"welcomed": ps.len(), "key_epoch": new_epoch, "seq": seq, "kind": kind}))
}

/// Slot plaintext `roster_head` of an OFF delivery: opaque marker plus the join secret key.
fn roster_with_join_sk(join_sk: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![1_u8];
    out.extend_from_slice(join_sk);
    out
}

/// Parses the join secret key out of a slot's `roster_head`.
pub(crate) fn join_sk_of(roster_head: &[u8]) -> Option<[u8; 32]> {
    match roster_head.split_first() {
        Some((1, rest)) => <[u8; 32]>::try_from(rest).ok(),
        _ => None,
    }
}

fn encode_chain(chain: &[Vec<u8>]) -> Result<Vec<u8>, SdkError> {
    let mut enc = Enc::default();
    enc.u32(u32::try_from(chain.len()).map_err(|_| lg_msg("admin chain"))?);
    for item in chain {
        enc.var(item);
    }
    Ok(enc.finish())
}

pub(crate) fn decode_chain(bytes: &[u8]) -> Result<Vec<Vec<u8>>, SdkError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut dec = Dec::new(bytes);
    let count = usize::try_from(dec.u32().map_err(lg_err)?).unwrap_or(usize::MAX);
    if count > 64 {
        return Err(lg_msg("admin chain length"));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(dec.var(16 * 1024).map_err(lg_err)?.to_vec());
    }
    dec.finish().map_err(lg_err)?;
    Ok(out)
}

/// A joiner's `slot_bad {key_epoch, bad_seq}`.
pub(crate) async fn slot_bad(
    rt: &Runtime,
    host: &mut Host<'_>,
    key_epoch: u64,
    bad_seq: u64,
) -> Result<(), SdkError> {
    let mut body = Enc::default();
    body.u64(key_epoch).u64(bad_seq);
    let req = SignedReq::sign("slot_bad", &rt.st.gid, &rt.st.p_seed, body.finish());
    host.call("slot_bad", req.encode()).await.map(|_| ())
}

/// The `ROLE_*` constants are re-exported for the bus layer.
pub(crate) const fn role_name(role: u8) -> &'static str {
    match role {
        ROLE_OWNER => "owner",
        ROLE_ADMIN => "admin",
        _ => "member",
    }
}

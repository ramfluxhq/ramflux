// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reading the log: head-chain and `appended_at` checks, roll-table acceptance, content opening
//! with `seen` classification, and the member/joiner key-delivery rules of design 2.4.1.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ramflux_crypto::large_group::{
    EntryKind, JoinPolicy, LgReader as Dec, LogView, ProvisionalKey, ProvisionalState, ReadReply,
    ReadRequest, Seen, SeenVerdict, SignedKeyBody, SignedReq, appended_at_ok, classify_seen,
    derive_k_content, derive_kc, entry_bind_hash, entry_chain_hash, header_hash, host_head_verify,
    kd_meta_decode, late_roll, next_head, open_entry, open_slot, random_array,
};
use serde_json::{Value, json};

use super::check::{
    KeyFault, check_body, check_inclusion, owner_of, parse_roll, ratchet_and_kc, roll_record,
    verify_admin_chain,
};
use super::ops::{Host, decode_chain, join_sk_of, schedule_refill, slot_bad};
use super::state::{Runtime, now_ms, pub_of};
use super::{lg_err, lg_msg};
use crate::SdkError;

const MAX_HEADS: u64 = 512;
const U_MAX_MS: u32 = 60_000;

struct Pass {
    receipt_ms: u64,
    live_te: u32,
    host_pk: [u8; 32],
    owner: [u8; 32],
    approval_on: bool,
    posts: Vec<Value>,
    bad: Option<(u64, u64)>,
}

/// One signed read page plus the processing of every entry in it.
pub(crate) async fn read(
    rt: &mut Runtime,
    host: &mut Host<'_>,
    limit: u32,
) -> Result<Value, SdkError> {
    let asked = ReadRequest { from_seq: rt.st.cursor.saturating_add(1), limit };
    let req = SignedReq::sign("read", &rt.st.gid, &rt.st.p_seed, asked.encode());
    let raw = host.call("read", req.encode()).await?;
    let reply = ReadReply::decode(&raw).map_err(lg_err)?;
    let receipt_ms = now_ms();
    let (genesis, owner) = owner_of(&rt.st.genesis).ok_or_else(|| lg_msg("stored genesis"))?;
    if reply.genesis != rt.st.genesis {
        rt.st.warn("host sent a different genesis: ignored");
    }
    rt.admin_chain.clone_from(&reply.admin_chain);
    let mut pass = Pass {
        receipt_ms,
        live_te: reply.te,
        host_pk: genesis.host_head_pk,
        owner,
        approval_on: genesis.join_policy == JoinPolicy::ApprovalOn,
        posts: Vec::new(),
        bad: None,
    };
    let mut processed = 0_u32;
    for entry in &reply.entries {
        if !process_entry(rt, entry, &mut pass) {
            break;
        }
        processed += 1;
    }
    if let Some((epoch, prov)) = &mut rt.prov
        && prov.tick(receipt_ms)
        && pass.bad.is_none()
    {
        pass.bad = Some((*epoch, rt.st.epoch_seq));
    }
    if let Some((epoch, seq)) = pass.bad {
        match slot_bad(rt, host, epoch, seq).await {
            Ok(()) => rt.st.warn("sent slot_bad for an unverifiable key delivery"),
            Err(error) => rt.st.warn(&format!("slot_bad not accepted: {error}")),
        }
    }
    Ok(json!({
        "processed": processed,
        "last_seq": rt.st.cursor,
        "host_last_seq": reply.last_seq,
        "key_epoch": rt.st.cur_epoch,
        "host_key_epoch": reply.key_epoch,
        "te": rt.st.te,
        "keyed": rt.st.keyed,
        "provisional": rt.prov.as_ref().map(|(_, p)| format!("{:?}", p.state())),
        "equivocation_alarm": rt.equivocation,
        "warnings": rt.st.warnings,
        "posts": pass.posts,
    }))
}

fn process_entry(rt: &mut Runtime, e: &LogView, pass: &mut Pass) -> bool {
    let gid = rt.st.gid;
    if e.seq != rt.st.cursor.saturating_add(1) {
        rt.st.warn("log gap or reorder from the host");
        return false;
    }
    let bind = entry_bind_hash(&header_hash(&e.header), &e.ciphertext);
    let chain = entry_chain_hash(&bind, &e.token, e.appended_at_ms, e.seq);
    let expected = next_head(&rt.st.last_head, e.seq, &chain);
    if expected != e.head
        || host_head_verify(&pass.host_pk, &gid, e.seq, &e.head, &e.host_sig).is_err()
    {
        rt.st.warn("host head chain does not verify: stopped reading");
        return false;
    }
    let previous = (rt.st.cursor > 0).then_some(rt.st.last_appended_ms);
    if !appended_at_ok(previous, e.appended_at_ms, pass.receipt_ms) {
        rt.st.warn("host appended_at decreased or is in the future");
    }
    rt.st.cursor = e.seq;
    rt.st.last_head = e.head;
    rt.st.last_sig = e.host_sig;
    rt.st.last_appended_ms = e.appended_at_ms;
    rt.heads.insert(e.seq, e.head);
    if let Some(old) = e.seq.checked_sub(MAX_HEADS) {
        rt.heads.remove(&old);
    }
    match e.header.kind {
        EntryKind::TOKEN_EPOCH => roll(rt, e, pass),
        EntryKind::POST | EntryKind::REACTION | EntryKind::EDIT => post(rt, e, pass),
        EntryKind::KEY_W | EntryKind::KEY_W_PRIME | EntryKind::KEY_REDELIVER => key(rt, e, pass),
        _ => {}
    }
    true
}

fn roll(rt: &mut Runtime, e: &LogView, pass: &Pass) {
    let Some(parsed) = parse_roll(&e.ciphertext) else {
        rt.st.warn("malformed token_epoch entry");
        return;
    };
    let Some(record) = roll_record(&parsed, e.appended_at_ms) else {
        rt.st.warn("group host is behaving unusually: bad roll");
        return;
    };
    if rt.rolls.accept(record).is_err() || parsed.te <= rt.st.te {
        rt.st.warn("group host is behaving unusually: roll fails its rule, no refill");
        return;
    }
    rt.st.te = parsed.te;
    rt.st.roll_a_ms = e.appended_at_ms;
    let u = random_array::<4>().map_or(0, |raw| u64::from(u32::from_be_bytes(raw) % U_MAX_MS));
    rt.st.roll_u_ms = u;
    rt.epochs.insert(parsed.te, (e.appended_at_ms, u));
    rt.tokens.retain(|held| held.secret.te == parsed.te);
    if parsed.te == pass.live_te {
        if late_roll(e.appended_at_ms, pass.receipt_ms) {
            rt.st.warn("group host is behaving unusually: roll received later than A+30s");
        }
        if schedule_refill(rt, pass.receipt_ms).is_err() {
            rt.st.warn("refill could not be scheduled");
        }
    }
}

fn post(rt: &mut Runtime, e: &LogView, pass: &mut Pass) {
    let epoch = e.header.key_epoch;
    let key = rt.st.key_for(epoch).or_else(|| {
        rt.prov
            .as_ref()
            .filter(|(prov_epoch, _)| *prov_epoch == epoch)
            .and_then(|(_, prov)| prov.candidate(0))
            .map(|k| ramflux_crypto::large_group::EpochKey::from_bytes(*k.expose()))
    });
    let Some(key) = key else {
        return;
    };
    let opened = derive_k_content(&key, &rt.st.gid, epoch)
        .ok()
        .and_then(|k| open_entry(&k, &rt.st.gid, &e.header, &e.ciphertext).ok());
    let Some(opened) = opened else {
        if let Some((prov_epoch, prov)) = &mut rt.prov
            && *prov_epoch == epoch
            && prov.entry_failed_aead()
        {
            pass.bad = Some((epoch, e.seq));
        } else {
            rt.st.warn("entry does not decrypt under the group key");
        }
        return;
    };
    if !opened.seen.is_empty()
        && let Ok(seen) = Seen::decode(&opened.seen)
    {
        match classify_seen(&pass.host_pk, &rt.st.gid, &seen, rt.heads.get(&seen.log_seq)) {
            SeenVerdict::Consistent => {}
            SeenVerdict::FlagAuthor => rt.st.warn("author flagged locally: invalid seen"),
            SeenVerdict::Equivocation { .. } => {
                rt.equivocation = true;
                rt.st.warn("ALARM: two host-signed heads for one position (host equivocation)");
            }
        }
    }
    pass.posts.push(json!({
        "seq": e.seq,
        "kind": e.header.kind,
        "post_id": ramflux_protocol::encode_base64url(e.header.post_id),
        "author": ramflux_protocol::encode_base64url(opened.author_pub),
        "text": String::from_utf8_lossy(&opened.body),
        "appended_at_ms": e.appended_at_ms,
    }));
}

fn key(rt: &mut Runtime, e: &LogView, pass: &mut Pass) {
    let epoch = e.header.key_epoch;
    let result = if e.slot.is_some() {
        joiner_key(rt, e, pass)
    } else if epoch == rt.st.cur_epoch.saturating_add(1) && rt.st.keyed {
        member_key(rt, e, pass)
    } else {
        Ok(())
    };
    if let Err(fault) = result {
        rt.st.warn(&format!("key entry {} not used: {}", e.seq, fault.text()));
        if e.slot.is_some() && e.header.kind != EntryKind::KEY_W {
            pass.bad = Some((epoch, e.seq));
        }
    }
}

/// An existing member advances on every host-accepted `W`/`W'` at `e+1`, then checks the entry.
fn member_key(rt: &mut Runtime, e: &LogView, pass: &Pass) -> Result<(), KeyFault> {
    let epoch = e.header.key_epoch;
    let kd = kd_meta_decode(&e.kd_meta).map_err(|_| KeyFault::Body)?;
    let body = SignedKeyBody::decode(&kd.body_bytes).ok();
    let k_e = rt.st.key_for(rt.st.cur_epoch).ok_or(KeyFault::Body)?;
    let (next, kc_ok) = ratchet_and_kc(
        &rt.st.gid,
        e.header.kind,
        epoch,
        rt.st.epoch_seq,
        &kd.joiners,
        &k_e,
        body.as_ref().map(|b| &b.kc),
    )?;
    let prev_seq = rt.st.epoch_seq;
    rt.st.keys.push((epoch, *next.expose()));
    rt.st.cur_epoch = epoch;
    rt.st.epoch_seq = e.seq;
    let body = body.ok_or(KeyFault::Body)?;
    check_body(&rt.st.gid, &body, epoch, prev_seq, &rt.admin_chain)?;
    let signer_ok = if e.header.kind == EntryKind::KEY_W {
        let admins = verify_admin_chain(&rt.st.gid, &pass.owner, &rt.admin_chain)?;
        match (kd.signer_p, kd.body_sig) {
            (Some(p), Some(sig)) => admins.contains(&p) && verify_sig(&p, &kd.body_bytes, &sig),
            _ => false,
        }
    } else {
        member_signature_ok(&k_e, rt, e, &kd.body_bytes)
    };
    if !signer_ok {
        return Err(KeyFault::Signer);
    }
    if !kc_ok {
        return Err(KeyFault::Kc);
    }
    Ok(())
}

fn member_signature_ok(
    k_e: &ramflux_crypto::large_group::EpochKey,
    rt: &Runtime,
    e: &LogView,
    body_bytes: &[u8],
) -> bool {
    let epoch = rt.st.cur_epoch;
    let Ok(k_content) = derive_k_content(k_e, &rt.st.gid, epoch) else {
        return false;
    };
    let Ok(opened) = open_entry(&k_content, &rt.st.gid, &e.header, &e.ciphertext) else {
        return false;
    };
    let mut dec = Dec::new(&opened.body);
    let (Ok(inner_body), Ok(sig)) = (dec.var(2048), dec.fixed::<64>()) else {
        return false;
    };
    inner_body == body_bytes && verify_sig(&opened.author_pub, body_bytes, &sig)
}

fn verify_sig(pk: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(pk)
        .and_then(|key| key.verify(message, &Signature::from_bytes(sig)))
        .is_ok()
}

/// A slot addressed to this pseudonym: inclusion, decryption, signed body, `kc`, admin chain.
fn joiner_key(rt: &mut Runtime, e: &LogView, pass: &Pass) -> Result<(), KeyFault> {
    let slot = e.slot.as_ref().ok_or(KeyFault::Body)?;
    let kd = kd_meta_decode(&e.kd_meta).map_err(|_| KeyFault::Body)?;
    let body = SignedKeyBody::decode(&kd.body_bytes).map_err(|_| KeyFault::Body)?;
    let p = pub_of(&rt.st.p_seed);
    let epoch = e.header.key_epoch;
    if slot.slot_root != body.slot_root || slot.slot_count != body.slot_count {
        return Err(KeyFault::Inclusion);
    }
    check_inclusion(&p, &slot.ct, slot.index, slot.slot_count, &slot.path, &slot.slot_root)?;
    let opened = open_slot(&rt.st.recv_sk, &rt.st.gid, epoch, body.prev_key_seq, &p, &slot.ct)
        .map_err(|_| KeyFault::Inclusion)?;
    let same = opened.body.key_epoch == body.key_epoch
        && opened.body.prev_key_seq == body.prev_key_seq
        && opened.body.kc == body.kc
        && opened.body.admin_chain_head == body.admin_chain_head
        && opened.body.slot_count == body.slot_count
        && opened.body.kind == body.kind;
    if !same || opened.body.verify(&opened.signer_pub, &opened.signature).is_err() {
        return Err(KeyFault::Body);
    }
    if derive_kc(&opened.key, &rt.st.gid, epoch).map_err(|_| KeyFault::Body)? != body.kc {
        return Err(KeyFault::Kc);
    }
    let chain = decode_chain(&opened.admin_chain).map_err(|_| KeyFault::Body)?;
    check_body(&rt.st.gid, &body, epoch, body.prev_key_seq, &chain)?;
    let admins = verify_admin_chain(&rt.st.gid, &pass.owner, &chain)?;
    rt.admin_chain = chain;
    if let Some(sk) = join_sk_of(&opened.roster_head) {
        rt.st.join_sk = Some(sk);
    }
    if e.header.kind == EntryKind::KEY_W {
        if !pass.approval_on
            || !admins.contains(&opened.signer_pub)
            || kd.signer_p != Some(opened.signer_pub)
        {
            return Err(KeyFault::Signer);
        }
        rt.st.keys.push((epoch, *opened.key.expose()));
        rt.st.cur_epoch = epoch;
        rt.st.epoch_seq = e.seq;
        rt.st.keyed = true;
        return Ok(());
    }
    rt.st.cur_epoch = rt.st.cur_epoch.max(epoch);
    rt.st.epoch_seq = e.seq;
    let writer = opened.signer_pub;
    let confirmed = match &mut rt.prov {
        Some((prov_epoch, prov)) if *prov_epoch == epoch => {
            prov.offer_slot(writer, opened.key) == ProvisionalState::Confirmed
        }
        _ => {
            rt.prov = Some((epoch, ProvisionalKey::new(writer, opened.key, pass.receipt_ms)));
            false
        }
    };
    if confirmed
        && let Some((_, prov)) = &rt.prov
        && let Some(key) = prov.confirmed_key()
    {
        rt.st.keys.push((epoch, *key.expose()));
        rt.st.keyed = true;
    }
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The router side of a group session op (MLS-SPEC r1.2 2.1, 2.3, 5): decode the op body, check
//! it against the session's kind and group, call the host, encode the reply. The call carries no
//! source key, session id or account, so nothing here can store or log one.

use ramflux_crypto::large_group::{
    EnvAuth, EnvKind, Envelope, JoinRequest, JoinSession, LgReader as Dec, LgWriter as Enc,
    ReadRequest, SignedReq, TOKEN_LEN, Token,
};

use crate::RouterRedbStore;
use crate::group_wire::{
    CREATE_SCOPE, GroupDirectKind, GroupHostCall, GroupHostReply, decode_b64, decode_body,
    router_op_allowed,
};
use crate::large_group::attach::AttachPut;
use crate::large_group::blobs::BlobPut;
use crate::large_group::entries::AppendReceipt;
use crate::large_group::host::{Authority, InviteSpec, LargeGroupHost};
use crate::large_group::refusal::{LgRefusal, LgResult};
use crate::large_group::route::{RouteMode, RouteRegistration};

/// Exact route delete secret length; the existing wire length prefix is retained.
const DEL_SECRET_BYTES: usize = 32;
/// Largest genesis a `create` carries (the host refuses more).
const GENESIS_MAX: usize = 4_096;
/// Chunk size of a blob upload (every chunk but the last).
const CHUNK_MAX: usize = 512 * 1024;
/// Largest sealed push token of `route.register`.
const SEALED_MAX: usize = crate::large_group::route::SEALED_TOKEN_MAX;

/// The refusal as a reply: the status token plus the datum the refusal carries.
#[must_use]
pub fn refusal_reply(refusal: &LgRefusal) -> GroupHostReply {
    let mut reply = GroupHostReply::status(refusal.code());
    match refusal {
        LgRefusal::Stale { epoch } => reply.epoch = Some(*epoch),
        LgRefusal::Paced { retry_at_ms } => reply.retry_at_ms = Some(*retry_at_ms),
        LgRefusal::Pruned { floor_seq } => reply.floor_seq = Some(*floor_seq),
        LgRefusal::JoinKeyStale { join_pk } => {
            reply.join_pk = Some(ramflux_protocol::encode_base64url(join_pk));
        }
        _ => {}
    }
    reply
}

/// Runs one op of a group session on the host at host time `now_ms`.
#[must_use]
pub fn dispatch(
    host: &LargeGroupHost,
    store: &RouterRedbStore,
    now_ms: u64,
    call: &GroupHostCall,
) -> GroupHostReply {
    match run(host, store, now_ms, call) {
        Ok(body) => GroupHostReply::ok(&body),
        Err(refusal) => refusal_reply(&refusal),
    }
}

fn run(
    host: &LargeGroupHost,
    store: &RouterRedbStore,
    now: u64,
    call: &GroupHostCall,
) -> LgResult<Vec<u8>> {
    if !router_op_allowed(call.session, &call.op) {
        return Err(LgRefusal::SessionScope);
    }
    let gid: [u8; 32] = decode_b64(&call.group_id).ok_or(LgRefusal::BadRequest)?;
    let creating = matches!(call.op.as_str(), "create.prepare" | "create");
    if creating != (gid == CREATE_SCOPE) {
        return Err(LgRefusal::SessionScope);
    }
    let body = decode_body(&call.body).ok_or(LgRefusal::BadRequest)?;
    match call.session {
        GroupDirectKind::Member => member(host, store, now, &gid, &call.op, &body),
        GroupDirectKind::Ident => ident(host, store, now, &gid, &call.op, &body),
    }
}

fn member(
    host: &LargeGroupHost,
    store: &RouterRedbStore,
    now: u64,
    gid: &[u8; 32],
    op: &str,
    body: &[u8],
) -> LgResult<Vec<u8>> {
    match op {
        "open" => {
            let mut dec = Dec::new(body);
            let nonce: [u8; 32] = dec.fixed()?;
            let token = body
                .get(32..)
                .and_then(|rest| Token::from_bytes(rest).ok())
                .ok_or(LgRefusal::BadRequest)?;
            host.open_session(store, now, gid, &token, &nonce)?;
            Ok(Vec::new())
        }
        "status" => {
            let status = host.status(store, gid)?;
            let mut enc = Enc::default();
            enc.u64(status.epoch)
                .u64(status.log_seq)
                .u32(status.te)
                .u64(status.floor_seq)
                .fixed(&status.head);
            Ok(enc.finish())
        }
        "read" => {
            let request = ReadRequest::decode(body)?;
            Ok(host.read(store, now, gid, request.from_seq, request.limit)?.encode())
        }
        "blob.get" => {
            let mut dec = Dec::new(body);
            let blob_ref: [u8; 32] = dec.fixed()?;
            let idx = dec.u32()?;
            dec.finish()?;
            host.blob_get(store, gid, &blob_ref, idx)
        }
        "submit" => {
            let envelope = Envelope::decode(body).map_err(|_| LgRefusal::BadRequest)?;
            // A member session never carries a pseudonym or admin signature (spec 2.1).
            if !matches!(envelope.header.auth, EnvAuth::Token(_) | EnvAuth::CommitTokens(_)) {
                return Err(LgRefusal::Unauthorized);
            }
            Ok(receipt(&host.submit(store, now, gid, body)?))
        }
        "blob.put" => blob_put(host, store, now, gid, body),
        "attach.put" => attach_put(host, store, now, gid, body),
        "attach.get" => {
            let mut dec = Dec::new(body);
            let blob_ref: [u8; 32] = dec.fixed()?;
            let idx = dec.u32()?;
            dec.finish()?;
            host.attach_get(store, gid, &blob_ref, idx)
        }
        "attach.delete" => {
            let mut dec = Dec::new(body);
            let blob_ref: [u8; 32] = dec.fixed()?;
            let del_secret: [u8; 32] = dec.fixed()?;
            dec.finish()?;
            host.attach_delete(store, now, gid, &blob_ref, &del_secret)?;
            Ok(Vec::new())
        }
        "route.register" => {
            route_register(host, store, now, gid, body)?;
            Ok(Vec::new())
        }
        "join" => join(host, store, now, JoinSession::Member, gid, body),
        _ => Err(LgRefusal::SessionScope),
    }
}

fn ident(
    host: &LargeGroupHost,
    store: &RouterRedbStore,
    now: u64,
    gid: &[u8; 32],
    op: &str,
    body: &[u8],
) -> LgResult<Vec<u8>> {
    match op {
        "route.delete" => {
            let mut dec = Dec::new(body);
            let rt: [u8; 16] = dec.fixed()?;
            let secret = dec.var(DEL_SECRET_BYTES)?;
            dec.finish()?;
            host.route_delete(store, now, gid, &rt, secret)?;
            Ok(Vec::new())
        }
        "create.prepare" => {
            if !body.is_empty() {
                return Err(LgRefusal::BadRequest);
            }
            let prepared = host.create_prepare()?;
            let mut enc = Enc::default();
            enc.fixed(&prepared.prep_id)
                .fixed(&prepared.host_head_pk)
                .fixed(&prepared.token_root_pk);
            Ok(enc.finish())
        }
        "create" => {
            let mut dec = Dec::new(body);
            let prep_id: [u8; 16] = dec.fixed()?;
            let genesis = dec.var(GENESIS_MAX)?;
            let owner_sig: [u8; 64] = dec.fixed()?;
            dec.finish()?;
            Ok(host.create(store, now, &prep_id, genesis, &owner_sig)?.to_vec())
        }
        "tokens" => {
            let request = scoped(gid, body)?;
            Ok(host.tokens(store, now, &request)?.encode())
        }
        "welcome.get" => {
            let info = host.welcome_get(store, now, &scoped(gid, body)?)?;
            let mut enc = Enc::default();
            enc.u64(info.commit_seq).fixed(&info.blob_ref).u32(info.total).u64(info.bytes);
            Ok(enc.finish())
        }
        "submit" | "leave" | "void" => {
            let envelope = Envelope::decode(body).map_err(|_| LgRefusal::BadRequest)?;
            // An ident session never spends a token (spec 2.1); `leave` and `void` name the kind.
            let signed = matches!(envelope.header.auth, EnvAuth::AdminSig(_) | EnvAuth::PSig(_));
            let kind_ok = match op {
                "leave" => envelope.header.kind == EnvKind::Leave,
                "void" => envelope.header.kind == EnvKind::Void,
                _ => true,
            };
            if !signed || !kind_ok {
                return Err(LgRefusal::Unauthorized);
            }
            Ok(receipt(&host.submit(store, now, gid, body)?))
        }
        "admin" => {
            host.admin(store, now, &scoped(gid, body)?)?;
            Ok(Vec::new())
        }
        "join" => join(host, store, now, JoinSession::Ident, gid, body),
        "join.pending" => {
            let rows = host.join_pending(store, now, &scoped(gid, body)?)?;
            let mut enc = Enc::default();
            enc.u32(u32::try_from(rows.len()).map_err(|_| LgRefusal::Internal)?);
            for row in &rows {
                enc.fixed(&row.p)
                    .u8(row.queue)
                    .u8(row.kind)
                    .fixed(&row.join_pk_id)
                    .var(&row.key_package)
                    .var(&row.sealed);
            }
            Ok(enc.finish())
        }
        "invite.put" => {
            let request = scoped(gid, body)?;
            let mut dec = Dec::new(&request.body);
            let spec = InviteSpec {
                invite_id: dec.fixed()?,
                pk: dec.fixed()?,
                max_uses: dec.u32()?,
                expires_ms: dec.u64()?,
            };
            dec.finish()?;
            host.invite_put(store, now, gid, &spec, Authority::Signed(&request))?;
            Ok(Vec::new())
        }
        "invite.revoke" => {
            let request = scoped(gid, body)?;
            let invite_id: [u8; 16] =
                request.body.as_slice().try_into().map_err(|_| LgRefusal::BadRequest)?;
            host.invite_revoke(store, now, gid, &invite_id, Authority::Signed(&request))?;
            Ok(Vec::new())
        }
        _ => Err(LgRefusal::SessionScope),
    }
}

/// A signed request whose group is the session's (the host reads the group from the request).
fn scoped(gid: &[u8; 32], body: &[u8]) -> LgResult<SignedReq> {
    let request = SignedReq::decode(body)?;
    if request.gid != *gid {
        return Err(LgRefusal::SessionScope);
    }
    Ok(request)
}

fn receipt(receipt: &AppendReceipt) -> Vec<u8> {
    let mut enc = Enc::default();
    enc.u64(receipt.log_seq)
        .u64(receipt.appended_at_ms)
        .fixed(&receipt.head)
        .fixed(&receipt.host_sig);
    enc.finish()
}

fn join(
    host: &LargeGroupHost,
    store: &RouterRedbStore,
    now: u64,
    session: JoinSession,
    gid: &[u8; 32],
    body: &[u8],
) -> LgResult<Vec<u8>> {
    let request = JoinRequest::decode(body)?;
    Ok(vec![host.join(store, now, session, &request, gid)?])
}

fn blob_put(
    host: &LargeGroupHost,
    store: &RouterRedbStore,
    now: u64,
    gid: &[u8; 32],
    body: &[u8],
) -> LgResult<Vec<u8>> {
    let mut dec = Dec::new(body);
    let blob_ref: [u8; 32] = dec.fixed()?;
    let idx = dec.u32()?;
    let total = dec.u32()?;
    let total_bytes = dec.u64()?;
    let auth = dec.var(TOKEN_LEN)?;
    let chunk = dec.var(CHUNK_MAX)?;
    dec.finish()?;
    // Chunk 0 spends one commit token; later chunks of a pending upload carry none (spec 2.2).
    let token = match (idx, auth.is_empty()) {
        (_, true) => None,
        (0, false) => Some(Token::from_bytes(auth).map_err(|_| LgRefusal::BadRequest)?),
        (_, false) => return Err(LgRefusal::BadRequest),
    };
    let put = BlobPut { blob_ref, idx, total, total_bytes, chunk };
    let progress = host.blob_put(store, now, gid, &put, token.as_ref().map(Authority::Token))?;
    let mut enc = Enc::default();
    enc.u32(progress.received).u8(u8::from(progress.complete));
    Ok(enc.finish())
}

fn attach_put(
    host: &LargeGroupHost,
    store: &RouterRedbStore,
    now: u64,
    gid: &[u8; 32],
    body: &[u8],
) -> LgResult<Vec<u8>> {
    let mut dec = Dec::new(body);
    let blob_ref: [u8; 32] = dec.fixed()?;
    let idx = dec.u32()?;
    let total = dec.u32()?;
    let total_bytes = dec.u64()?;
    let del_hash = dec.var(32)?;
    let auth = dec.var(TOKEN_LEN)?;
    let chunk = dec.var(CHUNK_MAX)?;
    dec.finish()?;
    // Chunk 0 carries `del_hash` and the one `attach` token; later chunks carry neither.
    let (del_hash, token) = if idx == 0 {
        let del_hash: [u8; 32] = del_hash.try_into().map_err(|_| LgRefusal::BadRequest)?;
        let token = Token::from_bytes(auth).map_err(|_| LgRefusal::BadRequest)?;
        (Some(del_hash), Some(token))
    } else if del_hash.is_empty() && auth.is_empty() {
        (None, None)
    } else {
        return Err(LgRefusal::BadRequest);
    };
    let put = AttachPut { blob_ref, idx, total, total_bytes, del_hash, chunk };
    let progress = host.attach_put(store, now, gid, &put, token.as_ref())?;
    let mut enc = Enc::default();
    enc.u32(progress.received).u8(u8::from(progress.complete));
    Ok(enc.finish())
}

fn route_register(
    host: &LargeGroupHost,
    store: &RouterRedbStore,
    now: u64,
    gid: &[u8; 32],
    body: &[u8],
) -> LgResult<()> {
    let mut dec = Dec::new(body);
    let rt: [u8; 16] = dec.fixed()?;
    let sealed = dec.var(SEALED_MAX)?.to_vec();
    let mention_key: [u8; 32] = dec.fixed()?;
    let mode = match dec.u8()? {
        1 => RouteMode::MentionsReplies,
        2 => RouteMode::All,
        _ => return Err(LgRefusal::BadRequest),
    };
    let del_hash: [u8; 32] = dec.fixed()?;
    dec.finish()?;
    let registration = RouteRegistration { rt, sealed_token: sealed, mention_key, mode, del_hash };
    host.route_register(store, now, gid, &registration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_key_stale_reply_carries_the_current_key() {
        let reply = refusal_reply(&LgRefusal::JoinKeyStale { join_pk: [7; 32] });
        assert_eq!(reply.status, "join_key_stale");
        assert_eq!(
            reply.join_pk.as_deref().and_then(decode_b64::<32>),
            Some([7; 32]),
            "the key is on the wire as base64url"
        );
        assert_eq!(refusal_reply(&LgRefusal::NotFound).join_pk, None);
    }
}

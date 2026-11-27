// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! `group.large.*` bus methods (LARGE-GROUP-01 P1) and the hidden `debug.lg.*` fixtures.

#![allow(clippy::missing_errors_doc)]
use ramflux_crypto::large_group::{LgWriter as Enc, kat_poprf};
use serde_json::{Value, json};

use crate::SdkError;
use crate::bus::state::LocalBusAccountState;
use crate::large_group::ops::{self, Host, role_name};
use crate::large_group::read::read;
use crate::large_group::state::{
    LgState, Runtime, checkpoint_name, now_ms, put_runtime, runtime_key, set_clock_offset_ms,
    take_runtime,
};
use crate::large_group::{lg_err, lg_msg};
use crate::prelude::*;

const DEFAULT_INVITE_USES: u32 = 100;
const DEFAULT_INVITE_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const READ_LIMIT: u32 = 64;
const BULK_JOIN_MAX: u64 = 1_000;
const BULK_RETRY_LIMIT: u32 = 30;

pub(crate) async fn dispatch(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?.to_owned();
    let account = local_bus_account_mut(state, &account_id)?;
    let body = &request.body;
    let value = match request.method.as_str() {
        "group.large.create" => create(account, &account_id, body).await?,
        "group.large.join" => join(account, &account_id, body).await?,
        "debug.lg.kat_poprf" => kat()?,
        "debug.lg.clock" => clock(account, body).await?,
        "debug.lg.bulk_join" => bulk_join(account, body).await?,
        method => group_op(account, &account_id, method, body).await?,
    };
    Ok(local_bus_ok(value))
}

fn gid_of(body: &Value) -> Result<[u8; 32], SdkError> {
    let text = body
        .get("group_id")
        .and_then(Value::as_str)
        .ok_or_else(|| lg_msg("group_id is required"))?;
    b64_32(text)
}

fn b64_32(text: &str) -> Result<[u8; 32], SdkError> {
    ramflux_protocol::decode_base64url(text)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .ok_or_else(|| lg_msg("expected a 32-byte base64url value"))
}

fn persist(account: &LocalBusAccountState, rt: &Runtime) -> Result<(), SdkError> {
    account.client.set_projection_checkpoint(&checkpoint_name(&rt.st.gid), &rt.st.encode())
}

fn load(account: &LocalBusAccountState, key: &str, gid: &[u8; 32]) -> Result<Runtime, SdkError> {
    if let Some(runtime) = take_runtime(key) {
        return Ok(runtime);
    }
    let stored = account
        .client
        .projection_checkpoint(&checkpoint_name(gid))?
        .ok_or_else(|| lg_msg("unknown large group"))?;
    Ok(Runtime::new(LgState::decode(&stored)?))
}

fn summary(rt: &Runtime) -> Value {
    let now = now_ms();
    json!({
        "group_id": ramflux_protocol::encode_base64url(rt.st.gid),
        "p": ramflux_protocol::encode_base64url(crate::large_group::state::pub_of(&rt.st.p_seed)),
        "role": role_name(rt.st.role),
        "keyed": rt.st.keyed,
        "key_epoch": rt.st.cur_epoch,
        "te": rt.st.te,
        "tokens": rt.tokens.len(),
        "tokens_spendable": rt.tokens.iter().filter(|t| t.settle_at_ms <= now).count(),
        "next_settle_at_ms": rt.tokens.iter().map(|t| t.settle_at_ms).min(),
        "refill_due_ms": rt.refill_due_ms,
        "now_ms": now,
        "provisional": rt.prov.as_ref().map(|(_, p)| format!("{:?}", p.state())),
        "warnings": rt.st.warnings,
    })
}

async fn create(
    account: &mut LocalBusAccountState,
    account_id: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    let approval_on = body.get("approval_on").and_then(Value::as_bool).unwrap_or(true);
    let node = body.get("host").and_then(Value::as_str).unwrap_or("home").to_owned();
    let mut engine = account.session_client().await?;
    let created = ops::create(&mut Host(&mut engine), &node, approval_on).await;
    account.apply_session_metadata(engine);
    let st = created?;
    let rt = Runtime::new(st);
    persist(account, &rt)?;
    let out = summary(&rt);
    put_runtime(runtime_key(account_id, &rt.st.gid), rt);
    Ok(out)
}

async fn join(
    account: &mut LocalBusAccountState,
    account_id: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    let link =
        body.get("link").and_then(Value::as_str).ok_or_else(|| lg_msg("link is required"))?;
    let mut engine = account.session_client().await?;
    let joined = ops::join(&mut Host(&mut engine), link).await;
    account.apply_session_metadata(engine);
    let (st, active) = joined?;
    let rt = Runtime::new(st);
    persist(account, &rt)?;
    let mut out = summary(&rt);
    out["host_active"] = json!(active);
    put_runtime(runtime_key(account_id, &rt.st.gid), rt);
    Ok(out)
}

async fn group_op(
    account: &mut LocalBusAccountState,
    account_id: &str,
    method: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    let gid = gid_of(body)?;
    let key = runtime_key(account_id, &gid);
    let mut rt = load(account, &key, &gid)?;
    if method == "group.large.status" {
        let out = summary(&rt);
        put_runtime(key, rt);
        return Ok(out);
    }
    let mut engine = match account.session_client().await {
        Ok(engine) => engine,
        Err(error) => {
            put_runtime(key, rt);
            return Err(error);
        }
    };
    let result = run(&mut rt, &mut Host(&mut engine), method, body).await;
    account.apply_session_metadata(engine);
    let saved = persist(account, &rt);
    put_runtime(key, rt);
    saved?;
    result
}

async fn run(
    rt: &mut Runtime,
    host: &mut Host<'_>,
    method: &str,
    body: &Value,
) -> Result<Value, SdkError> {
    match method {
        "group.large.read" => {
            let limit = body
                .get("limit")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(READ_LIMIT);
            read(rt, host, limit).await
        }
        "group.large.invite" => {
            let uses = body
                .get("max_uses")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(DEFAULT_INVITE_USES);
            let ttl = body.get("ttl_ms").and_then(Value::as_u64).unwrap_or(DEFAULT_INVITE_TTL_MS);
            Ok(json!({"link": ops::invite(rt, host, uses, ttl).await?}))
        }
        "group.large.tokens" => {
            let force = body.get("force").and_then(Value::as_bool).unwrap_or(false);
            ops::refill(rt, host, force).await
        }
        "group.large.post" => {
            let text = body
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| lg_msg("text is required"))?;
            ops::post(rt, host, text).await
        }
        "group.large.ratchet" => {
            read(rt, host, READ_LIMIT).await?;
            ops::welcome(rt, host).await
        }
        "group.large.admin" => {
            let action = match body.get("action").and_then(Value::as_str) {
                Some("promote") => 1,
                Some("demote") => 2,
                _ => return Err(lg_msg("action must be promote or demote")),
            };
            let target = b64_32(
                body.get("target").and_then(Value::as_str).ok_or_else(|| lg_msg("target"))?,
            )?;
            ops::admin(rt, host, action, target).await?;
            Ok(json!({"ok": true}))
        }
        "debug.lg.fault" => fault(rt, host, body).await,
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn kat() -> Result<Value, SdkError> {
    let report = kat_poprf().map_err(lg_err)?;
    Ok(json!({"all_match": report.all_match, "lines": report.lines}))
}

/// Sets the client clock offset and, with `host_offset_ms`, the host clock (debug hosts only).
async fn clock(account: &mut LocalBusAccountState, body: &Value) -> Result<Value, SdkError> {
    if let Some(offset) = body.get("client_offset_ms").and_then(Value::as_i64) {
        set_clock_offset_ms(offset);
    }
    if let Some(offset) = body.get("host_offset_ms").and_then(Value::as_i64) {
        let mut enc = Enc::default();
        enc.u64(u64::from_be_bytes(offset.to_be_bytes()));
        let mut engine = account.session_client().await?;
        let result = Host(&mut engine).call("debug_clock", enc.finish()).await;
        account.apply_session_metadata(engine);
        result?;
    }
    Ok(json!({"now_ms": now_ms()}))
}

async fn fault(rt: &Runtime, host: &mut Host<'_>, body: &Value) -> Result<Value, SdkError> {
    let kind = body.get("kind").and_then(Value::as_str).unwrap_or_default();
    let mut enc = Enc::default();
    let number = |name: &str| body.get(name).and_then(Value::as_u64).unwrap_or(0);
    let op = match kind {
        "roll" => {
            enc.fixed(&rt.st.gid).u8(u8::try_from(number("reason")).unwrap_or(2));
            "debug_roll"
        }
        "hold" => {
            let except = match body.get("except").and_then(Value::as_str) {
                Some(text) => b64_32(text)?,
                None => crate::large_group::state::pub_of(&rt.st.p_seed),
            };
            enc.fixed(&except).u64(number("from_seq")).u64(now_ms().saturating_add(number("ms")));
            "debug_hold"
        }
        "appended" => {
            enc.u64(number("ms"));
            "debug_appended"
        }
        "wrong_slot" => {
            let target = body.get("p").and_then(Value::as_str).ok_or_else(|| lg_msg("p"))?;
            enc.fixed(&b64_32(target)?);
            "debug_wrong_slot"
        }
        "alt_head" => {
            enc.fixed(&rt.st.gid).u64(number("n"));
            "debug_alt_head"
        }
        "garbage_w" => {
            enc.fixed(&rt.st.gid);
            "debug_garbage_w"
        }
        _ => return Err(lg_msg("unknown fault kind")),
    };
    let reply = host.call(op, enc.finish()).await?;
    Ok(json!({"ok": true, "reply": ramflux_protocol::encode_base64url(reply)}))
}

/// Joins `count` synthetic pseudonyms with real keys (their state is discarded); the host sees
/// the same requests as for real members. Retries the host join bucket (1/s, burst 10).
async fn bulk_join(account: &mut LocalBusAccountState, body: &Value) -> Result<Value, SdkError> {
    let link = body.get("link").and_then(Value::as_str).ok_or_else(|| lg_msg("link"))?;
    let count = body.get("count").and_then(Value::as_u64).unwrap_or(0).min(BULK_JOIN_MAX);
    let mut engine = account.session_client().await?;
    let mut joined = 0_u64;
    let mut failure = None;
    'outer: while joined < count {
        let mut retries = 0_u32;
        loop {
            match ops::join(&mut Host(&mut engine), link).await {
                Ok(_) => {
                    joined += 1;
                    break;
                }
                Err(SdkError::LocalBusRefused { body: refused, .. })
                    if refused.get("refusal").and_then(Value::as_str)
                        == Some("join_rate_limited")
                        && retries < BULK_RETRY_LIMIT =>
                {
                    retries += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
                }
                Err(error) => {
                    failure = Some(error.to_string());
                    break 'outer;
                }
            }
        }
    }
    account.apply_session_metadata(engine);
    Ok(json!({"joined": joined, "requested": count, "stopped": failure}))
}

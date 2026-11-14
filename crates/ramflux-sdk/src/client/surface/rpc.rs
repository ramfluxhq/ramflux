// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Immutable bound RPC replies; neither replay nor rejection enters the surface projection.
use super::resync_request::{ResyncDestination, ResyncReply};
use super::{Carrier, Outcome, PayloadKind, invalid, key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{RPC_SCHEMA, RpcFrame, RpcKind, SurfaceRpc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
const RETENTION_SECONDS: i64 = 24 * 60 * 60;
const MAX_ENTRIES: u32 = 256;
const CALLS_PER_MINUTE: u32 = 8;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    conversation: String,
    author: String,
    carrier_surface: String,
    surface: String,
    sender_device: String,
    known_version: u64,
    known_hash: Option<String>,
}
impl Scope {
    fn new(carrier: &Carrier, frame: &RpcFrame) -> Self {
        Self {
            conversation: carrier.conversation_id.clone(),
            author: carrier.author_principal_id.clone(),
            carrier_surface: carrier.surface_id.clone(),
            surface: frame.surface_id.clone(),
            sender_device: carrier.sender_device_id.clone(),
            known_version: frame.known_version,
            known_hash: frame.known_hash.clone(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    request_fingerprint: String,
    scope: Scope,
    response_base64: String,
    response_kind: RpcKind,
    expires_at: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Window {
    started_at: i64,
    count: u32,
}
fn accepted() -> Outcome {
    Outcome {
        accepted: true,
        fallback_text: String::new(),
        renderer_error: None,
        reason_code: None,
        retryable: false,
        queued: false,
    }
}
fn dropped() -> Outcome {
    Outcome::rejected(json!({"code":"rpc_dropped"}))
}
fn ledger_prefix(author: &str) -> String {
    key("rpc-ledger", author) + "/"
}
pub(super) fn ledger_key(carrier: &Carrier, id: &str) -> Result<String, SdkError> {
    Ok(ledger_prefix(&carrier.author_principal_id)
        + &ramflux_protocol::hash_base64url(
            ramflux_protocol::domain::SURFACE_RPC_REQUEST,
            &ramflux_protocol::canonical_json_bytes(&(
                &carrier.conversation_id,
                &carrier.author_principal_id,
                id,
            ))?,
        ))
}
impl RamfluxClient {
    pub(super) fn preflight_surface_rpc(
        &self,
        carrier: &Carrier,
        kind: RpcKind,
        rpc: &SurfaceRpc,
        outbound: bool,
    ) -> Result<Outcome, SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let author_call = kind == RpcKind::FunctionCall;
        if author_call && carrier.sender_principal_id != carrier.author_principal_id {
            return Ok(dropped());
        }
        if outbound {
            if carrier.sender_principal_id != local.principal_id {
                return Ok(dropped());
            }
            if !author_call && !self.surface_author_is_own_agent(&carrier.author_principal_id)? {
                return Ok(dropped());
            }
        } else if author_call {
            if !self.surface_author_is_own_agent(&carrier.author_principal_id)? {
                return Ok(dropped());
            }
        } else if local.principal_id != carrier.author_principal_id {
            return Ok(dropped());
        }
        if !outbound && kind != RpcKind::FunctionCall {
            let expected = self
                .born_v3_account
                .as_ref()
                .and_then(|a| a.record().body.profile.custodian.as_ref())
                .map(|c| c.account_anchor.as_str());
            let signer = self
                .surface_signer_record(&carrier.sender_principal_id, &carrier.sender_device_id)?;
            if expected.is_none()
                || expected != signer.get("principal_commitment").and_then(Value::as_str)
            {
                return Ok(dropped());
            }
            if let Some(id) = &rpc.frame().function_call_id {
                let Some(sent) =
                    self.account_db()?.load_actor_state::<Sent>(&sent_key(carrier, id)?)?
                else {
                    return Ok(dropped());
                };
                if sent.expires_at <= crate::prelude::now_unix_timestamp()
                    || kind == RpcKind::FunctionResponse && sent.surface != rpc.frame().surface_id
                {
                    return Ok(dropped());
                }
            }
        }
        if rpc.frame().conversation_id != carrier.conversation_id
            || rpc.frame().surface_id != carrier.surface_id
        {
            return Ok(dropped());
        }
        Ok(accepted())
    }
    pub(super) fn apply_surface_rpc(
        &self,
        carrier: &Carrier,
        kind: RpcKind,
        rpc: &SurfaceRpc,
        outbound: bool,
        group_epoch: Option<u64>,
    ) -> Result<Outcome, SdkError> {
        let preflight = self.preflight_surface_rpc(carrier, kind, rpc, outbound)?;
        if !preflight.accepted {
            return Ok(preflight);
        }
        if outbound {
            if kind == RpcKind::FunctionCall {
                return self.remember_outbound_rpc(carrier, rpc);
            }
            return Ok(preflight);
        }
        if kind != RpcKind::FunctionCall {
            return Ok(preflight);
        }
        let now = crate::prelude::now_unix_timestamp();
        let db = self.account_db()?;
        let thread = db
            .client_record("conversation", &carrier.conversation_id)?
            .ok_or_else(|| invalid("RPC conversation missing"))?;
        let group = thread.get("group_id").and_then(Value::as_str);
        self.authorize_surface_peer_context(
            &carrier.conversation_id,
            group,
            &carrier.sender_principal_id,
            &carrier.sender_device_id,
            group_epoch,
        )?;
        let rate_key = key("rpc-rate", &carrier.author_principal_id);
        let mut window = db
            .load_actor_state::<Window>(&rate_key)?
            .unwrap_or(Window { started_at: now, count: 0 });
        if now >= window.started_at.saturating_add(60) {
            window = Window { started_at: now, count: 0 };
        }
        if window.count >= CALLS_PER_MINUTE {
            return Ok(dropped());
        }
        window.count += 1;
        db.persist_actor_state(&rate_key, &window)?;
        let id =
            rpc.frame().function_call_id.as_deref().ok_or_else(|| invalid("RPC call id absent"))?;
        let prefix = ledger_prefix(&carrier.author_principal_id);
        for key in db.actor_state_key_page(&prefix, MAX_ENTRIES + 1)? {
            if db.load_actor_state::<Entry>(&key)?.is_some_and(|entry| entry.expires_at <= now) {
                db.remove_actor_state(&key)?;
            }
        }
        let entry_key = ledger_key(carrier, id)?;
        let fingerprint = rpc.request_fingerprint()?;
        let scope = Scope::new(carrier, rpc.frame());
        if let Some(entry) = db.load_actor_state::<Entry>(&entry_key)? {
            if entry.request_fingerprint != fingerprint || entry.scope != scope {
                db.append_journal(&crate::new_surface_message_id()?,"surface.rpc.conflict",&json!({"conversation_id":carrier.conversation_id,"author_principal_id":carrier.author_principal_id,"function_call_id":id}),now,None)?;
                return Ok(dropped());
            }
            self.queue_rpc_response(carrier, &entry, group, group_epoch)?;
            return Ok(accepted());
        }
        if db.actor_state_key_page(&prefix, MAX_ENTRIES)?.len() >= MAX_ENTRIES as usize {
            return Ok(dropped());
        }
        let well_formed = rpc.call_is_well_formed();
        let (response_kind, surface, a2ui) = if well_formed {
            (
                RpcKind::FunctionResponse,
                rpc.frame().surface_id.clone(),
                json!({"version":"1.0","rendererFunctionResponse":{"functionCallId":id,"error":{"code":"INVALID_FUNCTION_CALL","message":"function not callable by agent"}}}),
            )
        } else {
            (
                RpcKind::Error,
                "~rpc".into(),
                json!({"version":"1.0","error":{"code":"INVALID_FUNCTION_CALL","message":"malformed callRendererFunction","functionCallId":id}}),
            )
        };
        let state = if surface == "~rpc" {
            None
        } else {
            self.surface_state_scoped(
                &carrier.conversation_id,
                &carrier.author_principal_id,
                &surface,
            )?
            .map(|(_, s)| s)
        };
        let response = RpcFrame {
            schema: RPC_SCHEMA.into(),
            conversation_id: carrier.conversation_id.clone(),
            surface_id: surface,
            known_version: state.as_ref().map_or(0, ramflux_protocol::SurfaceState::version),
            known_hash: state.as_ref().and_then(|s| s.hash().map(str::to_owned)),
            function_call_id: Some(id.into()),
            rejected_version: None,
            a2ui,
        };
        let entry = Entry {
            request_fingerprint: fingerprint,
            scope,
            response_base64: ramflux_protocol::encode_base64url(
                response.wire_bytes(response_kind)?,
            ),
            response_kind,
            expires_at: now.saturating_add(RETENTION_SECONDS),
        };
        // Within the account writer transaction, first construction wins until expiry.
        db.persist_actor_state(&entry_key, &entry)?;
        self.queue_rpc_response(carrier, &entry, group, group_epoch)?;
        Ok(accepted())
    }
    fn queue_rpc_response(
        &self,
        call: &Carrier,
        entry: &Entry,
        group: Option<&str>,
        epoch: Option<u64>,
    ) -> Result<(), SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let bytes = ramflux_protocol::decode_base64url(&entry.response_base64)?;
        let frame = SurfaceRpc::from_wire_bytes(&bytes, entry.response_kind)?;
        let response = self.sign_surface_carrier(Carrier {
            schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
            content_type: "surface".into(),
            posted_at: None,
            updated_at: None,
            payload_kind: if entry.response_kind == RpcKind::Error {
                PayloadKind::Error
            } else {
                PayloadKind::FunctionResponse
            },
            conversation_id: call.conversation_id.clone(),
            surface_id: frame.frame().surface_id.clone(),
            message_id: crate::new_surface_message_id()?,
            sender_principal_id: local.principal_id.clone(),
            sender_device_id: local.device_id.clone(),
            author_principal_id: call.author_principal_id.clone(),
            wire_base64: entry.response_base64.clone(),
            signature: String::new(),
            snapshot: None,
        })?;
        let signer =
            self.surface_signer_record(&call.sender_principal_id, &call.sender_device_id)?;
        let required = |key: &str| {
            signer
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| invalid("RPC signer route missing"))
        };
        let destination = ResyncDestination {
            principal: call.sender_principal_id.clone(),
            root: required("principal_commitment")?,
            device: call.sender_device_id.clone(),
            target: required("target_delivery_id")?,
            group: group.map(str::to_owned),
            epoch,
            expires_at: entry.expires_at,
        };
        let id = ramflux_protocol::hash_base64url(
            ramflux_protocol::domain::SURFACE_RPC_REQUEST,
            &ramflux_protocol::canonical_json_bytes(&(
                &call.conversation_id,
                &call.author_principal_id,
                &call.sender_device_id,
                &entry.response_base64,
            ))?,
        );
        self.account_db()?.persist_actor_state(
            &format!("surface/rpc-response/{id}"),
            &ResyncReply { carrier: response, destination },
        )?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sent {
    fingerprint: String,
    scope: Scope,
    surface: String,
    expires_at: i64,
}
fn sent_key(carrier: &Carrier, id: &str) -> Result<String, SdkError> {
    Ok(key("rpc-sent", &carrier.author_principal_id)
        + "/"
        + &ramflux_protocol::hash_base64url(
            ramflux_protocol::domain::SURFACE_RPC_REQUEST,
            &ramflux_protocol::canonical_json_bytes(&(
                &carrier.conversation_id,
                &carrier.author_principal_id,
                id,
            ))?,
        ))
}
impl RamfluxClient {
    fn remember_outbound_rpc(
        &self,
        carrier: &Carrier,
        rpc: &SurfaceRpc,
    ) -> Result<Outcome, SdkError> {
        let id =
            rpc.frame().function_call_id.as_deref().ok_or_else(|| invalid("RPC call id absent"))?;
        let key = sent_key(carrier, id)?;
        let now = crate::prelude::now_unix_timestamp();
        let prefix = super::key("rpc-sent", &carrier.author_principal_id) + "/";
        let db = self.account_db()?;
        for candidate in db.actor_state_key_page(&prefix, MAX_ENTRIES + 1)? {
            if db.load_actor_state::<Sent>(&candidate)?.is_some_and(|sent| sent.expires_at <= now) {
                db.remove_actor_state(&candidate)?;
            }
        }
        let fingerprint = rpc.request_fingerprint()?;
        let scope = Scope::new(carrier, rpc.frame());
        if let Some(sent) = self.account_db()?.load_actor_state::<Sent>(&key)?
            && sent.expires_at > now
        {
            return Ok(if sent.fingerprint == fingerprint && sent.scope == scope {
                accepted()
            } else {
                dropped()
            });
        }
        if db.actor_state_key_page(&prefix, MAX_ENTRIES)?.len() >= MAX_ENTRIES as usize {
            return Ok(dropped());
        }
        let state = if rpc.frame().surface_id == "~rpc" {
            None
        } else {
            self.surface_state_scoped(
                &carrier.conversation_id,
                &carrier.author_principal_id,
                &rpc.frame().surface_id,
            )?
            .map(|(_, s)| s)
        };
        if rpc.frame().known_version
            != state.as_ref().map_or(0, ramflux_protocol::SurfaceState::version)
            || rpc.frame().known_hash.as_deref()
                != state.as_ref().and_then(ramflux_protocol::SurfaceState::hash)
        {
            return Ok(dropped());
        }
        self.account_db()?.persist_actor_state(
            &key,
            &Sent {
                fingerprint,
                scope,
                surface: rpc.frame().surface_id.clone(),
                expires_at: now.saturating_add(RETENTION_SECONDS),
            },
        )?;
        Ok(accepted())
    }
    pub(super) fn queue_surface_error_report(
        &self,
        carrier: &Carrier,
        event: &ramflux_protocol::SurfaceEvent,
        outcome: &Outcome,
        epoch: Option<u64>,
    ) -> Result<(), SdkError> {
        if !self.surface_author_is_own_agent(&carrier.author_principal_id)?
            || carrier.sender_principal_id != carrier.author_principal_id
        {
            return Ok(());
        }
        let marker = super::scoped_key(
            "rpc-error-reported",
            &[
                &carrier.conversation_id,
                &carrier.author_principal_id,
                &carrier.surface_id,
                &event.version().to_string(),
            ],
        )?;
        if self.account_db()?.actor_state_exists(&marker)? {
            return Ok(());
        }
        let code = match outcome
            .renderer_error
            .as_ref()
            .and_then(|v| v.pointer("/reject/reject"))
            .and_then(Value::as_str)
        {
            Some("validation" | "locale_dependent_check") => "VALIDATION_FAILED",
            Some("expression") => "EXPRESSION_ERROR",
            _ => "INTEGRITY_ERROR",
        };
        let mut error =
            json!({"code":code,"message":"surface update rejected","surfaceId":carrier.surface_id});
        if code == "VALIDATION_FAILED"
            && let Some(map) = error.as_object_mut()
        {
            map.insert("path".into(), json!(""));
        }
        let state = self
            .surface_state_scoped(
                &carrier.conversation_id,
                &carrier.author_principal_id,
                &carrier.surface_id,
            )?
            .map(|(_, s)| s);
        let frame = RpcFrame {
            schema: RPC_SCHEMA.into(),
            conversation_id: carrier.conversation_id.clone(),
            surface_id: carrier.surface_id.clone(),
            known_version: state.as_ref().map_or(0, ramflux_protocol::SurfaceState::version),
            known_hash: state.as_ref().and_then(|s| s.hash().map(str::to_owned)),
            function_call_id: None,
            rejected_version: Some(event.version()),
            a2ui: json!({"version":"1.0","error":error}),
        };
        let entry = Entry {
            request_fingerprint: String::new(),
            scope: Scope::new(carrier, &frame),
            response_base64: ramflux_protocol::encode_base64url(frame.wire_bytes(RpcKind::Error)?),
            response_kind: RpcKind::Error,
            expires_at: crate::prelude::now_unix_timestamp().saturating_add(RETENTION_SECONDS),
        };
        let thread = self
            .account_db()?
            .client_record("conversation", &carrier.conversation_id)?
            .ok_or_else(|| invalid("error report conversation missing"))?;
        self.queue_rpc_response(
            carrier,
            &entry,
            thread.get("group_id").and_then(Value::as_str),
            epoch,
        )?;
        self.account_db()?.persist_actor_state(&marker, &true)?;
        Ok(())
    }
}

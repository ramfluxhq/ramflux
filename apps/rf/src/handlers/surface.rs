// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::{LocalBusClient, PathBuf, RfError, SurfaceAction, SurfaceCommand, print_json};
use ramflux_protocol::{ResolvedSurface, SurfaceReject, SurfaceSnapshot, SurfaceState};
use ramflux_sdk::LocalBusFrame;
use serde_json::{Value, json};
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) async fn handle_surface(
    socket: PathBuf,
    command: SurfaceCommand,
) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    let (account, method, body) = match command.action {
        SurfaceAction::Get {
            account,
            surface_id,
            surface_ref,
            conversation,
            author,
            action_id,
            resolved,
        } => {
            let body = json!({"surface_id":surface_id,"surface_ref":surface_ref,"conversation_id":conversation,"author_principal_id":author,"action_id":action_id});
            if resolved {
                let response = bus.request(Some(account), "surface", "surface.get", body).await?;
                return print_resolved(&response);
            }
            (account, "surface.get", body)
        }
        SurfaceAction::List { account, conversation, limit, cursor } => (
            account,
            "surface.list",
            json!({"conversation_id":conversation,"limit":limit,"cursor":cursor}),
        ),
        SurfaceAction::RequestResync { account, surface_ref } => {
            (account, "surface.request_resync", json!({"surface_ref":surface_ref}))
        }
        SurfaceAction::Resync { account, surface_ref, message } => {
            let message = match message.as_deref() {
                Some(message) => {
                    let update = ramflux_sdk::bindings::cli::identity_update(
                        &account,
                        0,
                        message.as_bytes(),
                    )?;
                    let event_id = ramflux_sdk::bindings::cli::identity_event_id(&update)?;
                    Some(
                        String::from_utf8(event_id)
                            .map_err(|err| RfError::Message(err.to_string()))?,
                    )
                }
                None => None,
            };
            (account, "surface.resync", json!({"surface_ref":surface_ref,"message_id":message}))
        }
        action => {
            let (send, method) = match action {
                SurfaceAction::Send(send) => (send, "surface.send"),
                SurfaceAction::Action(send) => (send, "surface.action"),
                _ => return Err(RfError::Message("invalid surface command".into())),
            };
            let mut wire = Vec::new();
            std::fs::File::open(send.wire_file)?.take(700_001).read_to_end(&mut wire)?;
            if wire.len() > 700_000 {
                return Err(RfError::Message("surface payload exceeds bus frame budget".into()));
            }
            let message = match send.message {
                Some(id) => id,
                None => ramflux_sdk::new_surface_message_id()?,
            };
            (
                send.account,
                method,
                json!({"conversation_id":send.conversation,"message_id":message,"wire_base64":ramflux_protocol::encode_base64url(wire),"author_principal_id":send.author}),
            )
        }
    };
    if matches!(method, "surface.send" | "surface.action") {
        // Writes keep the daemon refusal on stdout and fail the process. A surface
        // action the bus accepts as a frame but marks `accepted: false` is the same refusal.
        let frame = LocalBusFrame::request(request_id(), Some(account), "surface", method, body);
        let response = bus.request_frame_response(frame).await?;
        return crate::handlers::conversation_ops::commit_write(method, &response);
    }
    let response = bus.request(Some(account), "surface", method, body).await?;
    print_json(&response)
}

/// Resolve the authorized snapshot of a `surface.get` read with the shared protocol resolver.
/// A refusal is printed as `{"refusal": …}` and fails the process.
fn print_resolved(view: &Value) -> Result<(), RfError> {
    let mut out = json!({
        "surface_ref": view.get("surface_ref"),
        "surface_id": view.get("surface_id"),
        "version": view.get("version"),
        "surface_hash": view.get("surface_hash"),
        "render_allowed": view.get("render_allowed"),
    });
    let resolved = match resolve_view(view) {
        Ok(resolved) => resolved,
        Err(refusal) => {
            out["refusal"] = refusal;
            print_json(&out)?;
            return Err(RfError::Message("surface resolver refused the snapshot".into()));
        }
    };
    out["resolved"] = serde_json::to_value(resolved)?;
    print_json(&out)
}

fn resolve_view(view: &Value) -> Result<ResolvedSurface, Value> {
    let snapshot = match view.get("snapshot") {
        Some(snapshot) if !snapshot.is_null() => snapshot.clone(),
        _ => return Err(json!({"reject":"snapshot_unavailable"})),
    };
    let snapshot: SurfaceSnapshot =
        serde_json::from_value(snapshot).map_err(|_| json!({"reject":"encoding"}))?;
    let (Some(conversation), Some(version)) = (
        view.get("conversation_id").and_then(Value::as_str),
        view.get("version").and_then(Value::as_u64),
    ) else {
        return Err(json!({"reject":"view_incomplete"}));
    };
    let refusal = |reject: SurfaceReject| json!(reject);
    let state =
        SurfaceState::from_authorized_snapshot(conversation, version, snapshot).map_err(refusal)?;
    if state.hash() != view.get("surface_hash").and_then(Value::as_str) {
        return Err(json!({"reject":"hash_mismatch"}));
    }
    state.content().ok_or_else(|| json!({"reject":"not_created"}))?.resolve().map_err(refusal)
}

fn request_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("rf-surface-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

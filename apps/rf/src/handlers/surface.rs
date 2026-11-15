// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::{LocalBusClient, PathBuf, RfError, SurfaceAction, SurfaceCommand, print_json};
use ramflux_sdk::LocalBusFrame;
use serde_json::json;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};

/// Upper bound for a typed surface command file; the bus frame budget is 700 KB.
const SURFACE_COMMAND_MAX_BYTES: u64 = 262_144;
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
        } => (
            account,
            "surface.get",
            json!({"surface_id":surface_id,"surface_ref":surface_ref,"conversation_id":conversation,"author_principal_id":author,"action_id":action_id}),
        ),
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
        SurfaceAction::Send(event) => {
            let mut raw = Vec::new();
            std::fs::File::open(event.command_file)?
                .take(SURFACE_COMMAND_MAX_BYTES + 1)
                .read_to_end(&mut raw)?;
            if u64::try_from(raw.len()).unwrap_or(u64::MAX) > SURFACE_COMMAND_MAX_BYTES {
                return Err(RfError::Message("surface command file exceeds 256 KiB".into()));
            }
            let command: ramflux_protocol::A2uiConversationCommand = serde_json::from_slice(&raw)?;
            let mut request = ramflux_sdk::SurfaceSendRequest::event(
                &event.conversation,
                event.version,
                &command,
            )?;
            if let Some(message) = event.message {
                request.message_id = message;
            }
            request.author_principal_id = event.author;
            (event.account, "surface.send", serde_json::to_value(request)?)
        }
        SurfaceAction::Action(send) => {
            let method = "surface.action";
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
        // Writes keep the daemon refusal code and details, as `rf conversation` does.
        let frame = LocalBusFrame::request(request_id(), Some(account), "surface", method, body);
        let response = bus.request_frame_response(frame).await?;
        return print_json(&crate::handlers::conversation_ops::outcome(method, &response));
    }
    let response = bus.request(Some(account), "surface", method, body).await?;
    print_json(&response)
}

fn request_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("rf-surface-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

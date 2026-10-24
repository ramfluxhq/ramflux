// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::{LocalBusClient, PathBuf, RfError, SurfaceAction, SurfaceCommand, print_json};
use serde_json::json;
use std::io::Read;
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
        SurfaceAction::Resync { account, surface_ref, message } => {
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
    let response = bus.request(Some(account), "surface", method, body).await?;
    print_json(&response)
}

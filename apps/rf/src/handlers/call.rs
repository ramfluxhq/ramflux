// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_call(socket: PathBuf, command: CallCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        CallAction::Invite(invite) => {
            let request = LocalBusCallInviteRequest { conversation_id: invite.conversation };
            print_json(
                &bus.request(
                    Some(invite.account),
                    "call",
                    "call.invite",
                    serde_json::to_value(request)?,
                )
                .await?,
            )
        }
        CallAction::Answer(answer) => {
            let request = LocalBusCallAnswerRequest { call_id: answer.call };
            print_json(
                &bus.request(
                    Some(answer.account),
                    "call",
                    "call.answer",
                    serde_json::to_value(request)?,
                )
                .await?,
            )
        }
        CallAction::Reject(selector) => print_json(
            &bus.request(
                Some(selector.account),
                "call",
                "call.reject",
                serde_json::json!({"call_id":selector.call}),
            )
            .await?,
        ),
        CallAction::List(selector) => print_json(
            &bus.request(Some(selector.account), "call", "call.list", serde_json::json!({}))
                .await?,
        ),
        CallAction::Hangup(hangup) => {
            let request = LocalBusCallHangupRequest { call_id: hangup.call };
            print_json(
                &bus.request(
                    Some(hangup.account),
                    "call",
                    "call.hangup",
                    serde_json::to_value(request)?,
                )
                .await?,
            )
        }
    }
}

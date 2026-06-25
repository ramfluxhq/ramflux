#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;

pub(crate) async fn handle_call(socket: PathBuf, command: CallCommand) -> Result<(), RfError> {
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        CallAction::Invite(invite) => {
            let request = LocalBusCallInviteRequest {
                call_id: invite.call,
                target_id: invite.to,
                opaque_offer_base64: ramflux_protocol::encode_base64url(invite.offer.as_bytes()),
                srtp_media_key_base64: invite
                    .srtp_key
                    .map(|key| ramflux_protocol::encode_base64url(key.as_bytes())),
            };
            print_json(&bus.request(Some(invite.account), "call", "call.invite", &request).await?)
        }
        CallAction::Answer(answer) => {
            let request = LocalBusCallAnswerRequest {
                call_id: answer.call,
                opaque_answer_base64: ramflux_protocol::encode_base64url(answer.answer.as_bytes()),
            };
            print_json(&bus.request(Some(answer.account), "call", "call.answer", &request).await?)
        }
        CallAction::Hangup(hangup) => {
            let request = LocalBusCallHangupRequest { call_id: hangup.call };
            print_json(&bus.request(Some(hangup.account), "call", "call.hangup", &request).await?)
        }
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner revocation of one shared object, sent through the existing native control carrier.
use super::daemon::local_bus_ok;
use crate::bus::daemon::LocalBusDispatchResult;
use crate::bus::protocol::{LocalBusFrame, LocalBusObjectRevokeRequest};
use crate::bus::state::LocalBusAccountState;
use crate::{GatewayDirectMessage, SdkError};
use ramflux_protocol::message::ObjectRevokeAccess;

pub(super) fn validate(body: &LocalBusObjectRevokeRequest) -> Result<(), SdkError> {
    if body.object_id.is_empty()
        || body.recipient_principal_id.is_empty()
        || body.link_id.is_empty()
        || body.conversation_id.is_empty()
        || body.recipient_device_id.is_empty()
        || body.target_delivery_id.is_empty()
        || body.effective_at == 0
    {
        return Err(SdkError::GeneratedRefused {
            code: crate::GeneratedRefusalCode::Content,
            reason: "object.revoke requires object, recipient, link, conversation, device, target and effective_at".into(),
        });
    }
    Ok(())
}

pub(super) async fn dispatch(
    request: &LocalBusFrame,
    account: &mut LocalBusAccountState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let body: LocalBusObjectRevokeRequest = serde_json::from_value(request.body.clone())?;
    validate(&body)?;
    let mut revoke_body = serde_json::json!({
        "object_id": body.object_id,
        "recipient_principal_id": body.recipient_principal_id,
        "link_id": body.link_id,
        "effective_at": body.effective_at,
    });
    if let Some(reason) = body.reason.as_deref().filter(|reason| !reason.is_empty()) {
        revoke_body["reason"] = serde_json::Value::String(reason.to_owned());
    }
    let revoke: ObjectRevokeAccess = serde_json::from_value(revoke_body)?;
    let mut engine = account.session_client().await?;
    let result = async {
        let recipient_principal_commitment = account
            .client
            .resolve_target_principal_commitment(
                &engine.config,
                body.recipient_principal_commitment.as_deref(),
                &body.recipient_device_id,
            )
            .await?;
        let message = GatewayDirectMessage {
            conversation_id: body.conversation_id.clone(),
            message_id: format!("object.revoke:{}:{}", body.object_id, body.link_id),
            envelope_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            source_principal_id: engine.config.principal_id.clone(),
            sender_id: body
                .sender_id
                .clone()
                .filter(|sender| !sender.is_empty())
                .unwrap_or_else(|| engine.config.device_id.clone()),
            recipient_device_id: Some(body.recipient_device_id.clone()),
            recipient_principal_commitment: Some(recipient_principal_commitment),
            target_delivery_id: body.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: crate::time::now_unix_timestamp(),
            ttl: account.client.content_ttl()?,
        };
        account.client.send_object_revoke_via_gateway(&mut engine, message, revoke).await
    }
    .await;
    account.apply_session_metadata(engine);
    let entry = result?;
    Ok(local_bus_ok(serde_json::to_value(entry)?))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn request(
        object_id: &str,
        recipient: &str,
        link: &str,
        conversation: &str,
        device: &str,
        target: &str,
        effective_at: i64,
    ) -> LocalBusObjectRevokeRequest {
        LocalBusObjectRevokeRequest {
            object_id: object_id.to_owned(),
            conversation_id: conversation.to_owned(),
            recipient_principal_id: recipient.to_owned(),
            link_id: link.to_owned(),
            reason: None,
            effective_at,
            recipient_device_id: device.to_owned(),
            recipient_principal_commitment: None,
            target_delivery_id: target.to_owned(),
            sender_id: None,
        }
    }

    #[test]
    fn incomplete_revoke_fields_refuse_before_a_session() {
        let started = std::time::Instant::now();
        let deadline = std::time::Duration::from_secs(10);
        let complete =
            request("object", "recipient", "link", "conversation", "device", "target", 1);
        assert!(validate(&complete).is_ok());
        let cases = [
            request("", "recipient", "link", "conversation", "device", "target", 1),
            request("object", "", "link", "conversation", "device", "target", 1),
            request("object", "recipient", "", "conversation", "device", "target", 1),
            request("object", "recipient", "link", "", "device", "target", 1),
            request("object", "recipient", "link", "conversation", "", "target", 1),
            request("object", "recipient", "link", "conversation", "device", "", 1),
            request("object", "recipient", "link", "conversation", "device", "target", 0),
        ];
        for body in cases {
            let error = validate(&body).expect_err("incomplete revoke");
            assert!(
                matches!(
                    error,
                    SdkError::GeneratedRefused { code: crate::GeneratedRefusalCode::Content, .. }
                ),
                "{error:?}"
            );
        }
        assert!(started.elapsed() < deadline, "deadline exceeded");
    }
}

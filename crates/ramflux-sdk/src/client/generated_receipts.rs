// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed receipt production and target-qualified admission; no application JSON carrier.
use crate::client::identity_authority::HeadUse;
use crate::dm::{SdkReceiptEventBody, SdkReceiptEventEnvelope};
use crate::{GatewayDirectMessage, GatewayInboxEntry, RamfluxClient, SdkError};
use ramflux_protocol::message as g;

fn refused(reason: &str) -> SdkError {
    SdkError::InboundRejected(format!("receipt: {reason}"))
}

impl RamfluxClient {
    pub(crate) fn prepare_generated_receipt(
        &self,
        message: &mut GatewayDirectMessage,
        event: &SdkReceiptEventEnvelope,
    ) -> Result<super::authored_send::PreparedMessage, SdkError> {
        let (conversation, id, at, device, state) = match &event.event {
            SdkReceiptEventBody::Delivered {
                conversation_id,
                message_id,
                delivered_at,
                receiver_device_id,
                ..
            } => (
                conversation_id,
                message_id,
                *delivered_at,
                receiver_device_id,
                g::ReceiptState::ReceiptDelivered,
            ),
            SdkReceiptEventBody::ReadPrivate {
                conversation_id,
                message_id,
                read_at,
                reader_identity,
                ..
            } => (
                conversation_id,
                message_id,
                *read_at,
                reader_identity,
                g::ReceiptState::ReceiptRead,
            ),
            SdkReceiptEventBody::ReadPublic { .. } => {
                return Err(refused("public receipts cannot use the E2EE path"));
            }
        };
        let own = self.owned_device_identity()?;
        if conversation != &message.conversation_id || device != own.device_id() {
            return Err(refused("local receipt scope or device mismatch"));
        }
        let db = self.account_db()?;
        let target = db
            .load_actor_state::<g::EventIdentity>(&format!("routed/generated-identity/{id}"))?
            .ok_or_else(|| refused("target has no authenticated identity"))?;
        let author = target.author.as_ref().ok_or_else(|| refused("target author missing"))?;
        if target.conversation_id != *conversation {
            return Err(refused("target conversation mismatch"));
        }
        let receipt = g::Receipt {
            targets: vec![g::MessageRef {
                id: target.id.clone(),
                conversation_id: conversation.clone(),
                author_anchor: author.account_anchor.clone(),
            }],
            state: state.into(),
            at: u64::try_from(at).map_err(|_| refused("negative timestamp"))?,
            receiver: Some(g::QualifiedDevice {
                account_anchor: own.root_commitment().into(),
                device_id: own.device_id().into(),
                device_epoch: self
                    .device_branch
                    .as_ref()
                    .ok_or(SdkError::IdentityRootMissing)?
                    .device_epoch,
            }),
        };
        self.prepare_authored_content(
            message,
            target.group_id.as_deref(),
            &g::Content { value: Some(g::content::Value::Receipt(receipt)) },
        )
    }

    pub(crate) fn apply_generated_receipt(
        &self,
        entry: &GatewayInboxEntry,
        identity: &g::EventIdentity,
        receipt: &g::Receipt,
    ) -> Result<(), SdkError> {
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let receiver = receipt.receiver.as_ref().ok_or_else(|| refused("receiver missing"))?;
        if identity.author.as_ref() != Some(receiver)
            || receiver.account_anchor != source.root_commitment()
            || receiver.device_id != source.device_id()
        {
            return Err(refused("receiver differs from authenticated sender"));
        }
        let at = i64::try_from(receipt.at).map_err(|_| refused("timestamp overflow"))?;
        let state =
            g::ReceiptState::try_from(receipt.state).map_err(|_| refused("unknown state"))?;
        let kind = match state {
            g::ReceiptState::ReceiptDelivered => "delivered",
            g::ReceiptState::ReceiptRead => "read",
            g::ReceiptState::ReceiptUnspecified => return Err(refused("unspecified state")),
        };
        let own = self.own_account_anchor()?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            for target in &receipt.targets {
                let id = ramflux_protocol::encode_base64url(&target.id);
                if target.conversation_id != identity.conversation_id || target.author_anchor != own
                {
                    return Err(refused("target scope or author mismatch"));
                }
                let row = db.direct_message_by_id(&id)?.ok_or_else(|| refused("target missing"))?;
                if row.deleted {
                    continue;
                }
                if !row.is_own || row.conversation_id != target.conversation_id {
                    return Err(refused("receipt does not refer to an authored message"));
                }
                let key = format!("{}/{}", ramflux_protocol::encode_base64url(&identity.id), id);
                if db.record_receipt_event_once(ramflux_storage::ReceiptEventWrite {
                    receipt_id: &key,
                    conversation_id: &target.conversation_id,
                    message_id: &id,
                    receipt_type: kind,
                    actor: &source,
                    created_at: at,
                })? {
                    match state {
                        g::ReceiptState::ReceiptDelivered => {
                            self.mark_delivered(
                                &target.conversation_id,
                                &source,
                                &id,
                                at,
                                crate::offline_retention::RECEIPT_TTL_SECS.into(),
                            )?;
                        }
                        g::ReceiptState::ReceiptRead => {
                            self.mark_read(&target.conversation_id, &source, &id)?;
                        }
                        g::ReceiptState::ReceiptUnspecified => {
                            return Err(refused("unspecified state"));
                        }
                    }
                }
            }
            Ok(())
        })
    }
}

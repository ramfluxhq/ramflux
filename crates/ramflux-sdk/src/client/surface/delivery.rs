// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated logical delivery, receipts and replay, before any decision consumption.
use super::{Carrier, Outcome, Payload, PayloadKind, Receipt, SurfaceSender, key};
use crate::{RamfluxClient, SdkError};
use serde_json::json;
impl RamfluxClient {
    pub(crate) fn project_surface_message(
        &self,
        conversation: &str,
        message: &str,
        sender: SurfaceSender<'_>,
        body: &[u8],
        outbound: bool,
    ) -> Result<Option<Outcome>, SdkError> {
        if !body.starts_with(super::carrier::PREFIX) {
            return Ok(None);
        }
        self.account_db()?.surface_transaction(|| {
            let result =
                self.project_surface_once(conversation, message, sender, body, outbound)?;
            if result.accepted
                && let Ok(Some(carrier)) = Carrier::decode(body)
                && (carrier.payload_kind == PayloadKind::Event
                    || carrier.payload_kind == PayloadKind::ActionReceipt)
            {
                self.drain_surface_pending(&carrier.surface_reference()?)?;
            }
            Ok(Some(result))
        })
    }
    pub(super) fn project_surface_once(
        &self,
        conversation: &str,
        message: &str,
        sender: SurfaceSender<'_>,
        body: &[u8],
        outbound: bool,
    ) -> Result<Outcome, SdkError> {
        let Ok(Some(carrier)) = Carrier::decode(body) else {
            return self.reject_surface_delivery(conversation, message, sender, "invalid_carrier");
        };
        if carrier.conversation_id != conversation {
            return self.reject_surface_delivery(
                conversation,
                message,
                sender,
                "transport_binding_mismatch",
            );
        }
        let Ok(payload) = self.verify_surface_carrier(&carrier, sender.principal, sender.device)
        else {
            return self.reject_surface_delivery(
                conversation,
                message,
                sender,
                "invalid_signature_or_wire",
            );
        };
        // A payload claim can never reserve another principal's logical-message id.
        let fingerprint =
            ramflux_protocol::hash_base64url("ramflux.surface.delivery.v1", &carrier.bytes()?);
        let receipt_key = super::receipt_key(&carrier)?;
        let db = self.account_db()?;
        if let Some(receipt) = db.load_actor_state::<Receipt>(&receipt_key)? {
            if receipt.fingerprint != fingerprint {
                return self.reject_surface_delivery(
                    conversation,
                    message,
                    sender,
                    "message_id_conflict",
                );
            }
            if !receipt.result.retryable {
                let result = self.refresh_surface_outcome(&carrier, receipt.result)?;
                self.store_surface_message_reference(&carrier, message, sender, &result)?;
                return Ok(result);
            }
        }
        if !self.surface_pending_id_matches(&carrier)? {
            return self.reject_surface_delivery(
                conversation,
                message,
                sender,
                "message_id_conflict",
            );
        }
        let version = match &payload {
            Payload::Event(event) => Some(event.version()),
            Payload::Action(action) | Payload::ActionReceipt { action, .. } => {
                Some(action.version())
            }
        };
        let covered = carrier.sender_principal_id == carrier.author_principal_id
            && matches!(&payload,Payload::Event(event) if event.version()<=self.surface_snapshot_floor(&carrier.surface_reference()?)?);
        let mut outcome = if covered {
            let (_, state) = self
                .surface_state_ref(&carrier.surface_reference()?)?
                .ok_or_else(|| super::invalid("snapshot floor has no surface state"))?;
            Outcome::accepted(&carrier.author_principal_id, &state)?
        } else {
            self.apply_surface_payload(&carrier, payload, outbound)?
        };
        if outcome.retryable
            && !outbound
            && let Some(version) = version
        {
            outcome.queued = self.queue_surface_pending(&carrier, message, sender, version)?;
        }
        if let Some(error) = &outcome.renderer_error {
            let reference = (carrier.sender_principal_id == carrier.author_principal_id
                && carrier.payload_kind == PayloadKind::Event)
                .then(|| carrier.surface_reference())
                .transpose()?;
            self.surface_error(conversation, message, sender, reference.as_deref(), error)?;
        }
        // Future versions and not-created events remain retryable, never terminal receipts.
        if !outcome.retryable {
            db.persist_actor_state(
                &receipt_key,
                &Receipt { fingerprint, result: outcome.clone() },
            )?;
        }
        self.store_surface_message_reference(&carrier, message, sender, &outcome)?;
        Ok(outcome)
    }
    fn reject_surface_delivery(
        &self,
        conversation: &str,
        message: &str,
        sender: SurfaceSender<'_>,
        code: &str,
    ) -> Result<Outcome, SdkError> {
        let error = json!({"code":code});
        self.surface_error(conversation, message, sender, None, &error)?;
        Ok(Outcome::rejected(error))
    }
    fn store_surface_message_reference(
        &self,
        carrier: &Carrier,
        message: &str,
        sender: SurfaceSender<'_>,
        result: &Outcome,
    ) -> Result<(), SdkError> {
        self.account_db()?.persist_actor_state(&key("message",message),&json!({"surface_ref":carrier.surface_reference()?,"surface_id":carrier.surface_id,"conversation_id":carrier.conversation_id,"group_id":self.account_db()?.client_record("conversation",&carrier.conversation_id)?.and_then(|v|v["group_id"].as_str().map(str::to_owned)),"group_epoch":sender.group_epoch,"accepted":result.accepted,"fallback_text":result.fallback_text,"kind":carrier.payload_kind}))?;
        if result.accepted
            && let Some(epoch) = sender.group_epoch
        {
            let epoch_key = key("group_epoch", &carrier.surface_reference()?);
            let old = self.account_db()?.load_actor_state::<u64>(&epoch_key)?.unwrap_or(0);
            self.account_db()?.persist_actor_state(&epoch_key, &old.max(epoch))?;
        }
        Ok(())
    }
    pub(crate) fn surface_delivery_receipt(
        &self,
        carrier: &Carrier,
    ) -> Result<Option<Outcome>, SdkError> {
        let receipt_key = super::receipt_key(carrier)?;
        let fingerprint =
            ramflux_protocol::hash_base64url("ramflux.surface.delivery.v1", &carrier.bytes()?);
        let Some(receipt) = self.account_db()?.load_actor_state::<Receipt>(&receipt_key)? else {
            return Ok(None);
        };
        if receipt.result.retryable {
            return Ok(None);
        }
        Ok(Some(if receipt.fingerprint == fingerprint {
            self.refresh_surface_outcome(carrier, receipt.result)?
        } else {
            Outcome::rejected(json!({"code":"message_id_conflict"}))
        }))
    }
    fn refresh_surface_outcome(
        &self,
        carrier: &Carrier,
        mut result: Outcome,
    ) -> Result<Outcome, SdkError> {
        if result.accepted {
            let view =
                self.account_db()?.client_record("surface", &carrier.surface_reference()?)?;
            result.fallback_text =
                view.as_ref().and_then(|v| v["fallback_text"].as_str()).map_or_else(
                    || "[Surface unavailable]".into(),
                    |text| super::fallback::render(&carrier.author_principal_id, text),
                );
        }
        Ok(result)
    }
}

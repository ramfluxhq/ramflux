// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One logical outgoing projection shared by recipient-specific surface envelopes.
use super::{Carrier, Outcome, SurfaceSender, invalid};
use crate::{GatewayDirectMessage, RamfluxClient, SdkError};
impl RamfluxClient {
    pub(crate) fn stage_surface_outgoing(
        &self,
        carrier: &Carrier,
        group_epoch: Option<u64>,
    ) -> Result<Outcome, SdkError> {
        let timeline = Self::surface_timeline_id(carrier)?;
        self.account_db()?.surface_transaction(|| {
            if let Some(previous) = self.reuse_authored_surface(carrier)?
                && previous.bytes()? != carrier.bytes()?
            {
                return Err(invalid("surface logical message id already used"));
            }
            let first = self.surface_delivery_receipt(carrier)?.is_none();
            let outcome = self
                .project_surface_message(
                    &carrier.conversation_id,
                    &timeline,
                    SurfaceSender {
                        principal: &carrier.sender_principal_id,
                        device: &carrier.sender_device_id,
                        envelope_id: &carrier.message_id,
                        expires_at: None,
                        group_epoch,
                    },
                    &carrier.bytes()?,
                    true,
                )?
                .ok_or_else(|| invalid("surface projection absent"))?;
            if outcome.accepted {
                if first {
                    self.mark_own_history_changed()?;
                }
                self.retain_authored_surface(carrier)?;
                if self.direct_message_by_id(&timeline)?.is_none() {
                    self.send_direct_message(
                        &carrier.conversation_id,
                        &timeline,
                        &carrier.sender_device_id,
                        &[],
                    )?;
                }
                self.account_db()?.replace_surface_message_content(
                    &carrier.conversation_id,
                    &timeline,
                    outcome.fallback_text.as_bytes(),
                )?;
                self.set_surface_outgoing_state(carrier, "failed")?;
            }
            Ok(outcome)
        })
    }
    pub(crate) fn journal_surface_frame(
        &self,
        message: &GatewayDirectMessage,
        carrier: &Carrier,
        encrypted: &[u8],
    ) -> Result<(), SdkError> {
        if message.conversation_id != carrier.conversation_id
            || message.sender_id != carrier.sender_device_id
        {
            return Err(invalid("surface outgoing transport scope differs"));
        }
        let db = self.account_db()?;
        db.surface_transaction(|| {
            let retained = self.reuse_authored_surface(carrier)?;
            if let Some(previous) = &retained
                && previous.bytes()? != carrier.bytes()?
            {
                return Err(invalid("surface logical message id already used"));
            }
            if let Some(previous) = self.direct_message_by_id(&message.message_id)? {
                if previous.conversation_id != message.conversation_id
                    || previous.sender_id != message.sender_id
                    || retained.is_none()
                {
                    return Err(invalid("surface logical message scope collision"));
                }
                db.fill_pending_message_body(
                    &message.conversation_id,
                    &message.message_id,
                    &message.sender_id,
                    encrypted,
                )?;
            } else {
                self.send_direct_message(
                    &message.conversation_id,
                    &message.message_id,
                    &message.sender_id,
                    encrypted,
                )?;
            }
            self.retain_authored_surface(carrier)?;
            let outcome = if let Some(outcome) = self.surface_delivery_receipt(carrier)? {
                outcome
            } else {
                self.preflight_surface(carrier)?
            };
            db.replace_surface_message_content(
                &message.conversation_id,
                &message.message_id,
                outcome.fallback_text.as_bytes(),
            )?;
            Ok(())
        })
    }
    pub(crate) fn surface_outgoing_too_large(&self, carrier: &Carrier) -> Result<(), SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if carrier.author_principal_id == local.principal_id
            && carrier.sender_principal_id == local.principal_id
        {
            let version = self
                .surface_state_ref(&carrier.surface_reference()?)?
                .map_or(1, |(_, state)| state.version().saturating_add(1));
            self.mark_surface_out_of_sync(carrier, version)?;
            self.set_surface_outgoing_state(carrier, "failed")?;
        }
        Ok(())
    }
}

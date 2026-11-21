// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One logical outgoing projection shared by recipient-specific surface envelopes.
use super::{Carrier, Outcome, SurfaceSender, invalid};
use crate::{RamfluxClient, SdkError};
impl RamfluxClient {
    #[cfg(test)]
    pub(crate) fn stage_surface_outgoing(
        &self,
        carrier: &Carrier,
        group_epoch: Option<u64>,
    ) -> Result<Outcome, SdkError> {
        let timeline = Self::surface_timeline_id(carrier)?;
        self.account_db()?.surface_transaction(|| {
            let outcome = self.stage_surface_outgoing_as(carrier, group_epoch, &timeline)?;
            if outcome.accepted {
                self.retain_authored_surface(carrier)?;
                if carrier.payload_kind.rpc_kind().is_some() {
                    return Ok(outcome);
                }
                self.queue_surface_own_copy(carrier, group_epoch)?;
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
            }
            Ok(outcome)
        })
    }

    pub(crate) fn stage_surface_outgoing_as(
        &self,
        carrier: &Carrier,
        group_epoch: Option<u64>,
        timeline: &str,
    ) -> Result<Outcome, SdkError> {
        self.account_db()?.surface_transaction(|| {
            if let Some(previous) = self.reuse_authored_surface(carrier)?
                && previous.bytes()? != carrier.bytes()?
            {
                return Err(invalid("surface logical message id already used"));
            }
            let outcome = self
                .project_surface_message(
                    &carrier.conversation_id,
                    timeline,
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
                self.retain_authored_surface(carrier)?;
                let (authored, _) = super::authored::authored_key(carrier)?;
                self.account_db()?.bind_message_container_reference(timeline, &authored)?;
                self.set_surface_outgoing_state(carrier, "failed")?;
            }
            Ok(outcome)
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

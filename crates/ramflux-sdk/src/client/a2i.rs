// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::client::identity_authority::HeadUse;
use crate::prelude::*;

impl RamfluxClient {
    pub fn send_a2i_control_event_via_gateway(
        &self,
        _engine: &mut impl GatewaySessionAccess,
        _event: &A2iControlEvent,
        _target_delivery_id: Option<String>,
    ) -> impl std::future::Future<Output = Result<GatewayInboxEntry, SdkError>> {
        std::future::ready(Self::refuse_a2i_binding_authority())
    }

    /// # Errors
    /// Returns an error when SDK-owned DM encryption, local projection persistence, envelope
    pub fn receive_a2i_control_events(
        &mut self,
        _engine: &mut impl GatewaySessionAccess,
        _limit: usize,
    ) -> impl std::future::Future<Output = Result<Vec<A2iControlEvent>, SdkError>> {
        std::future::ready(Self::refuse_a2i_binding_authority())
    }

    pub(crate) fn legacy_a2i_receipt_key(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<String, SdkError> {
        Ok(format!(
            "legacy/a2i/{}",
            self.authenticated_committed_key(HeadUse::NewAuthorization, entry)?
        ))
    }

    pub(crate) fn legacy_a2i_is_unbound(
        &self,
        local_device: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<bool, SdkError> {
        #[cfg(test)]
        if let Some(forced) = take_unbound_answer() {
            return Ok(forced);
        }
        let expected = a2i_control_conversation_id(&entry.envelope.source_device_id, local_device);
        Ok(self.legacy_routing_binding(local_device, entry)?.as_deref() != Some(expected.as_str()))
    }

    /// True when the entry has no exact A2I device-pair binding and was held unrouted.
    pub(crate) fn hold_unbound_legacy_a2i(
        &self,
        local_device: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<bool, SdkError> {
        if !self.legacy_a2i_is_unbound(local_device, entry)? {
            return Ok(false);
        }
        self.account_db()?.hold_unrouted(
            &entry.envelope.envelope_id,
            entry.inbox_seq,
            &serde_json::to_vec(&entry)?,
            now_unix_timestamp(),
        )?;
        Ok(true)
    }

    /// Existing receipt, or `InboundRejected` when the envelope id is reused with a new payload.
    pub(crate) fn load_legacy_a2i_receipt(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<LegacyControlReceipt>, SdkError> {
        let Some(receipt) = self
            .account_db()?
            .load_actor_state::<LegacyControlReceipt>(&self.legacy_a2i_receipt_key(entry)?)?
        else {
            return Ok(None);
        };
        reject_legacy_a2i_payload_reuse(&receipt, entry)?;
        Ok(Some(receipt))
    }

    pub(crate) fn decrypt_bound_legacy_a2i(
        local_device: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<LegacyA2iOpened, SdkError> {
        let _ = (local_device, entry);
        Self::require_a2i_binding_authority()?;
        Ok(LegacyA2iOpened)
    }

    pub(crate) fn persist_legacy_a2i_effect(
        entry: &GatewayInboxEntry,
        opened: &LegacyA2iOpened,
    ) -> Result<(), SdkError> {
        let _ = (entry, opened);
        Self::require_a2i_binding_authority()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct LegacyControlReceipt {
    pub event: A2iControlEvent,
    pub payload_hash: String,
}

pub(crate) struct LegacyA2iOpened;

/// Shared payload-hash check used by live receive and dormant W1.
pub(crate) fn reject_legacy_a2i_payload_reuse(
    receipt: &LegacyControlReceipt,
    entry: &GatewayInboxEntry,
) -> Result<(), SdkError> {
    if receipt.payload_hash != entry.envelope.payload_hash {
        return Err(SdkError::InboundRejected("legacy A2I envelope id reused".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static UNBOUND_QUEUE: std::cell::RefCell<Vec<bool>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn take_unbound_answer() -> Option<bool> {
    UNBOUND_QUEUE.with(|queue| {
        let mut queue = queue.borrow_mut();
        if queue.is_empty() { None } else { Some(queue.remove(0)) }
    })
}

#[cfg(test)]
pub(crate) fn queue_unbound_answers(answers: impl IntoIterator<Item = bool>) {
    UNBOUND_QUEUE.with(|queue| {
        let mut queue = queue.borrow_mut();
        queue.clear();
        queue.extend(answers);
    });
}

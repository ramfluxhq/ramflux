// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    pub(crate) fn candidate_group_target_plan(
        &self,
        group_id: &str,
        sender_id: &str,
        logical_event_id: &str,
        kind: ramflux_protocol::message::KindId,
    ) -> Result<Option<crate::client::target_selection::SelectionPlan>, SdkError> {
        Self::candidate_target_plan(|| {
            self.group_selection_request(group_id, sender_id, logical_event_id, kind)
        })
    }

    pub fn append_gateway_delivery(&self, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
        crate::client::routed::validate_routed_ciphertext(entry)?;
        if self.routed_seen_marker(entry)?.is_some() {
            return Ok(());
        }
        let event = format!("gateway/delivery/v2/{}", self.inbox_admission_key(entry)?);
        if self.event_body(&event)?.is_some() {
            return Ok(());
        }
        let body = ramflux_protocol::canonical_json_bytes(&entry.envelope)?;
        self.append_event(&event, "gateway.deliver.opaque", &body)
    }

    pub(crate) fn record_group_sender_key_counter(
        &self,
        envelope: &SdkGroupEncryptedEnvelope,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        message_id: &str,
    ) -> Result<bool, SdkError> {
        self.account_db()?
            .record_group_sender_key_counter(
                &GroupSenderKeyCounterRecord {
                    group_id: envelope.group_id.clone(),
                    group_key_epoch: envelope.group_key_epoch,
                    sender_id: envelope.sender_id.clone(),
                    session_id: envelope.ciphertext.session_id.clone(),
                    counter: envelope.ciphertext.counter,
                    message_id: message_id.to_owned(),
                    seen_at: now_unix_timestamp(),
                },
                source,
            )
            .map_err(SdkError::from)
    }
}

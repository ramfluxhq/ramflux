// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified domain projections; called only inside the receive commit transaction.
use super::{
    GatewayInboxEntry, Kind, MessageMetadata, Opened, RamfluxClient, SdkError,
    SdkGroupEncryptedEnvelope, SdkGroupSenderKeyDistribution,
    SdkGroupSenderKeyDistributionEnvelope, invalid, now_unix_timestamp,
};
impl RamfluxClient {
    pub(super) fn project_routed(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        body: &[u8],
        metadata: Option<&MessageMetadata>,
    ) -> Result<Option<Vec<u8>>, SdkError> {
        let route = &opened.routing;
        match route.kind {
            Kind::Direct => self.project_routed_direct(opened, entry, body, metadata),
            Kind::Receipt => {
                self.apply_receipt_event_plaintext(body, &entry.envelope.source_device_id)?
                    .ok_or_else(|| invalid("invalid routed receipt"))?;
                Ok(None)
            }
            Kind::GroupControl => self.project_routed_group_control(opened, entry, body),
            Kind::GroupMessage => self.project_routed_group_message(opened, entry, body),
            Kind::Control => self.project_routed_control(opened, entry, body),
        }
    }
    fn project_routed_direct(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        body: &[u8],
        metadata: Option<&MessageMetadata>,
    ) -> Result<Option<Vec<u8>>, SdkError> {
        let route = &opened.routing;

        if let Some(reason) = self.friend_rejection_reason(&entry.envelope.source_principal_id)? {
            self.account_db()?.reject_inbox_message(
                &route.conversation_id,
                &route.message_id,
                &entry.envelope.source_principal_id,
                &reason,
                now_unix_timestamp(),
            )?;
            return Ok(None);
        }
        self.append_plaintext_projection_once(&route.conversation_id, entry, body, metadata)?;
        if self.account_db()?.client_record("conversation", &route.conversation_id)?.is_none() {
            self.account_db()?.persist_client_record("conversation",&route.conversation_id,&serde_json::json!({"kind":"direct","title":null,"group_id":null,"participants":[self.device_branch.as_ref().map(|branch|&branch.principal_id),Some(&entry.envelope.source_principal_id)],"direct_route":null}))?;
        }
        Ok(Some(body.to_vec()))
    }
    fn project_routed_group_control(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        body: &[u8],
    ) -> Result<Option<Vec<u8>>, SdkError> {
        let route = &opened.routing;

        self.require_routed_group_member(
            route.group_id.as_deref().ok_or_else(|| invalid("group id missing"))?,
            entry,
        )?;
        if self.apply_group_control_plaintext(body)?.is_some() {
            self.account_db()?.store_message_content(
                &route.conversation_id,
                &route.message_id,
                body,
            )?;
            return Ok(None);
        }
        if let Ok(wrapper) = serde_json::from_slice::<SdkGroupSenderKeyDistributionEnvelope>(body) {
            let bytes = ramflux_protocol::decode_base64url(&wrapper.distribution_base64)
                .map_err(|_| invalid("invalid distribution"))?;
            let distribution: SdkGroupSenderKeyDistribution = serde_json::from_slice(&bytes)?;
            if distribution.sender_id != entry.envelope.source_device_id {
                return Err(invalid("distribution sender differs from authenticated device"));
            }
            self.require_routed_group_member(&distribution.group_id, entry)?;
            self.import_group_sender_key_distribution_inner(&bytes, true)?;
            self.account_db()?.store_message_content(
                &route.conversation_id,
                &route.message_id,
                body,
            )?;
        } else {
            return Err(invalid("unknown authenticated group control body"));
        }
        Ok(None)
    }
    fn project_routed_group_message(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        body: &[u8],
    ) -> Result<Option<Vec<u8>>, SdkError> {
        let route = &opened.routing;

        let group: SdkGroupEncryptedEnvelope = serde_json::from_slice(body)?;
        if Some(group.group_id.as_str()) != route.group_id.as_deref() {
            return Err(invalid("group message routing mismatch"));
        }
        self.require_routed_group_member(&group.group_id, entry)?;
        if group.sender_id != entry.envelope.source_device_id {
            return Err(invalid("group sender differs from authenticated device"));
        }
        let mut inner = entry.clone();
        inner.envelope.encrypted_payload = ramflux_protocol::encode_base64url(body);
        let plaintext = self.append_or_pending_group_message(
            &route.conversation_id,
            &route.message_id,
            &inner,
            body,
            &group,
        )?;
        if !route.conversation_id.starts_with("group.sender_key.distribution:") {
            self.merge_routed_group_link(&group.group_id, &route.conversation_id)?;
        }
        if self.direct_message_by_id(&route.message_id)?.is_some() {
            self.account_db()?.store_message_content(
                &route.conversation_id,
                &route.message_id,
                &plaintext,
            )?;
            Ok(Some(plaintext))
        } else {
            Ok(None)
        }
    }
}

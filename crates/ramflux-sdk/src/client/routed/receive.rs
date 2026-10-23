// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated routing dispatch and commit-before-cursor receive processing.
use super::{
    A2iControlEvent, GatewayInboxEntry, GatewayPlaintextDelivery, GatewaySessionEngine, Kind,
    MessageMetadata, Opened, RamfluxClient, Routing, SdkError, SdkGroupEncryptedEnvelope,
    SdkGroupSenderKeyDistribution, SdkGroupSenderKeyDistributionEnvelope, associated_data, decode,
    invalid, now_unix_timestamp,
};
use crate::client::dm::{decode_dm_attachment_body, franking_report_metadata_for_delivery};

pub(crate) struct Delivery {
    pub routing: Routing,
    pub plaintext: Option<GatewayPlaintextDelivery>,
}

impl RamfluxClient {
    pub(crate) async fn apply_routed_entry(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        entry: &GatewayInboxEntry,
        attachments: bool,
    ) -> Result<Delivery, SdkError> {
        self.append_gateway_delivery(entry)?;
        let commit = format!("routed/committed/{}", entry.envelope.envelope_id);
        if let Some(routing) = self.account_db()?.load_actor_state::<Routing>(&commit)? {
            let plaintext = self.routed_committed_content(&routing, entry)?;
            return Ok(Delivery { routing, plaintext });
        }
        let opened = self.open_routed(entry, &engine.config.device_id)?;
        self.confirm_routed_context(&opened.routing)?;
        let (body, refs) = if opened.routing.kind == Kind::Direct {
            decode_dm_attachment_body(&opened.body)?
        } else {
            (opened.body.clone(), Vec::new())
        };
        let mut imported = Vec::new();
        if attachments
            && opened.routing.kind == Kind::Direct
            && self.friend_rejection_reason(&entry.envelope.source_principal_id)?.is_none()
        {
            for attachment in &refs {
                imported.push(
                    self.import_dm_attachment_from_relay_via_gateway(
                        engine, pool, attachment, None,
                    )
                    .await?,
                );
            }
        }
        let membership = if opened.routing.kind == Kind::GroupControl {
            self.prepare_routed_group_control(engine, &opened).await?
        } else {
            None
        };
        if opened.routing.kind == Kind::Direct {
            self.apply_contact_event_plaintext(&body)?;
        }
        let envelope = decode(&entry.envelope)?;
        let aad = associated_data(
            &entry.envelope.envelope_id,
            &opened.remote_device,
            &opened.local_device,
            &opened.bundle_hash,
        )?;
        let metadata = if opened.routing.kind == Kind::Direct {
            franking_report_metadata_for_delivery(
                &opened.routing.conversation_id,
                entry,
                &envelope,
                &opened.decrypted,
                Some(&aad),
            )?
        } else {
            None
        };
        let plaintext = self.account_db()?.write_transaction(|| -> Result<_, SdkError> {
            if let Some((event, key)) = &membership {
                self.apply_bootstrap_group_member_join_event(
                    event,
                    &entry.envelope.source_device_id,
                    key,
                )?;
            }
            let plaintext = self.project_routed(&opened, entry, &body, metadata.as_ref())?;
            self.persist_pair(
                &opened.local_device,
                &opened.remote_device,
                &opened.bundle_hash,
                &opened.session,
            )?;
            self.persist_dm_session(
                &opened.routing.conversation_id,
                &entry.envelope.envelope_id,
                "recv",
                &opened.session,
            )?;
        for attachment in &refs {
            self.account_db()?.persist_client_record("object",&attachment.object_id,&serde_json::json!({"name":null,"mime":null,"direction":"incoming","owner":entry.envelope.source_principal_id,"conversation_id":opened.routing.conversation_id,"message_id":entry.envelope.envelope_id,"relay_endpoint":attachment.relay_endpoint}))?;
        }
            self.account_db()?.persist_actor_state(&commit, &opened.routing)?;
            Ok(plaintext)
        })?;
        let plaintext = plaintext.map(|plaintext| GatewayPlaintextDelivery {
            entry: entry.clone(),
            conversation_id: opened.routing.conversation_id.clone(),
            message_id: entry.envelope.envelope_id.clone(),
            sender_id: entry.envelope.source_principal_id.clone(),
            plaintext_body_base64: ramflux_protocol::encode_base64url(&plaintext),
            attachments: imported,
        });
        #[cfg(feature = "itest-rfd-fault")]
        crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::DmRecv).await?;
        Ok(Delivery { routing: opened.routing, plaintext })
    }

    fn routed_committed_content(
        &self,
        routing: &Routing,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<GatewayPlaintextDelivery>, SdkError> {
        if !matches!(routing.kind, Kind::Direct | Kind::GroupMessage)
            || self
                .direct_message_by_id(&routing.message_id)?
                .is_some_and(|message| message.deleted)
        {
            return Ok(None);
        }
        let plaintext =
            if let Some(body) = self.account_db()?.message_content(&routing.message_id)? {
                Some(GatewayPlaintextDelivery {
                    entry: entry.clone(),
                    conversation_id: routing.conversation_id.clone(),
                    message_id: routing.message_id.clone(),
                    sender_id: entry.envelope.source_principal_id.clone(),
                    plaintext_body_base64: ramflux_protocol::encode_base64url(&body),
                    attachments: Vec::new(),
                })
            } else {
                self.plaintext_projection_delivery(&routing.conversation_id, entry)?
            };
        Ok(plaintext)
    }

    fn confirm_routed_context(&self, route: &Routing) -> Result<(), SdkError> {
        if let Some(conversation) =
            self.account_db()?.client_record("conversation", &route.conversation_id)?
        {
            let kind = conversation.get("kind").and_then(serde_json::Value::as_str);
            if (route.kind == Kind::Direct && kind == Some("group"))
                || (matches!(route.kind, Kind::GroupMessage | Kind::GroupControl)
                    && kind == Some("direct"))
            {
                return Err(invalid(
                    "authenticated routing kind conflicts with local conversation",
                ));
            }
            if matches!(route.kind, Kind::GroupMessage | Kind::GroupControl)
                && let Some(group) =
                    conversation.get("group_id").and_then(serde_json::Value::as_str)
                && Some(group) != route.group_id.as_deref()
            {
                return Err(invalid("authenticated group conflicts with local conversation"));
            }
        }
        if let Some(group) = route.group_id.as_deref()
            && let Some(link) = self.account_db()?.client_record("group", group)?
            && let Some(conversation) =
                link.get("conversation_id").and_then(serde_json::Value::as_str)
            && conversation != route.conversation_id
        {
            return Err(invalid("authenticated group conversation conflicts with local binding"));
        }
        Ok(())
    }

    async fn prepare_routed_group_control(
        &self,
        engine: &GatewaySessionEngine,
        opened: &Opened,
    ) -> Result<Option<(ramflux_protocol::GroupEvent, String)>, SdkError> {
        if let Ok(control) =
            serde_json::from_slice::<crate::group::SdkGroupControlEnvelope>(&opened.body)
        {
            let value = serde_json::to_value(&control.event.body)?;
            if value.get("group_id").and_then(serde_json::Value::as_str)
                != opened.routing.group_id.as_deref()
            {
                return Err(invalid("group control routing mismatch"));
            }
            return Ok(None);
        }
        let wrapper: SdkGroupSenderKeyDistributionEnvelope = serde_json::from_slice(&opened.body)?;
        let bytes = ramflux_protocol::decode_base64url(&wrapper.distribution_base64)
            .map_err(|_| invalid("invalid group distribution"))?;
        let distribution: SdkGroupSenderKeyDistribution = serde_json::from_slice(&bytes)?;
        if Some(distribution.group_id.as_str()) != opened.routing.group_id.as_deref() {
            return Err(invalid("group distribution routing mismatch"));
        }
        let membership = self
            .verify_sender_key_membership_bootstrap(
                &engine.config,
                &engine.config.device_id,
                &wrapper,
            )
            .await?;
        if let Some((event, _)) = &membership {
            let body = serde_json::to_value(&event.body)?;
            if body.get("group_id").and_then(serde_json::Value::as_str)
                != opened.routing.group_id.as_deref()
            {
                return Err(invalid("group membership routing mismatch"));
            }
        }
        Ok(membership)
    }

    fn project_routed(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        body: &[u8],
        metadata: Option<&MessageMetadata>,
    ) -> Result<Option<Vec<u8>>, SdkError> {
        let route = &opened.routing;
        match route.kind {
            Kind::Direct => {
                if self
                    .apply_receipt_event_plaintext(body, &entry.envelope.source_device_id)?
                    .is_some()
                {
                    return Ok(None);
                }
                if let Some(reason) =
                    self.friend_rejection_reason(&entry.envelope.source_principal_id)?
                {
                    self.account_db()?.reject_inbox_message(
                        &route.conversation_id,
                        &route.message_id,
                        &entry.envelope.source_principal_id,
                        &reason,
                        now_unix_timestamp(),
                    )?;
                    return Ok(None);
                }
                self.append_plaintext_projection_once(
                    &route.conversation_id,
                    entry,
                    body,
                    metadata,
                )?;
                if self
                    .account_db()?
                    .client_record("conversation", &route.conversation_id)?
                    .is_none()
                {
                    self.account_db()?.persist_client_record("conversation",&route.conversation_id,&serde_json::json!({"kind":"direct","title":null,"group_id":null,"participants":[self.device_branch.as_ref().map(|branch|&branch.principal_id),Some(&entry.envelope.source_principal_id)],"direct_route":null}))?;
                }
                Ok(Some(body.to_vec()))
            }
            Kind::Receipt => {
                self.apply_receipt_event_plaintext(body, &entry.envelope.source_device_id)?
                    .ok_or_else(|| invalid("invalid routed receipt"))?;
                Ok(None)
            }
            Kind::GroupControl => {
                self.account_db()?.store_message_content(
                    &route.conversation_id,
                    &route.message_id,
                    body,
                )?;
                if self.apply_group_control_plaintext(body)?.is_some() {
                    return Ok(None);
                }
                if let Ok(wrapper) =
                    serde_json::from_slice::<SdkGroupSenderKeyDistributionEnvelope>(body)
                {
                    let bytes = ramflux_protocol::decode_base64url(&wrapper.distribution_base64)
                        .map_err(|_| invalid("invalid distribution"))?;
                    self.import_group_sender_key_distribution_inner(&bytes, true)?;
                }
                Ok(None)
            }
            Kind::GroupMessage => {
                let group: SdkGroupEncryptedEnvelope = serde_json::from_slice(body)?;
                if Some(group.group_id.as_str()) != route.group_id.as_deref() {
                    return Err(invalid("group message routing mismatch"));
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
                    self.account_db()?.persist_client_record("group",&group.group_id,&serde_json::json!({"conversation_id":route.conversation_id,"conversation_ids":[route.conversation_id]}))?;
                    self.account_db()?.persist_client_record("conversation",&route.conversation_id,&serde_json::json!({"kind":"group","group_id":group.group_id,"title":null,"direct_route":null}))?;
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
            Kind::Control => {
                let event: A2iControlEvent = serde_json::from_slice(body)?;
                self.account_db()?
                    .persist_actor_state(&format!("a2i/{}", event.event_id), &event)?;
                Ok(None)
            }
        }
    }
}

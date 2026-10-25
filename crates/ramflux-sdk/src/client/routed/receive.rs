// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated routing dispatch and commit-before-cursor receive processing.
use super::committed::Committed;
use super::{
    GatewayInboxEntry, GatewayPlaintextDelivery, GatewaySessionEngine, Kind, MessageMetadata,
    Opened, RamfluxClient, Routing, SdkError, SdkGroupSenderKeyDistribution,
    SdkGroupSenderKeyDistributionEnvelope, associated_data, decode, invalid,
};
use crate::client::dm::{decode_dm_attachment_body, franking_report_metadata_for_delivery};

pub(crate) struct Delivery {
    pub routing: Routing,
    pub plaintext: Option<GatewayPlaintextDelivery>,
}

struct Commit<'a> {
    opened: &'a Opened,
    entry: &'a GatewayInboxEntry,
    body: &'a [u8],
    metadata: Option<&'a MessageMetadata>,
    membership: Option<&'a (ramflux_protocol::GroupEvent, String)>,
    slots: &'a [crate::SdkObjectKeySlot],
    references: Vec<(
        &'a crate::dm::SdkDmAttachmentRef,
        Option<crate::client::object::DeferredObjectKeySlot>,
    )>,
    receipt: &'a str,
}

impl RamfluxClient {
    fn prepare_routed_surface_projection(
        &self,
        opened: &mut Opened,
        entry: &GatewayInboxEntry,
        body: &[u8],
    ) -> Result<(), SdkError> {
        // Only an authenticated carrier may select the reserved logical surface projection.
        // The pair packet and transport receipt retain their per-envelope identities.
        if opened.routing.kind == Kind::Direct
            && let Ok(Some(carrier)) = crate::client::surface::Carrier::decode(body)
            && carrier.conversation_id == opened.routing.conversation_id
            && self
                .verify_surface_carrier(
                    &carrier,
                    &entry.envelope.source_principal_id,
                    &entry.envelope.source_device_id,
                )
                .is_ok()
        {
            opened.routing.message_id = Self::surface_timeline_id(&carrier)?;
        }
        Ok(())
    }
    async fn import_routed_own_history(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        entry: &GatewayInboxEntry,
        opened: &Opened,
        body: &[u8],
    ) -> Result<(), SdkError> {
        if opened.routing.kind == Kind::Control
            && let Ok(value) = serde_json::from_slice::<serde_json::Value>(body)
            && value["schema"] == "ramflux.sdk.own_device_sync.v1"
        {
            let sync: crate::own_device_sync::SdkOwnDeviceSyncEnvelope =
                ramflux_protocol::parse_i_json(body)?;
            if sync.source_device_id != entry.envelope.source_device_id
                || sync.target_device_id != opened.local_device.device_id()
            {
                return Err(invalid("own-device history transport scope mismatch"));
            }
            let root = self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            let expected = crate::identity_root_public_key_commitment(
                &ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes()),
            )?;
            self.import_own_device_sync(engine, pool, &expected, &sync, None).await?;
        }
        Ok(())
    }
    pub(crate) async fn apply_routed_entry(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        entry: &GatewayInboxEntry,
        attachments: bool,
    ) -> Result<Delivery, SdkError> {
        if decode(&entry.envelope)?.schema == crate::client::contact_requests::ENVELOPE_SCHEMA {
            let manifest = self.contact_request_candidate(&engine.config, entry).await?;
            return self.commit_contact_request_bootstrap(
                entry,
                &manifest,
                &engine.config.device_id,
            );
        }
        self.ensure_inbound_device(&engine.config, entry).await?;
        self.upgrade_replay_identity(&self.authenticated_device_identity(entry)?)?;
        let commit = self.authenticated_committed_key(entry)?;
        if let Some(receipt) = self.account_db()?.load_actor_state::<Committed>(&commit)? {
            if receipt.entry.envelope.payload_hash != entry.envelope.payload_hash {
                return Err(invalid("envelope id reused with a different authenticated payload"));
            }
            let plaintext = self.routed_committed_content(&receipt.routing, &receipt.entry)?;
            return Ok(Delivery { routing: receipt.routing, plaintext });
        }
        let mut opened = self.open_routed_with_recovery(engine, entry).await?;
        self.contact_route_gate(entry, &opened.routing, &opened.body)?;
        if matches!(opened.routing.kind, Kind::Direct | Kind::GroupMessage) {
            opened.routing.message_id = self.projection_id(entry)?;
        }
        self.confirm_routed_context(&opened.routing, entry)?;
        let (body, refs) = if opened.routing.attachments {
            let (body, refs) = decode_dm_attachment_body(&opened.body)?;
            (zeroize::Zeroizing::new(body), refs)
        } else {
            (opened.body.clone(), Vec::new())
        };
        self.prepare_routed_surface_projection(&mut opened, entry, &body)?;
        let envelope = decode(&entry.envelope)?;
        let aad = associated_data(
            &entry.envelope.envelope_id,
            &entry.envelope.source_device_id,
            opened.local_device.device_id(),
            &opened.bundle_hash,
        )?;
        self.import_routed_own_history(engine, pool, entry, &opened, &body).await?;
        let metadata = routed_message_metadata(&opened, entry, &envelope, &aad)?;
        let mut consumed_slots = Vec::new();
        let mut references = Vec::new();
        let accepted = self.friend_rejection_reason(&entry.envelope.source_principal_id)?.is_none();
        let source = self.authenticated_device_identity(entry)?;
        let held = opened.routing.kind == Kind::Direct
            && self.pending_contact_root(source.root_commitment())?
            && !self.accepted_contact_source(
                source.root_commitment(),
                &entry.envelope.source_principal_id,
            )?;
        for attachment in refs.iter().filter(|_| accepted) {
            let prepared = if attachment.key_slot.version == 2 {
                self.decrypt_pair_object_slot(&attachment.key_slot, Some(&mut opened.session)).ok()
            } else {
                self.decrypt_object_key_slot(&attachment.key_slot).ok()
            };
            if prepared.is_some() && attachment.key_slot.version == 2 {
                consumed_slots.push(attachment.key_slot.clone());
            }
            references.push((attachment, prepared));
        }
        let membership = if opened.routing.kind == Kind::GroupControl {
            self.prepare_routed_group_control(engine, &opened, entry).await?
        } else {
            None
        };
        let plaintext = self.commit_routed_projection(Commit {
            opened: &opened,
            entry,
            body: &body,
            metadata: metadata.as_ref(),
            membership: membership.as_ref(),
            slots: &consumed_slots,
            references,
            receipt: &commit,
        })?;
        self.finish_pair_retirement()?;
        self.reply_pair_reset(engine, &opened, &body).await;
        let imported = if attachments && opened.routing.kind == Kind::Direct && accepted && !held {
            self.import_accepted_attachments(engine, pool, &refs).await?
        } else {
            Vec::new()
        };
        self.refresh_routed_control_cache(&opened, &body)?;
        let plaintext = plaintext.map(|plaintext| {
            let plaintext = zeroize::Zeroizing::new(plaintext);
            GatewayPlaintextDelivery {
                entry: entry.clone(),
                conversation_id: opened.routing.conversation_id.clone(),
                message_id: opened.routing.message_id.clone(),
                sender_id: entry.envelope.source_principal_id.clone(),
                plaintext_body_base64: ramflux_protocol::encode_base64url(&plaintext),
                attachments: imported,
            }
        });
        #[cfg(feature = "itest-rfd-fault")]
        crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::DmRecv).await?;
        Ok(Delivery { routing: opened.routing, plaintext })
    }

    async fn import_accepted_attachments(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        refs: &[crate::dm::SdkDmAttachmentRef],
    ) -> Result<Vec<crate::dm::SdkDmAttachmentImportResult>, SdkError> {
        let mut imported = Vec::new();
        for attachment in refs {
            imported.push(
                self.import_dm_attachment_from_relay_via_gateway(engine, pool, attachment, None)
                    .await?,
            );
        }
        Ok(imported)
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

    fn confirm_routed_context(
        &self,
        route: &Routing,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        let context = self.account_db()?.client_record("conversation", &route.conversation_id)?;
        if route.kind == Kind::Direct
            && context.is_none()
            && self
                .conversation_list()?
                .iter()
                .any(|conversation| conversation.conversation_id == route.conversation_id)
        {
            return Err(invalid(
                "existing direct conversation has no explicit participant binding",
            ));
        }
        if let Some(conversation) = context {
            let kind = conversation.get("kind").and_then(serde_json::Value::as_str);
            if route.kind == Kind::Direct
                && !self.authenticated_direct_participant(&conversation, entry)?
            {
                return Err(invalid(
                    "authenticated sender is not a direct conversation participant",
                ));
            }
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
        entry: &GatewayInboxEntry,
    ) -> Result<Option<(ramflux_protocol::GroupEvent, String)>, SdkError> {
        if let Some(group) = opened.routing.group_id.as_deref()
            && self.group_state(group).is_ok()
        {
            self.require_routed_group_member(group, entry)?;
        }
        if let Ok(control) =
            serde_json::from_slice::<crate::group::SdkGroupControlEnvelope>(&opened.body)
        {
            let value = serde_json::to_value(&control.event.body)?;
            if value.get("group_id").and_then(serde_json::Value::as_str)
                != opened.routing.group_id.as_deref()
            {
                return Err(invalid("group control routing mismatch"));
            }
            self.prepare_group_join_identity(&engine.config, &control.event).await?;
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

    fn commit_contact_request_bootstrap(
        &self,
        entry: &GatewayInboxEntry,
        manifest: &crate::prekey::SdkDeviceManifestResponse,
        local: &str,
    ) -> Result<Delivery, SdkError> {
        self.account_db()?.write_transaction(|| {
            // A malformed request cannot leave a cached root or device, pair state, consent,
            // or message projection behind. Candidate authentication preceded this transaction.
            self.remember_contact_request_cache(manifest)?;
            self.persist_root_verified_directory(manifest)?;
            let receipt = self.authenticated_committed_key(entry)?;
            if let Some(committed) = self.account_db()?.load_actor_state::<Committed>(&receipt)? {
                if committed.entry.envelope.payload_hash != entry.envelope.payload_hash {
                    return Err(invalid("contact envelope id reused with another payload"));
                }
                return Ok(Delivery { routing: committed.routing, plaintext: None });
            }
            let opened = self.open_routed(entry, local)?;
            let control = self.verify_contact_control(entry, &opened.routing, &opened.body)?;
            if control.body.kind != crate::client::contact_requests::Decision::Request {
                return Err(invalid("stranger envelope can only carry a contact request"));
            }
            self.confirm_routed_context(&opened.routing, entry)?;
            self.commit_routed_projection(Commit {
                opened: &opened,
                entry,
                body: &opened.body,
                metadata: None,
                membership: None,
                slots: &[],
                references: Vec::new(),
                receipt: &receipt,
            })?;
            Ok(Delivery { routing: opened.routing, plaintext: None })
        })
    }
    fn commit_routed_projection(&self, context: Commit<'_>) -> Result<Option<Vec<u8>>, SdkError> {
        let Commit { opened, entry, body, metadata, membership, slots, receipt, references } =
            context;
        self.account_db()?.write_transaction(|| -> Result<_, SdkError> {
            if let Some((event, key)) = membership {
                self.apply_bootstrap_group_member_join_event(
                    event,
                    &entry.envelope.source_device_id,
                    key,
                )?;
            }
            let source=self.authenticated_device_identity(entry)?;
            if opened.routing.kind == Kind::Direct
                && self.friend_rejection_reason(source.root_commitment())?.is_none()
                && !self.pending_contact_root(source.root_commitment())?
                && !self.accepted_contact_source(source.root_commitment(), &entry.envelope.source_principal_id)?
            {
                return Err(invalid("direct message requires current root consent at commit"));
            }
            let pending=opened.routing.kind==Kind::Direct
                && self.pending_contact_root(source.root_commitment())?
                && !self.accepted_contact_source(source.root_commitment(), &entry.envelope.source_principal_id)?;
            let plaintext=if pending {
                self.hold_contact_routed_message(&opened.routing,entry,body,metadata,references)?;
                None
            } else {
            for (reference, prepared) in references {
                self.persist_sender_attachment_reference(
                    reference,
                    &entry.envelope.source_device_id,
                    crate::client::deferred_attachment::ReferenceContext {
                        owner: &entry.envelope.source_principal_id,
                        conversation: &opened.routing.conversation_id,
                        message: &opened.routing.message_id,
                    },
                    prepared,
                )?;
            }
            self.project_routed(opened, entry, body, metadata)?
            };
            if self.friend_rejection_reason(&entry.envelope.source_principal_id)?.is_none()
                || matches!(opened.routing.kind, Kind::GroupMessage | Kind::GroupControl)
            {
                self.commit_bootstrap_sequence(
                    &opened.local_device,
                    &opened.remote_device,
                    decode(&entry.envelope)?.x3dh.as_ref(),
                    &opened.session.session_id,
                )?;
                self.persist_pair(
                    &opened.local_device,
                    &opened.remote_device,
                    &opened.bundle_hash,
                    &opened.session,
                )?;
                let reset = opened.routing.kind == Kind::Control
                    && serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|value| {
                        matches!(
                            value["type"].as_str(),
                            Some("pair.session.reset.v1" | "pair.session.reset.ack.v1")
                        )
                    });
                self.confirm_pair(
                    &opened.local_device,
                    &opened.remote_device,
                    &opened.session,
                    reset,
                    decode(&entry.envelope)?.x3dh.is_some(),
                )?;
            }
            for slot in slots {
                self.persist_pair_slot_receipt(slot)?;
            }
            if matches!(opened.routing.kind, Kind::Direct | Kind::GroupMessage) {
                self.persist_projection_owner(entry, &opened.routing.message_id)?;
                self.account_db()?.persist_actor_state(
                    &format!("routed/message-metadata/{}", opened.routing.message_id),
                    &opened.routing,
                )?;
            }
            self.account_db()?.persist_actor_state(
                &super::conversation_watermark(&opened.routing.conversation_id),
                &receipt,
            )?;
            let mut retained = entry.clone();
            if opened.routing.kind == Kind::Control && body.starts_with(crate::client::call::PREFIX) {
                // Reusable X3DH private prekeys can reconstruct a bootstrap chain. Do not retain
                // call ciphertext alongside them: committed replay needs only attribution/hash.
                retained.envelope.encrypted_payload.clear();
                self.append_event(&entry.envelope.envelope_id, "call.control.committed", &ramflux_protocol::canonical_json_bytes(&serde_json::json!({"envelope_id":entry.envelope.envelope_id,"source_device_id":entry.envelope.source_device_id,"payload_hash":entry.envelope.payload_hash}))?)?;
            } else {
                self.append_gateway_delivery(entry)?;
            }
            self.account_db()?.persist_actor_state(
                receipt,
                &Committed { routing: opened.routing.clone(), entry: retained, projected: false },
            )?;
            Ok(plaintext)
        })
    }
}

fn routed_message_metadata(
    opened: &Opened,
    entry: &GatewayInboxEntry,
    envelope: &crate::dm::SdkDmEncryptedEnvelope,
    aad: &[u8],
) -> Result<Option<MessageMetadata>, SdkError> {
    if opened.routing.kind == Kind::Direct {
        franking_report_metadata_for_delivery(
            &opened.routing.conversation_id,
            entry,
            envelope,
            &opened.decrypted,
            Some(aad),
        )
    } else {
        Ok(None)
    }
}

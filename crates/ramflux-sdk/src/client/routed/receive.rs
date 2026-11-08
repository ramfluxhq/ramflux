// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Authenticated routing dispatch and commit-before-cursor receive processing.
use super::committed::Committed;
use super::{
    GatewayInboxEntry, GatewayPlaintextDelivery, GatewaySessionAccess, Kind, MessageMetadata,
    Opened, RamfluxClient, Routing, SdkError, SdkGroupSenderKeyDistribution,
    SdkGroupSenderKeyDistributionEnvelope, associated_data, decode, invalid,
};
use crate::client::dm::{decode_dm_attachment_body, franking_report_metadata_for_delivery};
use crate::client::identity_authority::HeadUse;

pub(crate) struct Delivery {
    pub routing: Option<Routing>,
    pub plaintext: Option<GatewayPlaintextDelivery>,
    pub call_control: bool,
    pub pair_reply: Option<ramflux_protocol::Envelope>,
}
impl Delivery {
    fn committed(receipt: Committed, plaintext: Option<GatewayPlaintextDelivery>) -> Self {
        let call_control = receipt.routing.kind == Kind::Control
            && receipt.entry.envelope.encrypted_payload.is_empty();
        Self { routing: Some(receipt.routing), plaintext, call_control, pair_reply: None }
    }
    fn opened(opened: Opened, plaintext: Option<GatewayPlaintextDelivery>, body: &[u8]) -> Self {
        let call_control =
            opened.routing.kind == Kind::Control && body.starts_with(crate::client::call::PREFIX);
        Self { routing: Some(opened.routing), plaintext, call_control, pair_reply: None }
    }
}

struct Finish {
    opened: Opened,
    body: zeroize::Zeroizing<Vec<u8>>,
    plaintext: Option<Vec<u8>>,
    refs: Vec<crate::dm::SdkDmAttachmentRef>,
    import: bool,
    background: bool,
    consume_erased: bool,
}

struct PreparedGroupControls {
    legacy: Option<(ramflux_protocol::GroupEvent, String)>,
    shared: Option<crate::client::shared_group::PreparedSharedGroup>,
}

struct Commit<'a> {
    opened: &'a Opened,
    entry: &'a GatewayInboxEntry,
    body: &'a [u8],
    metadata: Option<&'a MessageMetadata>,
    membership: Option<&'a (ramflux_protocol::GroupEvent, String)>,
    shared_group: Option<&'a crate::client::shared_group::PreparedSharedGroup>,
    local_target: Option<&'a str>,
    slots: &'a [crate::SdkObjectKeySlot],
    references: Vec<(
        &'a crate::dm::SdkDmAttachmentRef,
        Option<crate::client::object::DeferredObjectKeySlot>,
    )>,
    receipt: &'a str,
    consume_erased: bool,
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
        engine: &mut impl GatewaySessionAccess,
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
            let expected = self.own_account_anchor()?;
            self.import_own_device_sync(engine, pool, &expected, &sync, None).await?;
        }
        Ok(())
    }
    async fn apply_contact_request_entry(
        &self,
        config: &crate::GatewaySessionConfig,
        entry: &GatewayInboxEntry,
        prepared: Option<crate::prekey::SdkDeviceManifestResponse>,
    ) -> Result<Delivery, SdkError> {
        if let Some(candidate) = prepared {
            self.confirm_contact_candidate_manifest(entry, &candidate)?;
            return self.commit_contact_request_bootstrap(entry, &candidate, &config.device_id);
        }
        let manifest = self.contact_request_candidate(config, entry).await?;
        if manifest.custody.is_some()
            && let Some((route, body)) =
                self.preview_native_contact_request(entry, &manifest, &config.device_id)?
        {
            self.prepare_native_contact_control(config, entry, &route, &body, Some(&manifest))
                .await?;
        }
        self.commit_contact_request_bootstrap(entry, &manifest, &config.device_id)
    }

    async fn open_authorized_routed_entry(
        &self,
        engine: &mut impl GatewaySessionAccess,
        entry: &GatewayInboxEntry,
        native_prepared: bool,
    ) -> Result<Opened, SdkError> {
        let mut opened = if native_prepared {
            self.require_pair_device_active(
                &self.local_device_identity(&engine.config().device_id)?,
            )?;
            self.open_routed(entry, &engine.config().device_id)?
        } else {
            self.open_routed_with_recovery(engine, entry).await?
        };
        if native_prepared {
            self.confirm_prepared_native_contact_control(entry, &opened.routing, &opened.body)?;
        } else {
            self.prepare_native_contact_control(
                engine.config(),
                entry,
                &opened.routing,
                &opened.body,
                None,
            )
            .await?;
        }
        self.contact_route_gate(entry, &opened.routing, &opened.body)?;
        if matches!(opened.routing.kind, Kind::Direct | Kind::GroupMessage) {
            opened.routing.message_id = self.projection_id(entry, &opened.routing)?;
        }
        self.confirm_routed_context(&opened.routing, entry)?;
        Ok(opened)
    }

    fn routed_duplicate_delivery(
        &self,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<Delivery>, SdkError> {
        let Some((_, payload_hash)) = self.routed_seen_marker(entry)? else { return Ok(None) };
        if payload_hash != entry.envelope.payload_hash {
            return Err(SdkError::ReplayMismatch);
        }
        // A seen marker bypasses authentication and decryption. Live copies may still supply
        // read-model routing; deletion removes both this index binding and the committed copy.
        let routing = self
            .account_db()?
            .message_copy_actor_states::<Committed>(
                &format!("payload:{}", entry.envelope.payload_hash),
                "routed/committed/",
            )?
            .into_iter()
            .find(|copy| {
                copy.entry.envelope.envelope_id == entry.envelope.envelope_id
                    && copy.entry.envelope.payload_hash == entry.envelope.payload_hash
            })
            .map(|copy| copy.routing);
        Ok(Some(Delivery { routing, plaintext: None, call_control: false, pair_reply: None }))
    }

    fn committed_routed_delivery(
        &self,
        commit: &str,
        entry: &GatewayInboxEntry,
    ) -> Result<Option<Delivery>, SdkError> {
        let Some(receipt) = self.account_db()?.load_actor_state::<Committed>(commit)? else {
            return Ok(None);
        };
        if receipt.entry.envelope.payload_hash != entry.envelope.payload_hash {
            return Err(invalid("envelope id reused with a different authenticated payload"));
        }
        let plaintext = self.routed_committed_content(&receipt.routing, &receipt.entry)?;
        Ok(Some(Delivery::committed(receipt, plaintext)))
    }

    pub(crate) async fn apply_routed_entry(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        entry: &GatewayInboxEntry,
        attachments: bool,
    ) -> Result<Delivery, SdkError> {
        self.apply_routed_entry_with_source::<true>(engine, pool, entry, attachments, None).await
    }

    pub(crate) async fn apply_routed_prepared_entry(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        entry: &GatewayInboxEntry,
        prepared: Result<super::PreparedInbound, SdkError>,
    ) -> Result<Delivery, SdkError> {
        self.apply_routed_entry_with_source::<true>(engine, pool, entry, false, Some(prepared))
            .await
    }

    async fn apply_routed_entry_with_source<const CONSUME_ERASED: bool>(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        entry: &GatewayInboxEntry,
        attachments: bool,
        prepared: Option<Result<super::PreparedInbound, SdkError>>,
    ) -> Result<Delivery, SdkError> {
        let consume_erased = CONSUME_ERASED;
        if let Some(delivery) = self.routed_duplicate_delivery(entry)? {
            return Ok(delivery);
        }
        let mut prepared = prepared.transpose()?;
        if decode(&entry.envelope)?.schema == crate::client::contact_requests::ENVELOPE_SCHEMA {
            return self
                .apply_contact_request_entry(
                    engine.config(),
                    entry,
                    prepared.and_then(|value| value.candidate),
                )
                .await;
        }
        let history = prepared.as_mut().and_then(|prepared| prepared.history.take());
        let (native_prepared, directory) =
            self.prepare_routed_authority(engine, entry, prepared).await?;
        let commit = self.authenticated_committed_key(HeadUse::NewAuthorization, entry)?;
        if let Some(delivery) = self.committed_routed_delivery(&commit, entry)? {
            return Ok(delivery);
        }
        let mut opened = self.open_authorized_routed_entry(engine, entry, native_prepared).await?;
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
        if native_prepared {
            if let Some(sync) = Self::routed_own_history_envelope(
                entry,
                &opened.routing,
                &body,
                opened.local_device.device_id(),
            )? {
                self.confirm_prepared_own_history(&sync, history.as_ref())?;
            }
        } else {
            self.import_routed_own_history(engine, pool, entry, &opened, &body).await?;
        }
        let metadata = routed_message_metadata(&opened, entry, &envelope, &aad)?;
        let mut consumed_slots = Vec::new();
        let mut references = Vec::new();
        let accepted = self.friend_rejection_reason(&entry.envelope.source_principal_id)?.is_none();
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
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
        let groups = self
            .prepare_routed_group_controls(engine, &opened, entry, &body, directory.as_ref())
            .await?;
        let (plaintext, admitted) = self.commit_routed_projection(Commit {
            opened: &opened,
            entry,
            body: &body,
            metadata: metadata.as_ref(),
            membership: groups.legacy.as_ref(),
            shared_group: groups.shared.as_ref(),
            local_target: Some(&engine.config().target_delivery_id),
            slots: &consumed_slots,
            references,
            receipt: &commit,
            consume_erased,
        })?;
        let refs = if consume_erased { admitted_refs(&refs, admitted) } else { refs };
        let import = attachments && opened.routing.kind == Kind::Direct && accepted && !held;
        let background = native_prepared;
        self.finish_routed_receive(
            engine,
            pool,
            entry,
            Finish { opened, body, plaintext, refs, import, background, consume_erased },
        )
        .await
    }

    async fn finish_routed_receive(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        entry: &GatewayInboxEntry,
        finish: Finish,
    ) -> Result<Delivery, SdkError> {
        let Finish { opened, body, plaintext, refs, import, background, consume_erased } = finish;
        // Durable pair-secret retirement runs at the end of `commit_routed_projection` /
        // `commit_contact_request_bootstrap` after that writer transaction commits (a WAL
        // checkpoint cannot run while the transaction is open). After commit, `voice_calls`,
        // `voice_transition`, and `object_store.tombstone` are RAM-only (rebuilt on load /
        // session). The call refresh (`refresh_call_control` -> `retire_call_without_keys`)
        // persists its call row durably; `dispatch::call::recover` rebuilds it at startup. Network post-commit (pair-reset reply, attachment import) is P17 / P16;
        // the seen early-return stays for those.
        let pair_reply = if background {
            match self.prepare_received_pair_reply(engine.config(), &opened, &body) {
                Ok(reply) => reply,
                Err(error) => {
                    tracing::debug!(%error, "encrypted reset acknowledgement awaits a later reset");
                    None
                }
            }
        } else {
            self.reply_pair_reset(engine, &opened, &body).await;
            None
        };
        let imported = if import {
            self.import_accepted_attachments(engine, pool, &refs, consume_erased).await?
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
        let mut delivery = Delivery::opened(opened, plaintext, &body);
        delivery.pair_reply = pair_reply;
        Ok(delivery)
    }

    async fn prepare_routed_authority(
        &self,
        engine: &impl GatewaySessionAccess,
        entry: &GatewayInboxEntry,
        mut prepared: Option<super::PreparedInbound>,
    ) -> Result<(bool, Option<super::ReceiveGroupDirectory>), SdkError> {
        let directory = prepared.as_mut().and_then(|value| value.group_directory.take());
        let native_prepared = prepared.as_ref().is_some_and(|value| value.native_prepared);
        self.ensure_prepared_inbound_device(
            engine.config(),
            entry,
            prepared.map(|value| Ok(value.manifest)),
        )
        .await?;
        self.upgrade_replay_identity(
            &self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?,
        )?;
        Ok((native_prepared, directory))
    }

    async fn import_accepted_attachments(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        refs: &[crate::dm::SdkDmAttachmentRef],
        consume_erased: bool,
    ) -> Result<Vec<crate::dm::SdkDmAttachmentImportResult>, SdkError> {
        let mut imported = Vec::new();
        for attachment in refs {
            #[cfg(test)]
            super::tests::selector_reopen::import_entry(self, attachment)?;
            match self
                .import_dm_attachment_from_relay_via_gateway(engine, pool, attachment, None)
                .await
            {
                Ok(result) => imported.push(result),
                Err(SdkError::ObjectErased) if consume_erased => {}
                Err(error) => return Err(error),
            }
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

    pub(crate) fn confirm_routed_context(
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

    async fn prepare_routed_group_controls(
        &self,
        engine: &impl GatewaySessionAccess,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        body: &[u8],
        directory: Option<&super::ReceiveGroupDirectory>,
    ) -> Result<PreparedGroupControls, SdkError> {
        let shared = match directory {
            Some(super::ReceiveGroupDirectory::Shared(evidence)) => {
                self.prepare_shared_group_receive_with_directory(
                    engine,
                    opened,
                    entry,
                    body,
                    Some(evidence),
                )
                .await?
            }
            _ => self.prepare_shared_group_receive(engine, opened, entry, body).await?,
        };
        let legacy = if opened.routing.kind == Kind::GroupControl && shared.is_none() {
            if let Some(super::ReceiveGroupDirectory::Legacy(evidence)) = directory {
                self.prepare_legacy_group_with_directory(engine.config(), opened, entry, evidence)?
            } else {
                self.prepare_routed_group_control(engine, opened, entry).await?
            }
        } else {
            None
        };
        Ok(PreparedGroupControls { legacy, shared })
    }
    async fn prepare_routed_group_control(
        &self,
        engine: &impl GatewaySessionAccess,
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
            self.prepare_group_join_identity(engine.config(), &control.event).await?;
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
                engine.config(),
                &engine.config().device_id,
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

    pub(super) fn commit_contact_request_bootstrap(
        &self,
        entry: &GatewayInboxEntry,
        manifest: &crate::prekey::SdkDeviceManifestResponse,
        local: &str,
    ) -> Result<Delivery, SdkError> {
        let delivery = self.account_db()?.write_transaction(|| {
            // Candidate authentication supplies receipt scope without resurrecting requester caches.
            let source = Self::device_identity_from_manifest(manifest,&entry.envelope.source_device_id)?;
            let packet = decode(&entry.envelope)?;
            if packet.source_principal_commitment.as_deref() != Some(source.root_commitment()) {
                return Err(invalid("contact receipt root mismatch"));
            }
            let device = manifest.devices.iter().find(|d| d.device_id == entry.envelope.source_device_id)
                .ok_or_else(|| invalid("contact receipt device missing"))?;
            super::verify_sender_record(entry,&serde_json::json!({"principal_id":manifest.principal_id,"signing_public_key":device.branch_public_key}))?;
            let receipt = super::committed::committed_key(&source,&entry.envelope.envelope_id)?;
            if let Some(committed) = self.account_db()?.load_actor_state::<Committed>(&receipt)? {
                if committed.entry.envelope.payload_hash != entry.envelope.payload_hash {
                    return Err(invalid("contact envelope id reused with another payload"));
                }
                return Ok(Delivery {
                    routing: Some(committed.routing),
                    plaintext: None,
                    call_control: false,
                    pair_reply: None,
                });
            }
            // A malformed request cannot leave a cached root or device, pair state, consent,
            // or message projection behind. Candidate authentication preceded this transaction.
            let first_seen =
                self.account_db()?.client_record("identity", &manifest.principal_id)?.is_none();
            self.remember_contact_request_cache(manifest)?;
            self.persist_root_verified_directory(manifest)?;
            if first_seen {
                // A requester's root comes from the network, never from an imported card.
                self.mark_lookup_root(&manifest.principal_id)?;
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
                shared_group: None,
                local_target: None,
                slots: &[],
                references: Vec::new(),
                receipt: &receipt,
                consume_erased: false,
            })?;
            // Fault after the marker and every effect, so the rollback must undo both.
            #[cfg(test)]
            commit_fault::take(commit_fault::Kind::Bootstrap)?;
            Ok(Delivery { routing: Some(opened.routing), plaintext: None, call_control: false, pair_reply: None })

        })?;
        self.finish_pair_retirement()?;
        Ok(delivery)
    }
    fn commit_routed_pair_context(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        body: &[u8],
    ) -> Result<(), SdkError> {
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
        Ok(())
    }

    fn commit_routed_projection(
        &self,
        context: Commit<'_>,
    ) -> Result<(Option<Vec<u8>>, Vec<usize>), SdkError> {
        let result =
            self.account_db()?.write_transaction(|| self.persist_routed_projection(context))?;
        self.finish_pair_retirement()?;
        Ok(result)
    }

    /// Joins an open receive transaction. Live [`Self::commit_routed_projection`] stays on its writer.
    #[allow(dead_code, reason = "P20c join point; actor uses live apply until P20f projection W1")]
    fn commit_routed_w1_in(
        &self,
        tx: &ramflux_storage::ReceiveTransaction<'_>,
        sequence: u64,
        context: Commit<'_>,
    ) -> Result<(Option<Vec<u8>>, Vec<usize>), SdkError> {
        tx.require_open_input(sequence)?;
        self.persist_routed_projection(context)
    }

    fn persist_routed_projection(
        &self,
        context: Commit<'_>,
    ) -> Result<(Option<Vec<u8>>, Vec<usize>), SdkError> {
        let Commit {
            opened,
            entry,
            body,
            metadata,
            membership,
            shared_group,
            local_target,
            slots,
            receipt,
            references,
            consume_erased,
        } = context;
        if matches!(opened.routing.kind, Kind::Direct | Kind::GroupMessage)
            && self.account_db()?.message_is_deleted(&opened.routing.message_id)?
        {
            self.persist_routed_seen(entry)?;
            return Ok((None, Vec::new()));
        }
        let mut admitted = Vec::new();
        if let Some(shared) = shared_group {
            self.apply_prepared_shared_group(
                shared,
                local_target.ok_or_else(|| invalid("group receive target is absent"))?,
            )?;
        }
        if let Some((event, key)) = membership {
            self.apply_bootstrap_group_member_join_event(
                event,
                &entry.envelope.source_device_id,
                key,
            )?;
        }
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        if opened.routing.kind == Kind::Direct
            && self.friend_rejection_reason(source.root_commitment())?.is_none()
            && !self.pending_contact_root(source.root_commitment())?
            && !self.accepted_contact_source(
                source.root_commitment(),
                &entry.envelope.source_principal_id,
            )?
        {
            return Err(invalid("direct message requires current root consent at commit"));
        }
        let pending = opened.routing.kind == Kind::Direct
            && self.pending_contact_root(source.root_commitment())?
            && !self.accepted_contact_source(
                source.root_commitment(),
                &entry.envelope.source_principal_id,
            )?;
        let plaintext = if pending {
            self.hold_contact_routed_message(&opened.routing, entry, body, metadata, references)?;
            None
        } else {
            for (index, (reference, prepared)) in references.into_iter().enumerate() {
                let registration = self.persist_sender_attachment_reference(
                    reference,
                    &entry.envelope.source_device_id,
                    crate::client::deferred_attachment::ReferenceContext {
                        owner: &entry.envelope.source_principal_id,
                        conversation: &opened.routing.conversation_id,
                        message: &opened.routing.message_id,
                    },
                    prepared,
                );
                #[cfg(test)]
                super::tests::selector_reopen::registered(&registration);
                match registration {
                    Ok(()) => admitted.push(index),
                    Err(SdkError::ObjectErased) if consume_erased => {}
                    Err(error) => return Err(error),
                }
            }
            self.project_routed(opened, entry, body, metadata)?
        };
        self.commit_routed_pair_context(opened, entry, body)?;
        for slot in slots {
            self.persist_message_slot_receipt(&opened.routing.message_id, slot)?;
        }
        if matches!(opened.routing.kind, Kind::Direct | Kind::GroupMessage) {
            self.persist_projection_owner(entry, &opened.routing.message_id)?;
            self.account_db()?.persist_actor_state(
                &format!("routed/message-metadata/{}", opened.routing.message_id),
                &opened.routing,
            )?;
        }
        self.persist_routed_marker(opened, entry, body, receipt)?;
        // Faults land after the marker, the last write before commit, so a rollback must undo
        // the effects and the marker together.
        #[cfg(test)]
        {
            commit_fault::take(commit_fault::Kind::Pair)?;
            commit_fault::take(commit_fault::projection(&opened.routing.kind))?;
        }
        Ok((plaintext, admitted))
    }

    fn persist_routed_marker(
        &self,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        body: &[u8],
        receipt: &str,
    ) -> Result<(), SdkError> {
        self.account_db()?.persist_message_watermark(
            &opened.routing.message_id,
            &opened.routing.conversation_id,
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
        self.persist_routed_seen(entry)
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

fn admitted_refs(
    refs: &[crate::dm::SdkDmAttachmentRef],
    admitted: Vec<usize>,
) -> Vec<crate::dm::SdkDmAttachmentRef> {
    admitted.into_iter().map(|index| refs[index].clone()).collect()
}

#[cfg(test)]
pub(crate) mod commit_fault {
    use super::SdkError;
    use std::cell::Cell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Kind {
        Bootstrap,
        Pair,
        GroupControl,
        Content,
        Control,
    }

    thread_local! {
        static FAIL: Cell<Option<Kind>> = const { Cell::new(None) };
    }

    pub(crate) fn projection(kind: &super::Kind) -> Kind {
        match kind {
            super::Kind::Direct | super::Kind::GroupMessage => Kind::Content,
            super::Kind::Control => Kind::Control,
            super::Kind::GroupControl | super::Kind::Receipt => Kind::GroupControl,
        }
    }

    pub(crate) fn fail_before(kind: Kind) {
        FAIL.with(|cell| cell.set(Some(kind)));
    }

    pub(crate) fn take(kind: Kind) -> Result<(), SdkError> {
        FAIL.with(|cell| {
            if cell.get() == Some(kind) {
                cell.set(None);
                return Err(SdkError::LocalBus("routed commit fault".into()));
            }
            Ok(())
        })
    }
}

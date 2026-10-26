// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(crate) async fn export_own_device_sync(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        principal_commitment: &str,
        target_device_id: &str,
        relay_endpoint: &str,
        relay_service_key_base64: Option<String>,
        chunk_size: usize,
    ) -> Result<SdkOwnDeviceSyncExportResponse, SdkError> {
        self.cache_verified_device_manifest(
            &engine.config,
            principal_commitment,
            "own_device_sync",
        )
        .await?;
        let source_branch = self.device_branch.clone().ok_or(SdkError::IdentityRootMissing)?;
        let source_device_id = source_branch.device_id.clone();
        let manifest = self
            .cache_verified_device_manifest(
                &engine.config,
                principal_commitment,
                "own_device_sync_export",
            )
            .await?;
        let source_device =
            manifest.devices.iter().find(|d| d.device_id == source_device_id).ok_or_else(|| {
                SdkError::InboundRejected("own sync source revoked or unavailable".into())
            })?;
        let target_device =
            manifest.devices.iter().find(|d| d.device_id == target_device_id).ok_or_else(|| {
                SdkError::InboundRejected("own sync target revoked or unavailable".into())
            })?;
        self.require_cached_root_authority(
            &self.device_identity_for_root(principal_commitment, &source_device_id)?,
        )?;
        self.require_cached_root_authority(
            &self.device_identity_for_root(principal_commitment, target_device_id)?,
        )?;
        if source_device.principal_commitment != target_device.principal_commitment {
            return Err(SdkError::LocalBus("own-device sync principal mismatch".to_owned()));
        }
        let snapshot_id = format!(
            "own-sync:{}:{}:{}",
            source_device_id,
            target_device_id,
            crate::new_surface_message_id()?
        );
        let bundle = self.own_device_history_bundle(
            principal_commitment,
            &source_device_id,
            target_device_id,
            &snapshot_id,
        )?;
        let mut next = None;
        let mut result = None;
        for mut page in super::own_device_history_pages::pages(bundle)?.into_iter().rev() {
            page.next_page = next;
            let exported = self
                .export_own_history_page(
                    engine,
                    pool,
                    page,
                    super::own_device_history_pages::UploadOptions {
                        endpoint: relay_endpoint,
                        service_key: relay_service_key_base64.clone(),
                        chunk_size,
                    },
                )
                .await?;
            next = Some(Box::new(exported.envelope.clone()));
            result = Some(exported);
        }
        result.ok_or_else(|| SdkError::InboundRejected("empty own history page sequence".into()))
    }
    async fn export_own_history_page(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        bundle: SdkOwnDeviceHistoryBundle,
        options: super::own_device_history_pages::UploadOptions<'_>,
    ) -> Result<SdkOwnDeviceSyncExportResponse, SdkError> {
        let relay_endpoint = options.endpoint;
        let chunk_size = options.chunk_size;
        let source_branch = self.device_branch.clone().ok_or(SdkError::IdentityRootMissing)?;
        let source_device_id = source_branch.device_id.clone();
        let target_device_id = bundle.target_device_id.as_str();
        let principal_commitment = bundle.principal_commitment.as_str();
        let snapshot_id = bundle.snapshot_id.clone();
        let manifest = self
            .cache_verified_device_manifest(
                &engine.config,
                principal_commitment,
                "own_history_page",
            )
            .await?;
        let target_device =
            manifest.devices.iter().find(|d| d.device_id == target_device_id).ok_or_else(|| {
                SdkError::InboundRejected("own history target unavailable".into())
            })?;
        let plaintext = serde_json::to_vec(&bundle)?;
        let object_id = format!("own-device-sync:{snapshot_id}");
        let object = self.put_encrypted_object(&object_id, &plaintext)?;
        let relay_options = self.own_history_relay_options(relay_endpoint, options.service_key)?;
        let transfer = self
            .upload_object_to_relay_inner_via_gateway(
                engine,
                pool,
                &object,
                chunk_size,
                &relay_options,
            )
            .await?;
        let object_key = self.object_store.object_key(&object.object_id)?;
        let slot_conversation_id =
            own_device_sync_slot_conversation_id(&snapshot_id, &object.object_id, target_device_id);
        let slot_message = GatewayDirectMessage {
            conversation_id: slot_conversation_id.clone(),
            message_id: format!("own-device.sync.slot:{snapshot_id}"),
            envelope_id: format!("own-device.sync.slot:{snapshot_id}"),
            source_principal_id: engine.config.principal_id.clone(),
            sender_id: source_device_id.clone(),
            recipient_device_id: Some(target_device_id.to_owned()),
            recipient_principal_commitment: Some(principal_commitment.into()),
            target_delivery_id: target_device.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: 3_600,
        };
        let (mut session, x3dh) =
            self.load_or_create_send_dm_session(engine, &slot_message).await?;
        let associated_data = object_key_slot_associated_data(
            &object.object_id,
            &slot_conversation_id,
            target_device_id,
        );
        let ciphertext = session.encrypt(&object_key, &associated_data)?;
        self.persist_dm_session(
            &slot_conversation_id,
            &format!("own-device-sync-slot:{}", object.object_id),
            "send",
            &session,
        )?;
        let manifest =
            chunk_manifest_for_object(&object.object_id, &object.ciphertext, chunk_size, None);
        let mut envelope = SdkOwnDeviceSyncEnvelope {
            schema: "ramflux.sdk.own_device_sync.v1".to_owned(),
            version: 1,
            principal_commitment: principal_commitment.to_owned(),
            source_device_id: source_device_id.clone(),
            target_device_id: target_device_id.to_owned(),
            snapshot_id: snapshot_id.clone(),
            snapshot_kind: "history_bundle".to_owned(),
            created_at: now_unix_timestamp(),
            expires_at: now_unix_timestamp().saturating_add(3_600),
            nonce: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            history_ref: own_device_history_ref(
                &object,
                &manifest,
                relay_endpoint,
                &relay_options,
                &source_branch,
                &self.device_identity_for_root(principal_commitment, target_device_id)?,
                slot_conversation_id,
                x3dh,
                ciphertext,
                u64::try_from(now_unix_timestamp()).unwrap_or(0),
            )?,
            signed: sdk_device_signed_fields(&source_device_id, ""),
        };
        envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
            &source_branch,
            &own_device_sync_signing_body(&envelope),
        )?;
        Ok(SdkOwnDeviceSyncExportResponse {
            snapshot_id,
            object_id: object.object_id,
            transfer,
            envelope,
        })
    }

    fn own_history_relay_options(
        &self,
        endpoint: &str,
        key: Option<String>,
    ) -> Result<RelayTransferOptions, SdkError> {
        self.relay_transfer_options(Some(endpoint.to_owned()), key, None)?
            .ok_or_else(|| SdkError::LocalBus("own-device sync relay endpoint missing".into()))
    }
    pub(crate) async fn import_own_device_sync(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        expected_principal_commitment: &str,
        envelope: &SdkOwnDeviceSyncEnvelope,
        relay_service_key_base64: Option<String>,
    ) -> Result<SdkOwnDeviceSyncImportResponse, SdkError> {
        let mut current = envelope.clone();
        let mut seen = BTreeSet::new();
        let mut total = SdkOwnDeviceSyncImportResponse {
            snapshot_id: envelope.snapshot_id.clone(),
            imported_messages: 0,
            imported_dm_sessions: 0,
            imported_groups: 0,
            imported_sender_keys: 0,
        };
        loop {
            if current.source_device_id != envelope.source_device_id
                || current.target_device_id != envelope.target_device_id
                || !seen.insert(current.snapshot_id.clone())
            {
                return Err(SdkError::InboundRejected(
                    "own history continuation binding or cycle".into(),
                ));
            }
            let (result, next) = self
                .import_own_history_page(
                    engine,
                    pool,
                    expected_principal_commitment,
                    &current,
                    relay_service_key_base64.clone(),
                )
                .await?;
            total.imported_messages += result.imported_messages;
            total.imported_dm_sessions += result.imported_dm_sessions;
            total.imported_groups += result.imported_groups;
            total.imported_sender_keys += result.imported_sender_keys;
            let Some(next) = next else { return Ok(total) };
            current = *next;
        }
    }
    async fn import_own_history_page(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        expected_principal_commitment: &str,
        envelope: &SdkOwnDeviceSyncEnvelope,
        relay_service_key_base64: Option<String>,
    ) -> Result<(SdkOwnDeviceSyncImportResponse, Option<Box<SdkOwnDeviceSyncEnvelope>>), SdkError>
    {
        self.verify_own_device_sync_envelope(
            &engine.config,
            expected_principal_commitment,
            envelope,
        )
        .await?;
        let receipt = Self::own_sync_receipt_key(envelope)?;
        if let Some(result) =
            self.account_db()?.load_actor_state::<SdkOwnDeviceSyncImportResponse>(&receipt)?
        {
            let next = self
                .account_db()?
                .load_actor_state::<SdkOwnDeviceSyncEnvelope>(&format!("{receipt}/next"))?;
            return Ok((result, next.map(Box::new)));
        }
        let cached = self
            .object_store_object(&envelope.history_ref.object_id)?
            .is_some_and(|object| object.manifest_hash == envelope.history_ref.manifest_hash);
        let plaintext = if cached {
            self.decrypt_object(&envelope.history_ref.object_id)?
        } else {
            let import = self
                .import_dm_attachment_from_relay_via_gateway(
                    engine,
                    pool,
                    &envelope.history_ref,
                    relay_service_key_base64,
                )
                .await?;
            ramflux_protocol::decode_base64url(&import.plaintext_base64).map_err(|_| {
                SdkError::InboundRejected("invalid own-device history encoding".into())
            })?
        };
        let plaintext = zeroize::Zeroizing::new(plaintext);
        let bundle: SdkOwnDeviceHistoryBundle = serde_json::from_slice(&plaintext)?;
        self.account_db()?.write_transaction(|| {
            let result = self.import_own_device_history_bundle(envelope, &bundle)?;
            self.cache_own_sync_import_receipt(envelope, &result)?;
            if let Some(next) = &bundle.next_page {
                self.account_db()?.persist_actor_state(&format!("{receipt}/next"), next)?;
            }
            Ok((result, bundle.next_page.clone()))
        })
    }
    pub(crate) fn own_sync_receipt_key(
        envelope: &SdkOwnDeviceSyncEnvelope,
    ) -> Result<String, SdkError> {
        Ok(format!(
            "own-device/imported/{}",
            ramflux_protocol::hash_base64url(
                "ramflux.own_device.import_receipt.v1",
                &ramflux_protocol::canonical_json_bytes(envelope)?
            )
        ))
    }
    pub(super) fn own_device_history_bundle(
        &self,
        principal_commitment: &str,
        source_device_id: &str,
        target_device_id: &str,
        snapshot_id: &str,
    ) -> Result<SdkOwnDeviceHistoryBundle, SdkError> {
        let groups = self.own_device_group_snapshots(source_device_id)?;
        let mut floor_by_group = BTreeMap::new();
        for group in &groups {
            floor_by_group.insert(group.group_id.clone(), group.local_joined_epoch);
        }
        let mut messages = Vec::new();
        let mut surface_message_epochs = BTreeMap::new();
        for message in self.account_db()?.all_direct_messages()? {
            if self.task_message_metadata(&message.conversation_id, &message.message_id)?.is_some()
            {
                continue;
            }
            let surface_epoch = self.surface_message_group_epoch(&message.message_id)?;
            if !Self::message_allowed_by_group_floor(&message, &floor_by_group)
                || surface_epoch.as_ref().is_some_and(|(group, epoch)| {
                    floor_by_group.get(group).is_none_or(|floor| epoch < floor)
                })
            {
                continue;
            }
            if let Some(epoch) = surface_epoch {
                surface_message_epochs.insert(message.message_id.clone(), epoch);
            }
            messages.push(message);
        }
        let mut contents = BTreeMap::new();
        for message in &messages {
            if let Some(body) = self.account_db()?.message_content(&message.message_id)? {
                contents.insert(message.message_id.clone(), zeroize::Zeroizing::new(body));
            }
        }
        let dm_sessions = Vec::new();
        let sender_key_distributions_base64 =
            self.own_device_sender_key_distributions(source_device_id, &groups)?;
        let mut surface_pages = self.own_surface_history_pages()?;
        let surfaces = if surface_pages.is_empty() {
            crate::client::surface::SurfaceHistoryExport::default()
        } else {
            surface_pages.remove(0)
        };
        let group_member_pins = self.own_device_group_member_pins(&groups)?;
        let device_manifests = self.own_history_device_manifests(&group_member_pins)?;
        let accepted_contacts = self.own_history_contacts()?;
        Ok(SdkOwnDeviceHistoryBundle {
            authority_only: false,
            next_page: None,
            schema: "ramflux.sdk.own_device_history_bundle.v1".to_owned(),
            version: 1,
            principal_commitment: principal_commitment.to_owned(),
            source_device_id: source_device_id.to_owned(),
            target_device_id: target_device_id.to_owned(),
            snapshot_id: snapshot_id.to_owned(),
            messages,
            task_packets: self.own_task_packets(target_device_id)?,
            task_export_metadata: self
                .account_db()?
                .load_actor_state(&crate::client::task::key("export_metadata", target_device_id))?
                .unwrap_or_default(),
            surface_pages,
            surface_controls: surfaces.controls,
            surface_checkpoints: surfaces.checkpoints,
            surface_export_metadata: surfaces.metadata,
            surface_message_epochs,
            contents,
            dm_sessions,
            group_member_pins,
            device_manifests,
            accepted_contacts,
            groups,
            sender_key_distributions_base64,
        })
    }

    pub(crate) fn own_device_group_snapshots(
        &self,
        source_device_id: &str,
    ) -> Result<Vec<SdkOwnDeviceGroupSnapshot>, SdkError> {
        self.groups()?
            .into_iter()
            .filter_map(|group| {
                self.own_device_group_snapshot(&group.group_id, source_device_id).transpose()
            })
            .collect()
    }
    pub(crate) fn own_device_group_snapshot(
        &self,
        id: &str,
        source_device_id: &str,
    ) -> Result<Option<SdkOwnDeviceGroupSnapshot>, SdkError> {
        let source = self.local_device_identity(source_device_id)?;
        if let Some(state) = self.account_db()?.shared_group_state(id)? {
            let Some(role) =
                state.view().effective_role(source.root_commitment(), source.device_id())
            else {
                return Ok(None);
            };
            let joined = self
                .account_db()?
                .group_member_joined_epoch(id, &source)?
                .ok_or(StorageError::GroupPermissionDenied)?;
            return Ok(Some(SdkOwnDeviceGroupSnapshot {
                shared_state: Some(state.snapshot().clone()),
                group_id: id.into(),
                group_epoch: state.view().epoch,
                max_members: state.view().max_members,
                new_member_history: state.view().new_member_history.clone(),
                local_role: role.as_str().into(),
                local_joined_epoch: joined,
                members: state
                    .view()
                    .members
                    .iter()
                    .map(|m| SdkOwnDeviceGroupMemberSnapshot {
                        member_id: m.identity.device_id.clone(),
                        role: m.role.as_str().into(),
                        joined_epoch: m.joined_epoch,
                    })
                    .collect(),
                routes: Vec::new(),
            }));
        }
        let group = self.group_state(id)?;
        let Some(role) = group.roles.get(source.device_id()).cloned() else { return Ok(None) };
        let Some(joined_epoch) =
            self.account_db()?.group_member_joined_epoch_metadata(id, source.device_id())?
        else {
            return Ok(None);
        };
        let mut members = Vec::with_capacity(group.members.len());
        for member in &group.members {
            if let Some(role) = group.roles.get(member).cloned()
                && let Some(joined_epoch) =
                    self.account_db()?.group_member_joined_epoch_metadata(id, member)?
            {
                members.push(SdkOwnDeviceGroupMemberSnapshot {
                    member_id: member.clone(),
                    role,
                    joined_epoch,
                });
            }
        }
        Ok(Some(SdkOwnDeviceGroupSnapshot {
            shared_state: self
                .account_db()?
                .shared_group_state(id)?
                .map(|state| state.snapshot().clone()),
            group_id: id.into(),
            group_epoch: group.group_epoch,
            max_members: group.max_members,
            new_member_history: group.new_member_history,
            local_role: role,
            local_joined_epoch: joined_epoch,
            members,
            routes: self.group_member_routes(id)?,
        }))
    }

    fn own_device_sender_key_distributions(
        &self,
        source_device_id: &str,
        groups: &[SdkOwnDeviceGroupSnapshot],
    ) -> Result<Vec<String>, SdkError> {
        let mut distributions = Vec::new();
        for group in groups {
            let state = self.group_state(&group.group_id)?;
            if state.members.contains(source_device_id) {
                let distribution =
                    self.export_group_sender_key_distribution(&group.group_id, source_device_id)?;
                distributions.push(ramflux_protocol::encode_base64url(&distribution));
            }
            // Shared snapshots carry authenticated root-qualified declarations. Peer sender keys
            // arrive from their own authenticated controls; a bare-name legacy list cannot convey them.
            if group.shared_state.is_some() {
                continue;
            }
            for member_id in &state.members {
                if member_id == source_device_id {
                    continue;
                }
                if let Ok(state) = self.load_group_sender_key_state(
                    &group.group_id,
                    &self.device_identity(
                        &self.group_device_reference(&group.group_id, member_id)?,
                    )?,
                    group.group_epoch,
                    "recv",
                ) {
                    let distribution = SdkGroupSenderKeyDistribution {
                        schema: if state.chain_version == 3 {
                            "ramflux.sdk.group_sender_key.distribution.v3"
                        } else {
                            "ramflux.sdk.group_sender_key.distribution.v1"
                        }
                        .to_owned(),
                        version: if state.chain_version == 3 { 3 } else { 1 },
                        group_id: group.group_id.clone(),
                        sender_id: member_id.clone(),
                        group_key_epoch: group.group_epoch,
                        group_state_hash: None,
                        sender_key_seed: state.session_snapshot.root_key_bytes(),
                        sender_key_signature: None,
                        sender_device_signing_public_key: self
                            .account_db()?
                            .group_member_device_key(
                                &group.group_id,
                                &self.device_identity(
                                    &self.group_device_reference(&group.group_id, member_id)?,
                                )?,
                            )?,
                    };
                    distributions.push(ramflux_protocol::encode_base64url(&serde_json::to_vec(
                        &distribution,
                    )?));
                }
            }
        }
        Ok(distributions)
    }

    fn message_allowed_by_group_floor(
        message: &DirectMessageRecord,
        floor_by_group: &BTreeMap<String, u64>,
    ) -> bool {
        let Some((group_id, group_key_epoch)) = group_message_epoch(message) else {
            return true;
        };
        floor_by_group.get(&group_id).is_some_and(|floor| group_key_epoch >= *floor)
    }

    pub(crate) async fn verify_own_device_sync_envelope(
        &self,
        gateway: &GatewaySessionConfig,
        expected_principal_commitment: &str,
        envelope: &SdkOwnDeviceSyncEnvelope,
    ) -> Result<(), SdkError> {
        if envelope.schema != "ramflux.sdk.own_device_sync.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported own-device sync schema: {}",
                envelope.schema
            )));
        }
        if envelope.principal_commitment != expected_principal_commitment {
            return Err(SdkError::LocalBus("own-device sync local principal mismatch".to_owned()));
        }
        if envelope.expires_at < now_unix_timestamp() {
            return Err(SdkError::LocalBus("own-device sync envelope expired".to_owned()));
        }
        let local_device_id =
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id.as_str();
        if envelope.target_device_id != local_device_id {
            return Err(SdkError::LocalBus("own-device sync target device mismatch".to_owned()));
        }
        if envelope.history_ref.key_slot.recipient_device_id != envelope.target_device_id {
            return Err(SdkError::LocalBus("own-device sync key slot target mismatch".to_owned()));
        }
        if envelope.history_ref.key_slot.object_id != envelope.history_ref.object_id {
            return Err(SdkError::LocalBus("own-device sync key slot object mismatch".to_owned()));
        }
        let expected_slot_conversation_id = own_device_sync_slot_conversation_id(
            &envelope.snapshot_id,
            &envelope.history_ref.object_id,
            &envelope.target_device_id,
        );
        if envelope.history_ref.key_slot.conversation_id != expected_slot_conversation_id {
            return Err(SdkError::LocalBus(
                "own-device sync key slot conversation mismatch".to_owned(),
            ));
        }
        let manifest = self
            .cache_verified_device_manifest(
                gateway,
                &envelope.principal_commitment,
                "own_device_sync_import",
            )
            .await?;
        let source = manifest
            .devices
            .iter()
            .find(|device| device.device_id == envelope.source_device_id)
            .ok_or_else(|| {
                SdkError::LocalBus(format!(
                    "own-device sync source {} is not in verified manifest",
                    envelope.source_device_id
                ))
            })?;
        let target = manifest
            .devices
            .iter()
            .find(|device| device.device_id == envelope.target_device_id)
            .ok_or_else(|| {
                SdkError::LocalBus(format!(
                    "own-device sync target {} is not in verified manifest",
                    envelope.target_device_id
                ))
            })?;
        self.require_cached_root_authority(
            &self.device_identity_for_root(&envelope.principal_commitment, &source.device_id)?,
        )?;
        self.require_cached_root_authority(
            &self.device_identity_for_root(&envelope.principal_commitment, &target.device_id)?,
        )?;
        if source.principal_commitment != envelope.principal_commitment
            || target.principal_commitment != envelope.principal_commitment
        {
            return Err(SdkError::LocalBus(
                "own-device sync manifest principal mismatch".to_owned(),
            ));
        }
        if envelope.signed.signing_key_id != format!("device:{}", envelope.source_device_id) {
            return Err(SdkError::LocalBus("own-device sync signing key id mismatch".to_owned()));
        }
        ramflux_crypto::verify_device_branch_signature(
            &source.branch_public_key,
            &own_device_sync_signing_body(envelope),
            &envelope.signed.signature,
        )?;
        Ok(())
    }

    fn import_own_device_history_bundle(
        &self,
        envelope: &SdkOwnDeviceSyncEnvelope,
        bundle: &SdkOwnDeviceHistoryBundle,
    ) -> Result<SdkOwnDeviceSyncImportResponse, SdkError> {
        self.account_db()?
            .write_transaction(|| self.import_own_device_history_bundle_inner(envelope, bundle))
    }
    fn import_own_history_messages(
        &self,
        bundle: &SdkOwnDeviceHistoryBundle,
        floor_by_group: &BTreeMap<String, u64>,
        blocked: &BTreeSet<(String, String)>,
    ) -> Result<usize, SdkError> {
        let mut imported_messages = 0_usize;
        for message in &bundle.messages {
            if serde_json::from_slice::<SdkGroupEncryptedEnvelope>(&message.encrypted_body)
                .is_ok_and(|g| !floor_by_group.contains_key(&g.group_id))
            {
                self.account_db()?.record_own_device_restore_skip(
                    &bundle.snapshot_id,
                    &message.message_id,
                    "group_message_unavailable",
                )?;
                continue;
            }
            if !Self::message_allowed_by_group_floor(message, floor_by_group) {
                self.account_db()?.record_own_device_restore_skip(
                    &bundle.snapshot_id,
                    &message.message_id,
                    "group_message_below_join_floor",
                )?;
                continue;
            }
            if let Ok(group) =
                serde_json::from_slice::<SdkGroupEncryptedEnvelope>(&message.encrypted_body)
                && (!floor_by_group.contains_key(&group.group_id)
                    || blocked.contains(&(group.group_id.clone(), group.sender_id.clone()))
                    || blocked.contains(&(group.group_id.clone(), String::new()))
                    || !self
                        .own_history_group_member_name_present(&group.group_id, &group.sender_id)?)
            {
                self.account_db()?.record_own_device_restore_skip(
                    &bundle.snapshot_id,
                    &message.message_id,
                    "group_message_unavailable",
                )?;
                continue;
            }
            if self.skip_owned_surface_message(bundle, &message.message_id, floor_by_group)? {
                continue;
            }
            self.account_db()?.import_direct_message_projection(DirectMessageWrite {
                conversation_id: &message.conversation_id,
                message_id: &message.message_id,
                sender_id: &message.sender_id,
                encrypted_body: &message.encrypted_body,
                metadata: &message.metadata,
                created_at: message.created_at,
            })?;
            if let Some(content) = bundle.contents.get(&message.message_id) {
                self.account_db()?.store_message_content(
                    &message.conversation_id,
                    &message.message_id,
                    content,
                )?;
            }
            imported_messages = imported_messages.saturating_add(1);
        }
        Ok(imported_messages)
    }
    fn import_own_device_history_bundle_inner(
        &self,
        envelope: &SdkOwnDeviceSyncEnvelope,
        bundle: &SdkOwnDeviceHistoryBundle,
    ) -> Result<SdkOwnDeviceSyncImportResponse, SdkError> {
        if !matches!(
            (bundle.schema.as_str(), bundle.version),
            ("ramflux.sdk.own_device_history_bundle.v1", 1)
                | ("ramflux.sdk.own_device_history_bundle.v2", 2)
        ) || bundle.principal_commitment != envelope.principal_commitment
            || bundle.source_device_id != envelope.source_device_id
            || bundle.target_device_id != envelope.target_device_id
            || bundle.snapshot_id != envelope.snapshot_id
        {
            return Err(SdkError::LocalBus("own-device sync bundle binding mismatch".to_owned()));
        }
        let local_device_id =
            self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_id.clone();
        if bundle.target_device_id != local_device_id {
            return Err(SdkError::LocalBus("own-device sync bundle target mismatch".to_owned()));
        }
        super::own_device_history_pages::validate(bundle)?;
        self.restore_own_history_authority(bundle)?;
        if bundle.authority_only {
            return Ok(SdkOwnDeviceSyncImportResponse {
                snapshot_id: bundle.snapshot_id.clone(),
                imported_messages: 0,
                imported_dm_sessions: 0,
                imported_groups: 0,
                imported_sender_keys: 0,
            });
        }
        let floor_by_group = self.restore_own_groups(bundle)?;
        let blocked = self.restore_own_device_group_member_pins(bundle, &floor_by_group)?;
        self.import_own_task_packets(&bundle.task_packets, &bundle.source_device_id)?;
        let imported_messages =
            self.import_own_history_messages(bundle, &floor_by_group, &blocked)?;
        let imported_dm_sessions = 0;
        let mut imported_sender_keys = 0_usize;
        for distribution_base64 in &bundle.sender_key_distributions_base64 {
            if self.restore_own_sender_key(bundle, distribution_base64, &blocked)? {
                imported_sender_keys = imported_sender_keys.saturating_add(1);
            }
        }
        if bundle.surface_pages.len() > 63
            || serde_json::to_vec(&bundle.surface_pages)?.len() > 8 * 1024 * 1024
        {
            return Err(SdkError::LocalBus("surface history pages budget exceeded".into()));
        }
        self.import_owned_surface_checkpoints(&bundle.surface_checkpoints)?;
        for page in &bundle.surface_pages {
            self.import_owned_surface_checkpoints(&page.checkpoints)?;
            self.import_own_surface_history(envelope, &page.controls)?;
        }
        self.import_own_surface_history(envelope, &bundle.surface_controls)?;
        Ok(SdkOwnDeviceSyncImportResponse {
            snapshot_id: bundle.snapshot_id.clone(),
            imported_messages,
            imported_dm_sessions,
            imported_groups: floor_by_group.len(),
            imported_sender_keys,
        })
    }
}

/// Builds the own-device-sync `history_ref` attachment, binding the owner lineage to the effective
/// relay options this snapshot was actually uploaded with.
///
/// T21-A2: the target device's v3 grantee GET/ACK reads `owner_home_node_id` / `relay_audience_node_id`
/// from this ref. Populating them from the same `relay_options` used for the upload keeps a stale
/// export from silently breaking the target's v3 download. The grant is signed by the source device
/// with Get+Ack for the target device only.
#[allow(clippy::too_many_arguments)]
pub(crate) fn own_device_history_ref(
    object: &EncryptedObject,
    manifest: &ChunkManifest,
    relay_endpoint: &str,
    relay_options: &RelayTransferOptions,
    source_branch: &DeviceBranch,
    target: &ramflux_crypto::RootQualifiedDeviceRef,
    slot_conversation_id: String,
    x3dh: Option<SdkDmX3dhHeader>,
    ciphertext: ramflux_crypto::DmCiphertext,
    now: u64,
) -> Result<SdkDmAttachmentRef, SdkError> {
    Ok(SdkDmAttachmentRef {
        schema: "ramflux.sdk.dm_attachment_ref.v1".to_owned(),
        version: 1,
        object_id: object.object_id.clone(),
        manifest_hash: object.manifest_hash.clone(),
        plaintext_hash: object.plaintext_hash.clone(),
        cipher_size: u64::try_from(object.ciphertext.len()).unwrap_or(u64::MAX),
        chunk_size: manifest.chunk_size,
        total_chunks: manifest.total_chunks,
        relay_endpoint: relay_endpoint.to_owned(),
        owner_home_node_id: relay_options.relay_owner_home_node_id.clone(),
        relay_audience_node_id: relay_options.relay_audience_node_id.clone(),
        owner_principal_id: source_branch.principal_id.clone(),
        owner_device_epoch: source_branch.device_epoch,
        access_grant: Some(build_signed_object_access_grant(
            source_branch,
            object.object_id.clone(),
            object.manifest_hash.clone(),
            recipient_device_hash(target),
            vec![
                ramflux_protocol::ObjectRelayCapability::Get,
                ramflux_protocol::ObjectRelayCapability::Ack,
            ],
            now,
            now.saturating_add(3_600),
        )?),
        key_slot: SdkObjectKeySlot {
            schema: "ramflux.sdk.object_key_slot.dm.v1".to_owned(),
            version: 1,
            object_id: object.object_id.clone(),
            conversation_id: slot_conversation_id,
            recipient_device_id: target.device_id().to_owned(),
            source_principal_commitment: Some(target.root_commitment().into()),
            x3dh,
            ciphertext,
        },
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn own_device_history_ref_binds_effective_upload_lineage() -> Result<(), SdkError> {
        let source =
            ramflux_crypto::create_device_branch("own_principal", "own_device", 3, [5u8; 32]);
        let object = EncryptedObject {
            object_id: "own_object".to_owned(),
            manifest_hash: "own_manifest".to_owned(),
            nonce: "own_nonce".to_owned(),
            ciphertext: vec![0u8; 16],
            plaintext_hash: "own_plaintext".to_owned(),
            tombstoned: false,
            backup_excluded: false,
        };
        let manifest = ChunkManifest {
            object_id: "own_object".to_owned(),
            manifest_hash: "own_manifest".to_owned(),
            chunk_size: 1024,
            total_chunks: 1,
            object_created_group_key_epoch: None,
        };
        // The effective relay options this snapshot was uploaded with carry a concrete lineage.
        let relay_options = RelayTransferOptions {
            relay_endpoint: "http://127.0.0.1:2".to_owned(),
            token_provider: RelayTokenProvider::GatewayIssued,
            interrupt_after_chunks: None,
            relay_quic_peer_addr: None,
            relay_quic_server_name: None,
            relay_quic_ca_cert: None,
            relay_owner_home_node_id: Some("node_own_effective".to_owned()),
            relay_owner_principal_id: Some("own_principal_effective".to_owned()),
            relay_audience_node_id: Some("aud_own_effective".to_owned()),
        };
        let ciphertext: ramflux_crypto::DmCiphertext = serde_json::from_value(serde_json::json!({
            "session_id": "s", "counter": 0, "nonce": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            "ciphertext": []
        }))?;
        let history_ref = own_device_history_ref(
            &object,
            &manifest,
            "http://127.0.0.1:2",
            &relay_options,
            &source,
            &ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
                &ramflux_crypto::create_identity_root("own_principal", [9; 32]),
                "target_own_device",
            )?,
            "slot_own".to_owned(),
            None,
            ciphertext,
            1_000_000,
        )?;
        // The constructed ref binds the exact lineage the upload used, not a null owner home node.
        assert_eq!(history_ref.owner_home_node_id.as_deref(), Some("node_own_effective"));
        assert_eq!(history_ref.relay_audience_node_id.as_deref(), Some("aud_own_effective"));
        assert_eq!(history_ref.owner_principal_id, "own_principal");
        assert_eq!(history_ref.owner_device_epoch, 3);
        // The grant authorizes exactly Get+Ack for the named target device.
        let grant = history_ref
            .access_grant
            .as_ref()
            .ok_or_else(|| SdkError::LocalBus("history ref missing grant".to_owned()))?;
        assert_eq!(
            grant.capabilities,
            vec![
                ramflux_protocol::ObjectRelayCapability::Get,
                ramflux_protocol::ObjectRelayCapability::Ack,
            ]
        );
        assert_eq!(
            grant.grantee_device_hash,
            recipient_device_hash(
                &ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
                    &ramflux_crypto::create_identity_root("own_principal", [9; 32]),
                    "target_own_device"
                )?
            )
        );
        Ok(())
    }

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos =
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!("ramflux-sdk-own-device-sync-{test_name}-{nanos}"))
    }

    pub(super) fn client_with_account(
        test_name: &str,
        principal: &str,
        device_id: &str,
    ) -> Result<(RamfluxClient, PathBuf), SdkError> {
        let root = temp_root(test_name);
        let mut client = RamfluxClient::new();
        client.create_identity_root(principal, [0x51; 32]);
        client.create_device_branch(principal, device_id, 1, [0x52; 32]);
        client.open_account_index(&root)?;
        client.create_account("acct", principal)?;
        client.unlock_account("acct", b"own-device-sync-test")?;
        Ok((client, root))
    }

    pub(crate) fn envelope(
        source_device_id: &str,
        target_device_id: &str,
    ) -> SdkOwnDeviceSyncEnvelope {
        SdkOwnDeviceSyncEnvelope {
            schema: "ramflux.sdk.own_device_sync.v1".to_owned(),
            version: 1,
            principal_commitment: "principal_sync".to_owned(),
            source_device_id: source_device_id.to_owned(),
            target_device_id: target_device_id.to_owned(),
            snapshot_id: "snapshot_sync".to_owned(),
            snapshot_kind: "history_bundle".to_owned(),
            created_at: 1_760_000_000,
            expires_at: 1_760_003_600,
            nonce: "nonce_sync".to_owned(),
            history_ref: SdkDmAttachmentRef {
                schema: "ramflux.sdk.dm_attachment_ref.v1".to_owned(),
                version: 1,
                object_id: "object_sync".to_owned(),
                manifest_hash: "manifest_sync".to_owned(),
                plaintext_hash: "plaintext_sync".to_owned(),
                cipher_size: 0,
                chunk_size: 1024,
                total_chunks: 1,
                relay_endpoint: "http://127.0.0.1:1".to_owned(),
                owner_home_node_id: None,
                relay_audience_node_id: None,
                owner_principal_id: String::new(),
                owner_device_epoch: 0,
                access_grant: None,
                key_slot: SdkObjectKeySlot {
                    schema: "ramflux.sdk.object_key_slot.dm.v1".to_owned(),
                    version: 1,
                    object_id: "object_sync".to_owned(),
                    conversation_id: "slot_sync".to_owned(),
                    recipient_device_id: target_device_id.to_owned(),
                    source_principal_commitment: None,
                    x3dh: None,
                    ciphertext: ramflux_crypto::DmCiphertext {
                        session_id: "slot_sync".to_owned(),
                        counter: 0,
                        nonce: [0; 12],
                        ciphertext: Vec::new(),
                        ratchet_public_key: None,
                        previous_chain_length: 0,
                        sender_device_id_hash: [0; 32],
                        recipient_device_id_hash: [0; 32],
                        device_epoch: 0,
                        message_event_id: String::new(),
                        canonical_header_bytes: Vec::new(),
                        header_hash: String::new(),
                        key_commitment: String::new(),
                        franking_commitment: String::new(),
                        commitment: String::new(),
                        ciphertext_hash: String::new(),
                    },
                },
            },
            signed: sdk_device_signed_fields(source_device_id, ""),
        }
    }

    pub(super) fn bundle(
        source_device_id: &str,
        target_device_id: &str,
        messages: Vec<DirectMessageRecord>,
        groups: Vec<SdkOwnDeviceGroupSnapshot>,
    ) -> SdkOwnDeviceHistoryBundle {
        SdkOwnDeviceHistoryBundle {
            authority_only: false,
            next_page: None,
            task_packets: Vec::new(),
            task_export_metadata: crate::client::task::own_history::TaskExportMetadata::default(),
            surface_controls: Vec::new(),
            surface_pages: Vec::new(),
            surface_checkpoints: Vec::new(),
            surface_export_metadata: crate::client::surface::SurfaceExportMetadata::default(),
            surface_message_epochs: BTreeMap::new(),
            schema: "ramflux.sdk.own_device_history_bundle.v1".to_owned(),
            version: 1,
            principal_commitment: "principal_sync".to_owned(),
            source_device_id: source_device_id.to_owned(),
            target_device_id: target_device_id.to_owned(),
            snapshot_id: "snapshot_sync".to_owned(),
            messages,
            contents: BTreeMap::new(),
            dm_sessions: Vec::new(),
            groups,
            group_member_pins: Vec::new(),
            device_manifests: Vec::new(),
            accepted_contacts: Vec::new(),
            sender_key_distributions_base64: Vec::new(),
        }
    }

    #[test]
    fn rejected_task_history_items_do_not_abort_ordinary_message_restore() -> Result<(), SdkError> {
        let (client, root) =
            client_with_account("task-best-effort", "principal_sync", "target_device_sync")?;
        let message = DirectMessageRecord {
            conversation_id: "direct".into(),
            message_id: "safe".into(),
            sender_id: "source_device_sync".into(),
            encrypted_body: b"safe history".to_vec(),
            metadata: MessageMetadata::default(),
            deleted: false,
            created_at: 1,
            receipts: Vec::new(),
        };
        let mut history =
            bundle("source_device_sync", "target_device_sync", vec![message], Vec::new());
        history.task_packets.push(serde_json::from_value(serde_json::json!({
            "context":{"conversation_id":"missing-task-thread","participants":["principal_sync","peer"],"group":null,"friend":null},
            "history":{"events":[],"created_at":1,"updated_at":1},"manifests":[],"pins":[],"base":0,"prefix_hash":"invalid"
        }))?);
        let result = client.import_own_device_history_bundle(
            &envelope("source_device_sync", "target_device_sync"),
            &history,
        )?;
        assert_eq!(result.imported_messages, 1);
        assert_eq!(
            client
                .direct_message_by_id("safe")?
                .ok_or_else(|| SdkError::LocalBus("message absent".into()))?
                .encrypted_body,
            b"safe history"
        );
        assert_eq!(client.account_db()?.task_state_usage("task/import_skip/")?.0, 1);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn own_device_history_import_preserves_direct_message_created_at() -> Result<(), SdkError> {
        let (client, root) =
            client_with_account("created-at", "principal_sync", "target_device_sync")?;
        let message = DirectMessageRecord {
            conversation_id: "conv_sync_dm".to_owned(),
            message_id: "msg_sync_original_time".to_owned(),
            sender_id: "source_device_sync".to_owned(),
            encrypted_body: b"ciphertext".to_vec(),
            metadata: MessageMetadata::default(),
            deleted: false,
            created_at: 1_760_000_111,
            receipts: Vec::new(),
        };
        let response = client.import_own_device_history_bundle(
            &envelope("source_device_sync", "target_device_sync"),
            &bundle("source_device_sync", "target_device_sync", vec![message], Vec::new()),
        )?;
        assert_eq!(response.imported_messages, 1);
        let imported = client
            .direct_message_by_id("msg_sync_original_time")?
            .ok_or_else(|| SdkError::LocalBus("imported message missing".to_owned()))?;
        assert_eq!(imported.created_at, 1_760_000_111);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn own_device_history_import_skips_group_message_below_joined_epoch() -> Result<(), SdkError> {
        let (client, root) =
            client_with_account("joined-epoch", "principal_sync", "target_device_sync")?;
        let old_group_message = DirectMessageRecord {
            conversation_id: "conv_sync_group".to_owned(),
            message_id: "msg_sync_before_join".to_owned(),
            sender_id: "source_device_sync".to_owned(),
            encrypted_body: serde_json::to_vec(&SdkGroupEncryptedEnvelope {
                schema: "ramflux.sdk.group_sender_key.message.v1".to_owned(),
                version: 1,
                group_id: "group_sync".to_owned(),
                sender_id: "source_device_sync".to_owned(),
                group_key_epoch: 1,
                group_state_hash: None,
                ciphertext: ramflux_crypto::DmCiphertext {
                    session_id: "group_sync".to_owned(),
                    counter: 0,
                    nonce: [0; 12],
                    ciphertext: b"old".to_vec(),
                    ratchet_public_key: None,
                    previous_chain_length: 0,
                    sender_device_id_hash: [0; 32],
                    recipient_device_id_hash: [0; 32],
                    device_epoch: 0,
                    message_event_id: String::new(),
                    canonical_header_bytes: Vec::new(),
                    header_hash: String::new(),
                    key_commitment: String::new(),
                    franking_commitment: String::new(),
                    commitment: String::new(),
                    ciphertext_hash: String::new(),
                },
            })?,
            metadata: MessageMetadata::default(),
            deleted: false,
            created_at: 1_760_000_010,
            receipts: Vec::new(),
        };
        let group = SdkOwnDeviceGroupSnapshot {
            shared_state: None,
            group_id: "group_sync".to_owned(),
            group_epoch: 2,
            max_members: 64,
            new_member_history: "none".to_owned(),
            local_role: "member".to_owned(),
            local_joined_epoch: 2,
            members: vec![SdkOwnDeviceGroupMemberSnapshot {
                member_id: "target_device_sync".to_owned(),
                role: "member".to_owned(),
                joined_epoch: 2,
            }],
            routes: Vec::new(),
        };
        let result = client.import_own_device_history_bundle(
            &envelope("source_device_sync", "target_device_sync"),
            &bundle(
                "source_device_sync",
                "target_device_sync",
                vec![old_group_message],
                vec![group],
            ),
        )?;
        assert_eq!(result.imported_messages, 0);
        assert!(
            client
                .account_db()?
                .list_actor_states::<serde_json::Value>("own-device/restore-skip/")?
                .iter()
                .any(|row| row["reason"] == "group_message_below_join_floor")
        );
        assert!(client.direct_message_by_id("msg_sync_before_join")?.is_none());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn own_device_history_does_not_export_live_device_pair_secrets() -> Result<(), SdkError> {
        let (source, source_root) =
            client_with_account("pair-history-source", "principal_sync", "source_device_sync")?;
        let (target, target_root) =
            client_with_account("pair-history-target", "principal_sync", "target_device_sync")?;
        let session = ramflux_crypto::DmSession::initiator(
            [1; 32],
            dm_device_id_hash("source_device_sync"),
            dm_device_id_hash("remote_device"),
            [2; 32],
        )?;
        let remote = ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(
            source.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            "remote_device",
        )?;
        source.persist_pair(
            &source.local_device_identity("source_device_sync")?,
            &source.device_identity(remote.storage_key())?,
            &[3; 32],
            &session,
        )?;
        source.send_direct_message(
            "history-thread",
            "history-message",
            "source_device_sync",
            b"ciphertext history",
        )?;
        source.account_db()?.store_message_content(
            "history-thread",
            "history-message",
            b"approved history plaintext",
        )?;
        source.persist_dm_session("history-thread", "legacy-checkpoint", "send", &session)?;
        source.create_group("history-group", "source_device_sync")?;
        let mut own_manifest =
            crate::client::identity_authority::test_support::public_manifest(&source)?;
        own_manifest.devices.extend(
            crate::client::identity_authority::test_support::public_manifest(&target)?.devices,
        );
        crate::client::identity_authority::test_support::sign_manifest(
            source.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
            &mut own_manifest,
            1,
        )?;
        source.persist_root_verified_directory(&own_manifest)?;
        target.persist_root_verified_directory(&own_manifest)?;
        source.add_group_member(
            "history-group",
            target.owned_device_identity()?.storage_key(),
            "member",
        )?;
        let history = source.own_device_history_bundle(
            "principal_sync",
            "source_device_sync",
            "target_device_sync",
            "snapshot_sync",
        )?;
        assert!(serde_json::to_value(&history)?.get("pair_sessions").is_none());
        assert_eq!(history.dm_sessions.len(), 0);
        let imported = target.import_own_device_history_bundle(
            &envelope("source_device_sync", "target_device_sync"),
            &history,
        )?;
        let group_before = serde_json::to_value(target.group_state("history-group")?)?;
        target.import_own_device_history_bundle(
            &envelope("source_device_sync", "target_device_sync"),
            &history,
        )?;
        assert_eq!(serde_json::to_value(target.group_state("history-group")?)?, group_before);
        assert_eq!(
            target.direct_message_by_id("history-message")?.map(|m| m.message_id),
            Some("history-message".into())
        );
        assert_eq!(imported.imported_dm_sessions, 0);
        assert_eq!(
            target.account_db()?.message_content("history-message")?,
            Some(b"approved history plaintext".to_vec())
        );
        assert!(!format!("{history:?}").contains("approved history plaintext"));
        assert_eq!(
            target
                .account_db()?
                .list_actor_states::<serde_json::Value>("own-device/pair-history/")?
                .len(),
            0
        );
        assert_eq!(
            target.account_db()?.list_actor_states::<serde_json::Value>("dm-pair/")?.len(),
            0
        );
        assert!(target.load_dm_session("thread", "recv").is_err());
        drop(source);
        drop(target);
        std::fs::remove_dir_all(source_root)?;
        std::fs::remove_dir_all(target_root)?;
        Ok(())
    }
    #[path = "own_device_group_pin_tests.rs"]
    mod group_pin_tests;
    #[path = "shared_group_history_tests.rs"]
    mod shared_group_history_tests;
    #[path = "stale_group_snapshot_tests.rs"]
    mod stale_group_snapshot_tests;
    #[test]
    fn control_import_skip_keys_distinguish_pages_and_are_retry_idempotent() -> Result<(), SdkError>
    {
        let (client, root) =
            client_with_account("surface-skip-pages", "principal_sync", "target_device_sync")?;
        let envelope = envelope("source_device_sync", "target_device_sync");
        let mut control = crate::client::surface::SurfaceControl {
            kind: crate::client::surface::ControlKind::Peer,
            carrier_base64: "page-one".into(),
            group_epoch: None,
            context: None,
            manifests: Vec::new(),
        };
        client.import_own_surface_history(&envelope, &[control.clone()])?;
        control.carrier_base64 = "page-two".into();
        client.import_own_surface_history(&envelope, &[control.clone()])?;
        client.import_own_surface_history(&envelope, &[control])?;
        let rows = client.account_db()?.surface_history_page::<serde_json::Value>(
            "surface/import_control_skip/",
            "surface/import_control_skip/",
            100,
        )?;
        assert_eq!(rows.len(), 2);
        drop(client);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

#[cfg(test)]
mod backup_paging_tests {
    use super::tests::bundle;
    use super::*;
    #[test]
    fn own_history_continuation_pages_preserve_every_contact_beyond_old_count_and_byte_caps()
    -> Result<(), SdkError> {
        let mut history = bundle("source", "target", Vec::new(), Vec::new());
        history.accepted_contacts =
            (0..1100).map(|n| format!("{n:04}:{}", "x".repeat(4096))).collect();
        let expected = history.accepted_contacts.clone();
        let pages = crate::client::own_device_history_pages::pages(history)?;
        assert!(pages.len() > 2);
        let mut actual = Vec::new();
        for page in &pages {
            RamfluxClient::check_own_history_authority_budget(
                &page.device_manifests,
                &page.accepted_contacts,
            )?;
            actual.extend(page.accepted_contacts.iter().cloned());
        }
        assert_eq!(actual, expected);
        assert!(
            !pages
                .last()
                .ok_or_else(|| SdkError::InboundRejected("page absent".into()))?
                .authority_only
        );
        Ok(())
    }
}

#[cfg(test)]
mod backup_contact_paging_tests {
    use super::*;
    #[test]
    fn every_restricted_contact_is_restored_across_authenticated_authority_pages()
    -> Result<(), SdkError> {
        let (source, source_root) = super::tests::client_with_account(
            "backup-contact-pages-source",
            "principal_sync",
            "source",
        )?;
        let (target, target_root) = super::tests::client_with_account(
            "backup-contact-pages-target",
            "principal_sync",
            "target",
        )?;
        let root = source.owned_device_identity()?.root_commitment().to_owned();
        for n in 0..1100_u32 {
            let id = format!("link-{n:04}");
            source.account_db()?.establish_friend_link(
                &id,
                &root,
                &ramflux_protocol::hash_base64url("backup-peer", &n.to_be_bytes()),
            )?;
            source.account_db()?.block_friend_link(&id, 1_800_000_000)?;
        }
        let mut history = super::tests::bundle("source", "target", Vec::new(), Vec::new());
        history.principal_commitment = root.clone();
        history.accepted_contacts = source.own_history_contacts()?;
        assert_eq!(history.accepted_contacts.len(), 1100);
        let mut envelope = super::tests::envelope("source", "target");
        envelope.principal_commitment = root;
        for page in crate::client::own_device_history_pages::pages(history)? {
            envelope.snapshot_id = page.snapshot_id.clone();
            target.import_own_device_history_bundle(&envelope, &page)?;
        }
        let links = target.account_db()?.friend_links()?;
        assert_eq!(links.len(), 1100);
        assert!(links.iter().all(|link| link.blocked));
        drop(source);
        drop(target);
        std::fs::remove_dir_all(source_root)?;
        std::fs::remove_dir_all(target_root)?;
        Ok(())
    }
}

#[cfg(test)]
mod backup_page_shape_tests {
    use super::*;
    #[test]
    fn authority_only_pages_refuse_ordinary_history_instead_of_silently_discarding_it()
    -> Result<(), SdkError> {
        let mut bundle = super::tests::bundle("source", "target", Vec::new(), Vec::new());
        bundle.version = 2;
        bundle.schema = "ramflux.sdk.own_device_history_bundle.v2".into();
        bundle.authority_only = true;
        crate::client::own_device_history_pages::validate(&bundle)?;
        bundle
            .contents
            .insert("message".into(), zeroize::Zeroizing::new(b"must not disappear".to_vec()));
        assert!(crate::client::own_device_history_pages::validate(&bundle).is_err());
        bundle.contents.clear();
        bundle.version = 1;
        assert!(crate::client::own_device_history_pages::validate(&bundle).is_err());
        Ok(())
    }
}

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
        principal_commitment: &str,
        target_device_id: &str,
        relay_endpoint: &str,
        relay_service_key_base64: Option<String>,
        chunk_size: usize,
    ) -> Result<SdkOwnDeviceSyncExportResponse, SdkError> {
        let source_branch = self.device_branch.clone().ok_or(SdkError::IdentityRootMissing)?;
        let source_device_id = source_branch.device_id.clone();
        let source_device = assert_target_manifest_active_device(
            &engine.config,
            Some(principal_commitment),
            &source_device_id,
        )
        .await?;
        let target_device = assert_target_manifest_active_device(
            &engine.config,
            Some(principal_commitment),
            target_device_id,
        )
        .await?;
        if source_device.principal_commitment != target_device.principal_commitment {
            return Err(SdkError::LocalBus("own-device sync principal mismatch".to_owned()));
        }
        let snapshot_id =
            format!("own-sync:{}:{}:{}", source_device_id, target_device_id, now_unix_timestamp());
        let bundle = self.own_device_history_bundle(
            principal_commitment,
            &source_device_id,
            target_device_id,
            &snapshot_id,
        )?;
        let plaintext = serde_json::to_vec(&bundle)?;
        let object_id = format!("own-device-sync:{snapshot_id}");
        let object = self.put_encrypted_object(&object_id, &plaintext)?;
        let relay_options = parse_relay_transfer_options(
            Some(relay_endpoint.to_owned()),
            relay_service_key_base64,
            None,
        )?
        .ok_or_else(|| SdkError::LocalBus("own-device sync relay endpoint missing".to_owned()))?;
        let transfer = self
            .upload_object_to_relay_inner_via_gateway(engine, &object, chunk_size, &relay_options)
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
            target_delivery_id: target_device.target_delivery_id,
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
            history_ref: SdkDmAttachmentRef {
                schema: "ramflux.sdk.dm_attachment_ref.v1".to_owned(),
                version: 1,
                object_id: object.object_id.clone(),
                manifest_hash: object.manifest_hash.clone(),
                plaintext_hash: object.plaintext_hash.clone(),
                cipher_size: u64::try_from(object.ciphertext.len()).unwrap_or(u64::MAX),
                chunk_size: manifest.chunk_size,
                total_chunks: manifest.total_chunks,
                relay_endpoint: relay_endpoint.to_owned(),
                key_slot: SdkObjectKeySlot {
                    schema: "ramflux.sdk.object_key_slot.dm.v1".to_owned(),
                    version: 1,
                    object_id: object.object_id.clone(),
                    conversation_id: slot_conversation_id,
                    recipient_device_id: target_device_id.to_owned(),
                    x3dh,
                    ciphertext,
                },
            },
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

    pub(crate) async fn import_own_device_sync(
        &mut self,
        engine: &mut GatewaySessionEngine,
        expected_principal_commitment: &str,
        envelope: &SdkOwnDeviceSyncEnvelope,
        relay_service_key_base64: Option<String>,
    ) -> Result<SdkOwnDeviceSyncImportResponse, SdkError> {
        self.verify_own_device_sync_envelope(
            &engine.config,
            expected_principal_commitment,
            envelope,
        )
        .await?;
        let import = self
            .import_dm_attachment_from_relay_via_gateway(
                engine,
                &envelope.history_ref,
                relay_service_key_base64,
            )
            .await?;
        let plaintext = ramflux_protocol::decode_base64url(&import.plaintext_base64)
            .map_err(|error| SdkError::LocalBus(format!("invalid sync bundle body: {error}")))?;
        let bundle: SdkOwnDeviceHistoryBundle = serde_json::from_slice(&plaintext)?;
        self.import_own_device_history_bundle(envelope, &bundle)
    }

    fn own_device_history_bundle(
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
        let messages = self
            .account_db()?
            .all_direct_messages()?
            .into_iter()
            .filter(|message| Self::message_allowed_by_group_floor(message, &floor_by_group))
            .collect::<Vec<_>>();
        let dm_sessions = self.own_device_dm_session_snapshots(&messages);
        let sender_key_distributions_base64 =
            self.own_device_sender_key_distributions(source_device_id, &groups)?;
        Ok(SdkOwnDeviceHistoryBundle {
            schema: "ramflux.sdk.own_device_history_bundle.v1".to_owned(),
            version: 1,
            principal_commitment: principal_commitment.to_owned(),
            source_device_id: source_device_id.to_owned(),
            target_device_id: target_device_id.to_owned(),
            snapshot_id: snapshot_id.to_owned(),
            messages,
            dm_sessions,
            groups,
            sender_key_distributions_base64,
        })
    }

    fn own_device_dm_session_snapshots(
        &self,
        messages: &[DirectMessageRecord],
    ) -> Vec<SdkOwnDeviceDmSessionSnapshot> {
        let mut conversations = BTreeSet::new();
        for message in messages {
            conversations.insert(message.conversation_id.clone());
        }
        let mut sessions = Vec::new();
        for conversation_id in conversations {
            for direction in ["send", "recv"] {
                if let Ok(session) = self.load_dm_session(&conversation_id, direction) {
                    sessions.push(SdkOwnDeviceDmSessionSnapshot {
                        conversation_id: conversation_id.clone(),
                        direction: direction.to_owned(),
                        snapshot: session.snapshot(),
                    });
                }
            }
        }
        sessions
    }

    fn own_device_group_snapshots(
        &self,
        source_device_id: &str,
    ) -> Result<Vec<SdkOwnDeviceGroupSnapshot>, SdkError> {
        let mut groups = Vec::new();
        for group in self.groups()? {
            let Some(role) = group.roles.get(source_device_id).cloned() else {
                continue;
            };
            let Some(joined_epoch) =
                self.account_db()?.group_member_joined_epoch(&group.group_id, source_device_id)?
            else {
                continue;
            };
            let mut members = Vec::with_capacity(group.members.len());
            for member_id in &group.members {
                let Some(role) = group.roles.get(member_id).cloned() else {
                    continue;
                };
                let Some(member_joined_epoch) =
                    self.account_db()?.group_member_joined_epoch(&group.group_id, member_id)?
                else {
                    continue;
                };
                members.push(SdkOwnDeviceGroupMemberSnapshot {
                    member_id: member_id.clone(),
                    role,
                    joined_epoch: member_joined_epoch,
                });
            }
            let group_id = group.group_id.clone();
            let routes = self.group_member_routes(&group_id)?;
            groups.push(SdkOwnDeviceGroupSnapshot {
                group_id,
                group_epoch: group.group_epoch,
                max_members: group.max_members,
                new_member_history: group.new_member_history,
                local_role: role,
                local_joined_epoch: joined_epoch,
                members,
                routes,
            });
        }
        Ok(groups)
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
            for member_id in &state.members {
                if member_id == source_device_id {
                    continue;
                }
                if let Ok(state) = self.load_group_sender_key_state(
                    &group.group_id,
                    member_id,
                    group.group_epoch,
                    "recv",
                ) {
                    let distribution = SdkGroupSenderKeyDistribution {
                        schema: "ramflux.sdk.group_sender_key.distribution.v1".to_owned(),
                        version: 1,
                        group_id: group.group_id.clone(),
                        sender_id: member_id.clone(),
                        group_key_epoch: group.group_epoch,
                        sender_key_seed: state.session_snapshot.root_key_bytes(),
                        sender_device_signing_public_key: self
                            .account_db()?
                            .group_member_device_key(&group.group_id, member_id)?,
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

    async fn verify_own_device_sync_envelope(
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
        let manifest = crate::client::contact::fetch_verified_device_manifest(
            gateway,
            &envelope.principal_commitment,
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
        if bundle.schema != "ramflux.sdk.own_device_history_bundle.v1"
            || bundle.principal_commitment != envelope.principal_commitment
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
        let mut floor_by_group = BTreeMap::new();
        for group in &bundle.groups {
            self.account_db()?.upsert_group_local_membership_snapshot(
                &group.group_id,
                group.group_epoch,
                group.max_members,
                &group.new_member_history,
                &local_device_id,
                &group.local_role,
                group.local_joined_epoch,
            )?;
            for member in &group.members {
                self.account_db()?.upsert_group_member_snapshot(
                    &group.group_id,
                    &member.member_id,
                    &member.role,
                    member.joined_epoch,
                )?;
            }
            for route in &group.routes {
                self.persist_group_member_route(&group.group_id, route)?;
            }
            floor_by_group.insert(group.group_id.clone(), group.local_joined_epoch);
        }
        let mut imported_messages = 0_usize;
        let mut imported_dm_sessions = 0_usize;
        for session in &bundle.dm_sessions {
            self.persist_dm_session_snapshot(
                &session.conversation_id,
                &format!("own-device-sync:{}", bundle.snapshot_id),
                &session.direction,
                &session.snapshot,
            )?;
            imported_dm_sessions = imported_dm_sessions.saturating_add(1);
        }
        for message in &bundle.messages {
            if !Self::message_allowed_by_group_floor(message, &floor_by_group) {
                return Err(SdkError::LocalBus(
                    "own-device sync message below joined epoch".to_owned(),
                ));
            }
            self.account_db()?.import_direct_message_projection(DirectMessageWrite {
                conversation_id: &message.conversation_id,
                message_id: &message.message_id,
                sender_id: &message.sender_id,
                encrypted_body: &message.encrypted_body,
                metadata: &message.metadata,
                created_at: message.created_at,
            })?;
            imported_messages = imported_messages.saturating_add(1);
        }
        let mut imported_sender_keys = 0_usize;
        for distribution_base64 in &bundle.sender_key_distributions_base64 {
            let distribution =
                ramflux_protocol::decode_base64url(distribution_base64).map_err(|error| {
                    SdkError::LocalBus(format!("invalid own-device sender key: {error}"))
                })?;
            self.import_group_sender_key_distribution(&distribution)?;
            imported_sender_keys = imported_sender_keys.saturating_add(1);
        }
        Ok(SdkOwnDeviceSyncImportResponse {
            snapshot_id: bundle.snapshot_id.clone(),
            imported_messages,
            imported_dm_sessions,
            imported_groups: bundle.groups.len(),
            imported_sender_keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos =
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!("ramflux-sdk-own-device-sync-{test_name}-{nanos}"))
    }

    fn client_with_account(
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

    fn envelope(source_device_id: &str, target_device_id: &str) -> SdkOwnDeviceSyncEnvelope {
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
                key_slot: SdkObjectKeySlot {
                    schema: "ramflux.sdk.object_key_slot.dm.v1".to_owned(),
                    version: 1,
                    object_id: "object_sync".to_owned(),
                    conversation_id: "slot_sync".to_owned(),
                    recipient_device_id: target_device_id.to_owned(),
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

    fn bundle(
        source_device_id: &str,
        target_device_id: &str,
        messages: Vec<DirectMessageRecord>,
        groups: Vec<SdkOwnDeviceGroupSnapshot>,
    ) -> SdkOwnDeviceHistoryBundle {
        SdkOwnDeviceHistoryBundle {
            schema: "ramflux.sdk.own_device_history_bundle.v1".to_owned(),
            version: 1,
            principal_commitment: "principal_sync".to_owned(),
            source_device_id: source_device_id.to_owned(),
            target_device_id: target_device_id.to_owned(),
            snapshot_id: "snapshot_sync".to_owned(),
            messages,
            dm_sessions: Vec::new(),
            groups,
            sender_key_distributions_base64: Vec::new(),
        }
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
    fn own_device_history_import_rejects_group_message_below_joined_epoch() -> Result<(), SdkError>
    {
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
        let Err(error) = client.import_own_device_history_bundle(
            &envelope("source_device_sync", "target_device_sync"),
            &bundle(
                "source_device_sync",
                "target_device_sync",
                vec![old_group_message],
                vec![group],
            ),
        ) else {
            return Err(SdkError::LocalBus("old group message imported".to_owned()));
        };
        assert!(error.to_string().contains("below joined epoch"));
        assert!(client.direct_message_by_id("msg_sync_before_join")?.is_none());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

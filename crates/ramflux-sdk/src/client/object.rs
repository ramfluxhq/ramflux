// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

/// T21-A2a: the decrypted attachment key slot plus its advanced recv session, held so the caller can
/// commit the slot recv checkpoint only after the whole import (download, persist, plaintext verify,
/// ACK) has succeeded. No `Debug`/serialization is derived: the session holds secret key material.
pub(crate) struct DeferredObjectKeySlot {
    pub object_key: [u8; 32],
    session: ramflux_crypto::DmSession,
    conversation_id: String,
    commit_label: String,
}

impl RamfluxClient {
    fn persist_object_if_unlocked(
        &self,
        object: &EncryptedObject,
        content_key: Option<&[u8; 32]>,
    ) -> Result<(), SdkError> {
        let Some(db) = self.active_account_db.as_ref() else {
            return Ok(());
        };
        db.upsert_object(&ObjectWrite {
            object_id: &object.object_id,
            manifest_hash: &object.manifest_hash,
            nonce: &object.nonce,
            ciphertext: &object.ciphertext,
            plaintext_hash: &object.plaintext_hash,
            tombstoned: object.tombstoned,
            backup_excluded: object.backup_excluded,
            content_key,
            object,
            updated_at: now_unix_timestamp(),
        })?;
        Ok(())
    }

    pub(crate) fn hydrate_object_store_from_account_db(&mut self) -> Result<(), SdkError> {
        let (objects, object_keys) = self.account_db()?.load_objects::<EncryptedObject>()?;
        self.object_store.replace_persisted(objects, object_keys);
        Ok(())
    }

    pub async fn share_object_key_with_dm_recipient(
        &self,
        engine: &mut GatewaySessionEngine,
        request: LocalBusObjectShareRequest,
    ) -> Result<SdkObjectSharePackage, SdkError> {
        let object = self
            .object_store
            .objects()
            .into_iter()
            .find(|object| object.object_id == request.object_id)
            .ok_or(SyncError::ObjectNotFound)?;
        let object_key = self.object_store.object_key(&object.object_id)?;
        let recipient_device_id = request.recipient_device_id.clone().ok_or_else(|| {
            SdkError::LocalBus("object.share requires recipient_device_id".to_owned())
        })?;
        let sender_id = request.sender_id.clone().unwrap_or_else(|| {
            self.device_branch
                .as_ref()
                .map_or_else(|| "rf_object_sender".to_owned(), |branch| branch.device_id.clone())
        });
        let target_delivery_id = request.target_delivery_id.clone().ok_or_else(|| {
            SdkError::LocalBus("object.share requires target_delivery_id".to_owned())
        })?;
        let message = GatewayDirectMessage {
            conversation_id: request.conversation_id.clone(),
            message_id: format!("object.slot:{}:{recipient_device_id}", object.object_id),
            envelope_id: format!("object.slot:{}:{recipient_device_id}", object.object_id),
            source_principal_id: sender_id.clone(),
            sender_id,
            recipient_device_id: Some(recipient_device_id.clone()),
            target_delivery_id,
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: 3_600,
        };
        let (mut session, x3dh) = self.load_or_create_send_dm_session(engine, &message).await?;
        let associated_data = object_key_slot_associated_data(
            &object.object_id,
            &request.conversation_id,
            &recipient_device_id,
        );
        let ciphertext = session.encrypt(&object_key, &associated_data)?;
        self.persist_dm_session(
            &request.conversation_id,
            &format!("object-slot:{}", object.object_id),
            "send",
            &session,
        )?;
        Ok(SdkObjectSharePackage {
            schema: "ramflux.sdk.object_share_package.v1".to_owned(),
            version: 1,
            ciphertext_base64: ramflux_protocol::encode_base64url(&object.ciphertext),
            key_slot: SdkObjectKeySlot {
                schema: "ramflux.sdk.object_key_slot.dm.v1".to_owned(),
                version: 1,
                object_id: object.object_id.clone(),
                conversation_id: request.conversation_id,
                recipient_device_id,
                x3dh,
                ciphertext,
            },
            object,
        })
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) async fn dm_attachment_ref_for_recipient(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        message: &GatewayDirectMessage,
        attachment: &LocalBusMessageAttachmentInput,
        plaintext: &[u8],
    ) -> Result<SdkDmAttachmentRef, SdkError> {
        let relay_options = parse_relay_transfer_options(
            Some(attachment.relay_endpoint.clone()),
            attachment.relay_service_key_base64.clone(),
            None,
        )?
        .ok_or_else(|| SdkError::LocalBus("DM attachment requires relay endpoint".to_owned()))?;
        let object = self.object_store.put_encrypted_object(&attachment.object_id, plaintext)?;
        let object_key = self.object_store.object_key(&object.object_id)?;
        self.persist_object_if_unlocked(&object, Some(&object_key))?;
        self.upload_object_to_relay_inner_via_gateway(
            engine,
            pool,
            &object,
            attachment.chunk_size,
            &relay_options,
        )
        .await?;
        let recipient_device_id = message.recipient_device_id.clone().ok_or_else(|| {
            SdkError::LocalBus("DM attachment requires recipient_device_id".to_owned())
        })?;
        let slot_conversation_id = dm_attachment_slot_conversation_id(
            &message.conversation_id,
            &object.object_id,
            &recipient_device_id,
        );
        let slot_message = GatewayDirectMessage {
            conversation_id: slot_conversation_id.clone(),
            message_id: format!("attachment.slot:{}", object.object_id),
            envelope_id: format!("attachment.slot:{}", object.object_id),
            source_principal_id: message.source_principal_id.clone(),
            sender_id: message.sender_id.clone(),
            recipient_device_id: Some(recipient_device_id.clone()),
            target_delivery_id: message.target_delivery_id.clone(),
            encrypted_body: Vec::new(),
            created_at: message.created_at,
            ttl: message.ttl,
        };
        let (mut session, x3dh) =
            self.load_or_create_send_dm_session(engine, &slot_message).await?;
        let associated_data = object_key_slot_associated_data(
            &object.object_id,
            &slot_conversation_id,
            &recipient_device_id,
        );
        let ciphertext = session.encrypt(&object_key, &associated_data)?;
        self.persist_dm_session(
            &slot_conversation_id,
            &format!("attachment-slot:{}", object.object_id),
            "send",
            &session,
        )?;
        let manifest = chunk_manifest_for_object(
            &object.object_id,
            &object.ciphertext,
            attachment.chunk_size,
            None,
        );
        let owner_branch = self.device_branch.as_ref().ok_or_else(|| {
            SdkError::LocalBus("object relay requires an owner device branch".to_owned())
        })?;
        let access_grant = build_signed_object_access_grant(
            owner_branch,
            object.object_id.clone(),
            object.manifest_hash.clone(),
            ramflux_crypto::blake3_256_base64url(
                "ramflux.object_relay.recipient_device.v1",
                recipient_device_id.as_bytes(),
            ),
            vec![
                ramflux_protocol::ObjectRelayCapability::Get,
                ramflux_protocol::ObjectRelayCapability::Ack,
            ],
            u64::try_from(now_unix_timestamp()).unwrap_or(0),
            relay_expires_at(),
        )?;
        Ok(SdkDmAttachmentRef {
            schema: "ramflux.sdk.dm_attachment_ref.v1".to_owned(),
            version: 1,
            object_id: object.object_id.clone(),
            manifest_hash: object.manifest_hash.clone(),
            plaintext_hash: object.plaintext_hash.clone(),
            cipher_size: u64::try_from(object.ciphertext.len()).unwrap_or(u64::MAX),
            chunk_size: manifest.chunk_size,
            total_chunks: manifest.total_chunks,
            relay_endpoint: attachment.relay_endpoint.clone(),
            // T21-A2: explicit per-message override wins; a None input is fixed to the lineage this
            // upload actually used (effective relay options); an explicit empty string is preserved
            // and fails closed downstream. See `effective_attachment_lineage`.
            owner_home_node_id: effective_attachment_lineage(
                attachment.owner_home_node_id.clone(),
                relay_options.relay_owner_home_node_id.clone(),
            ),
            relay_audience_node_id: effective_attachment_lineage(
                attachment.relay_audience_node_id.clone(),
                relay_options.relay_audience_node_id.clone(),
            ),
            owner_principal_id: owner_branch.principal_id.clone(),
            owner_device_epoch: owner_branch.device_epoch,
            access_grant: Some(access_grant),
            key_slot: SdkObjectKeySlot {
                schema: "ramflux.sdk.object_key_slot.dm.v1".to_owned(),
                version: 1,
                object_id: object.object_id,
                conversation_id: slot_conversation_id,
                recipient_device_id,
                x3dh,
                ciphertext,
            },
        })
    }

    /// # Errors
    /// Returns an error when the key slot cannot be decrypted or the object cannot be imported.
    pub fn import_shared_object(
        &mut self,
        package: &SdkObjectSharePackage,
    ) -> Result<EncryptedObject, SdkError> {
        if package.schema != "ramflux.sdk.object_share_package.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported object share package schema: {}",
                package.schema
            )));
        }
        if package.key_slot.schema != "ramflux.sdk.object_key_slot.dm.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported object key slot schema: {}",
                package.key_slot.schema
            )));
        }
        let mut session = self.load_or_create_recv_dm_session(
            &package.key_slot.conversation_id,
            package.key_slot.x3dh.as_ref(),
        )?;
        let associated_data = object_key_slot_associated_data(
            &package.key_slot.object_id,
            &package.key_slot.conversation_id,
            &package.key_slot.recipient_device_id,
        );
        let plaintext_key = session.decrypt(&package.key_slot.ciphertext, &associated_data)?;
        let object_key: [u8; 32] = plaintext_key
            .try_into()
            .map_err(|_err| SdkError::LocalBus("invalid object key length".to_owned()))?;
        self.persist_dm_session(
            &package.key_slot.conversation_id,
            &format!("object-slot:{}", package.object.object_id),
            "recv",
            &session,
        )?;
        let ciphertext = ramflux_protocol::decode_base64url(&package.ciphertext_base64)
            .map_err(|error| SdkError::LocalBus(format!("invalid object ciphertext: {error}")))?;
        let object = self.object_store.put_received_encrypted_object_with_key(
            &package.object.object_id,
            &package.object.manifest_hash,
            &ciphertext,
            &package.object.plaintext_hash,
            object_key,
        );
        self.persist_object_if_unlocked(&object, Some(&object_key))?;
        Ok(object)
    }

    /// Decrypts the attachment key slot, returning the object key and the advanced slot recv session
    /// as a deferred commit. T21-A2a: the slot recv checkpoint is intentionally NOT persisted here.
    /// The caller commits it (via `commit_object_key_slot_session`) only after the object/transfer
    /// are durable and every ACK has succeeded, so a failed import leaves the persisted slot ratchet
    /// snapshot unchanged and the slot ciphertext can be re-decrypted on a retry.
    pub(crate) fn decrypt_object_key_slot(
        &self,
        key_slot: &SdkObjectKeySlot,
    ) -> Result<DeferredObjectKeySlot, SdkError> {
        if key_slot.schema != "ramflux.sdk.object_key_slot.dm.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported object key slot schema: {}",
                key_slot.schema
            )));
        }
        let mut session =
            self.load_or_create_recv_dm_session(&key_slot.conversation_id, key_slot.x3dh.as_ref())?;
        let associated_data = object_key_slot_associated_data(
            &key_slot.object_id,
            &key_slot.conversation_id,
            &key_slot.recipient_device_id,
        );
        let plaintext_key = session.decrypt(&key_slot.ciphertext, &associated_data)?;
        let object_key: [u8; 32] = plaintext_key
            .try_into()
            .map_err(|_err| SdkError::LocalBus("invalid object key length".to_owned()))?;
        Ok(DeferredObjectKeySlot {
            object_key,
            session,
            conversation_id: key_slot.conversation_id.clone(),
            commit_label: format!("object-slot:{}", key_slot.object_id),
        })
    }

    /// Commits the advanced attachment key-slot recv session. T21-A2a: only called once the whole
    /// attachment import (download, persist, plaintext verification, and every ACK) has succeeded.
    pub(crate) fn commit_object_key_slot_session(
        &mut self,
        deferred: &DeferredObjectKeySlot,
    ) -> Result<(), SdkError> {
        self.persist_dm_session(
            &deferred.conversation_id,
            &deferred.commit_label,
            "recv",
            &deferred.session,
        )
    }

    #[cfg(feature = "itest-local-mint")]
    #[allow(dead_code)]
    pub(crate) fn import_dm_attachment_from_relay(
        &mut self,
        attachment: &SdkDmAttachmentRef,
        relay_service_key_base64: Option<String>,
    ) -> Result<SdkDmAttachmentImportResult, SdkError> {
        if attachment.schema != "ramflux.sdk.dm_attachment_ref.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported DM attachment ref schema: {}",
                attachment.schema
            )));
        }
        let key_slot = self.decrypt_object_key_slot(&attachment.key_slot)?;
        let object_key = key_slot.object_key;
        let download = self.download_dm_attachment_ciphertext(
            attachment,
            object_key,
            relay_service_key_base64,
        )?;
        let ciphertext = download.ciphertext;
        let assembled_hash = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::OBJECT_MANIFEST,
            &ciphertext,
        );
        if assembled_hash != attachment.manifest_hash {
            return Err(SdkError::LocalBus("DM attachment manifest hash mismatch".to_owned()));
        }
        let object = self.object_store.put_received_encrypted_object_with_key(
            &attachment.object_id,
            &attachment.manifest_hash,
            &ciphertext,
            &attachment.plaintext_hash,
            object_key,
        );
        self.persist_object_if_unlocked(&object, Some(&object_key))?;
        self.persist_object_transfer(ObjectTransferPersist {
            transfer_id: &download.transfer_id,
            object: &object,
            direction: OBJECT_TRANSFER_DOWNLOAD,
            relay_endpoint: Some(&download.relay_endpoint),
            chunk_size: download.manifest.chunk_size,
            total_chunks: download.manifest.total_chunks,
            completed: &download.completed,
            done_bytes: u64::try_from(object.ciphertext.len()).unwrap_or(u64::MAX),
            state: "complete",
            last_error: None,
            resume_token: None,
            expires_at: Some(i64::try_from(download.expires_at).unwrap_or(i64::MAX)),
        })?;
        let plaintext = self.decrypt_object(&attachment.object_id)?;
        let plaintext_hash =
            ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &plaintext);
        if plaintext_hash != attachment.plaintext_hash {
            return Err(SdkError::LocalBus("DM attachment plaintext hash mismatch".to_owned()));
        }
        // T21-A2a: the object is durable and verified; only now commit the slot recv checkpoint.
        self.commit_object_key_slot_session(&key_slot)?;
        Ok(SdkDmAttachmentImportResult {
            object_id: attachment.object_id.clone(),
            manifest_hash: attachment.manifest_hash.clone(),
            plaintext_base64: ramflux_protocol::encode_base64url(&plaintext),
            plaintext_hash,
            imported: true,
        })
    }

    pub(crate) async fn import_dm_attachment_from_relay_via_gateway(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        attachment: &SdkDmAttachmentRef,
        relay_service_key_base64: Option<String>,
    ) -> Result<SdkDmAttachmentImportResult, SdkError> {
        if attachment.schema != "ramflux.sdk.dm_attachment_ref.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported DM attachment ref schema: {}",
                attachment.schema
            )));
        }
        let key_slot = self.decrypt_object_key_slot(&attachment.key_slot)?;
        let object_key = key_slot.object_key;
        let download = self
            .download_dm_attachment_ciphertext_via_gateway(
                engine,
                pool,
                attachment,
                object_key,
                relay_service_key_base64.clone(),
            )
            .await?;
        let ciphertext = download.ciphertext;
        let assembled_hash = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::OBJECT_MANIFEST,
            &ciphertext,
        );
        if assembled_hash != attachment.manifest_hash {
            return Err(SdkError::LocalBus("DM attachment manifest hash mismatch".to_owned()));
        }
        let object = self.object_store.put_received_encrypted_object_with_key(
            &attachment.object_id,
            &attachment.manifest_hash,
            &ciphertext,
            &attachment.plaintext_hash,
            object_key,
        );
        self.persist_object_if_unlocked(&object, Some(&object_key))?;
        self.persist_object_transfer(ObjectTransferPersist {
            transfer_id: &download.transfer_id,
            object: &object,
            direction: OBJECT_TRANSFER_DOWNLOAD,
            relay_endpoint: Some(&download.relay_endpoint),
            chunk_size: download.manifest.chunk_size,
            total_chunks: download.manifest.total_chunks,
            completed: &download.completed,
            done_bytes: u64::try_from(object.ciphertext.len()).unwrap_or(u64::MAX),
            state: "complete",
            last_error: None,
            resume_token: None,
            expires_at: Some(i64::try_from(download.expires_at).unwrap_or(i64::MAX)),
        })?;
        let plaintext = self.decrypt_object(&attachment.object_id)?;
        let plaintext_hash =
            ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &plaintext);
        if plaintext_hash != attachment.plaintext_hash {
            return Err(SdkError::LocalBus("DM attachment plaintext hash mismatch".to_owned()));
        }
        // T21-A2: the encrypted object + key + transfer state are now durably persisted and the
        // plaintext hash verified. Only now — and only when a durable account store actually holds
        // the object — do we ACK each chunk, so a crash can never leave a relay chunk acked while
        // the grantee holds the object only in memory. ACK reuses the received A-signed grant (B
        // signs only its own PoP) and requires Ack capability; a Get-only grant imports without
        // acking. Relay ACK is idempotent, so a retried import safely re-acks the persisted object.
        let grant_authorizes_ack = attachment.access_grant.as_ref().is_some_and(|grant| {
            grant.capabilities.contains(&ramflux_protocol::ObjectRelayCapability::Ack)
        });
        if self.active_account_db.is_some() && grant_authorizes_ack {
            let ack_options = parse_relay_transfer_options(
                Some(attachment.relay_endpoint.clone()),
                relay_service_key_base64,
                None,
            )?
            .ok_or_else(|| SdkError::LocalBus("DM attachment relay options missing".to_owned()))?;
            if matches!(ack_options.token_provider, RelayTokenProvider::GatewayIssued) {
                let branch = self
                    .device_branch
                    .as_ref()
                    .ok_or_else(|| {
                        SdkError::LocalBus("object relay requires a device branch".to_owned())
                    })?
                    .clone();
                let ack_ctx = DmAttachmentFetch {
                    options: &ack_options,
                    branch: &branch,
                    attachment: Some(attachment),
                    object: &object,
                    manifest: &download.manifest,
                    object_key,
                    expires_at: download.expires_at,
                };
                for chunk_index in 0..download.manifest.total_chunks {
                    ack_dm_attachment_chunk_via_relay_quic(engine, pool, &ack_ctx, chunk_index)
                        .await?;
                }
            }
        }
        // T21-A2a: every chunk was downloaded, persisted, plaintext-verified, and ACKed; only now
        // commit the slot recv checkpoint so a failed ACK above leaves the slot ratchet re-usable.
        self.commit_object_key_slot_session(&key_slot)?;
        Ok(SdkDmAttachmentImportResult {
            object_id: attachment.object_id.clone(),
            manifest_hash: attachment.manifest_hash.clone(),
            plaintext_base64: ramflux_protocol::encode_base64url(&plaintext),
            plaintext_hash,
            imported: true,
        })
    }

    #[cfg(feature = "itest-local-mint")]
    #[allow(dead_code)]
    fn download_dm_attachment_ciphertext(
        &self,
        attachment: &SdkDmAttachmentRef,
        object_key: [u8; 32],
        relay_service_key_base64: Option<String>,
    ) -> Result<DmAttachmentDownload, SdkError> {
        let options = parse_relay_transfer_options(
            Some(attachment.relay_endpoint.clone()),
            relay_service_key_base64,
            None,
        )?
        .ok_or_else(|| SdkError::LocalBus("DM attachment relay options missing".to_owned()))?;
        let branch = self
            .device_branch
            .as_ref()
            .ok_or_else(|| SdkError::LocalBus("object relay requires a device branch".to_owned()))?
            .clone();
        verify_recipient_object_access_grant(
            attachment.access_grant.as_ref(),
            &branch,
            &attachment.object_id,
            &attachment.manifest_hash,
            u64::try_from(now_unix_timestamp()).unwrap_or(0),
        )?;
        let manifest = ChunkManifest {
            object_id: attachment.object_id.clone(),
            manifest_hash: attachment.manifest_hash.clone(),
            chunk_size: attachment.chunk_size.max(1),
            total_chunks: attachment.total_chunks,
            object_created_group_key_epoch: None,
        };
        let object_stub = dm_attachment_object_stub(attachment);
        let mut session = ObjectSyncSession::new(manifest.clone(), object_key);
        let expires_at = relay_expires_at();
        let transfer_id = object_transfer_id(
            &attachment.object_id,
            &attachment.manifest_hash,
            OBJECT_TRANSFER_DOWNLOAD,
        );
        let mut completed = Vec::new();
        let mut done_bytes = 0_u64;
        for chunk_index in 0..manifest.total_chunks {
            let plaintext_chunk = fetch_dm_attachment_chunk(
                &DmAttachmentFetch {
                    options: &options,
                    branch: &branch,
                    attachment: Some(attachment),
                    object: &object_stub,
                    manifest: &manifest,
                    object_key,
                    expires_at,
                },
                chunk_index,
            )?;
            session.receive_chunk(plaintext_chunk.payload, &branch)?;
            completed.push(chunk_index);
            completed.sort_unstable();
            completed.dedup();
            done_bytes = done_bytes.saturating_add(plaintext_chunk.len);
            self.persist_object_transfer(ObjectTransferPersist {
                transfer_id: &transfer_id,
                object: &object_stub,
                direction: OBJECT_TRANSFER_DOWNLOAD,
                relay_endpoint: Some(&options.relay_endpoint),
                chunk_size: manifest.chunk_size,
                total_chunks: manifest.total_chunks,
                completed: &completed,
                done_bytes,
                state: "running",
                last_error: None,
                resume_token: None,
                expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
            })?;
        }
        Ok(DmAttachmentDownload {
            ciphertext: session.assemble()?,
            manifest,
            transfer_id,
            relay_endpoint: options.relay_endpoint,
            completed,
            expires_at,
        })
    }

    async fn download_dm_attachment_ciphertext_via_gateway(
        &self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        attachment: &SdkDmAttachmentRef,
        object_key: [u8; 32],
        relay_service_key_base64: Option<String>,
    ) -> Result<DmAttachmentDownload, SdkError> {
        let options = parse_relay_transfer_options(
            Some(attachment.relay_endpoint.clone()),
            relay_service_key_base64,
            None,
        )?
        .ok_or_else(|| SdkError::LocalBus("DM attachment relay options missing".to_owned()))?;
        let branch = self
            .device_branch
            .as_ref()
            .ok_or_else(|| SdkError::LocalBus("object relay requires a device branch".to_owned()))?
            .clone();
        verify_recipient_object_access_grant(
            attachment.access_grant.as_ref(),
            &branch,
            &attachment.object_id,
            &attachment.manifest_hash,
            u64::try_from(now_unix_timestamp()).unwrap_or(0),
        )?;
        let manifest = ChunkManifest {
            object_id: attachment.object_id.clone(),
            manifest_hash: attachment.manifest_hash.clone(),
            chunk_size: attachment.chunk_size.max(1),
            total_chunks: attachment.total_chunks,
            object_created_group_key_epoch: None,
        };
        let object_stub = dm_attachment_object_stub(attachment);
        let mut session = ObjectSyncSession::new(manifest.clone(), object_key);
        let expires_at = relay_expires_at();
        let transfer_id = object_transfer_id(
            &attachment.object_id,
            &attachment.manifest_hash,
            OBJECT_TRANSFER_DOWNLOAD,
        );
        let mut completed = Vec::new();
        let mut done_bytes = 0_u64;
        for chunk_index in 0..manifest.total_chunks {
            let plaintext_chunk = fetch_dm_attachment_chunk_via_gateway(
                engine,
                pool,
                &DmAttachmentFetch {
                    options: &options,
                    branch: &branch,
                    attachment: Some(attachment),
                    object: &object_stub,
                    manifest: &manifest,
                    object_key,
                    expires_at,
                },
                chunk_index,
            )
            .await?;
            session.receive_chunk(plaintext_chunk.payload, &branch)?;
            completed.push(chunk_index);
            completed.sort_unstable();
            completed.dedup();
            done_bytes = done_bytes.saturating_add(plaintext_chunk.len);
            self.persist_object_transfer(ObjectTransferPersist {
                transfer_id: &transfer_id,
                object: &object_stub,
                direction: OBJECT_TRANSFER_DOWNLOAD,
                relay_endpoint: Some(&options.relay_endpoint),
                chunk_size: manifest.chunk_size,
                total_chunks: manifest.total_chunks,
                completed: &completed,
                done_bytes,
                state: "running",
                last_error: None,
                resume_token: None,
                expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
            })?;
        }
        Ok(DmAttachmentDownload {
            ciphertext: session.assemble()?,
            manifest,
            transfer_id,
            relay_endpoint: options.relay_endpoint,
            completed,
            expires_at,
        })
    }

    /// # Errors
    /// Returns an error when the OS CSPRNG cannot generate an object key.
    pub fn put_encrypted_object(
        &mut self,
        object_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedObject, SdkError> {
        let object = self.object_store.put_encrypted_object(object_id, plaintext)?;
        let object_key = self.object_store.object_key(&object.object_id)?;
        self.persist_object_if_unlocked(&object, Some(&object_key))?;
        Ok(object)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn decrypt_object(&self, object_id: &str) -> Result<Vec<u8>, SdkError> {
        Ok(self.object_store.decrypt_object(object_id)?)
    }

    /// # Errors
    /// Returns an error when the object does not exist or cannot be tombstoned.
    pub fn tombstone_object(&mut self, object_id: &str) -> Result<(), SdkError> {
        self.object_store.tombstone(object_id)?;
        if let Some(db) = self.active_account_db.as_ref() {
            db.set_object_tombstoned(object_id)?;
        }
        Ok(())
    }

    /// Tombstones the local object only after the owner-session v3 relay mutation succeeds.
    ///
    /// # Errors
    /// Returns an error when v3 relay configuration, owner lineage, signing, transport, or relay
    /// authorization is incomplete. The local object remains live when the remote mutation fails.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn tombstone_object_to_relay_via_gateway(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        object_id: &str,
        options: &RelayTransferOptions,
    ) -> Result<(), SdkError> {
        if !matches!(options.token_provider, RelayTokenProvider::GatewayIssued)
            || relay_quic_config(options)?.is_none()
        {
            return Err(SdkError::CapabilityDenied(
                "v3 relay tombstone requires gateway-issued QUIC configuration".to_owned(),
            ));
        }
        let object = self
            .object_store
            .objects()
            .into_iter()
            .find(|object| object.object_id == object_id)
            .ok_or(SyncError::ObjectNotFound)?;
        let branch = self
            .device_branch
            .as_ref()
            .ok_or_else(|| SdkError::LocalBus("object relay requires a device branch".to_owned()))?
            .clone();
        let owner_home_node_id = options.relay_owner_home_node_id.as_deref().ok_or_else(|| {
            SdkError::CapabilityDenied(
                "v3 tombstone requires RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(),
            )
        })?;
        let owner_principal_id = options.relay_owner_principal_id.as_deref().ok_or_else(|| {
            SdkError::CapabilityDenied(
                "v3 tombstone requires RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(),
            )
        })?;
        let audience_node_id = options.relay_audience_node_id.as_deref().ok_or_else(|| {
            SdkError::CapabilityDenied(
                "v3 tombstone requires RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(),
            )
        })?;
        let issued_at = u64::try_from(now_unix_timestamp()).unwrap_or(0);
        let expires_at = issued_at.saturating_add(120);
        let signed_at = issued_at;
        let source_event_id = format!("object-tombstone:{object_id}:{issued_at}");
        let tombstone_descriptor = serde_json::json!({
            "expires_at": expires_at,
            "manifest_hash": object.manifest_hash,
            "object_id": object.object_id,
            "signed_at": signed_at,
            "source_event_id": source_event_id,
        });
        let tombstone_hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.tombstone.v3",
            &ramflux_protocol::canonical_json_bytes(&tombstone_descriptor)?,
        );
        let chunk_id =
            format!("object-relay:{}:{}:tombstone", object.object_id, object.manifest_hash);
        let nonce = format!("sdk-tombstone-{issued_at}");
        let owner_proof = build_signed_owner_authorization_proof(
            &branch,
            ramflux_protocol::ObjectRelayCapability::Tombstone,
            object.object_id.clone(),
            Some(object.manifest_hash.clone()),
            None,
            owner_home_node_id.to_owned(),
            owner_principal_id.to_owned(),
            branch.device_epoch,
            nonce.clone(),
            tombstone_hash.clone(),
            issued_at,
            expires_at,
        )?;
        let authorization_binding_hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.owner_authorization_proof.binding.v3",
            &ramflux_protocol::canonical_json_bytes(&owner_proof)?,
        );
        let issue_body = build_v3_owner_session_token_issue_body(
            &branch,
            &object,
            &chunk_id,
            ramflux_protocol::ObjectRelayCapability::Tombstone,
            owner_home_node_id,
            audience_node_id,
            owner_principal_id,
            &authorization_binding_hash,
            issued_at,
            expires_at,
            &nonce,
        )?;
        let token = engine.issue_relay_token_v3(issue_body).await?;
        let pop = build_signed_requester_pop(
            &branch,
            token.token_id.clone(),
            ramflux_protocol::ObjectRelayCapability::Tombstone,
            token.object_id.clone(),
            token.manifest_hash.clone(),
            token.chunk_id.clone(),
            format!("sdk-pop-{issued_at}"),
            tombstone_hash.clone(),
            issued_at,
            expires_at,
        )?;
        let certificate = token.issuer_certificate.clone();
        let body = serde_json::json!({
            "token": token,
            "certificate": certificate,
            "owner_proof": owner_proof,
            "pop": pop,
            "body_hash": tombstone_hash.clone(),
            "capability": "tombstone",
            "tombstone_hash": tombstone_hash,
            "source_event_id": source_event_id,
            "signed_at": signed_at,
            "expires_at": expires_at,
        });
        relay_quic_success_body(
            relay_quic_request(pool, options, "/relay/v1/object/tombstone", body).await?,
        )?;
        self.tombstone_object(object_id)
    }

    pub(crate) fn object_transfer_status(
        &self,
        object_id: &str,
        direction: Option<&str>,
    ) -> Result<Option<SdkObjectTransferStatus>, SdkError> {
        Ok(self.account_db()?.object_transfer(object_id, direction)?.map(object_transfer_status))
    }

    #[cfg(feature = "itest-local-mint")]
    pub(crate) fn upload_object_to_relay(
        &self,
        object_id: &str,
        chunk_size: usize,
        options: &RelayTransferOptions,
    ) -> Result<SdkObjectTransferStatus, SdkError> {
        let object = self
            .object_store
            .objects()
            .into_iter()
            .find(|object| object.object_id == object_id)
            .ok_or(SyncError::ObjectNotFound)?;
        self.upload_object_to_relay_inner(&object, chunk_size, options)
    }

    pub(crate) async fn upload_object_to_relay_via_gateway(
        &self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        object_id: &str,
        chunk_size: usize,
        options: &RelayTransferOptions,
    ) -> Result<SdkObjectTransferStatus, SdkError> {
        let object = self
            .object_store
            .objects()
            .into_iter()
            .find(|object| object.object_id == object_id)
            .ok_or(SyncError::ObjectNotFound)?;
        self.upload_object_to_relay_inner_via_gateway(engine, pool, &object, chunk_size, options)
            .await
    }

    #[allow(clippy::too_many_lines)]
    #[cfg(feature = "itest-local-mint")]
    pub(crate) fn download_object_from_relay(
        &mut self,
        object_id: &str,
        options: &RelayTransferOptions,
        ack: bool,
    ) -> Result<Vec<u8>, SdkError> {
        let object = self
            .object_store
            .objects()
            .into_iter()
            .find(|object| object.object_id == object_id)
            .ok_or(SyncError::ObjectNotFound)?;
        let object_key = self.object_store.object_key(&object.object_id)?;
        let branch = self
            .device_branch
            .as_ref()
            .ok_or_else(|| SdkError::LocalBus("object relay requires a device branch".to_owned()))?
            .clone();
        let chunk_size = self
            .account_db()?
            .object_transfer(object_id, Some(OBJECT_TRANSFER_UPLOAD))?
            .map_or(64 * 1024, |record| usize::try_from(record.chunk_size).unwrap_or(64 * 1024))
            .max(1);
        let manifest =
            chunk_manifest_for_object(&object.object_id, &object.ciphertext, chunk_size, None);
        let transfer_id =
            object_transfer_id(&object.object_id, &object.manifest_hash, OBJECT_TRANSFER_DOWNLOAD);
        let mut completed = self
            .account_db()?
            .object_transfer(&object.object_id, Some(OBJECT_TRANSFER_DOWNLOAD))?
            .map_or_else(Vec::new, |record| record.completed_chunks);
        let mut chunks: Vec<Option<Vec<u8>>> =
            vec![None; usize::try_from(manifest.total_chunks).unwrap_or(0)];
        let mut done_bytes = 0_u64;
        for chunk_index in completed.iter().copied() {
            if let Some(slice) = ciphertext_slice(&object.ciphertext, chunk_size, chunk_index) {
                done_bytes = done_bytes.saturating_add(u64::try_from(slice.len()).unwrap_or(0));
            }
        }
        let expires_at = relay_expires_at();
        let mut transferred = 0_u32;
        for chunk_index in 0..manifest.total_chunks {
            if completed.contains(&chunk_index) {
                if let Some(slice) = ciphertext_slice(&object.ciphertext, chunk_size, chunk_index) {
                    let slot = usize::try_from(chunk_index).unwrap_or(0);
                    if let Some(entry) = chunks.get_mut(slot) {
                        *entry = Some(slice.to_vec());
                    }
                }
                continue;
            }
            if options.interrupt_after_chunks.is_some_and(|limit| transferred >= limit) {
                self.persist_object_transfer(ObjectTransferPersist {
                    transfer_id: &transfer_id,
                    object: &object,
                    direction: OBJECT_TRANSFER_DOWNLOAD,
                    relay_endpoint: Some(&options.relay_endpoint),
                    chunk_size,
                    total_chunks: manifest.total_chunks,
                    completed: &completed,
                    done_bytes,
                    state: "paused",
                    last_error: None,
                    resume_token: None,
                    expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
                })?;
                return Err(SdkError::LocalBus("object relay download interrupted".to_owned()));
            }
            let token = local_relay_token_for_chunk(
                options,
                &branch,
                &object,
                chunk_index,
                SdkObjectRelayCapability::Get,
                expires_at,
            )?;
            let permission = object_permission_for_chunk(
                &branch,
                &object,
                chunk_index,
                SdkObjectRelayCapability::Get,
                expires_at,
            )?;
            let request = SdkObjectRelayGetRequest {
                chunk_id: token.chunk_id.clone(),
                relay_token: token,
                object_permission_envelope: permission,
            };
            let response: SdkObjectRelayGetResponse =
                relay_post_json(&options.relay_endpoint, "/relay/v1/object/get_chunk", &request)?;
            let expected_hash = object_relay_chunk_cipher_hash(
                &object.manifest_hash,
                chunk_index,
                &response.chunk.encrypted_chunk,
            );
            if response.chunk.chunk_cipher_hash != expected_hash {
                return Err(SdkError::LocalBus("object relay chunk hash mismatch".to_owned()));
            }
            let payload: ChunkPayload = serde_json::from_slice(&response.chunk.encrypted_chunk)?;
            let plaintext_chunk = decrypt_chunk_payload(&object_key, &manifest, &payload)?;
            let slot = usize::try_from(chunk_index).unwrap_or(0);
            if let Some(entry) = chunks.get_mut(slot) {
                *entry = Some(plaintext_chunk.clone());
            }
            done_bytes =
                done_bytes.saturating_add(u64::try_from(plaintext_chunk.len()).unwrap_or(0));
            completed.push(chunk_index);
            completed.sort_unstable();
            completed.dedup();
            transferred = transferred.saturating_add(1);
            self.persist_object_transfer(ObjectTransferPersist {
                transfer_id: &transfer_id,
                object: &object,
                direction: OBJECT_TRANSFER_DOWNLOAD,
                relay_endpoint: Some(&options.relay_endpoint),
                chunk_size,
                total_chunks: manifest.total_chunks,
                completed: &completed,
                done_bytes,
                state: "running",
                last_error: None,
                resume_token: None,
                expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
            })?;
            if ack {
                let ack_token = local_relay_token_for_chunk(
                    options,
                    &branch,
                    &object,
                    chunk_index,
                    SdkObjectRelayCapability::Ack,
                    expires_at,
                )?;
                let ack_permission = object_permission_for_chunk(
                    &branch,
                    &object,
                    chunk_index,
                    SdkObjectRelayCapability::Ack,
                    expires_at,
                )?;
                let ack = SdkObjectRelayAck {
                    object_id: object.object_id.clone(),
                    manifest_hash: object.manifest_hash.clone(),
                    chunk_id: ack_token.chunk_id.clone(),
                    recipient_device_hash: ack_token.recipient_device_hash.clone(),
                    relay_token: ack_token,
                    object_permission_envelope: ack_permission,
                    acked_at: u64::try_from(now_unix_timestamp()).unwrap_or(0),
                };
                let _response: SdkObjectRelayAckResponse =
                    relay_post_json(&options.relay_endpoint, "/relay/v1/object/ack", &ack)?;
            }
        }
        let assembled = chunks
            .into_iter()
            .map(|chunk| {
                chunk.ok_or_else(|| {
                    SdkError::LocalBus("object relay download incomplete".to_owned())
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .concat();
        if assembled != object.ciphertext {
            return Err(SdkError::LocalBus(
                "object relay assembled ciphertext mismatch".to_owned(),
            ));
        }
        self.persist_object_transfer(ObjectTransferPersist {
            transfer_id: &transfer_id,
            object: &object,
            direction: OBJECT_TRANSFER_DOWNLOAD,
            relay_endpoint: Some(&options.relay_endpoint),
            chunk_size,
            total_chunks: manifest.total_chunks,
            completed: &completed,
            done_bytes: u64::try_from(object.ciphertext.len()).unwrap_or(u64::MAX),
            state: "complete",
            last_error: None,
            resume_token: None,
            expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
        })?;
        self.decrypt_object(object_id)
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) async fn download_object_from_relay_via_gateway(
        &mut self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        object_id: &str,
        options: &RelayTransferOptions,
        ack: bool,
    ) -> Result<Vec<u8>, SdkError> {
        let branch = self
            .device_branch
            .as_ref()
            .ok_or_else(|| SdkError::LocalBus("object relay requires a device branch".to_owned()))?
            .clone();
        let object = self
            .object_store
            .objects()
            .into_iter()
            .find(|object| object.object_id == object_id)
            .ok_or(SyncError::ObjectNotFound)?;
        let object_key = self.object_store.object_key(object_id)?;
        let chunk_size = self
            .account_db()?
            .object_transfer(object_id, Some(OBJECT_TRANSFER_UPLOAD))?
            .map_or(64 * 1024, |record| usize::try_from(record.chunk_size).unwrap_or(64 * 1024))
            .max(1);
        let manifest =
            chunk_manifest_for_object(&object.object_id, &object.ciphertext, chunk_size, None);
        let transfer_id =
            object_transfer_id(&object.object_id, &object.manifest_hash, OBJECT_TRANSFER_DOWNLOAD);
        let mut completed = self
            .account_db()?
            .object_transfer(&object.object_id, Some(OBJECT_TRANSFER_DOWNLOAD))?
            .map_or_else(Vec::new, |record| record.completed_chunks);
        let mut chunks: Vec<Option<Vec<u8>>> =
            vec![None; usize::try_from(manifest.total_chunks).unwrap_or(0)];
        let mut done_bytes = 0_u64;
        for chunk_index in completed.iter().copied() {
            if let Some(slice) = ciphertext_slice(&object.ciphertext, chunk_size, chunk_index) {
                done_bytes = done_bytes.saturating_add(u64::try_from(slice.len()).unwrap_or(0));
            }
        }
        let expires_at = relay_expires_at();
        let mut transferred = 0_u32;
        for chunk_index in 0..manifest.total_chunks {
            if completed.contains(&chunk_index) {
                if let Some(slice) = ciphertext_slice(&object.ciphertext, chunk_size, chunk_index) {
                    let slot = usize::try_from(chunk_index).unwrap_or(0);
                    if let Some(entry) = chunks.get_mut(slot) {
                        *entry = Some(slice.to_vec());
                    }
                }
                continue;
            }
            if options.interrupt_after_chunks.is_some_and(|limit| transferred >= limit) {
                self.persist_object_transfer(ObjectTransferPersist {
                    transfer_id: &transfer_id,
                    object: &object,
                    direction: OBJECT_TRANSFER_DOWNLOAD,
                    relay_endpoint: Some(&options.relay_endpoint),
                    chunk_size,
                    total_chunks: manifest.total_chunks,
                    completed: &completed,
                    done_bytes,
                    state: "paused",
                    last_error: None,
                    resume_token: None,
                    expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
                })?;
                return Err(SdkError::LocalBus("object relay download interrupted".to_owned()));
            }
            // T21-A1: GatewayIssued object GET must use the v3 QUIC path only. The QUIC helper
            // fails closed on missing/partial QUIC config or owner lineage; there is no implicit
            // HTTP/v2 fallback. LocalMint stays on the synchronous itest-compatibility path and
            // must never reach this async production function (dispatch routes it to the sync fn).
            if !matches!(options.token_provider, RelayTokenProvider::GatewayIssued) {
                return Err(SdkError::CapabilityDenied(
                    "gateway object GET requires gateway-issued v3 QUIC transport".to_owned(),
                ));
            }
            let response: SdkObjectRelayGetResponse = get_object_chunk_via_relay_quic(
                engine,
                pool,
                options,
                &branch,
                &object,
                chunk_index,
                expires_at,
            )
            .await?;
            let expected_hash = object_relay_chunk_cipher_hash(
                &object.manifest_hash,
                chunk_index,
                &response.chunk.encrypted_chunk,
            );
            if response.chunk.chunk_cipher_hash != expected_hash {
                return Err(SdkError::LocalBus("object relay chunk hash mismatch".to_owned()));
            }
            let payload: ChunkPayload = serde_json::from_slice(&response.chunk.encrypted_chunk)?;
            let plaintext_chunk = decrypt_chunk_payload(&object_key, &manifest, &payload)?;
            let slot = usize::try_from(chunk_index).unwrap_or(0);
            if let Some(entry) = chunks.get_mut(slot) {
                *entry = Some(plaintext_chunk.clone());
            }
            done_bytes =
                done_bytes.saturating_add(u64::try_from(plaintext_chunk.len()).unwrap_or(0));
            completed.push(chunk_index);
            completed.sort_unstable();
            completed.dedup();
            transferred = transferred.saturating_add(1);
            self.persist_object_transfer(ObjectTransferPersist {
                transfer_id: &transfer_id,
                object: &object,
                direction: OBJECT_TRANSFER_DOWNLOAD,
                relay_endpoint: Some(&options.relay_endpoint),
                chunk_size,
                total_chunks: manifest.total_chunks,
                completed: &completed,
                done_bytes,
                state: "running",
                last_error: None,
                resume_token: None,
                expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
            })?;
            if ack {
                // T21-A1: GatewayIssued owner ACK is v3 QUIC only; no implicit HTTP/v2 fallback.
                if !matches!(options.token_provider, RelayTokenProvider::GatewayIssued) {
                    return Err(SdkError::CapabilityDenied(
                        "gateway object ACK requires gateway-issued v3 QUIC transport".to_owned(),
                    ));
                }
                let _response = ack_object_chunk_via_relay_quic(
                    engine,
                    pool,
                    options,
                    &branch,
                    &object,
                    chunk_index,
                    expires_at,
                )
                .await?;
            }
        }
        let assembled = chunks
            .into_iter()
            .map(|chunk| {
                chunk.ok_or_else(|| {
                    SdkError::LocalBus("object relay download incomplete".to_owned())
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .concat();
        if assembled != object.ciphertext {
            return Err(SdkError::LocalBus(
                "object relay assembled ciphertext mismatch".to_owned(),
            ));
        }
        self.persist_object_transfer(ObjectTransferPersist {
            transfer_id: &transfer_id,
            object: &object,
            direction: OBJECT_TRANSFER_DOWNLOAD,
            relay_endpoint: Some(&options.relay_endpoint),
            chunk_size,
            total_chunks: manifest.total_chunks,
            completed: &completed,
            done_bytes: u64::try_from(object.ciphertext.len()).unwrap_or(u64::MAX),
            state: "complete",
            last_error: None,
            resume_token: None,
            expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
        })?;
        self.decrypt_object(object_id)
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) async fn upload_object_to_relay_inner_via_gateway(
        &self,
        engine: &mut GatewaySessionEngine,
        pool: &ramflux_transport::RelayQuicPool,
        object: &EncryptedObject,
        chunk_size: usize,
        options: &RelayTransferOptions,
    ) -> Result<SdkObjectTransferStatus, SdkError> {
        let object_key = self.object_store.object_key(&object.object_id)?;
        let branch = self.device_branch.as_ref().ok_or_else(|| {
            SdkError::LocalBus("object relay requires a device branch".to_owned())
        })?;
        let chunk_size = chunk_size.max(1);
        let manifest =
            chunk_manifest_for_object(&object.object_id, &object.ciphertext, chunk_size, None);
        let transfer_id =
            object_transfer_id(&object.object_id, &object.manifest_hash, OBJECT_TRANSFER_UPLOAD);
        let mut completed = self
            .account_db()?
            .object_transfer(&object.object_id, Some(OBJECT_TRANSFER_UPLOAD))?
            .map_or_else(Vec::new, |record| record.completed_chunks);
        let mut done_bytes = completed
            .iter()
            .filter_map(|chunk_index| {
                ciphertext_slice(&object.ciphertext, chunk_size, *chunk_index)
            })
            .map(|slice| u64::try_from(slice.len()).unwrap_or(0))
            .sum::<u64>();
        let expires_at = relay_expires_at();
        let mut transferred = 0_u32;
        for chunk_index in 0..manifest.total_chunks {
            if completed.contains(&chunk_index) {
                continue;
            }
            if options.interrupt_after_chunks.is_some_and(|limit| transferred >= limit) {
                self.persist_object_transfer(ObjectTransferPersist {
                    transfer_id: &transfer_id,
                    object,
                    direction: OBJECT_TRANSFER_UPLOAD,
                    relay_endpoint: Some(&options.relay_endpoint),
                    chunk_size,
                    total_chunks: manifest.total_chunks,
                    completed: &completed,
                    done_bytes,
                    state: "paused",
                    last_error: None,
                    resume_token: None,
                    expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
                })?;
                return Err(SdkError::LocalBus("object relay upload interrupted".to_owned()));
            }
            let Some(ciphertext_chunk) =
                ciphertext_slice(&object.ciphertext, chunk_size, chunk_index)
            else {
                continue;
            };
            let payload =
                ramflux_sync::chunk_payload(&object_key, &manifest, chunk_index, ciphertext_chunk);
            let encrypted_chunk = serde_json::to_vec(&payload)?;
            let expected_chunk_id =
                object_relay_chunk_id(&object.object_id, &object.manifest_hash, chunk_index);
            // T21-A1: GatewayIssued owner PUT is v3 QUIC only; no implicit HTTP/v2 fallback. The
            // QUIC helper fails closed on missing/partial QUIC config or owner lineage.
            if !matches!(options.token_provider, RelayTokenProvider::GatewayIssued) {
                return Err(SdkError::CapabilityDenied(
                    "gateway object PUT requires gateway-issued v3 QUIC transport".to_owned(),
                ));
            }
            let response: SdkObjectRelayPutResponse = put_object_chunk_via_relay_quic(
                engine,
                pool,
                options,
                branch,
                object,
                chunk_index,
                encrypted_chunk,
                expires_at,
            )
            .await?;
            if response.chunk_id != expected_chunk_id
                || response.object_id != object.object_id
                || response.manifest_hash != object.manifest_hash
                || response.status != SdkRelayChunkStatus::Available
            {
                return Err(SdkError::LocalBus(
                    "object relay put response binding mismatch".to_owned(),
                ));
            }
            completed.push(chunk_index);
            completed.sort_unstable();
            completed.dedup();
            done_bytes =
                done_bytes.saturating_add(u64::try_from(ciphertext_chunk.len()).unwrap_or(0));
            transferred = transferred.saturating_add(1);
            self.persist_object_transfer(ObjectTransferPersist {
                transfer_id: &transfer_id,
                object,
                direction: OBJECT_TRANSFER_UPLOAD,
                relay_endpoint: Some(&options.relay_endpoint),
                chunk_size,
                total_chunks: manifest.total_chunks,
                completed: &completed,
                done_bytes,
                state: "running",
                last_error: None,
                resume_token: None,
                expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
            })?;
        }
        self.persist_object_transfer(ObjectTransferPersist {
            transfer_id: &transfer_id,
            object,
            direction: OBJECT_TRANSFER_UPLOAD,
            relay_endpoint: Some(&options.relay_endpoint),
            chunk_size,
            total_chunks: manifest.total_chunks,
            completed: &completed,
            done_bytes: u64::try_from(object.ciphertext.len()).unwrap_or(u64::MAX),
            state: "complete",
            last_error: None,
            resume_token: None,
            expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
        })?;
        let record = self
            .account_db()?
            .object_transfer(&object.object_id, Some(OBJECT_TRANSFER_UPLOAD))?
            .ok_or_else(|| SdkError::LocalBus("missing object transfer state".to_owned()))?;
        Ok(object_transfer_status(record))
    }

    #[allow(clippy::too_many_lines)]
    #[cfg(feature = "itest-local-mint")]
    fn upload_object_to_relay_inner(
        &self,
        object: &EncryptedObject,
        chunk_size: usize,
        options: &RelayTransferOptions,
    ) -> Result<SdkObjectTransferStatus, SdkError> {
        let object_key = self.object_store.object_key(&object.object_id)?;
        let branch = self.device_branch.as_ref().ok_or_else(|| {
            SdkError::LocalBus("object relay requires a device branch".to_owned())
        })?;
        let chunk_size = chunk_size.max(1);
        let manifest =
            chunk_manifest_for_object(&object.object_id, &object.ciphertext, chunk_size, None);
        let transfer_id =
            object_transfer_id(&object.object_id, &object.manifest_hash, OBJECT_TRANSFER_UPLOAD);
        let mut completed = self
            .account_db()?
            .object_transfer(&object.object_id, Some(OBJECT_TRANSFER_UPLOAD))?
            .map_or_else(Vec::new, |record| record.completed_chunks);
        let mut done_bytes = completed
            .iter()
            .filter_map(|chunk_index| {
                ciphertext_slice(&object.ciphertext, chunk_size, *chunk_index)
            })
            .map(|slice| u64::try_from(slice.len()).unwrap_or(0))
            .sum::<u64>();
        let expires_at = relay_expires_at();
        let mut transferred = 0_u32;
        for chunk_index in 0..manifest.total_chunks {
            if completed.contains(&chunk_index) {
                continue;
            }
            if options.interrupt_after_chunks.is_some_and(|limit| transferred >= limit) {
                self.persist_object_transfer(ObjectTransferPersist {
                    transfer_id: &transfer_id,
                    object,
                    direction: OBJECT_TRANSFER_UPLOAD,
                    relay_endpoint: Some(&options.relay_endpoint),
                    chunk_size,
                    total_chunks: manifest.total_chunks,
                    completed: &completed,
                    done_bytes,
                    state: "paused",
                    last_error: None,
                    resume_token: None,
                    expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
                })?;
                return Err(SdkError::LocalBus("object relay upload interrupted".to_owned()));
            }
            let Some(ciphertext_chunk) =
                ciphertext_slice(&object.ciphertext, chunk_size, chunk_index)
            else {
                continue;
            };
            let payload =
                ramflux_sync::chunk_payload(&object_key, &manifest, chunk_index, ciphertext_chunk);
            let encrypted_chunk = serde_json::to_vec(&payload)?;
            let token = local_relay_token_for_chunk(
                options,
                branch,
                object,
                chunk_index,
                SdkObjectRelayCapability::Put,
                expires_at,
            )?;
            let permission = object_permission_for_chunk(
                branch,
                object,
                chunk_index,
                SdkObjectRelayCapability::Put,
                expires_at,
            )?;
            let frame = SdkObjectChunkFrame {
                schema: "ramflux.object_chunk_frame.v1".to_owned(),
                object_id: object.object_id.clone(),
                manifest_hash: object.manifest_hash.clone(),
                chunk_index,
                chunk_id: token.chunk_id.clone(),
                chunk_cipher_hash: object_relay_chunk_cipher_hash(
                    &object.manifest_hash,
                    chunk_index,
                    &encrypted_chunk,
                ),
                cipher_size: u64::try_from(encrypted_chunk.len()).unwrap_or(u64::MAX),
                encrypted_chunk,
                relay_token: token,
                object_permission_envelope: permission,
                expires_at,
                delete_after_ack: false,
            };
            let response: SdkObjectRelayPutResponse =
                relay_post_json(&options.relay_endpoint, "/relay/v1/object/put_chunk", &frame)?;
            if response.chunk_id != frame.chunk_id
                || response.object_id != object.object_id
                || response.manifest_hash != object.manifest_hash
                || response.status != SdkRelayChunkStatus::Available
            {
                return Err(SdkError::LocalBus(
                    "object relay put response binding mismatch".to_owned(),
                ));
            }
            completed.push(chunk_index);
            completed.sort_unstable();
            completed.dedup();
            done_bytes =
                done_bytes.saturating_add(u64::try_from(ciphertext_chunk.len()).unwrap_or(0));
            transferred = transferred.saturating_add(1);
            self.persist_object_transfer(ObjectTransferPersist {
                transfer_id: &transfer_id,
                object,
                direction: OBJECT_TRANSFER_UPLOAD,
                relay_endpoint: Some(&options.relay_endpoint),
                chunk_size,
                total_chunks: manifest.total_chunks,
                completed: &completed,
                done_bytes,
                state: "running",
                last_error: None,
                resume_token: None,
                expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
            })?;
        }
        self.persist_object_transfer(ObjectTransferPersist {
            transfer_id: &transfer_id,
            object,
            direction: OBJECT_TRANSFER_UPLOAD,
            relay_endpoint: Some(&options.relay_endpoint),
            chunk_size,
            total_chunks: manifest.total_chunks,
            completed: &completed,
            done_bytes: u64::try_from(object.ciphertext.len()).unwrap_or(u64::MAX),
            state: "complete",
            last_error: None,
            resume_token: None,
            expires_at: Some(i64::try_from(expires_at).unwrap_or(i64::MAX)),
        })?;
        let record = self
            .account_db()?
            .object_transfer(&object.object_id, Some(OBJECT_TRANSFER_UPLOAD))?
            .ok_or_else(|| SdkError::LocalBus("missing object transfer state".to_owned()))?;
        Ok(object_transfer_status(record))
    }

    fn persist_object_transfer(&self, persist: ObjectTransferPersist<'_>) -> Result<(), SdkError> {
        let missing = (0..persist.total_chunks)
            .filter(|chunk_index| !persist.completed.contains(chunk_index))
            .collect::<Vec<_>>();
        let next_chunk_index = missing.first().copied();
        self.account_db()?.upsert_object_transfer(&ObjectTransferWrite {
            transfer_id: persist.transfer_id,
            object_id: &persist.object.object_id,
            direction: persist.direction,
            peer_device_id: self
                .device_branch
                .as_ref()
                .map_or("local-device", |branch| branch.device_id.as_str()),
            manifest_hash: &persist.object.manifest_hash,
            relay_endpoint: persist.relay_endpoint,
            resume_token: persist.resume_token,
            missing_chunks: &missing,
            completed_chunks: persist.completed,
            state: persist.state,
            last_error: persist.last_error,
            chunk_size: u64::try_from(persist.chunk_size).unwrap_or(u64::MAX),
            total_bytes: u64::try_from(persist.object.ciphertext.len()).unwrap_or(u64::MAX),
            done_bytes: persist.done_bytes,
            total_chunks: persist.total_chunks,
            next_chunk_index,
            updated_at: now_unix_timestamp(),
            expires_at: persist.expires_at,
        })?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ObjectTransferPersist<'a> {
    transfer_id: &'a str,
    object: &'a EncryptedObject,
    direction: &'a str,
    relay_endpoint: Option<&'a str>,
    chunk_size: usize,
    total_chunks: u32,
    completed: &'a [u32],
    done_bytes: u64,
    state: &'a str,
    last_error: Option<&'a str>,
    resume_token: Option<&'a str>,
    expires_at: Option<i64>,
}

struct DmAttachmentDownload {
    ciphertext: Vec<u8>,
    manifest: ChunkManifest,
    transfer_id: String,
    relay_endpoint: String,
    completed: Vec<u32>,
    expires_at: u64,
}

struct DmAttachmentChunk {
    payload: ChunkPayload,
    len: u64,
}

struct DmAttachmentFetch<'a> {
    options: &'a RelayTransferOptions,
    branch: &'a DeviceBranch,
    attachment: Option<&'a SdkDmAttachmentRef>,
    object: &'a EncryptedObject,
    manifest: &'a ChunkManifest,
    object_key: [u8; 32],
    // Read only by the itest-local-mint v2 fetch path; the v3 async fetch derives its own expiry.
    #[cfg_attr(not(feature = "itest-local-mint"), allow(dead_code))]
    expires_at: u64,
}

#[cfg(feature = "itest-local-mint")]
#[allow(dead_code)]
struct RelayTokenIssueContext<'a> {
    options: &'a RelayTransferOptions,
    branch: &'a DeviceBranch,
    object: &'a EncryptedObject,
    chunk_index: u32,
    capability: SdkObjectRelayCapability,
    expires_at: u64,
    permission: &'a SdkObjectPermissionEnvelope,
}

#[cfg(feature = "itest-local-mint")]
#[allow(dead_code)]
fn fetch_dm_attachment_chunk(
    ctx: &DmAttachmentFetch<'_>,
    chunk_index: u32,
) -> Result<DmAttachmentChunk, SdkError> {
    let permission = object_permission_for_chunk(
        ctx.branch,
        ctx.object,
        chunk_index,
        SdkObjectRelayCapability::Get,
        ctx.expires_at,
    )?;
    let token = local_relay_token_for_chunk(
        ctx.options,
        ctx.branch,
        ctx.object,
        chunk_index,
        SdkObjectRelayCapability::Get,
        ctx.expires_at,
    )?;
    let response: SdkObjectRelayGetResponse = relay_post_json(
        &ctx.options.relay_endpoint,
        "/relay/v1/object/get_chunk",
        &SdkObjectRelayGetRequest {
            chunk_id: token.chunk_id.clone(),
            relay_token: token,
            object_permission_envelope: permission,
        },
    )?;
    let expected_hash = object_relay_chunk_cipher_hash(
        &ctx.object.manifest_hash,
        chunk_index,
        &response.chunk.encrypted_chunk,
    );
    if response.chunk.chunk_cipher_hash != expected_hash {
        return Err(SdkError::LocalBus("object relay chunk hash mismatch".to_owned()));
    }
    let payload: ChunkPayload = serde_json::from_slice(&response.chunk.encrypted_chunk)?;
    let plaintext_chunk = decrypt_chunk_payload(&ctx.object_key, ctx.manifest, &payload)?;
    Ok(DmAttachmentChunk { payload, len: u64::try_from(plaintext_chunk.len()).unwrap_or(0) })
}

async fn fetch_dm_attachment_chunk_via_gateway(
    engine: &mut GatewaySessionEngine,
    pool: &ramflux_transport::RelayQuicPool,
    ctx: &DmAttachmentFetch<'_>,
    chunk_index: u32,
) -> Result<DmAttachmentChunk, SdkError> {
    // T21-A2: grantee GatewayIssued GET is v3 QUIC only — no implicit HTTP/v2 fallback. The QUIC
    // helper fails closed on missing/partial QUIC config or grant. LocalMint stays on the
    // synchronous itest-compatibility path and must not reach this async production function.
    if !matches!(ctx.options.token_provider, RelayTokenProvider::GatewayIssued) {
        return Err(SdkError::CapabilityDenied(
            "gateway DM attachment GET requires gateway-issued v3 QUIC transport".to_owned(),
        ));
    }
    fetch_dm_attachment_chunk_via_relay_quic(engine, pool, ctx, chunk_index).await
}

async fn fetch_dm_attachment_chunk_via_relay_quic(
    engine: &mut GatewaySessionEngine,
    pool: &ramflux_transport::RelayQuicPool,
    ctx: &DmAttachmentFetch<'_>,
    chunk_index: u32,
) -> Result<DmAttachmentChunk, SdkError> {
    let attachment = ctx.attachment.ok_or_else(|| {
        SdkError::CapabilityDenied("v3 relay GET requires the signed attachment grant".to_owned())
    })?;
    let issued_at = u64::try_from(now_unix_timestamp()).unwrap_or(0);
    let expires_at = issued_at.saturating_add(120);
    let chunk_id =
        object_relay_chunk_id(&ctx.object.object_id, &ctx.object.manifest_hash, chunk_index);
    let body_descriptor = serde_json::json!({
        "capability": "get",
        "chunk_id": chunk_id,
        "manifest_hash": ctx.object.manifest_hash,
        "object_id": ctx.object.object_id,
    });
    let body_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.v3.get.body",
        &ramflux_protocol::canonical_json_bytes(&body_descriptor)?,
    );
    let issue_body = build_v3_get_token_issue_body(
        attachment.access_grant.as_ref(),
        attachment,
        ctx.branch,
        &chunk_id,
        issued_at,
        expires_at,
        &format!("sdk-get-{issued_at}-{chunk_index}"),
    )?;
    let token = engine.issue_relay_token_v3(issue_body).await?;
    let pop = build_signed_requester_pop(
        ctx.branch,
        token.token_id.clone(),
        ramflux_protocol::ObjectRelayCapability::Get,
        token.object_id.clone(),
        token.manifest_hash.clone(),
        token.chunk_id.clone(),
        format!("sdk-pop-{issued_at}-{chunk_index}"),
        body_hash.clone(),
        issued_at,
        expires_at,
    )?;
    let certificate = token.issuer_certificate.clone();
    let body = serde_json::json!({
        "token": token,
        "certificate": certificate,
        "grant": attachment.access_grant,
        "pop": pop,
        "body_hash": body_hash,
        "capability": "get",
    });
    let response = relay_quic_success_body(
        relay_quic_request(pool, ctx.options, "/relay/v1/object/get_chunk", body).await?,
    )?;
    let response: SdkObjectRelayGetResponse = serde_json::from_value(response)?;
    let expected_hash = object_relay_chunk_cipher_hash(
        &ctx.object.manifest_hash,
        chunk_index,
        &response.chunk.encrypted_chunk,
    );
    if response.chunk.chunk_cipher_hash != expected_hash {
        return Err(SdkError::LocalBus("object relay chunk hash mismatch".to_owned()));
    }
    let payload: ChunkPayload = serde_json::from_slice(&response.chunk.encrypted_chunk)?;
    let plaintext_chunk = decrypt_chunk_payload(&ctx.object_key, ctx.manifest, &payload)?;
    Ok(DmAttachmentChunk { payload, len: u64::try_from(plaintext_chunk.len()).unwrap_or(0) })
}

// T21-A2: a distinct grantee (B) acknowledges a chunk using the SAME A-signed grant it received in
// the attachment — B never re-signs the grant, it only signs its own requester PoP. The grant must
// authorize Ack; `build_v3_ack_token_issue_body` reuses the grant's canonical bytes and rejects a
// grant that does not carry the Ack capability. GatewayIssued v3 QUIC only, no HTTP fallback.
async fn ack_dm_attachment_chunk_via_relay_quic(
    engine: &mut GatewaySessionEngine,
    pool: &ramflux_transport::RelayQuicPool,
    ctx: &DmAttachmentFetch<'_>,
    chunk_index: u32,
) -> Result<SdkObjectRelayAckResponse, SdkError> {
    let attachment = ctx.attachment.ok_or_else(|| {
        SdkError::CapabilityDenied("v3 relay ACK requires the signed attachment grant".to_owned())
    })?;
    let issued_at = u64::try_from(now_unix_timestamp()).unwrap_or(0);
    let expires_at = issued_at.saturating_add(120);
    let chunk_id =
        object_relay_chunk_id(&ctx.object.object_id, &ctx.object.manifest_hash, chunk_index);
    let body_descriptor = serde_json::json!({
        "capability": "ack",
        "chunk_id": chunk_id,
        "manifest_hash": ctx.object.manifest_hash,
        "object_id": ctx.object.object_id,
    });
    let body_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.v3.ack.body",
        &ramflux_protocol::canonical_json_bytes(&body_descriptor)?,
    );
    let issue_body = build_v3_ack_token_issue_body(
        attachment.access_grant.as_ref(),
        attachment,
        ctx.branch,
        &chunk_id,
        issued_at,
        expires_at,
        &format!("sdk-ack-{issued_at}-{chunk_index}"),
    )?;
    let token = engine.issue_relay_token_v3(issue_body).await?;
    let pop = build_signed_requester_pop(
        ctx.branch,
        token.token_id.clone(),
        ramflux_protocol::ObjectRelayCapability::Ack,
        token.object_id.clone(),
        token.manifest_hash.clone(),
        token.chunk_id.clone(),
        format!("sdk-pop-ack-{issued_at}-{chunk_index}"),
        body_hash.clone(),
        issued_at,
        expires_at,
    )?;
    let certificate = token.issuer_certificate.clone();
    let body = serde_json::json!({
        "token": token,
        "certificate": certificate,
        "grant": attachment.access_grant,
        "pop": pop,
        "body_hash": body_hash,
        "capability": "ack",
    });
    let response = relay_quic_success_body(
        relay_quic_request(pool, ctx.options, "/relay/v1/object/ack", body).await?,
    )?;
    Ok(serde_json::from_value(response)?)
}

// T24-A2: relay requests now ride the account's persistent `RelayQuicPool` instead of a fresh
// per-request QUIC handshake. The token/PoP/nonce and `body` are built exactly once by the caller;
// this fn constructs the `GatewayQuicRequest` once and issues it via `request_once`. A single
// same-frame retry is attempted ONLY when the first failure is a transport-level
// `is_reconnect_retryable()` (no complete application response AND the connection was closed +
// evicted) — the identical request value is re-sent (no re-issued token, no regenerated nonce, no
// re-entry of the upper helper). A complete `GatewayQuicResponse` of any HTTP status is returned
// as-is for the caller's business-status handling; the pool never retries on HTTP status.
async fn relay_quic_request(
    pool: &ramflux_transport::RelayQuicPool,
    options: &RelayTransferOptions,
    path: &str,
    body: serde_json::Value,
) -> Result<ramflux_transport::GatewayQuicResponse, SdkError> {
    let config = relay_quic_config(options)?
        .ok_or_else(|| SdkError::LocalBus("relay QUIC configuration is missing".to_owned()))?;
    let request = ramflux_transport::GatewayQuicRequest {
        method: "POST".to_owned(),
        path: path.to_owned(),
        body,
    };
    issue_relay_request_with_single_retry(&request, |frame| pool.request_once(&config, frame)).await
}

/// The same-frame single-retry decision, factored out so it can be unit-tested without a live
/// relay. `attempt` is invoked with the identical `request` value each time — the token/PoP/nonce
/// live inside `request.body` and are never rebuilt here. A first failure is retried **once** iff
/// it is a transport-level `is_reconnect_retryable()` (no complete application response + the
/// connection was closed/evicted); the second outcome is returned verbatim (no third attempt). Any
/// other first failure, and any complete `GatewayQuicResponse` (all HTTP statuses, including 4xx
/// and 5xx), returns immediately.
async fn issue_relay_request_with_single_retry<'a, F, Fut>(
    request: &'a ramflux_transport::GatewayQuicRequest,
    attempt: F,
) -> Result<ramflux_transport::GatewayQuicResponse, SdkError>
where
    F: Fn(&'a ramflux_transport::GatewayQuicRequest) -> Fut,
    Fut: std::future::Future<
            Output = Result<
                ramflux_transport::GatewayQuicResponse,
                ramflux_transport::RelayQuicRequestError,
            >,
        >,
{
    match attempt(request).await {
        Ok(response) => Ok(response),
        Err(first) if first.is_reconnect_retryable() => {
            attempt(request).await.map_err(relay_pool_error_to_sdk)
        }
        Err(other) => Err(relay_pool_error_to_sdk(other)),
    }
}

/// Maps a transport-layer relay pool error to `SdkError`. Backpressure is preserved as an explicit
/// transport/capacity error (never collapsed into `CapabilityDenied` or a faked HTTP status); every
/// other typed failure becomes a transport QUIC error. Complete HTTP responses never reach here —
/// they are returned `Ok` and handled by the caller's business-status logic.
fn relay_pool_error_to_sdk(error: ramflux_transport::RelayQuicRequestError) -> SdkError {
    match error {
        ramflux_transport::RelayQuicRequestError::Backpressure { capacity, in_flight } => {
            SdkError::Transport(ramflux_transport::TransportError::BackpressureRejected {
                capacity,
                in_flight,
            })
        }
        other => SdkError::Transport(ramflux_transport::TransportError::Quic(other.to_string())),
    }
}

fn relay_quic_success_body(
    response: ramflux_transport::GatewayQuicResponse,
) -> Result<serde_json::Value, SdkError> {
    if response.status != 200 {
        return Err(SdkError::CapabilityDenied(format!(
            "relay v3 request rejected with HTTP status {}: {}",
            response.status, response.body
        )));
    }
    Ok(response.body)
}

#[allow(clippy::too_many_arguments)]
async fn get_object_chunk_via_relay_quic(
    engine: &mut GatewaySessionEngine,
    pool: &ramflux_transport::RelayQuicPool,
    options: &RelayTransferOptions,
    branch: &DeviceBranch,
    object: &EncryptedObject,
    chunk_index: u32,
    expires_at: u64,
) -> Result<SdkObjectRelayGetResponse, SdkError> {
    if !matches!(options.token_provider, RelayTokenProvider::GatewayIssued) {
        return Err(SdkError::CapabilityDenied(
            "v3 relay GET requires gateway-issued token material".to_owned(),
        ));
    }
    let owner_home_node_id = options.relay_owner_home_node_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner GET requires RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(),
        )
    })?;
    let owner_principal_id = options.relay_owner_principal_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner GET requires RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(),
        )
    })?;
    let audience_node_id = options.relay_audience_node_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner GET requires RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(),
        )
    })?;
    let issued_at = u64::try_from(now_unix_timestamp()).unwrap_or(0);
    let chunk_id = object_relay_chunk_id(&object.object_id, &object.manifest_hash, chunk_index);
    let nonce = format!("sdk-get-{issued_at}-{chunk_index}");
    let grant = build_signed_object_access_grant(
        branch,
        object.object_id.clone(),
        object.manifest_hash.clone(),
        recipient_device_hash(branch),
        vec![ramflux_protocol::ObjectRelayCapability::Get],
        issued_at,
        expires_at,
    )?;
    let issue_body = build_v3_grant_token_issue_body(
        &grant,
        branch,
        &object.object_id,
        &object.manifest_hash,
        &chunk_id,
        ramflux_protocol::ObjectRelayCapability::Get,
        owner_home_node_id,
        owner_principal_id,
        branch.device_epoch,
        audience_node_id,
        issued_at,
        expires_at,
        &nonce,
    )?;
    let token = engine.issue_relay_token_v3(issue_body).await?;
    let body_descriptor = serde_json::json!({
        "capability": "get",
        "chunk_id": chunk_id,
        "manifest_hash": object.manifest_hash,
        "object_id": object.object_id,
    });
    let body_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.v3.get.body",
        &ramflux_protocol::canonical_json_bytes(&body_descriptor)?,
    );
    let pop = build_signed_requester_pop(
        branch,
        token.token_id.clone(),
        ramflux_protocol::ObjectRelayCapability::Get,
        token.object_id.clone(),
        token.manifest_hash.clone(),
        token.chunk_id.clone(),
        format!("sdk-pop-{issued_at}-{chunk_index}"),
        body_hash.clone(),
        issued_at,
        expires_at,
    )?;
    let certificate = token.issuer_certificate.clone();
    let body = serde_json::json!({
        "token": token,
        "certificate": certificate,
        "grant": grant,
        "pop": pop,
        "body_hash": body_hash,
        "capability": "get",
    });
    let response = relay_quic_success_body(
        relay_quic_request(pool, options, "/relay/v1/object/get_chunk", body).await?,
    )?;
    Ok(serde_json::from_value(response)?)
}

#[allow(clippy::too_many_arguments)]
async fn ack_object_chunk_via_relay_quic(
    engine: &mut GatewaySessionEngine,
    pool: &ramflux_transport::RelayQuicPool,
    options: &RelayTransferOptions,
    branch: &DeviceBranch,
    object: &EncryptedObject,
    chunk_index: u32,
    expires_at: u64,
) -> Result<SdkObjectRelayAckResponse, SdkError> {
    if !matches!(options.token_provider, RelayTokenProvider::GatewayIssued) {
        return Err(SdkError::CapabilityDenied(
            "v3 relay ACK requires gateway-issued token material".to_owned(),
        ));
    }
    let owner_home_node_id = options.relay_owner_home_node_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner ACK requires RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(),
        )
    })?;
    let owner_principal_id = options.relay_owner_principal_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner ACK requires RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(),
        )
    })?;
    let audience_node_id = options.relay_audience_node_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner ACK requires RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(),
        )
    })?;
    let issued_at = u64::try_from(now_unix_timestamp()).unwrap_or(0);
    let chunk_id = object_relay_chunk_id(&object.object_id, &object.manifest_hash, chunk_index);
    let nonce = format!("sdk-ack-{issued_at}-{chunk_index}");
    let grant = build_signed_object_access_grant(
        branch,
        object.object_id.clone(),
        object.manifest_hash.clone(),
        recipient_device_hash(branch),
        vec![ramflux_protocol::ObjectRelayCapability::Ack],
        issued_at,
        expires_at,
    )?;
    let issue_body = build_v3_grant_token_issue_body(
        &grant,
        branch,
        &object.object_id,
        &object.manifest_hash,
        &chunk_id,
        ramflux_protocol::ObjectRelayCapability::Ack,
        owner_home_node_id,
        owner_principal_id,
        branch.device_epoch,
        audience_node_id,
        issued_at,
        expires_at,
        &nonce,
    )?;
    let token = engine.issue_relay_token_v3(issue_body).await?;
    let body_descriptor = serde_json::json!({
        "capability": "ack",
        "chunk_id": chunk_id,
        "manifest_hash": object.manifest_hash,
        "object_id": object.object_id,
    });
    let body_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.v3.ack.body",
        &ramflux_protocol::canonical_json_bytes(&body_descriptor)?,
    );
    let pop = build_signed_requester_pop(
        branch,
        token.token_id.clone(),
        ramflux_protocol::ObjectRelayCapability::Ack,
        token.object_id.clone(),
        token.manifest_hash.clone(),
        token.chunk_id.clone(),
        format!("sdk-pop-{issued_at}-{chunk_index}"),
        body_hash.clone(),
        issued_at,
        expires_at,
    )?;
    let certificate = token.issuer_certificate.clone();
    let body = serde_json::json!({
        "token": token,
        "certificate": certificate,
        "grant": grant,
        "pop": pop,
        "body_hash": body_hash,
        "capability": "ack",
    });
    let response = relay_quic_success_body(
        relay_quic_request(pool, options, "/relay/v1/object/ack", body).await?,
    )?;
    Ok(serde_json::from_value(response)?)
}

#[allow(clippy::too_many_arguments)]
async fn put_object_chunk_via_relay_quic(
    engine: &mut GatewaySessionEngine,
    pool: &ramflux_transport::RelayQuicPool,
    options: &RelayTransferOptions,
    branch: &DeviceBranch,
    object: &EncryptedObject,
    chunk_index: u32,
    encrypted_chunk: Vec<u8>,
    expires_at: u64,
) -> Result<SdkObjectRelayPutResponse, SdkError> {
    let owner_home_node_id = options.relay_owner_home_node_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner PUT requires RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(),
        )
    })?;
    let owner_principal_id = options.relay_owner_principal_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner PUT requires RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(),
        )
    })?;
    let audience_node_id = options.relay_audience_node_id.as_deref().ok_or_else(|| {
        SdkError::CapabilityDenied(
            "v3 owner PUT requires RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(),
        )
    })?;
    let issued_at = u64::try_from(now_unix_timestamp()).unwrap_or(0);
    let chunk_id = object_relay_chunk_id(&object.object_id, &object.manifest_hash, chunk_index);
    let chunk_cipher_hash =
        object_relay_chunk_cipher_hash(&object.manifest_hash, chunk_index, &encrypted_chunk);
    let nonce = format!("sdk-put-{issued_at}-{chunk_index}");
    let owner_proof = build_signed_owner_authorization_proof(
        branch,
        ramflux_protocol::ObjectRelayCapability::Put,
        object.object_id.clone(),
        Some(object.manifest_hash.clone()),
        Some(chunk_id.clone()),
        owner_home_node_id.to_owned(),
        owner_principal_id.to_owned(),
        branch.device_epoch,
        nonce.clone(),
        chunk_cipher_hash.clone(),
        issued_at,
        expires_at,
    )?;
    let authorization_binding_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.owner_authorization_proof.binding.v3",
        &ramflux_protocol::canonical_json_bytes(&owner_proof)?,
    );
    let issue_body = build_v3_owner_session_token_issue_body(
        branch,
        object,
        &chunk_id,
        ramflux_protocol::ObjectRelayCapability::Put,
        owner_home_node_id,
        audience_node_id,
        owner_principal_id,
        &authorization_binding_hash,
        issued_at,
        expires_at,
        &nonce,
    )?;
    let token = engine.issue_relay_token_v3(issue_body).await?;
    let pop = build_signed_requester_pop(
        branch,
        token.token_id.clone(),
        ramflux_protocol::ObjectRelayCapability::Put,
        token.object_id.clone(),
        token.manifest_hash.clone(),
        token.chunk_id.clone(),
        format!("sdk-pop-{issued_at}-{chunk_index}"),
        chunk_cipher_hash.clone(),
        issued_at,
        expires_at,
    )?;
    let certificate = token.issuer_certificate.clone();
    let body = serde_json::json!({
        "token": token,
        "certificate": certificate,
        "owner_proof": owner_proof,
        "pop": pop,
        "body_hash": chunk_cipher_hash.clone(),
        "capability": "put",
        "chunk_index": chunk_index,
        "chunk_cipher_hash": chunk_cipher_hash,
        "encrypted_chunk": encrypted_chunk,
        "expires_at": expires_at,
        "delete_after_ack": false,
    });
    let response = relay_quic_success_body(
        relay_quic_request(pool, options, "/relay/v1/object/put_chunk", body).await?,
    )?;
    Ok(serde_json::from_value(response)?)
}

#[cfg(feature = "itest-local-mint")]
fn local_relay_token_for_chunk(
    options: &RelayTransferOptions,
    branch: &DeviceBranch,
    object: &EncryptedObject,
    chunk_index: u32,
    capability: SdkObjectRelayCapability,
    expires_at: u64,
) -> Result<SdkRelayToken, SdkError> {
    let RelayTokenProvider::LocalMint { relay_service_key } = &options.token_provider else {
        return Err(SdkError::LocalBus(
            "object relay requires gateway-issued token; local mint is disabled".to_owned(),
        ));
    };
    relay_token_for_chunk(relay_service_key, branch, object, chunk_index, capability, expires_at)
}

// v2 relay token issuance retained only for the synchronous LocalMint / explicit itest HTTP
// compatibility surface; all v3 GatewayIssued production paths now use the QUIC token builders.
// Full removal of the v2 gateway-issuance fallback belongs to the RQ-04 v2-HMAC deprecation.
#[cfg(feature = "itest-local-mint")]
#[allow(dead_code)]
async fn issue_or_mint_relay_token(
    engine: &mut GatewaySessionEngine,
    ctx: &RelayTokenIssueContext<'_>,
) -> Result<SdkRelayToken, SdkError> {
    match &ctx.options.token_provider {
        RelayTokenProvider::LocalMint { relay_service_key } => relay_token_for_chunk(
            relay_service_key,
            ctx.branch,
            ctx.object,
            ctx.chunk_index,
            ctx.capability,
            ctx.expires_at,
        ),
        RelayTokenProvider::GatewayIssued => {
            let owner_public_key = ramflux_protocol::encode_base64url(
                ctx.branch.signing_key.verifying_key().to_bytes(),
            );
            engine
                .issue_relay_token(GatewayRelayTokenIssueBody {
                    object_id: ctx.object.object_id.clone(),
                    manifest_hash: ctx.object.manifest_hash.clone(),
                    chunk_id: object_relay_chunk_id(
                        &ctx.object.object_id,
                        &ctx.object.manifest_hash,
                        ctx.chunk_index,
                    ),
                    recipient_device_hash: relay_recipient_device_hash(&ctx.branch.device_id),
                    owner_signing_key_id: ctx.branch.device_id.clone(),
                    owner_public_key,
                    capability: ctx.capability,
                    delete_after_ack: false,
                    issued_at: u64::try_from(now_unix_timestamp()).unwrap_or(0),
                    expires_at: ctx.expires_at,
                    object_permission_envelope: ctx.permission.clone(),
                })
                .await
        }
    }
}

#[allow(dead_code)]
fn relay_recipient_device_hash(device_id: &str) -> String {
    ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        device_id.as_bytes(),
    )
}

fn dm_attachment_object_stub(attachment: &SdkDmAttachmentRef) -> EncryptedObject {
    EncryptedObject {
        object_id: attachment.object_id.clone(),
        manifest_hash: attachment.manifest_hash.clone(),
        nonce: String::new(),
        ciphertext: vec![0; usize::try_from(attachment.cipher_size).unwrap_or(0)],
        plaintext_hash: attachment.plaintext_hash.clone(),
        tombstoned: false,
        backup_excluded: false,
    }
}

fn ciphertext_slice(ciphertext: &[u8], chunk_size: usize, chunk_index: u32) -> Option<&[u8]> {
    let start = usize::try_from(chunk_index).ok()?.checked_mul(chunk_size)?;
    if start >= ciphertext.len() {
        return None;
    }
    let end = start.saturating_add(chunk_size).min(ciphertext.len());
    Some(&ciphertext[start..end])
}

fn relay_expires_at() -> u64 {
    // Gateway/node-core enforce a 300s maximum token window; leave clock-skew and request
    // processing headroom instead of asking the gateway for an impossible 15-minute token.
    u64::try_from(now_unix_timestamp()).unwrap_or(0).saturating_add(240)
}

#[cfg(test)]
mod t21a1_tests {
    use super::*;

    #[test]
    fn relay_quic_success_body_rejects_non_200_without_fallback() -> Result<(), SdkError> {
        // 200 -> body passes through unchanged.
        let ok = ramflux_transport::GatewayQuicResponse {
            status: 200,
            body: serde_json::json!({ "chunk": "opaque" }),
        };
        assert_eq!(relay_quic_success_body(ok)?, serde_json::json!({ "chunk": "opaque" }));

        // Any non-200 relay response (business rejection or transport-mapped status) is terminal
        // CapabilityDenied. The v3 QUIC object path must never downgrade to HTTP on a non-200,
        // so there is no code branch that retries these over the legacy relay HTTP endpoint.
        for status in [400_u16, 401, 403, 404, 409, 500, 503] {
            let response = ramflux_transport::GatewayQuicResponse {
                status,
                body: serde_json::json!({ "error": "denied" }),
            };
            assert!(
                matches!(relay_quic_success_body(response), Err(SdkError::CapabilityDenied(_))),
                "status {status} must fail closed as CapabilityDenied"
            );
        }
        Ok(())
    }

    fn slot_test_client(test_name: &str) -> Result<(std::path::PathBuf, RamfluxClient), SdkError> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let root = std::env::temp_dir()
            .join(format!("ramflux-sdk-slot-{test_name}-{}-{nanos}", std::process::id()));
        let mut client = RamfluxClient::new();
        client.open_account_index(&root)?;
        client.create_account("acct", "principal")?;
        client.unlock_account("acct", b"test-secret")?;
        Ok((root, client))
    }

    // T21-A2a / CTRL-028 item 2: `decrypt_object_key_slot` advances the attachment key-slot recv
    // ratchet in memory but must NOT persist it. The slot recv checkpoint may only move once the
    // caller explicitly commits after the whole import succeeds, so a failed import leaves the
    // persisted slot ratchet unchanged and the slot ciphertext can be re-decrypted on retry.
    #[test]
    fn decrypt_object_key_slot_defers_slot_session_commit_until_committed() -> Result<(), SdkError>
    {
        let (root, mut client) = slot_test_client("defer-commit")?;
        let object_id = "object_slot_defer";
        let slot_conversation_id = "conv_slot_defer";
        let recipient_device_id = "recipient_device_slot";
        let root_seed = [9_u8; 32];
        let sender_hash = [1_u8; 32];
        let recipient_hash = [2_u8; 32];
        let bootstrap = [3_u8; 32];

        // Matched sender/recipient sessions: the recipient session is persisted as the slot recv
        // session so `decrypt_object_key_slot` loads it and can decrypt the sender's ciphertext.
        let mut sender = ramflux_crypto::DmSession::initiator(
            root_seed,
            sender_hash,
            recipient_hash,
            bootstrap,
        )?;
        let recipient = ramflux_crypto::DmSession::recipient(
            root_seed,
            recipient_hash,
            sender_hash,
            bootstrap,
        )?;
        client.persist_dm_session(slot_conversation_id, "slot-bootstrap", "recv", &recipient)?;

        let checkpoint_name = dm_session_checkpoint_name(slot_conversation_id, "recv");
        let before = client.projection_checkpoint(&checkpoint_name)?;

        let object_key = [7_u8; 32];
        let associated_data =
            object_key_slot_associated_data(object_id, slot_conversation_id, recipient_device_id);
        let ciphertext = sender.encrypt(&object_key, &associated_data)?;
        let slot = SdkObjectKeySlot {
            schema: "ramflux.sdk.object_key_slot.dm.v1".to_owned(),
            version: 1,
            object_id: object_id.to_owned(),
            conversation_id: slot_conversation_id.to_owned(),
            recipient_device_id: recipient_device_id.to_owned(),
            x3dh: None,
            ciphertext,
        };

        // Decrypt advances the in-memory ratchet but must leave the persisted slot checkpoint alone.
        let deferred = client.decrypt_object_key_slot(&slot)?;
        // Compare without formatting the key material (DeferredObjectKeySlot has no Debug by design).
        assert!(deferred.object_key == object_key, "deferred slot must decrypt to the object key");
        assert!(
            client.projection_checkpoint(&checkpoint_name)? == before,
            "decrypt must not move the slot recv checkpoint before commit",
        );

        // Commit moves the checkpoint to the object-slot event id, and only then.
        client.commit_object_key_slot_session(&deferred)?;
        let expected =
            dm_session_event_id(slot_conversation_id, "recv", &format!("object-slot:{object_id}"));
        assert_eq!(client.projection_checkpoint(&checkpoint_name)?, Some(expected));

        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}

#[cfg(test)]
mod t24a2_relay_retry_tests {
    //! T24-A2 same-frame single-retry decision (pure, no live relay). Proves: only a transport
    //! `is_reconnect_retryable()` first failure triggers exactly one retry with the byte-identical
    //! frame (never a rebuilt token/PoP/nonce/body); complete HTTP responses (any status incl.
    //! 4xx/5xx) and every other typed failure return on the first attempt; Backpressure stays a
    //! transport/capacity error and is never collapsed into `CapabilityDenied`.
    use super::{SdkError, issue_relay_request_with_single_retry};
    use ramflux_transport::{
        GatewayQuicRequest, GatewayQuicResponse, RelayQuicRequestError, TransportError,
    };
    use std::cell::RefCell;

    fn frame() -> GatewayQuicRequest {
        GatewayQuicRequest {
            method: "POST".to_owned(),
            path: "/relay/v1/object/put_chunk".to_owned(),
            body: serde_json::json!({
                "token": { "token_id": "tok-1", "nonce": "sdk-pop-1700000000-0" },
                "chunk": "opaque-ciphertext",
            }),
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn ok(status: u16) -> Result<GatewayQuicResponse, RelayQuicRequestError> {
        Ok(GatewayQuicResponse { status, body: serde_json::json!({ "ok": true }) })
    }

    async fn drive(
        request: &GatewayQuicRequest,
        outcomes: Vec<Result<GatewayQuicResponse, RelayQuicRequestError>>,
    ) -> (Result<GatewayQuicResponse, SdkError>, Vec<GatewayQuicRequest>) {
        let seen = RefCell::new(Vec::new());
        let queue = RefCell::new(outcomes.into_iter());
        let result = issue_relay_request_with_single_retry(request, |sent| {
            seen.borrow_mut().push(sent.clone());
            let outcome = queue.borrow_mut().next().unwrap_or_else(|| {
                Err(RelayQuicRequestError::Config("no more programmed outcomes".to_owned()))
            });
            async move { outcome }
        })
        .await;
        (result, seen.into_inner())
    }

    #[tokio::test]
    async fn connection_lost_then_success_retries_once_with_identical_frame() {
        let request = frame();
        let (result, seen) = drive(
            &request,
            vec![Err(RelayQuicRequestError::ConnectionLost("reset".to_owned())), ok(200)],
        )
        .await;
        assert!(matches!(&result, Ok(r) if r.status == 200));
        assert_eq!(seen.len(), 2, "exactly two attempts");
        assert_eq!(seen[0], seen[1], "retry re-sends the byte-identical frame");
        assert_eq!(seen[1], request, "no token/nonce/body rebuild between attempts");
    }

    #[tokio::test]
    async fn request_timeout_then_success_retries_once_with_identical_frame() {
        let request = frame();
        let (result, seen) = drive(
            &request,
            vec![Err(RelayQuicRequestError::RequestTimeout("deadline".to_owned())), ok(200)],
        )
        .await;
        assert!(matches!(&result, Ok(r) if r.status == 200));
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], seen[1]);
        assert_eq!(seen[1], request);
    }

    #[tokio::test]
    async fn complete_403_returns_on_first_attempt() {
        let request = frame();
        let (result, seen) = drive(&request, vec![ok(403)]).await;
        assert!(matches!(&result, Ok(r) if r.status == 403), "complete 403 passes through");
        assert_eq!(seen.len(), 1, "a complete HTTP response is never retried");
    }

    #[tokio::test]
    async fn complete_503_returns_on_first_attempt() {
        let request = frame();
        let (result, seen) = drive(&request, vec![ok(503)]).await;
        assert!(
            matches!(&result, Ok(r) if r.status == 503),
            "complete 5xx passes through, not retried"
        );
        assert_eq!(seen.len(), 1);
    }

    #[tokio::test]
    async fn handshake_failure_is_not_retried() {
        let request = frame();
        let (result, seen) =
            drive(&request, vec![Err(RelayQuicRequestError::Handshake("tls".to_owned()))]).await;
        assert!(matches!(result, Err(SdkError::Transport(_))));
        assert_eq!(seen.len(), 1, "handshake failure is not reconnect-retryable");
    }

    #[tokio::test]
    async fn peer_auth_failure_is_not_retried() {
        let request = frame();
        let (result, seen) =
            drive(&request, vec![Err(RelayQuicRequestError::PeerAuth("bad ca".to_owned()))]).await;
        assert!(matches!(result, Err(SdkError::Transport(_))));
        assert_eq!(seen.len(), 1);
    }

    #[tokio::test]
    async fn protocol_failure_is_not_retried() {
        let request = frame();
        let (result, seen) =
            drive(&request, vec![Err(RelayQuicRequestError::Protocol("partial".to_owned()))]).await;
        assert!(matches!(result, Err(SdkError::Transport(_))));
        assert_eq!(seen.len(), 1, "a complete-but-invalid frame is not reconnect-retryable");
    }

    #[tokio::test]
    async fn backpressure_maps_to_transport_capacity_not_capability_denied() {
        let request = frame();
        let (result, seen) = drive(
            &request,
            vec![Err(RelayQuicRequestError::Backpressure { capacity: 8, in_flight: 9 })],
        )
        .await;
        assert_eq!(seen.len(), 1, "backpressure is not retried");
        assert!(
            matches!(
                &result,
                Err(SdkError::Transport(TransportError::BackpressureRejected {
                    capacity: 8,
                    in_flight: 9,
                }))
            ),
            "backpressure must stay a transport/capacity error, never CapabilityDenied: {result:?}"
        );
    }

    #[tokio::test]
    async fn two_retryable_failures_stop_at_two_attempts_and_return_the_second() {
        let request = frame();
        let (result, seen) = drive(
            &request,
            vec![
                Err(RelayQuicRequestError::ConnectionLost("first".to_owned())),
                Err(RelayQuicRequestError::RequestTimeout("second".to_owned())),
            ],
        )
        .await;
        assert_eq!(seen.len(), 2, "at most one retry — no third attempt");
        assert_eq!(seen[0], seen[1], "the single retry re-sent the identical frame");
        // The second (post-retry) error is returned verbatim, mapped to a transport error.
        assert!(
            matches!(&result, Err(SdkError::Transport(TransportError::Quic(message))) if message.contains("second")),
            "expected the second attempt's transport error verbatim: {result:?}"
        );
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

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

    pub(crate) async fn dm_attachment_ref_for_recipient(
        &mut self,
        engine: &mut GatewaySessionEngine,
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
        self.upload_object_to_relay_inner(&object, attachment.chunk_size, &relay_options)?;
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

    pub(crate) fn decrypt_object_key_slot(
        &mut self,
        key_slot: &SdkObjectKeySlot,
    ) -> Result<[u8; 32], SdkError> {
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
        self.persist_dm_session(
            &key_slot.conversation_id,
            &format!("object-slot:{}", key_slot.object_id),
            "recv",
            &session,
        )?;
        Ok(object_key)
    }

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
        let object_key = self.decrypt_object_key_slot(&attachment.key_slot)?;
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
        Ok(SdkDmAttachmentImportResult {
            object_id: attachment.object_id.clone(),
            manifest_hash: attachment.manifest_hash.clone(),
            plaintext_base64: ramflux_protocol::encode_base64url(&plaintext),
            plaintext_hash,
            imported: true,
        })
    }

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

    pub(crate) fn object_transfer_status(
        &self,
        object_id: &str,
        direction: Option<&str>,
    ) -> Result<Option<SdkObjectTransferStatus>, SdkError> {
        Ok(self.account_db()?.object_transfer(object_id, direction)?.map(object_transfer_status))
    }

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

    #[allow(clippy::too_many_lines)]
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
            let token = relay_token_for_chunk(
                &options.relay_service_key,
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
                let ack_token = relay_token_for_chunk(
                    &options.relay_service_key,
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
            let token = relay_token_for_chunk(
                &options.relay_service_key,
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
    object: &'a EncryptedObject,
    manifest: &'a ChunkManifest,
    object_key: [u8; 32],
    expires_at: u64,
}

fn fetch_dm_attachment_chunk(
    ctx: &DmAttachmentFetch<'_>,
    chunk_index: u32,
) -> Result<DmAttachmentChunk, SdkError> {
    let token = relay_token_for_chunk(
        &ctx.options.relay_service_key,
        ctx.branch,
        ctx.object,
        chunk_index,
        SdkObjectRelayCapability::Get,
        ctx.expires_at,
    )?;
    let permission = object_permission_for_chunk(
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
    u64::try_from(now_unix_timestamp()).unwrap_or(0).saturating_add(15 * 60)
}

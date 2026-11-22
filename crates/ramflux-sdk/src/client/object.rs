// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;
pub(crate) mod fetch_job;
mod relay_transport;
use relay_transport::{
    ack_dm_attachment_chunk_via_relay_quic, ack_object_chunk_via_relay_quic,
    fetch_dm_attachment_chunk_via_gateway, get_object_chunk_via_relay_quic,
    put_object_chunk_via_relay_quic, relay_quic_request, relay_quic_success_body,
};

pub(crate) mod upload_job;
use ramflux_storage::ObjectRetention;
#[cfg(test)]
#[path = "object_cache_tests.rs"]
mod cache_tests;
#[path = "object_cached_download.rs"]
mod cached_download;
#[cfg(test)]
#[path = "object_history_ownership.rs"]
mod history_ownership;
#[cfg(test)]
#[path = "object_listing_tests.rs"]
mod listing_tests;

/// T21-A2a: the decrypted attachment key slot plus its advanced recv session, held so the caller can
/// commit the slot recv checkpoint only after the whole import (download, persist, plaintext verify,
/// ACK) has succeeded. No `Debug`/serialization is derived: the session holds secret key material.
pub(crate) struct DeferredObjectKeySlot {
    pub object_key: [u8; 32],
    pub(super) session: Option<ramflux_crypto::DmSession>,
    pub(super) conversation_id: String,
    pub(super) commit_label: String,
    pub(super) pair_slot: Option<SdkObjectKeySlot>,
}

impl Drop for DeferredObjectKeySlot {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.object_key);
    }
}

struct VerifiedAttachmentImport {
    object: EncryptedObject,
    plaintext: zeroize::Zeroizing<Vec<u8>>,
    plaintext_hash: String,
}

impl RamfluxClient {
    fn persist_object_if_unlocked(
        &self,
        object: &EncryptedObject,
        content_key: Option<&[u8; 32]>,
        retention: ObjectRetention,
    ) -> Result<(), SdkError> {
        let actual = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::OBJECT_MANIFEST,
            &object.ciphertext,
        );
        if actual != object.manifest_hash {
            return Err(SdkError::LocalBus("object ciphertext manifest mismatch".to_owned()));
        }
        let Some(db) = self.active_account_db.as_ref() else {
            return Ok(());
        };
        db.write_transaction(|| -> Result<(), SdkError> {
            db.retain_object(&object.object_id, &object.manifest_hash, retention)?;
            db.upsert_object(&ObjectWrite {
                object_id: &object.object_id,
                manifest_hash: &object.manifest_hash,
                nonce: &object.nonce,
                ciphertext: &object.ciphertext,
                plaintext_hash: &object.plaintext_hash,
                tombstoned: object.tombstoned,
                backup_excluded: object.backup_excluded,
                content_key,
                object: &persisted_descriptor(object),
                updated_at: now_unix_timestamp(),
            })?;
            Ok(())
        })
    }

    pub(crate) fn hydrate_object_store_from_account_db(&mut self) -> Result<(), SdkError> {
        let (objects, object_keys) = if let Some(limit) = self.object_store.cache_capacity() {
            self.account_db()?.load_recent_objects::<EncryptedObject>(limit)?
        } else {
            self.account_db()?.load_objects::<EncryptedObject>()?
        };
        self.object_store.replace_persisted(objects, object_keys);
        self.bind_object_retirement()
    }

    pub(super) fn bind_object_retirement(&self) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let handle = self.object_store.retirement_handle(db.object_erasure_root());
        db.observe_object_retirement(std::sync::Arc::new(move |commitments| {
            if let Some(commitments) = commitments {
                handle.retire(commitments);
            } else {
                handle.clear();
            }
        }))?;
        Ok(())
    }

    pub async fn share_object_key_with_dm_recipient(
        &self,
        engine: &mut impl GatewaySessionAccess,
        request: LocalBusObjectShareRequest,
    ) -> Result<SdkObjectSharePackage, SdkError> {
        let object =
            self.object_store_object(&request.object_id)?.ok_or(SyncError::ObjectNotFound)?;
        let object_key = zeroize::Zeroizing::new(self.object_content_key(&object.object_id)?);
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
        let mut message = GatewayDirectMessage {
            conversation_id: request.conversation_id.clone(),
            message_id: format!("object.slot:{}:{recipient_device_id}", object.object_id),
            envelope_id: format!(
                "slot_{}",
                ramflux_protocol::encode_base64url(X25519KeyPair::random()?.public)
            ),
            source_principal_id: sender_id.clone(),
            sender_id,
            recipient_device_id: Some(recipient_device_id.clone()),
            recipient_principal_commitment: request.recipient_principal_commitment.clone(),
            target_delivery_id,
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: self.content_ttl()?,
        };
        self.resolve_message_recipient(engine.config(), &mut message).await?;
        let key_slot = self
            .make_pair_object_slot(
                engine,
                &message,
                &object.object_id,
                &object_key,
                &request.conversation_id,
            )
            .await?;
        self.account_db()?.check_object_identity(&object.object_id, &object.manifest_hash)?;
        Ok(SdkObjectSharePackage {
            schema: "ramflux.sdk.object_share_package.v1".to_owned(),
            version: 1,
            ciphertext_base64: ramflux_protocol::encode_base64url(&object.ciphertext),
            key_slot,
            object,
        })
    }

    /// # Errors
    /// Returns an error when the key slot cannot be decrypted or the object cannot be imported.
    pub fn import_shared_object(
        &mut self,
        package: &SdkObjectSharePackage,
    ) -> Result<EncryptedObject, SdkError> {
        let (object, slot) = self.prepare_shared_import(package)?;
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            self.persist_object_if_unlocked(
                &object,
                Some(&slot.object_key),
                ObjectRetention::Standalone,
            )?;
            self.commit_object_key_slot_session(&slot)
        })?;
        self.object_store.cache_persisted_object(object.clone(), Some(slot.object_key));
        Ok(object)
    }

    /// Explicitly replaces the expected prior identity, or requires an absent retired wire id.
    /// # Errors
    /// Refuses unexpected state, active owners of a different identity, or an erased incoming identity.
    pub fn replace_shared_object(
        &mut self,
        package: &SdkObjectSharePackage,
        expected_manifest: Option<&str>,
    ) -> Result<EncryptedObject, SdkError> {
        let (object, slot) = self.prepare_shared_import(package)?;
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            self.account_db()?.replace_object(
                expected_manifest,
                &ObjectWrite {
                    object_id: &object.object_id,
                    manifest_hash: &object.manifest_hash,
                    nonce: &object.nonce,
                    ciphertext: &object.ciphertext,
                    plaintext_hash: &object.plaintext_hash,
                    tombstoned: false,
                    backup_excluded: false,
                    content_key: Some(&slot.object_key),
                    object: &persisted_descriptor(&object),
                    updated_at: now_unix_timestamp(),
                },
            )?;
            self.commit_object_key_slot_session(&slot)
        })?;
        self.object_store.cache_persisted_object(object.clone(), Some(slot.object_key));
        Ok(object)
    }

    fn prepare_shared_import(
        &self,
        package: &SdkObjectSharePackage,
    ) -> Result<(EncryptedObject, DeferredObjectKeySlot), SdkError> {
        if package.schema != "ramflux.sdk.object_share_package.v1" || package.version != 1 {
            return Err(SdkError::LocalBus("unsupported object share package version".into()));
        }
        let db = self.account_db()?;
        db.check_object_identity(&package.object.object_id, &package.object.manifest_hash)?;
        if db.object_is_tombstoned(&package.object.object_id)? {
            return Err(SdkError::AttachmentDeleted);
        }
        let slot = self.decrypt_object_key_slot(&package.key_slot)?;
        let ciphertext = ramflux_protocol::decode_base64url(&package.ciphertext_base64)
            .map_err(|_| SdkError::LocalBus("invalid object ciphertext encoding".into()))?;
        let manifest = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::OBJECT_MANIFEST,
            &ciphertext,
        );
        if manifest != package.object.manifest_hash {
            return Err(SdkError::LocalBus("object ciphertext manifest mismatch".into()));
        }
        let mut staged = ObjectStore::new();
        let object = staged.put_received_encrypted_object_with_key(
            &package.object.object_id,
            &manifest,
            &ciphertext,
            &package.object.plaintext_hash,
            slot.object_key,
        );
        let plaintext = zeroize::Zeroizing::new(staged.decrypt_object(&object.object_id)?);
        if ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &plaintext)
            != object.plaintext_hash
        {
            return Err(SdkError::LocalBus("object plaintext hash mismatch".into()));
        }
        Ok((object, slot))
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
        if key_slot.version != 2 {
            return Err(SdkError::GeneratedRefused {
                code: crate::GeneratedRefusalCode::Content,
                reason: "retired object key slot requires MediaKeySlot".into(),
            });
        }
        self.decrypt_pair_object_slot(key_slot, None)
    }

    /// Commits the advanced attachment key-slot recv session. T21-A2a: only called once the whole
    /// attachment import (download, persist, plaintext verification, and every ACK) has succeeded.
    pub(crate) fn commit_object_key_slot_session(
        &self,
        deferred: &DeferredObjectKeySlot,
    ) -> Result<(), SdkError> {
        let slot = deferred.pair_slot.as_ref().ok_or_else(|| SdkError::GeneratedRefused {
            code: crate::GeneratedRefusalCode::Content,
            reason: "retired object key slot has no native pair binding".into(),
        })?;
        self.commit_pair_object_slot(slot, &deferred.object_key)
    }

    pub(super) fn object_key_slot_committed(
        &self,
        slot: &SdkObjectKeySlot,
    ) -> Result<bool, SdkError> {
        if slot.version != 2 {
            return Err(SdkError::GeneratedRefused {
                code: crate::GeneratedRefusalCode::Content,
                reason: "retired object key slot requires MediaKeySlot".into(),
            });
        }
        self.pair_object_slot_committed(slot)
    }

    pub(crate) async fn import_dm_attachment_from_relay_via_gateway(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        attachment: &SdkDmAttachmentRef,
        relay_service_key_base64: Option<String>,
    ) -> Result<SdkDmAttachmentImportResult, SdkError> {
        self.import_dm_attachment_retained(
            engine,
            pool,
            attachment,
            relay_service_key_base64,
            ObjectRetention::Imported,
        )
        .await
    }

    pub(crate) async fn import_dm_attachment_retained(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        attachment: &SdkDmAttachmentRef,
        relay_service_key_base64: Option<String>,
        retention: ObjectRetention,
    ) -> Result<SdkDmAttachmentImportResult, SdkError> {
        let mut check = "verified_local_cache";
        let outcome = Box::pin(async {
            let cached = if matches!(retention, ObjectRetention::Imported) {
                self.try_import_cached_attachment(attachment)?
            } else {
                self.try_import_cached_attachment_retained(attachment, retention)?
            };
            if let Some(imported) = cached {
                return Ok(imported);
            }
            check = "reference_schema";
            self.validate_attachment_import(attachment)?;
            check = "prepared_key_slot";
            let key_slot = if let Some(slot) = self.received_attachment_prepared_slot(attachment)? {
                slot
            } else {
                check = "key_slot_decrypt";
                self.decrypt_object_key_slot(&attachment.key_slot)?
            };
            let object_key = zeroize::Zeroizing::new(key_slot.object_key);
            check = "relay_download";
            let download = self
                .download_dm_attachment_ciphertext_via_gateway(
                    engine,
                    pool,
                    attachment,
                    object_key.clone(),
                    relay_service_key_base64.as_deref(),
                )
                .await?;
            check = "verify_and_persist";
            let verified = self.verify_persist_dm_attachment_retained(
                attachment,
                &download,
                *object_key,
                retention,
            )?;
            let object = &verified.object;
            #[cfg(feature = "itest-rfd-fault")]
            crate::itest_rfd_fault::barrier(crate::itest_rfd_fault::Mode::GranteeImport).await?;
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
                check = "relay_ack_options";
                let ack_options = self
                    .relay_transfer_options(
                        Some(attachment.relay_endpoint.clone()),
                        relay_service_key_base64.as_deref(),
                        None,
                    )?
                    .ok_or_else(|| {
                        SdkError::LocalBus("DM attachment relay options missing".to_owned())
                    })?;

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
                    object,
                    manifest: &download.manifest,
                    object_key: *object_key,
                };
                check = "relay_ack";
                self.acknowledge_dm_attachment_chunks(engine, pool, attachment, &ack_ctx).await?;
            }
            // T21-A2a: every chunk was downloaded, persisted, plaintext-verified, and ACKed; only now
            // commit the slot recv checkpoint so a failed ACK above leaves the slot ratchet re-usable.
            check = "key_slot_commit";
            self.commit_received_attachment_import(attachment, &key_slot)?;
            Ok(SdkDmAttachmentImportResult {
                object_id: attachment.object_id.clone(),
                manifest_hash: attachment.manifest_hash.clone(),
                plaintext_base64: ramflux_protocol::encode_base64url(&verified.plaintext),
                plaintext_hash: verified.plaintext_hash,
                imported: true,
            })
        })
        .await;
        let outcome = outcome.map_err(|error| self.attachment_error(attachment, error));
        if check == "verified_local_cache" {
            super::attachment_diagnostics::checked_context(outcome, &attachment.object_id, check)
        } else {
            super::attachment_diagnostics::checked(outcome, &attachment.object_id, check)
        }
    }

    fn validate_attachment_import(&self, attachment: &SdkDmAttachmentRef) -> Result<(), SdkError> {
        if attachment.schema != "ramflux.sdk.dm_attachment_ref.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported DM attachment ref schema: {}",
                attachment.schema
            )));
        }
        self.account_db()?
            .check_object_identity(&attachment.object_id, &attachment.manifest_hash)?;
        Ok(())
    }

    async fn acknowledge_dm_attachment_chunks(
        &self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        attachment: &SdkDmAttachmentRef,
        context: &DmAttachmentFetch<'_>,
    ) -> Result<(), SdkError> {
        self.acknowledge_received_attachment_with(
            attachment,
            context.manifest.total_chunks,
            async |index| {
                ack_dm_attachment_chunk_via_relay_quic(engine, pool, context, index).await?;
                Ok(())
            },
        )
        .await
    }

    #[cfg(test)]
    fn verify_persist_dm_attachment(
        &mut self,
        attachment: &SdkDmAttachmentRef,
        download: &DmAttachmentDownload,
        object_key: [u8; 32],
    ) -> Result<VerifiedAttachmentImport, SdkError> {
        let object_key = zeroize::Zeroizing::new(object_key);
        self.verify_persist_dm_attachment_retained(
            attachment,
            download,
            *object_key,
            ObjectRetention::Imported,
        )
    }

    fn verify_persist_dm_attachment_retained(
        &mut self,
        attachment: &SdkDmAttachmentRef,
        download: &DmAttachmentDownload,
        object_key: [u8; 32],
        retention: ObjectRetention,
    ) -> Result<VerifiedAttachmentImport, SdkError> {
        let object_key = zeroize::Zeroizing::new(object_key);
        let mut check = "manifest_hash";
        let outcome = (|| {
            let ciphertext = &download.ciphertext;
            check = "manifest_hash";
            let assembled_hash = ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::OBJECT_MANIFEST,
                ciphertext,
            );
            if assembled_hash != attachment.manifest_hash {
                return Err(SdkError::LocalBus("DM attachment manifest hash mismatch".to_owned()));
            }
            let mut staged = ObjectStore::new();
            let object = staged.put_received_encrypted_object_with_key(
                &attachment.object_id,
                &attachment.manifest_hash,
                ciphertext,
                &attachment.plaintext_hash,
                *object_key,
            );
            check = "content_decrypt";
            let plaintext = zeroize::Zeroizing::new(staged.decrypt_object(&object.object_id)?);
            check = "plaintext_hash";
            let plaintext_hash = verify_attachment_plaintext(attachment, &plaintext)?;
            self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
                check = "object_persist";
                self.persist_object_if_unlocked(&object, Some(&object_key), retention)?;
                check = "transfer_persist";
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
                Ok(())
            })?;
            self.object_store.cache_persisted_object(object.clone(), Some(*object_key));
            Ok(VerifiedAttachmentImport { object, plaintext, plaintext_hash })
        })();
        super::attachment_diagnostics::checked(outcome, &attachment.object_id, check)
    }

    async fn download_dm_attachment_ciphertext_via_gateway(
        &self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        attachment: &SdkDmAttachmentRef,
        object_key: zeroize::Zeroizing<[u8; 32]>,
        relay_service_key_base64: Option<&str>,
    ) -> Result<DmAttachmentDownload, SdkError> {
        let options = self
            .relay_transfer_options(
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
            &self.owned_device_identity()?,
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
        let mut session = ObjectSyncSession::new(manifest.clone(), *object_key);
        let expires_at = relay_expires_at();
        let transfer_id = object_transfer_id(
            &attachment.object_id,
            &attachment.manifest_hash,
            OBJECT_TRANSFER_DOWNLOAD,
        );
        let mut completed = Vec::new();
        let mut done_bytes = 0_u64;
        for chunk_index in 0..manifest.total_chunks {
            let cached = self.received_attachment_chunk(attachment, chunk_index)?;
            let fresh = cached.is_none();
            let plaintext_chunk = match cached {
                Some(payload) => DmAttachmentChunk {
                    len: u64::try_from(
                        decrypt_chunk_payload(&object_key, &manifest, &payload)?.len(),
                    )
                    .unwrap_or(0),
                    payload,
                },
                None => {
                    fetch_dm_attachment_chunk_via_gateway(
                        engine,
                        pool,
                        &DmAttachmentFetch {
                            options: &options,
                            branch: &branch,
                            attachment: Some(attachment),
                            object: &object_stub,
                            manifest: &manifest,
                            object_key: *object_key,
                        },
                        chunk_index,
                    )
                    .await?
                }
            };
            validate_dm_attachment_chunk(attachment, chunk_index, &plaintext_chunk)?;
            session.receive_chunk(plaintext_chunk.payload.clone(), &branch)?;
            if fresh {
                self.persist_received_attachment_chunk(attachment, &plaintext_chunk.payload)?;
            }
            completed.push(chunk_index);
            done_bytes = done_bytes.saturating_add(plaintext_chunk.len);
            // Cached chunks are already durable. Rewriting their payload and transfer snapshot
            // can exhaust every retry window before the importer reaches its outstanding ACKs.
            if fresh {
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
        let prepared = self.object_store.prepare_encrypted_object(object_id, plaintext)?;
        self.persist_object_if_unlocked(
            prepared.object(),
            Some(prepared.object_key()),
            ObjectRetention::Standalone,
        )?;
        Ok(self.object_store.install_prepared_object(prepared))
    }

    /// Replaces only an explicitly expected, unowned identity. Existing message owners refuse it.
    /// # Errors
    /// Returns typed erasure/conflict errors or encryption/storage failures.
    pub fn replace_encrypted_object(
        &mut self,
        object_id: &str,
        expected_manifest: Option<&str>,
        plaintext: &[u8],
    ) -> Result<EncryptedObject, SdkError> {
        let prepared = self.object_store.prepare_encrypted_object(object_id, plaintext)?;
        let object = prepared.object();
        self.account_db()?.replace_object(
            expected_manifest,
            &ObjectWrite {
                object_id: &object.object_id,
                manifest_hash: &object.manifest_hash,
                nonce: &object.nonce,
                ciphertext: &object.ciphertext,
                plaintext_hash: &object.plaintext_hash,
                tombstoned: false,
                backup_excluded: false,
                content_key: Some(prepared.object_key()),
                object: &persisted_descriptor(object),
                updated_at: now_unix_timestamp(),
            },
        )?;
        Ok(self.object_store.install_prepared_object(prepared))
    }

    #[cfg(test)]
    pub(crate) fn prepare_history_transport(
        &mut self,
        object_id: &str,
        plaintext: &[u8],
        messages: &[DirectMessageRecord],
    ) -> Result<EncryptedObject, SdkError> {
        let prepared = self.object_store.prepare_encrypted_object(object_id, plaintext)?;
        let object = prepared.object();
        self.account_db()?.write_transaction(|| -> Result<(), SdkError> {
            self.persist_object_if_unlocked(
                object,
                Some(prepared.object_key()),
                ObjectRetention::OwnDeviceTransport,
            )?;
            self.bind_history_transport_owners::<false>(
                object_id,
                &object.manifest_hash,
                plaintext,
                messages,
                false,
            )?;
            Ok(())
        })?;
        Ok(self.object_store.install_prepared_object(prepared))
    }

    #[cfg(test)]
    pub(super) fn bind_history_transport_owners<const CONSUME_ERASED: bool>(
        &self,
        object_id: &str,
        manifest_hash: &str,
        plaintext: &[u8],
        messages: &[DirectMessageRecord],
        consumed: bool,
    ) -> Result<bool, SdkError> {
        let owners = history_ownership::from_bytes(plaintext)?;
        let safe_deleted = messages
            .iter()
            .filter(|message| message.deleted)
            .map(|message| message.message_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for (wire, manifest) in &owners.objects {
            self.account_db()?.retain_transport_dependency(
                object_id,
                manifest_hash,
                wire,
                manifest,
            )?;
        }
        let mut retire = false;
        for owner in &owners.messages {
            if safe_deleted.contains(owner.as_str()) {
                continue;
            }
            if self.account_db()?.message_is_deleted(owner)? {
                if consumed {
                    retire = true;
                    continue;
                }
                return Err(SdkError::ObjectErased);
            }
            let message_id = owner;
            let hash = ramflux_crypto::blake3_256_base64url(
                "ramflux.object.transport.owner.v1",
                &ramflux_protocol::canonical_json_bytes(&(object_id, manifest_hash, message_id))?,
            );
            let registration = self
                .account_db()?
                .register_object_reference(
                    ramflux_storage::ObjectReferenceAdmission::OwnCopy,
                    &ramflux_storage::ObjectReferenceOwner {
                        reference_hash: &hash,
                        wire_id: object_id,
                        manifest_hash,
                        selector: object_id,
                        message_id,
                        reference: &serde_json::json!({}),
                        metadata: &serde_json::json!({}),
                    },
                )
                .map_err(SdkError::from);
            match registration {
                Ok(()) => {}
                Err(SdkError::ObjectErased) if CONSUME_ERASED => {
                    retire = true;
                }
                Err(error) => return Err(error),
            }
        }

        if retire {
            self.account_db()?.retire_transport_object(object_id, manifest_hash)?;
        }
        Ok(retire)
    }

    /// T25-A2 (OBJ-IPC-01) P0-1: prepare the whole-object encryption (fresh key + AEAD seal)
    /// WITHOUT publishing it to the in-memory store.
    ///
    /// # Errors
    /// Returns an error when the OS CSPRNG cannot generate an object key.
    pub(crate) fn prepare_encrypted_object(
        &self,
        object_id: &str,
        plaintext: &[u8],
    ) -> Result<PreparedEncryptedObject, SdkError> {
        Ok(self.object_store.prepare_encrypted_object(object_id, plaintext)?)
    }

    /// T25-A2 (OBJ-IPC-01) P0-1: atomically persist {object row + key} and set the operation
    /// record to `LocalCommitted` in ONE `SQLCipher` transaction, then install the prepared object
    /// into the in-memory store. If the durable commit fails the prepared object — and its key —
    /// is dropped zeroized and nothing is installed (fail closed, no half state).
    ///
    /// # Errors
    /// Returns an error when the account DB is locked or the transaction fails.
    pub(crate) fn commit_prepared_object_local(
        &mut self,
        prepared: PreparedEncryptedObject,
        operation_id: &str,
        request_hash: &str,
        created_at: i64,
        now: i64,
    ) -> Result<EncryptedObject, SdkError> {
        {
            let object = prepared.object();
            let object_write = ObjectWrite {
                object_id: &object.object_id,
                manifest_hash: &object.manifest_hash,
                nonce: &object.nonce,
                ciphertext: &object.ciphertext,
                plaintext_hash: &object.plaintext_hash,
                tombstoned: object.tombstoned,
                backup_excluded: object.backup_excluded,
                content_key: Some(prepared.object_key()),
                object: &persisted_descriptor(object),
                updated_at: now,
            };
            let operation = ObjectOperationWrite {
                object_id: &object.object_id,
                operation_id,
                state: OBJECT_OPERATION_LOCAL_COMMITTED,
                request_hash,
                manifest_hash: Some(&object.manifest_hash),
                plaintext_hash: Some(&object.plaintext_hash),
                terminal_result: None,
                last_error: None,
                created_at,
                updated_at: now,
            };
            self.account_db()?.commit_object_local(&object_write, &operation)?;
        }
        Ok(self.object_store.install_prepared_object(prepared))
    }

    /// Looks up an installed/adopted object by id from the in-memory store.
    pub(crate) fn object_store_object(
        &self,
        object_id: &str,
    ) -> Result<Option<EncryptedObject>, SdkError> {
        if let Some(db) = self.active_account_db.as_ref() {
            db.check_object_access(object_id)?;
        }
        let alias = self.received_object_alias(object_id)?;
        let wire = alias.as_ref().map_or(object_id, |(wire, _)| wire);
        if let Some(db) = self.active_account_db.as_ref() {
            for id in std::iter::once(object_id).chain((wire != object_id).then_some(wire)) {
                if db.object_is_tombstoned(id)? {
                    return Ok(db.load_object::<EncryptedObject>(id)?.map(|(object, _)| object));
                }
            }
        }
        let object = if let Some(object) = self.object_store.cached_object(wire) {
            Some(object.clone())
        } else if let Some(db) = self.active_account_db.as_ref() {
            db.load_object::<EncryptedObject>(wire)?.map(|(object, _)| object)
        } else {
            None
        };
        let object = object.filter(|object| {
            alias.as_ref().is_none_or(|(_, manifest)| object.manifest_hash == *manifest)
        });
        if let (Some(db), Some(object)) = (self.active_account_db.as_ref(), object.as_ref()) {
            db.check_object_identity(&object.object_id, &object.manifest_hash)?;
        }
        Ok(object)
    }

    pub(super) fn object_content_key(&self, object_id: &str) -> Result<[u8; 32], SdkError> {
        if let Some(db) = self.active_account_db.as_ref() {
            db.check_object_access(object_id)?;
        }
        if let Some(object) = self.object_store.cached_object(object_id) {
            if let Some(db) = self.active_account_db.as_ref() {
                db.check_object_identity(object_id, &object.manifest_hash)?;
            }
            return Ok(self.object_store.object_key(object_id)?);
        }
        let Some(db) = self.active_account_db.as_ref() else {
            return Err(SyncError::ObjectKeyMissing.into());
        };
        db.load_object::<EncryptedObject>(object_id)?
            .and_then(|(_, key)| key)
            .ok_or_else(|| SyncError::ObjectKeyMissing.into())
    }

    pub(crate) fn persisted_objects(&self) -> Result<Vec<EncryptedObject>, SdkError> {
        match self.active_account_db.as_ref() {
            Some(db) => {
                let (objects, mut keys) = db.load_objects::<EncryptedObject>()?;
                for key in keys.values_mut() {
                    zeroize::Zeroize::zeroize(key);
                }
                Ok(objects)
            }
            None => Ok(self.object_store.objects()),
        }
    }

    /// Reads the durable reconciliation record for `object_id`, if any.
    ///
    /// # Errors
    /// Returns an error when the account DB is locked.
    pub(crate) fn object_operation(
        &self,
        object_id: &str,
    ) -> Result<Option<ObjectOperationRecord>, SdkError> {
        Ok(self.account_db()?.object_operation(object_id)?)
    }

    /// Upserts the reconciliation record for `object_id`.
    ///
    /// # Errors
    /// Returns an error when the account DB is locked or the write fails.
    pub(crate) fn upsert_object_operation(
        &self,
        write: &ObjectOperationWrite<'_>,
    ) -> Result<(), SdkError> {
        self.account_db()?.upsert_object_operation(write)?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn decrypt_object(&self, object_id: &str) -> Result<Vec<u8>, SdkError> {
        let alias = self.received_object_alias(object_id)?;
        if let Some(db) = self.active_account_db.as_ref() {
            db.check_object_access(object_id)?;
            let wire = alias.as_ref().map_or(object_id, |(wire, _)| wire.as_str());
            if wire != object_id {
                db.check_object_access(wire)?;
            }
            if db.object_is_tombstoned(object_id)?
                || (wire != object_id && db.object_is_tombstoned(wire)?)
            {
                return Err(SyncError::ObjectTombstoned.into());
            }
        }
        let object = self.object_store_object(object_id)?.ok_or(SyncError::ObjectNotFound)?;
        let wire = &object.object_id;
        let mut plaintext =
            zeroize::Zeroizing::new(if self.object_store.cached_object(wire).is_some() {
                self.object_store.decrypt_object(wire)?
            } else {
                let db = self.active_account_db.as_ref().ok_or(SyncError::ObjectNotFound)?;
                let (persisted, key) =
                    db.load_object::<EncryptedObject>(wire)?.ok_or(SyncError::ObjectNotFound)?;
                let mut single = ObjectStore::new();
                single.cache_persisted_object(persisted, key);
                single.decrypt_object(wire)?
            });
        if let Some(db) = self.active_account_db.as_ref() {
            db.check_object_identity(wire, &object.manifest_hash)?;
        }
        Ok(std::mem::take(&mut *plaintext))
    }

    /// # Errors
    /// Returns an error when the object does not exist or cannot be tombstoned.
    pub fn tombstone_object(&mut self, object_id: &str) -> Result<(), SdkError> {
        if let Some(db) = self.active_account_db.as_ref() {
            db.check_object_access(object_id)?;
        }
        if self.object_store.cached_object(object_id).is_none() {
            let db = self.active_account_db.as_ref().ok_or(SyncError::ObjectNotFound)?;
            let (object, key) =
                db.load_object::<EncryptedObject>(object_id)?.ok_or(SyncError::ObjectNotFound)?;
            self.object_store.cache_persisted_object(object, key);
        }
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
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        object_id: &str,
        options: &RelayTransferOptions,
    ) -> Result<(), SdkError> {
        if relay_quic_config(options)?.is_none() {
            return Err(SdkError::CapabilityDenied(
                "v3 relay tombstone requires gateway-issued QUIC configuration".to_owned(),
            ));
        }
        let object = self.object_store_object(object_id)?.ok_or(SyncError::ObjectNotFound)?;
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
            &self.owned_device_identity()?,
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

    pub(crate) async fn upload_object_to_relay_via_gateway(
        &self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        object_id: &str,
        chunk_size: usize,
        options: &RelayTransferOptions,
    ) -> Result<SdkObjectTransferStatus, SdkError> {
        let object = self.object_store_object(object_id)?.ok_or(SyncError::ObjectNotFound)?;
        self.upload_object_to_relay_inner_via_gateway(engine, pool, &object, chunk_size, options)
            .await
    }

    #[allow(clippy::too_many_lines)]
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn download_object_from_relay_via_gateway(
        &mut self,
        engine: &mut impl GatewaySessionAccess,
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
        let object = self.object_store_object(object_id)?.ok_or(SyncError::ObjectNotFound)?;
        let object_key = zeroize::Zeroizing::new(self.object_content_key(object_id)?);
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
            // HTTP fallback.

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

    pub(crate) async fn upload_object_to_relay_inner_via_gateway(
        &self,
        engine: &mut impl GatewaySessionAccess,
        pool: &ramflux_transport::RelayQuicPool,
        object: &EncryptedObject,
        chunk_size: usize,
        options: &RelayTransferOptions,
    ) -> Result<SdkObjectTransferStatus, SdkError> {
        let input = self.prepare_upload_input(
            std::sync::Arc::new(object.clone()),
            chunk_size,
            options.clone(),
        )?;
        upload_job::run(engine, pool, &input, |progress| {
            std::future::ready(self.persist_upload_progress(&input, &progress).map(|_| ()))
        })
        .await?;
        let record = self
            .account_db()?
            .object_transfer(&object.object_id, Some(OBJECT_TRANSFER_UPLOAD))?
            .ok_or_else(|| SdkError::LocalBus("missing object transfer state".into()))?;
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

fn validate_dm_attachment_chunk(
    reference: &SdkDmAttachmentRef,
    index: u32,
    chunk: &DmAttachmentChunk,
) -> Result<(), SdkError> {
    let expected_len = reference
        .cipher_size
        .saturating_sub(u64::from(index) * reference.chunk_size as u64)
        .min(reference.chunk_size as u64);
    if chunk.payload.chunk_index != index || chunk.len != expected_len {
        return Err(SdkError::LocalBus("DM attachment chunk size or index mismatch".to_owned()));
    }
    Ok(())
}

struct DmAttachmentFetch<'a> {
    options: &'a RelayTransferOptions,
    branch: &'a DeviceBranch,
    attachment: Option<&'a SdkDmAttachmentRef>,
    object: &'a EncryptedObject,
    manifest: &'a ChunkManifest,
    object_key: [u8; 32],
}

impl Drop for DmAttachmentFetch<'_> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.object_key);
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

    fn slot_test_client(
        test_name: &str,
    ) -> Result<(ramflux_test_support::TestPath, RamfluxClient), SdkError> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let root = ramflux_test_support::TestPath::new()
            .expect("test: allocate fixture directory")
            .child(format!("ramflux-sdk-slot-{test_name}-{}-{nanos}", std::process::id()));
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
    fn retired_object_key_slot_is_refused_without_changing_the_receive_checkpoint()
    -> Result<(), SdkError> {
        let (_root, client) = slot_test_client("defer-commit")?;
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
            source_principal_commitment: None,
            x3dh: None,
            ciphertext,
        };

        assert!(
            matches!(
                client.decrypt_object_key_slot(&slot),
                Err(SdkError::GeneratedRefused { code: crate::GeneratedRefusalCode::Content, .. })
            ),
            "generation one must refuse the retired key-slot codec"
        );
        assert_eq!(
            client.projection_checkpoint(&checkpoint_name)?,
            before,
            "refusing the retired key slot must preserve its receive checkpoint"
        );
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
    use super::{SdkError, relay_transport::issue_relay_request_with_single_retry};
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
        assert!(matches!(result, Err(SdkError::Transport(TransportError::Tls(_)))));
        assert_eq!(seen.len(), 1);
    }

    #[tokio::test]
    async fn protocol_failure_is_not_retried() {
        let request = frame();
        let (result, seen) =
            drive(&request, vec![Err(RelayQuicRequestError::Protocol("partial".to_owned()))]).await;
        assert!(matches!(result, Err(SdkError::Transport(TransportError::Protocol(_)))));
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

fn verify_attachment_plaintext(
    attachment: &SdkDmAttachmentRef,
    plaintext: &[u8],
) -> Result<String, SdkError> {
    let hash = ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, plaintext);
    if hash != attachment.plaintext_hash {
        return Err(SdkError::LocalBus("DM attachment plaintext hash mismatch".to_owned()));
    }
    Ok(hash)
}

// Payload bytes live once in the incremental BLOB column, never duplicated as a JSON array.
fn persisted_descriptor(object: &EncryptedObject) -> serde_json::Value {
    serde_json::json!({"object_id":object.object_id,"manifest_hash":object.manifest_hash,
        "nonce":object.nonce,"ciphertext":"ramflux:column:1","plaintext_hash":object.plaintext_hash,
        "tombstoned":object.tombstoned,"backup_excluded":object.backup_excluded})
}

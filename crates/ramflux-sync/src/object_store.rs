// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::SyncError;
use ramflux_core::ObjectId;
use ramflux_crypto::DeviceBranch;
use ramflux_protocol::{decode_base64url, encode_base64url};

const OBJECT_SYNC_V1: &str = "object_sync_v1";
const DEFAULT_SYNC_SESSION_ID: &str = "local_object_sync_session";
const DEFAULT_PEER_DEVICE_ID: &str = "local_peer_device";
const DEFAULT_RESUME_TOKEN_EXPIRES_AT: i64 = 1_760_086_400;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct EncryptedObject {
    pub object_id: String,
    pub manifest_hash: String,
    pub nonce: String,
    pub ciphertext: Vec<u8>,
    pub plaintext_hash: String,
    pub tombstoned: bool,
    pub backup_excluded: bool,
}

/// T25-A2 (OBJ-IPC-01) P0-1: a whole-object encryption that has been *prepared* (fresh object key
/// derived + AEAD sealed) but NOT yet published to the in-memory [`ObjectStore`]. Holding the
/// prepared material separately lets the caller run ONE durable `SQLCipher` transaction
/// ({object row + key} + operation record → `LocalCommitted`) and only then [`install`] it, so a
/// crash before that commit leaves no stored object and no half-published in-memory state.
///
/// Security gate: this value carries the NEW object key. It deliberately derives neither `Debug`,
/// `Serialize`, nor `Clone` — the key must never be logged or copied — and the key is wrapped in
/// [`zeroize::Zeroizing`] so any early return before [`ObjectStore::install_prepared_object`] drops
/// it zeroized. Ownership transfers one-way into the store on install (the value is consumed).
///
/// [`install`]: ObjectStore::install_prepared_object
pub struct PreparedEncryptedObject {
    object: EncryptedObject,
    object_key: zeroize::Zeroizing<[u8; 32]>,
}

impl PreparedEncryptedObject {
    /// The public (non-secret) encrypted-object descriptor: id, manifest/plaintext hashes,
    /// nonce, ciphertext. Never contains the key.
    #[must_use]
    pub fn object(&self) -> &EncryptedObject {
        &self.object
    }

    /// The freshly derived object key. Borrow only to hand it to the durable account-DB write;
    /// never log it or copy it into a response/terminal result.
    #[must_use]
    pub fn object_key(&self) -> &[u8; 32] {
        &self.object_key
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObjectStore {
    objects: BTreeMap<String, EncryptedObject>,
    object_keys: BTreeMap<String, [u8; 32]>,
}

impl ObjectStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// T25-A2 (OBJ-IPC-01) P0-1: derive a fresh object key and AEAD-seal `plaintext` WITHOUT
    /// publishing anything to the in-memory store. The returned [`PreparedEncryptedObject`] holds
    /// the (zeroize-on-drop) key; the caller durably commits {object row + key} + the operation
    /// record in one `SQLCipher` transaction, then [`install_prepared_object`] to publish it.
    ///
    /// The crypto here is byte-for-byte identical to the previous `put_encrypted_object` body — no
    /// AEAD / nonce / manifest-hash / `EncryptedObject` layout change.
    ///
    /// # Errors
    /// Returns an error when the operating system CSPRNG cannot generate an object key.
    ///
    /// [`install_prepared_object`]: ObjectStore::install_prepared_object
    pub fn prepare_encrypted_object(
        &self,
        object_id: &str,
        plaintext: &[u8],
    ) -> Result<PreparedEncryptedObject, SyncError> {
        let object_id = ObjectId::new(object_id)?;
        let object_key = ramflux_crypto::random_32()?;
        let nonce = object_nonce(object_id.as_str());
        let ciphertext = encrypt_aead(&object_key, &nonce, object_id.as_str(), plaintext)?;
        let object_id = object_id.into_string();
        let plaintext_hash =
            ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, plaintext);
        let manifest_hash = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::OBJECT_MANIFEST,
            &ciphertext,
        );
        Ok(PreparedEncryptedObject {
            object: EncryptedObject {
                object_id,
                manifest_hash,
                nonce: encode_base64url(nonce),
                ciphertext,
                plaintext_hash,
                tombstoned: false,
                backup_excluded: false,
            },
            object_key: zeroize::Zeroizing::new(object_key),
        })
    }

    /// Publish a [`PreparedEncryptedObject`] into the in-memory store, consuming it (one-way
    /// ownership transfer). Returns the installed [`EncryptedObject`]. The wrapped key is copied
    /// into the key map and the (zeroizing) prepared wrapper is dropped zeroized.
    #[must_use]
    pub fn install_prepared_object(
        &mut self,
        prepared: PreparedEncryptedObject,
    ) -> EncryptedObject {
        let PreparedEncryptedObject { object, object_key } = prepared;
        self.objects.insert(object.object_id.clone(), object.clone());
        self.object_keys.insert(object.object_id.clone(), *object_key);
        object
    }

    /// # Errors
    /// Returns an error when the operating system CSPRNG cannot generate an object key.
    pub fn put_encrypted_object(
        &mut self,
        object_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedObject, SyncError> {
        let prepared = self.prepare_encrypted_object(object_id, plaintext)?;
        Ok(self.install_prepared_object(prepared))
    }

    /// # Errors
    /// Returns an error when the operating system CSPRNG cannot generate an object key.
    pub fn put_short_term_transport_object(
        &mut self,
        object_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedObject, SyncError> {
        let mut object = self.put_encrypted_object(object_id, plaintext)?;
        object.backup_excluded = true;
        self.objects.insert(object_id.to_owned(), object.clone());
        Ok(object)
    }

    #[must_use]
    pub fn put_received_encrypted_object(
        &mut self,
        object_id: &str,
        manifest_hash: &str,
        ciphertext: &[u8],
        plaintext_hash: &str,
    ) -> EncryptedObject {
        let object = EncryptedObject {
            object_id: object_id.to_owned(),
            manifest_hash: manifest_hash.to_owned(),
            nonce: encode_base64url(object_nonce(object_id)),
            ciphertext: ciphertext.to_vec(),
            plaintext_hash: plaintext_hash.to_owned(),
            tombstoned: false,
            backup_excluded: false,
        };
        self.objects.insert(object_id.to_owned(), object.clone());
        object
    }

    #[must_use]
    pub fn put_received_encrypted_object_with_key(
        &mut self,
        object_id: &str,
        manifest_hash: &str,
        ciphertext: &[u8],
        plaintext_hash: &str,
        object_key: [u8; 32],
    ) -> EncryptedObject {
        let object = self.put_received_encrypted_object(
            object_id,
            manifest_hash,
            ciphertext,
            plaintext_hash,
        );
        self.object_keys.insert(object_id.to_owned(), object_key);
        object
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn decrypt_object(&self, object_id: &str) -> Result<Vec<u8>, SyncError> {
        let object = self.objects.get(object_id).ok_or(SyncError::ObjectNotFound)?;
        if object.tombstoned {
            return Err(SyncError::ObjectTombstoned);
        }
        let object_key = self.object_keys.get(object_id).ok_or(SyncError::ObjectKeyMissing)?;
        let nonce = decode_nonce(&object.nonce)?;
        decrypt_aead(object_key, &nonce, object_id, &object.ciphertext)
    }

    /// # Errors
    /// Returns an error when the object key is missing.
    pub fn object_key(&self, object_id: &str) -> Result<[u8; 32], SyncError> {
        self.object_keys.get(object_id).copied().ok_or(SyncError::ObjectKeyMissing)
    }

    #[must_use]
    pub fn objects(&self) -> Vec<EncryptedObject> {
        self.objects.values().cloned().collect()
    }

    pub fn replace_persisted(
        &mut self,
        objects: Vec<EncryptedObject>,
        object_keys: BTreeMap<String, [u8; 32]>,
    ) {
        self.objects =
            objects.into_iter().map(|object| (object.object_id.clone(), object)).collect();
        self.object_keys = object_keys;
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn sync_to_peer(&self, object_id: &str, peer: &mut Self) -> Result<(), SyncError> {
        let object = self.objects.get(object_id).ok_or(SyncError::ObjectNotFound)?;
        let object_key =
            self.object_keys.get(object_id).copied().ok_or(SyncError::ObjectKeyMissing)?;
        let manifest = chunk_manifest_for_object(object_id, &object.ciphertext, 64 * 1024, None);
        let mut session = ObjectSyncSession::new(manifest.clone(), object_key);
        for chunk_index in 0..manifest.total_chunks {
            let start = usize::try_from(chunk_index)
                .unwrap_or(usize::MAX)
                .saturating_mul(manifest.chunk_size);
            let end = start.saturating_add(manifest.chunk_size).min(object.ciphertext.len());
            session.store_received_chunk(chunk_payload(
                &object_key,
                &manifest,
                chunk_index,
                &object.ciphertext[start..end],
            ))?;
        }
        let assembled = session.assemble()?;
        let _received = peer.put_received_encrypted_object_with_key(
            object_id,
            &object.manifest_hash,
            &assembled,
            &object.plaintext_hash,
            object_key,
        );
        Ok(())
    }

    #[must_use]
    pub fn relay_history_bundle(&self, encrypted_bundle: &[u8]) -> RelayOpaqueBundle {
        RelayOpaqueBundle {
            ciphertext_hash: ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::OBJECT,
                encrypted_bundle,
            ),
            plaintext_visible: false,
        }
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn tombstone(&mut self, object_id: &str) -> Result<(), SyncError> {
        let object = self.objects.get_mut(object_id).ok_or(SyncError::ObjectNotFound)?;
        object.tombstoned = true;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn exclude_from_backup(&mut self, object_id: &str) -> Result<(), SyncError> {
        let object = self.objects.get_mut(object_id).ok_or(SyncError::ObjectNotFound)?;
        object.backup_excluded = true;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn apply_tombstone_from(
        &mut self,
        source: &Self,
        object_id: &str,
    ) -> Result<(), SyncError> {
        let source_object = source.objects.get(object_id).ok_or(SyncError::ObjectNotFound)?;
        if source_object.tombstoned { self.tombstone(object_id) } else { Ok(()) }
    }

    #[cfg(test)]
    #[must_use]
    pub fn backup_manifest(&self, request: BackupManifestRequest) -> BackupManifest {
        let mut manifest = self.backup_manifest_unsigned(request);
        manifest.signer_public_key = ramflux_crypto::fixture_public_key_base64url();
        manifest.signature = backup_manifest_signature(&manifest);
        manifest
    }

    fn backup_manifest_unsigned(&self, request: BackupManifestRequest) -> BackupManifest {
        let mut object_manifest_hashes = Vec::new();
        let mut object_tombstone_heads = Vec::new();
        for object in self.objects.values() {
            if object.tombstoned {
                object_tombstone_heads.push(object_tombstone_head(object));
            } else if !object.backup_excluded {
                object_manifest_hashes.push(object.manifest_hash.clone());
            }
        }
        object_manifest_hashes.sort();
        object_tombstone_heads.sort();
        BackupManifest {
            backup_id: request.backup_id,
            source_device_id: request.source_device_id,
            target_device_id: request.target_device_id,
            principal_commitment: request.principal_commitment,
            event_batch_heads: request.event_batch_heads,
            object_manifest_hashes,
            object_tombstone_heads,
            projection_checkpoint_hash: request.projection_checkpoint_hash,
            created_at: request.created_at,
            signer_public_key: String::new(),
            signature: String::new(),
        }
    }

    /// # Errors
    /// Returns an error when the device branch cannot sign the manifest body.
    pub fn backup_manifest_with_device_branch(
        &self,
        request: BackupManifestRequest,
        device_branch: &DeviceBranch,
    ) -> Result<BackupManifest, SyncError> {
        let mut manifest = self.backup_manifest_unsigned(request);
        manifest.signer_public_key =
            encode_base64url(device_branch.signing_key.verifying_key().to_bytes());
        manifest.signature = backup_manifest_device_signature(&manifest, device_branch)?;
        Ok(manifest)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn import_backup_manifest(
        &self,
        manifest: &BackupManifest,
        imported_at: i64,
    ) -> Result<BackupCheckpoint, SyncError> {
        verify_backup_manifest(manifest)?;
        Ok(BackupCheckpoint {
            backup_id: manifest.backup_id.clone(),
            source_device_id: manifest.source_device_id.clone(),
            target_device_id: manifest.target_device_id.clone(),
            principal_commitment: manifest.principal_commitment.clone(),
            event_batch_head_count: u32::try_from(manifest.event_batch_heads.len())
                .unwrap_or(u32::MAX),
            object_manifest_count: u32::try_from(manifest.object_manifest_hashes.len())
                .unwrap_or(u32::MAX),
            object_tombstone_count: u32::try_from(manifest.object_tombstone_heads.len())
                .unwrap_or(u32::MAX),
            projection_checkpoint_hash: manifest.projection_checkpoint_hash.clone(),
            imported_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayOpaqueBundle {
    pub ciphertext_hash: String,
    pub plaintext_visible: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupManifest {
    pub backup_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub principal_commitment: String,
    pub event_batch_heads: Vec<String>,
    pub object_manifest_hashes: Vec<String>,
    pub object_tombstone_heads: Vec<String>,
    pub projection_checkpoint_hash: Option<String>,
    pub created_at: i64,
    pub signer_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupCheckpoint {
    pub backup_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub principal_commitment: String,
    pub event_batch_head_count: u32,
    pub object_manifest_count: u32,
    pub object_tombstone_count: u32,
    pub projection_checkpoint_hash: Option<String>,
    pub imported_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupManifestRequest {
    pub backup_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub principal_commitment: String,
    pub event_batch_heads: Vec<String>,
    pub projection_checkpoint_hash: Option<String>,
    pub created_at: i64,
}

/// # Errors
/// Returns an error when validation, serialization, storage, or state checks fail.
pub fn verify_backup_manifest(manifest: &BackupManifest) -> Result<(), SyncError> {
    let body = backup_manifest_signing_body(manifest);
    ramflux_crypto::verify_device_branch_signature(
        &manifest.signer_public_key,
        &body,
        &manifest.signature,
    )
    .map_err(|_err| SyncError::BackupManifestSignatureInvalid)
}

#[cfg(test)]
#[must_use]
pub fn backup_manifest_signature(manifest: &BackupManifest) -> String {
    backup_manifest_signature_with_seed(manifest, ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES)
        .unwrap_or_default()
}

/// # Errors
/// Returns an error when canonical signing bytes cannot be produced.
pub fn backup_manifest_device_signature(
    manifest: &BackupManifest,
    device_branch: &DeviceBranch,
) -> Result<String, SyncError> {
    Ok(ramflux_crypto::sign_with_device_branch(
        device_branch,
        &backup_manifest_signing_body(manifest),
    )?)
}

#[cfg(test)]
fn backup_manifest_signature_with_seed(
    manifest: &BackupManifest,
    seed: [u8; 32],
) -> Result<String, SyncError> {
    Ok(ramflux_crypto::sign_protocol_object_with_seed(
        &backup_manifest_signing_body(manifest),
        seed,
    )?)
}

#[derive(Serialize)]
struct BackupManifestSigningBody<'a> {
    backup_id: &'a str,
    source_device_id: &'a str,
    target_device_id: &'a str,
    principal_commitment: &'a str,
    event_batch_heads: &'a [String],
    object_manifest_hashes: &'a [String],
    object_tombstone_heads: &'a [String],
    projection_checkpoint_hash: &'a Option<String>,
    created_at: i64,
}

fn backup_manifest_signing_body(manifest: &BackupManifest) -> BackupManifestSigningBody<'_> {
    BackupManifestSigningBody {
        backup_id: &manifest.backup_id,
        source_device_id: &manifest.source_device_id,
        target_device_id: &manifest.target_device_id,
        principal_commitment: &manifest.principal_commitment,
        event_batch_heads: &manifest.event_batch_heads,
        object_manifest_hashes: &manifest.object_manifest_hashes,
        object_tombstone_heads: &manifest.object_tombstone_heads,
        projection_checkpoint_hash: &manifest.projection_checkpoint_hash,
        created_at: manifest.created_at,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ChunkManifest {
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_size: usize,
    pub total_chunks: u32,
    pub object_created_group_key_epoch: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ChunkPayload {
    pub chunk_index: u32,
    pub nonce: String,
    pub ciphertext: Vec<u8>,
    pub cipher_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ResumeToken {
    pub object_id: String,
    pub manifest_hash: String,
    pub next_missing_chunk: Option<u32>,
    pub received_count: u32,
    pub session_id: String,
    pub peer_device_id: String,
    pub completed_bitmap_hash: String,
    pub expires_at: i64,
    pub signer_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct MissingChunkBitmap {
    pub total_chunks: u32,
    pub missing_indices: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectSyncSession {
    manifest: ChunkManifest,
    content_key: [u8; 32],
    session_id: String,
    peer_device_id: String,
    resume_expires_at: i64,
    chunks: BTreeMap<u32, ReceivedChunk>,
    quarantine: Vec<ObjectTransferError>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReceivedChunk {
    payload: ChunkPayload,
    plaintext: Vec<u8>,
}

impl ObjectSyncSession {
    #[must_use]
    pub fn new(manifest: ChunkManifest, content_key: [u8; 32]) -> Self {
        Self::with_session(
            manifest,
            content_key,
            DEFAULT_SYNC_SESSION_ID,
            DEFAULT_PEER_DEVICE_ID,
            DEFAULT_RESUME_TOKEN_EXPIRES_AT,
        )
    }

    #[must_use]
    pub fn with_session(
        manifest: ChunkManifest,
        content_key: [u8; 32],
        session_id: &str,
        peer_device_id: &str,
        resume_expires_at: i64,
    ) -> Self {
        Self {
            manifest,
            content_key,
            session_id: session_id.to_owned(),
            peer_device_id: peer_device_id.to_owned(),
            resume_expires_at,
            chunks: BTreeMap::new(),
            quarantine: Vec::new(),
        }
    }

    #[must_use]
    pub fn manifest(&self) -> &ChunkManifest {
        &self.manifest
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn receive_chunk(
        &mut self,
        chunk: ChunkPayload,
        device_branch: &DeviceBranch,
    ) -> Result<ResumeToken, SyncError> {
        self.store_received_chunk(chunk)?;
        self.resume_token_with_device_branch(device_branch)
    }

    #[cfg(test)]
    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn receive_chunk_with_fixture_signer(
        &mut self,
        chunk: ChunkPayload,
    ) -> Result<ResumeToken, SyncError> {
        self.store_received_chunk(chunk)?;
        Ok(self.resume_token())
    }

    fn store_received_chunk(&mut self, chunk: ChunkPayload) -> Result<(), SyncError> {
        if chunk.chunk_index >= self.manifest.total_chunks {
            return Err(SyncError::ChunkOutOfRange);
        }
        let expected_hash =
            chunk_cipher_hash(&self.manifest.manifest_hash, chunk.chunk_index, &chunk.ciphertext);
        if chunk.cipher_hash != expected_hash {
            return Err(SyncError::ChunkHashMismatch);
        }
        let plaintext = match decrypt_chunk_payload(&self.content_key, &self.manifest, &chunk) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                self.quarantine.push(ObjectTransferError {
                    schema: "ramflux.object_transfer_error.v1".to_owned(),
                    session_id: self.session_id.clone(),
                    request_id: format!("chunk:{}", chunk.chunk_index),
                    error_code: "chunk_aead_failed".to_owned(),
                    retry_after: None,
                });
                return Err(error);
            }
        };
        self.chunks.insert(chunk.chunk_index, ReceivedChunk { payload: chunk, plaintext });
        Ok(())
    }

    #[must_use]
    pub fn missing_chunks(&self) -> MissingChunkBitmap {
        let mut missing_indices = Vec::new();
        for index in 0..self.manifest.total_chunks {
            if !self.chunks.contains_key(&index) {
                missing_indices.push(index);
            }
        }
        MissingChunkBitmap { total_chunks: self.manifest.total_chunks, missing_indices }
    }

    #[cfg(test)]
    #[must_use]
    pub fn resume_token(&self) -> ResumeToken {
        self.resume_token_with_fixture_signer()
    }

    /// # Errors
    /// Returns an error when the device branch cannot sign the token body.
    pub fn resume_token_with_device_branch(
        &self,
        device_branch: &DeviceBranch,
    ) -> Result<ResumeToken, SyncError> {
        let signer_public_key =
            encode_base64url(device_branch.signing_key.verifying_key().to_bytes());
        let mut token = self.resume_token_with_signer_public_key(signer_public_key);
        token.signature = sign_resume_token_with_device_branch(&token, device_branch)?;
        Ok(token)
    }

    #[cfg(test)]
    #[must_use]
    fn resume_token_with_fixture_signer(&self) -> ResumeToken {
        let mut token = self
            .resume_token_with_signer_public_key(ramflux_crypto::fixture_public_key_base64url());
        token.signature = sign_resume_token(&token).unwrap_or_default();
        token
    }

    #[must_use]
    fn resume_token_with_signer_public_key(&self, signer_public_key: String) -> ResumeToken {
        let missing = self.missing_chunks();
        let completed_bitmap_hash = completed_bitmap_hash(self.manifest.total_chunks, &self.chunks);
        ResumeToken {
            object_id: self.manifest.object_id.clone(),
            manifest_hash: self.manifest.manifest_hash.clone(),
            next_missing_chunk: missing.missing_indices.first().copied(),
            received_count: u32::try_from(self.chunks.len()).unwrap_or(u32::MAX),
            session_id: self.session_id.clone(),
            peer_device_id: self.peer_device_id.clone(),
            completed_bitmap_hash,
            expires_at: self.resume_expires_at,
            signer_public_key,
            signature: String::new(),
        }
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.chunks.len() == self.manifest.total_chunks as usize
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn assemble(&self) -> Result<Vec<u8>, SyncError> {
        if !self.is_complete() {
            return Err(SyncError::ObjectNotFound);
        }
        let mut bytes = Vec::new();
        for index in 0..self.manifest.total_chunks {
            let chunk = self.chunks.get(&index).ok_or(SyncError::ObjectNotFound)?;
            bytes.extend_from_slice(&chunk.plaintext);
        }
        Ok(bytes)
    }

    #[must_use]
    pub fn quarantine(&self) -> &[ObjectTransferError] {
        &self.quarantine
    }
}

#[must_use]
pub fn chunk_manifest_for_object(
    object_id: &str,
    ciphertext: &[u8],
    chunk_size: usize,
    object_created_group_key_epoch: Option<u64>,
) -> ChunkManifest {
    let safe_chunk_size = chunk_size.max(1);
    let total_chunks_usize = ciphertext.len().div_ceil(safe_chunk_size);
    let total_chunks = u32::try_from(total_chunks_usize).unwrap_or(u32::MAX);
    ChunkManifest {
        object_id: object_id.to_owned(),
        manifest_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::OBJECT_MANIFEST,
            ciphertext,
        ),
        chunk_size: safe_chunk_size,
        total_chunks,
        object_created_group_key_epoch,
    }
}

#[must_use]
pub fn chunk_payload(
    content_key: &[u8; 32],
    manifest: &ChunkManifest,
    chunk_index: u32,
    ciphertext: &[u8],
) -> ChunkPayload {
    encrypted_chunk_payload(content_key, manifest, chunk_index, ciphertext)
}

#[must_use]
pub fn encrypted_chunk_payload(
    content_key: &[u8; 32],
    manifest: &ChunkManifest,
    chunk_index: u32,
    plaintext: &[u8],
) -> ChunkPayload {
    let key = chunk_aead_key(content_key, &manifest.manifest_hash, chunk_index);
    let nonce = chunk_nonce(&manifest.manifest_hash, chunk_index);
    let associated_data = chunk_associated_data(manifest, chunk_index);
    let ciphertext = encrypt_aead_with_ad(&key, &nonce, &associated_data, plaintext)
        .unwrap_or_else(|_err| Vec::new());
    ChunkPayload {
        chunk_index,
        nonce: encode_base64url(nonce),
        cipher_hash: chunk_cipher_hash(&manifest.manifest_hash, chunk_index, &ciphertext),
        ciphertext,
    }
}

/// # Errors
/// Returns an error when the nonce is malformed or AEAD authentication fails.
pub fn decrypt_chunk_payload(
    content_key: &[u8; 32],
    manifest: &ChunkManifest,
    chunk: &ChunkPayload,
) -> Result<Vec<u8>, SyncError> {
    let nonce = decode_nonce(&chunk.nonce)?;
    let key = chunk_aead_key(content_key, &manifest.manifest_hash, chunk.chunk_index);
    let associated_data = chunk_associated_data(manifest, chunk.chunk_index);
    decrypt_aead_with_ad(&key, &nonce, &associated_data, &chunk.ciphertext)
}

#[must_use]
pub fn chunk_cipher_hash(manifest_hash: &str, chunk_index: u32, ciphertext: &[u8]) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(manifest_hash.as_bytes());
    bytes.extend_from_slice(&chunk_index.to_be_bytes());
    bytes.extend_from_slice(ciphertext);
    ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT_CHUNK_ID, &bytes)
}

#[must_use]
pub fn object_tombstone_head(object: &EncryptedObject) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(object.object_id.as_bytes());
    bytes.extend_from_slice(object.manifest_hash.as_bytes());
    bytes.extend_from_slice(if object.tombstoned { b"tombstoned" } else { b"live" });
    ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT_MANIFEST, &bytes)
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum ObjectSyncControlMessage {
    ObjectHello(ObjectHello),
    ObjectAuth(ObjectAuth),
    ObjectManifestOffer(ObjectManifestOffer),
    ObjectChunkRequest(ramflux_protocol::ObjectChunkRequest),
    ObjectChunkResponse(ObjectChunkResponse),
    ObjectChunkAck(ObjectChunkAck),
    ObjectTransferComplete(ObjectTransferComplete),
    ObjectTransferError(ObjectTransferError),
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ObjectHello {
    pub schema: String,
    pub version: u32,
    pub session_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub protocol_versions: Vec<String>,
    pub transport_backend: String,
    pub nonce: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ObjectAuth {
    pub schema: String,
    pub session_id: String,
    pub device_proof_hash: String,
    pub branch_proof_hash: String,
    pub peer_proof: PeerProof,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ObjectManifestOffer {
    pub schema: String,
    pub session_id: String,
    pub manifest_hash: String,
    pub object_manifest: ChunkManifest,
    pub offer_reason: String,
    pub tombstone_head: Option<ObjectTombstone>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ObjectChunkResponse {
    pub schema: String,
    pub session_id: String,
    pub request_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub chunk_index: u32,
    pub chunk_id: String,
    pub chunk_cipher_hash: String,
    pub cipher_size: u64,
    pub stream_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ObjectChunkAck {
    pub schema: String,
    pub session_id: String,
    pub request_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub received_bitmap: String,
    pub resume_token: ResumeToken,
    pub ack_state: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ObjectTransferComplete {
    pub schema: String,
    pub session_id: String,
    pub object_id: String,
    pub manifest_hash: String,
    pub completed_bitmap: String,
    pub completed_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ObjectTransferError {
    pub schema: String,
    pub session_id: String,
    pub request_id: String,
    pub error_code: String,
    pub retry_after: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectQuinnStreamLayout {
    ControlBidi,
    ChunkUni { stream_id: u64, chunk_index: u32 },
    ProgressBidi,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct LanAnnounce {
    pub schema: String,
    pub protocol_versions: Vec<String>,
    pub principal_commitment: String,
    pub device_id: String,
    pub device_epoch: u64,
    pub instance_id: String,
    pub lan_endpoint: String,
    pub capabilities: Vec<String>,
    pub nonce: String,
    pub ttl: u32,
    pub signer_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Default)]
pub struct LanPairingRegistry {
    highest_device_epoch: BTreeMap<String, u64>,
    pending_devices: BTreeSet<String>,
}

impl LanPairingRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    /// Returns an error for invalid signatures, epoch rollback, or principal mismatch.
    pub fn verify_announce(
        &mut self,
        announce: &LanAnnounce,
        expected_principal_commitment: &str,
        known_device: bool,
    ) -> Result<(), SyncError> {
        verify_lan_announce(announce, expected_principal_commitment)?;
        let highest = self.highest_device_epoch.entry(announce.device_id.clone()).or_default();
        if announce.device_epoch < *highest {
            return Err(SyncError::LanAnnounceEpochRollback);
        }
        *highest = announce.device_epoch;
        if known_device {
            self.pending_devices.remove(&announce.device_id);
            Ok(())
        } else {
            self.pending_devices.insert(announce.device_id.clone());
            Err(SyncError::LanPeerPending)
        }
    }

    #[must_use]
    pub fn is_pending(&self, device_id: &str) -> bool {
        self.pending_devices.contains(device_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PeerProof {
    pub session_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub principal_commitment: String,
    pub nonce: String,
    pub signer_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Default)]
pub struct PeerProofVerifier {
    used_nonces: BTreeSet<String>,
}

impl PeerProofVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    /// Returns an error when the peer proof signature is invalid, principal mismatches, or nonce
    /// has already been used.
    pub fn verify_once(
        &mut self,
        proof: &PeerProof,
        expected_principal_commitment: &str,
    ) -> Result<(), SyncError> {
        if !self.used_nonces.insert(proof.nonce.clone()) {
            return Err(SyncError::PeerProofNonceReplay);
        }
        verify_peer_proof(proof, expected_principal_commitment)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ObjectTombstone {
    pub object_id: String,
    pub manifest_hash: String,
    pub causal_event_id: String,
    pub tombstone_state: String,
    pub created_at: i64,
    pub signer_public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct SyncBatch {
    pub schema: String,
    pub cursor_id: String,
    pub device_id: String,
    pub after_inbox_seq: u64,
    pub envelopes: Vec<ramflux_protocol::Envelope>,
    pub tombstones: Vec<ObjectTombstone>,
    pub next_cursor: Option<ramflux_protocol::Cursor>,
}

#[must_use]
pub fn client_sync_path(after_inbox_seq: u64, limit: u32) -> String {
    format!("/client/v1/sync?after_inbox_seq={after_inbox_seq}&limit={limit}")
}

#[must_use]
pub fn sync_batch_v1(
    cursor_id: &str,
    device_id: &str,
    after_inbox_seq: u64,
    envelopes: Vec<ramflux_protocol::Envelope>,
    tombstones: Vec<ObjectTombstone>,
    next_cursor: Option<ramflux_protocol::Cursor>,
) -> SyncBatch {
    SyncBatch {
        schema: "ramflux.sync_batch.v1".to_owned(),
        cursor_id: cursor_id.to_owned(),
        device_id: device_id.to_owned(),
        after_inbox_seq,
        envelopes,
        tombstones,
        next_cursor,
    }
}

/// # Errors
/// Returns an error when canonicalization or signing fails.
pub fn sign_lan_announce(
    mut announce: LanAnnounce,
    device_branch: &DeviceBranch,
) -> Result<LanAnnounce, SyncError> {
    announce.signer_public_key =
        encode_base64url(device_branch.signing_key.verifying_key().to_bytes());
    announce.signature = ramflux_crypto::sign_with_device_branch(
        device_branch,
        &lan_announce_signing_body(&announce),
    )?;
    Ok(announce)
}

/// # Errors
/// Returns an error when the signature, principal commitment, or schema is invalid.
pub fn verify_lan_announce(
    announce: &LanAnnounce,
    expected_principal_commitment: &str,
) -> Result<(), SyncError> {
    if announce.schema != "ramflux.object_lan_announce.v1" {
        return Err(SyncError::LanAnnounceSignatureInvalid);
    }
    if announce.principal_commitment != expected_principal_commitment {
        return Err(SyncError::LanPeerPrincipalMismatch);
    }
    ramflux_crypto::verify_device_branch_signature(
        &announce.signer_public_key,
        &lan_announce_signing_body(announce),
        &announce.signature,
    )
    .map_err(|_err| SyncError::LanAnnounceSignatureInvalid)
}

/// # Errors
/// Returns an error when canonicalization or signing fails.
pub fn sign_peer_proof(
    session_id: &str,
    source_device_id: &str,
    target_device_id: &str,
    principal_commitment: &str,
    nonce: &str,
    device_branch: &DeviceBranch,
) -> Result<PeerProof, SyncError> {
    let mut proof = PeerProof {
        session_id: session_id.to_owned(),
        source_device_id: source_device_id.to_owned(),
        target_device_id: target_device_id.to_owned(),
        principal_commitment: principal_commitment.to_owned(),
        nonce: nonce.to_owned(),
        signer_public_key: encode_base64url(device_branch.signing_key.verifying_key().to_bytes()),
        signature: String::new(),
    };
    proof.signature =
        ramflux_crypto::sign_with_device_branch(device_branch, &peer_proof_signing_body(&proof))?;
    Ok(proof)
}

/// # Errors
/// Returns an error when the proof signature or principal commitment is invalid.
pub fn verify_peer_proof(
    proof: &PeerProof,
    expected_principal_commitment: &str,
) -> Result<(), SyncError> {
    if proof.principal_commitment != expected_principal_commitment {
        return Err(SyncError::LanPeerPrincipalMismatch);
    }
    ramflux_crypto::verify_device_branch_signature(
        &proof.signer_public_key,
        &peer_proof_signing_body(proof),
        &proof.signature,
    )
    .map_err(|_err| SyncError::PeerProofInvalid)
}

/// # Errors
/// Returns an error when the resume token signature is invalid.
pub fn verify_resume_token(token: &ResumeToken) -> Result<(), SyncError> {
    ramflux_crypto::verify_device_branch_signature(
        &token.signer_public_key,
        &resume_token_signing_body(token),
        &token.signature,
    )
    .map_err(|_err| SyncError::ResumeTokenInvalid)
}

/// # Errors
/// Returns an error when canonicalization or signing fails.
pub fn sign_object_tombstone(
    mut tombstone: ObjectTombstone,
    device_branch: &DeviceBranch,
) -> Result<ObjectTombstone, SyncError> {
    tombstone.signer_public_key =
        encode_base64url(device_branch.signing_key.verifying_key().to_bytes());
    tombstone.signature = ramflux_crypto::sign_with_device_branch(
        device_branch,
        &object_tombstone_signing_body(&tombstone),
    )?;
    Ok(tombstone)
}

/// # Errors
/// Returns an error when the tombstone signature or causal event id is invalid.
pub fn verify_object_tombstone(tombstone: &ObjectTombstone) -> Result<(), SyncError> {
    if tombstone.causal_event_id.is_empty() {
        return Err(SyncError::ObjectTombstoneInvalid);
    }
    ramflux_crypto::verify_device_branch_signature(
        &tombstone.signer_public_key,
        &object_tombstone_signing_body(tombstone),
        &tombstone.signature,
    )
    .map_err(|_err| SyncError::ObjectTombstoneInvalid)
}

#[derive(Serialize)]
struct LanAnnounceSigningBody<'a> {
    schema: &'a str,
    protocol_versions: &'a [String],
    principal_commitment: &'a str,
    device_id: &'a str,
    device_epoch: u64,
    instance_id: &'a str,
    lan_endpoint: &'a str,
    capabilities: &'a [String],
    nonce: &'a str,
    ttl: u32,
}

fn lan_announce_signing_body(announce: &LanAnnounce) -> LanAnnounceSigningBody<'_> {
    LanAnnounceSigningBody {
        schema: &announce.schema,
        protocol_versions: &announce.protocol_versions,
        principal_commitment: &announce.principal_commitment,
        device_id: &announce.device_id,
        device_epoch: announce.device_epoch,
        instance_id: &announce.instance_id,
        lan_endpoint: &announce.lan_endpoint,
        capabilities: &announce.capabilities,
        nonce: &announce.nonce,
        ttl: announce.ttl,
    }
}

#[derive(Serialize)]
struct PeerProofSigningBody<'a> {
    session_id: &'a str,
    source_device_id: &'a str,
    target_device_id: &'a str,
    principal_commitment: &'a str,
    nonce: &'a str,
}

fn peer_proof_signing_body(proof: &PeerProof) -> PeerProofSigningBody<'_> {
    PeerProofSigningBody {
        session_id: &proof.session_id,
        source_device_id: &proof.source_device_id,
        target_device_id: &proof.target_device_id,
        principal_commitment: &proof.principal_commitment,
        nonce: &proof.nonce,
    }
}

#[derive(Serialize)]
struct ResumeTokenSigningBody<'a> {
    object_id: &'a str,
    manifest_hash: &'a str,
    next_missing_chunk: Option<u32>,
    received_count: u32,
    session_id: &'a str,
    peer_device_id: &'a str,
    completed_bitmap_hash: &'a str,
    expires_at: i64,
}

fn resume_token_signing_body(token: &ResumeToken) -> ResumeTokenSigningBody<'_> {
    ResumeTokenSigningBody {
        object_id: &token.object_id,
        manifest_hash: &token.manifest_hash,
        next_missing_chunk: token.next_missing_chunk,
        received_count: token.received_count,
        session_id: &token.session_id,
        peer_device_id: &token.peer_device_id,
        completed_bitmap_hash: &token.completed_bitmap_hash,
        expires_at: token.expires_at,
    }
}

#[cfg(test)]
fn sign_resume_token(token: &ResumeToken) -> Result<String, SyncError> {
    Ok(ramflux_crypto::sign_protocol_object_with_seed(
        &resume_token_signing_body(token),
        ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
    )?)
}

fn sign_resume_token_with_device_branch(
    token: &ResumeToken,
    device_branch: &DeviceBranch,
) -> Result<String, SyncError> {
    Ok(ramflux_crypto::sign_with_device_branch(device_branch, &resume_token_signing_body(token))?)
}

#[derive(Serialize)]
struct ObjectTombstoneSigningBody<'a> {
    object_id: &'a str,
    manifest_hash: &'a str,
    causal_event_id: &'a str,
    tombstone_state: &'a str,
    created_at: i64,
}

fn object_tombstone_signing_body(tombstone: &ObjectTombstone) -> ObjectTombstoneSigningBody<'_> {
    ObjectTombstoneSigningBody {
        object_id: &tombstone.object_id,
        manifest_hash: &tombstone.manifest_hash,
        causal_event_id: &tombstone.causal_event_id,
        tombstone_state: &tombstone.tombstone_state,
        created_at: tombstone.created_at,
    }
}

fn object_nonce(object_id: &str) -> [u8; 12] {
    let hash = ramflux_crypto::blake3_256(ramflux_protocol::domain::OBJECT, object_id.as_bytes());
    nonce_from_hash(hash)
}

fn chunk_nonce(manifest_hash: &str, chunk_index: u32) -> [u8; 12] {
    let mut input = Vec::with_capacity(manifest_hash.len() + 4 + 5);
    input.extend_from_slice(manifest_hash.as_bytes());
    input.extend_from_slice(&chunk_index.to_be_bytes());
    input.extend_from_slice(b"nonce");
    let hash = ramflux_crypto::blake3_256(ramflux_protocol::domain::OBJECT_CHUNK_ID, &input);
    nonce_from_hash(hash)
}

fn nonce_from_hash(hash: [u8; 32]) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&hash[..12]);
    nonce
}

fn decode_nonce(encoded: &str) -> Result<[u8; 12], SyncError> {
    let bytes = decode_base64url(encoded).map_err(ramflux_crypto::CryptoError::Base64)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        ramflux_crypto::CryptoError::InvalidPublicKeyLength(bytes.len()).into()
    })
}

fn chunk_aead_key(content_key: &[u8; 32], manifest_hash: &str, chunk_index: u32) -> [u8; 32] {
    let mut context = Vec::with_capacity(
        ramflux_protocol::domain::OBJECT_CHUNK_ID.len() + manifest_hash.len() + 4,
    );
    context.extend_from_slice(ramflux_protocol::domain::OBJECT_CHUNK_ID.as_bytes());
    context.extend_from_slice(manifest_hash.as_bytes());
    context.extend_from_slice(&chunk_index.to_be_bytes());
    ramflux_crypto::blake3_keyed_derive(content_key, &context)
}

fn chunk_associated_data(manifest: &ChunkManifest, chunk_index: u32) -> Vec<u8> {
    let mut associated_data =
        Vec::with_capacity(manifest.object_id.len() + manifest.manifest_hash.len() + 16);
    associated_data.extend_from_slice(OBJECT_SYNC_V1.as_bytes());
    associated_data.extend_from_slice(manifest.object_id.as_bytes());
    associated_data.extend_from_slice(manifest.manifest_hash.as_bytes());
    associated_data.extend_from_slice(&chunk_index.to_be_bytes());
    associated_data
}

fn encrypt_aead(
    key: &[u8; 32],
    nonce: &[u8; 12],
    object_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, SyncError> {
    encrypt_aead_with_ad(key, nonce, object_id.as_bytes(), plaintext)
}

fn decrypt_aead(
    key: &[u8; 32],
    nonce: &[u8; 12],
    object_id: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, SyncError> {
    decrypt_aead_with_ad(key, nonce, object_id.as_bytes(), ciphertext)
}

fn encrypt_aead_with_ad(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SyncError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad: associated_data })
        .map_err(|_err| SyncError::ChunkAeadFailed)
}

fn decrypt_aead_with_ad(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SyncError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: associated_data })
        .map_err(|_err| SyncError::ChunkAeadFailed)
}

fn completed_bitmap_hash(total_chunks: u32, chunks: &BTreeMap<u32, ReceivedChunk>) -> String {
    let mut completed = Vec::new();
    for index in 0..total_chunks {
        completed.push(if chunks.contains_key(&index) { b'1' } else { b'0' });
    }
    ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT_CHUNK_ID, &completed)
}

#[cfg(test)]
mod tests {
    use super::{
        BackupManifestRequest, ChunkPayload, LanAnnounce, LanPairingRegistry, ObjectStore,
        ObjectSyncSession, ObjectTombstone, PeerProofVerifier, chunk_cipher_hash,
        chunk_manifest_for_object, chunk_payload, client_sync_path, decrypt_chunk_payload,
        sign_lan_announce, sign_object_tombstone, sign_peer_proof, sync_batch_v1,
        verify_backup_manifest, verify_lan_announce, verify_object_tombstone, verify_peer_proof,
        verify_resume_token,
    };
    use crate::SyncError;

    fn device_branch(device_id: &str, epoch: u64, seed: [u8; 32]) -> ramflux_crypto::DeviceBranch {
        ramflux_crypto::create_device_branch("principal_a", device_id, epoch, seed)
    }

    #[test]
    fn prepare_does_not_publish_until_install_and_roundtrips()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = ObjectStore::new();
        let prepared = store.prepare_encrypted_object("object_prepare", b"prepare-plaintext")?;
        // Prepared but not installed: the in-memory store must not yet see the object or key.
        assert!(store.objects().is_empty(), "prepare must not publish to the in-memory store");
        assert!(matches!(store.decrypt_object("object_prepare"), Err(SyncError::ObjectNotFound)));
        let manifest_hash = prepared.object().manifest_hash.clone();
        let plaintext_hash = prepared.object().plaintext_hash.clone();
        let installed = store.install_prepared_object(prepared);
        assert_eq!(installed.manifest_hash, manifest_hash);
        assert_eq!(installed.plaintext_hash, plaintext_hash);
        // After install the object decrypts to the original plaintext with its adopted key.
        assert_eq!(store.decrypt_object("object_prepare")?, b"prepare-plaintext");
        // put_encrypted_object routes through prepare+install and stays byte-compatible.
        let mut store2 = ObjectStore::new();
        let put = store2.put_encrypted_object("object_prepare", b"prepare-plaintext")?;
        assert_eq!(put.plaintext_hash, plaintext_hash, "plaintext hash is key-independent");
        assert_eq!(store2.decrypt_object("object_prepare")?, b"prepare-plaintext");
        Ok(())
    }

    #[test]
    fn chunk_aead_roundtrip_and_tamper_rejects() -> Result<(), Box<dyn std::error::Error>> {
        let content_key = [0xA5; 32];
        let wrong_content_key = [0x5A; 32];
        let manifest = chunk_manifest_for_object("object_chunked", b"abcdef", 3, Some(9));
        let chunk = chunk_payload(&content_key, &manifest, 0, b"abc");
        assert_ne!(chunk.ciphertext, b"abc");
        assert_eq!(decrypt_chunk_payload(&content_key, &manifest, &chunk)?, b"abc");
        assert!(matches!(
            decrypt_chunk_payload(&wrong_content_key, &manifest, &chunk),
            Err(SyncError::ChunkAeadFailed)
        ));
        let manifest_derived_key = ramflux_crypto::blake3_256(
            ramflux_protocol::domain::OBJECT_CHUNK_ID,
            manifest.manifest_hash.as_bytes(),
        );
        assert!(matches!(
            decrypt_chunk_payload(&manifest_derived_key, &manifest, &chunk),
            Err(SyncError::ChunkAeadFailed)
        ));

        let mut tampered = ChunkPayload {
            chunk_index: chunk.chunk_index,
            nonce: chunk.nonce.clone(),
            ciphertext: chunk.ciphertext.clone(),
            cipher_hash: String::new(),
        };
        if let Some(first) = tampered.ciphertext.first_mut() {
            *first ^= 0x01;
        }
        tampered.cipher_hash =
            chunk_cipher_hash(&manifest.manifest_hash, tampered.chunk_index, &tampered.ciphertext);
        let mut session = ObjectSyncSession::new(manifest, content_key);
        let branch = device_branch("device_chunk", 1, [0x54; 32]);
        assert!(matches!(
            session.receive_chunk(tampered, &branch),
            Err(SyncError::ChunkAeadFailed)
        ));
        assert_eq!(session.quarantine().len(), 1);
        assert_eq!(session.quarantine()[0].error_code, "chunk_aead_failed");
        Ok(())
    }

    #[test]
    fn lan_announce_signature_epoch_and_pending_pairing() -> Result<(), Box<dyn std::error::Error>>
    {
        let branch = device_branch("device_a", 7, [0x11; 32]);
        let announce = sign_lan_announce(
            LanAnnounce {
                schema: "ramflux.object_lan_announce.v1".to_owned(),
                protocol_versions: vec!["object_sync_v1".to_owned()],
                principal_commitment: "principal_commitment_a".to_owned(),
                device_id: "device_a".to_owned(),
                device_epoch: 7,
                instance_id: "instance_a".to_owned(),
                lan_endpoint: "127.0.0.1:4433".to_owned(),
                capabilities: vec!["object_sync".to_owned()],
                nonce: "nonce_a".to_owned(),
                ttl: 30,
                signer_public_key: String::new(),
                signature: String::new(),
            },
            &branch,
        )?;
        verify_lan_announce(&announce, "principal_commitment_a")?;
        let mut registry = LanPairingRegistry::new();
        assert!(matches!(
            registry.verify_announce(&announce, "principal_commitment_a", false),
            Err(SyncError::LanPeerPending)
        ));
        assert!(registry.is_pending("device_a"));
        registry.verify_announce(&announce, "principal_commitment_a", true)?;

        let mut rollback = announce.clone();
        rollback.device_epoch = 6;
        rollback = sign_lan_announce(rollback, &branch)?;
        assert!(matches!(
            registry.verify_announce(&rollback, "principal_commitment_a", true),
            Err(SyncError::LanAnnounceEpochRollback)
        ));
        Ok(())
    }

    #[test]
    fn peer_proof_signature_and_nonce_single_use() -> Result<(), Box<dyn std::error::Error>> {
        let branch = device_branch("device_a", 1, [0x22; 32]);
        let proof = sign_peer_proof(
            "session_a",
            "device_a",
            "device_b",
            "principal_commitment_a",
            "challenge_nonce_1",
            &branch,
        )?;
        verify_peer_proof(&proof, "principal_commitment_a")?;
        let mut verifier = PeerProofVerifier::new();
        verifier.verify_once(&proof, "principal_commitment_a")?;
        assert!(matches!(
            verifier.verify_once(&proof, "principal_commitment_a"),
            Err(SyncError::PeerProofNonceReplay)
        ));
        Ok(())
    }

    #[test]
    fn resume_token_binds_completed_bitmap_and_resume_transfer()
    -> Result<(), Box<dyn std::error::Error>> {
        let branch = device_branch("device_resume", 4, [0x55; 32]);
        let content_key = [0xB6; 32];
        let ciphertext = b"aaabbbccc";
        let manifest = chunk_manifest_for_object("object_resume", ciphertext, 3, None);
        let mut receiver = ObjectSyncSession::with_session(
            manifest.clone(),
            content_key,
            "session_resume",
            "peer_b",
            1_760_100_000,
        );
        let token =
            receiver.receive_chunk(chunk_payload(&content_key, &manifest, 0, b"aaa"), &branch)?;
        receiver.receive_chunk(chunk_payload(&content_key, &manifest, 2, b"ccc"), &branch)?;
        verify_resume_token(&token)?;
        let device_token = receiver.resume_token_with_device_branch(&branch)?;
        verify_resume_token(&device_token)?;
        assert_eq!(token.signer_public_key, device_token.signer_public_key);
        assert_eq!(token.session_id, "session_resume");
        assert_eq!(token.peer_device_id, "peer_b");
        assert_eq!(token.next_missing_chunk, Some(1));
        let wrong_branch = device_branch("device_wrong", 4, [0x56; 32]);
        let mut wrong_key_token = device_token.clone();
        wrong_key_token.signer_public_key =
            ramflux_protocol::encode_base64url(wrong_branch.signing_key.verifying_key().to_bytes());
        assert!(matches!(
            verify_resume_token(&wrong_key_token),
            Err(SyncError::ResumeTokenInvalid)
        ));

        receiver.receive_chunk(chunk_payload(&content_key, &manifest, 1, b"bbb"), &branch)?;
        assert!(receiver.is_complete());
        assert_eq!(receiver.assemble()?, ciphertext);
        verify_resume_token(&receiver.resume_token_with_device_branch(&branch)?)?;
        Ok(())
    }

    #[test]
    fn tombstone_requires_causal_event_id_and_signature() -> Result<(), Box<dyn std::error::Error>>
    {
        let branch = device_branch("device_a", 2, [0x33; 32]);
        let tombstone = sign_object_tombstone(
            ObjectTombstone {
                object_id: "object_deleted".to_owned(),
                manifest_hash: "manifest_hash_a".to_owned(),
                causal_event_id: "event_delete_1".to_owned(),
                tombstone_state: "deleted".to_owned(),
                created_at: 1_760_000_000,
                signer_public_key: String::new(),
                signature: String::new(),
            },
            &branch,
        )?;
        verify_object_tombstone(&tombstone)?;
        let mut missing_causal = tombstone.clone();
        missing_causal.causal_event_id.clear();
        assert!(matches!(
            verify_object_tombstone(&missing_causal),
            Err(SyncError::ObjectTombstoneInvalid)
        ));
        let mut tampered = tombstone;
        "revoked".clone_into(&mut tampered.tombstone_state);
        assert!(matches!(
            verify_object_tombstone(&tampered),
            Err(SyncError::ObjectTombstoneInvalid)
        ));
        Ok(())
    }

    #[test]
    fn backup_manifest_uses_device_signature_and_sync_batch_path_is_canonical()
    -> Result<(), Box<dyn std::error::Error>> {
        let branch = device_branch("device_a", 3, [0x44; 32]);
        let mut store = ObjectStore::new();
        store.put_encrypted_object("object_backup", b"backup")?;
        let manifest = store.backup_manifest_with_device_branch(
            BackupManifestRequest {
                backup_id: "backup_1".to_owned(),
                source_device_id: "device_a".to_owned(),
                target_device_id: "device_b".to_owned(),
                principal_commitment: "principal_commitment_a".to_owned(),
                event_batch_heads: vec!["event_head".to_owned()],
                projection_checkpoint_hash: None,
                created_at: 1_760_000_001,
            },
            &branch,
        )?;
        verify_backup_manifest(&manifest)?;
        let wrong_branch = device_branch("device_wrong", 3, [0x45; 32]);
        let mut wrong_key_manifest = manifest.clone();
        wrong_key_manifest.signer_public_key =
            ramflux_protocol::encode_base64url(wrong_branch.signing_key.verifying_key().to_bytes());
        assert!(matches!(
            verify_backup_manifest(&wrong_key_manifest),
            Err(SyncError::BackupManifestSignatureInvalid)
        ));
        assert_eq!(client_sync_path(42, 100), "/client/v1/sync?after_inbox_seq=42&limit=100");
        let batch = sync_batch_v1("cursor_a", "device_a", 42, Vec::new(), Vec::new(), None);
        assert_eq!(batch.schema, "ramflux.sync_batch.v1");
        assert_eq!(batch.after_inbox_seq, 42);
        Ok(())
    }
}

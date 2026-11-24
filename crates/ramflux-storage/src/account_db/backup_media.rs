// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Message-owned media recovery in the encrypted account database, without device authority.
use super::{AccountDb, backup_database::BackupDatabase};
use crate::StorageError;
use ramflux_crypto::large_attachment::{open_segment, segment_digest};
use ramflux_protocol::large_attachment::{MediaRef, SEGMENT_BYTES};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::io::Write;
use zeroize::{Zeroize, Zeroizing};

const PREFIX: &str = "attachment/recovery/";
const MAX_RECORD: usize = 8 * 1024 * 1024;

fn invalid() -> StorageError {
    StorageError::ObjectOwnershipUnverified { schema_version: 13 }
}

/// Data decryption material only. Never contains signing keys or a live device identity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupMedia {
    pub object_id: String,
    pub manifest_hash: String,
    pub message_id: String,
    pub index: u64,
    pub media: Vec<u8>,
    pub key: [u8; 32],
    pub ciphertext_bytes: u64,
}

impl Drop for BackupMedia {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Ciphertext is stored one checked segment at a time, never as plaintext staging.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupMediaSegment {
    pub object_id: String,
    pub manifest_hash: String,
    pub ciphertext: String,
}

impl BackupMedia {
    /// Stable key binds recovery material to this exact message, entry and canonical media.
    pub fn state_key(message: &str, index: u64, media: &[u8]) -> Result<String, StorageError> {
        Ok(format!(
            "{PREFIX}{}/metadata",
            ramflux_crypto::blake3_256_base64url(
                "ramflux.attachment.recovery.v1",
                &ramflux_protocol::canonical_json_bytes(&(message, index, media))?,
            )
        ))
    }

    pub fn segment_key(&self, index: u32) -> Result<String, StorageError> {
        let key = Self::state_key(&self.message_id, self.index, &self.media)?;
        let prefix = key.strip_suffix("metadata").ok_or_else(invalid)?;
        Ok(format!("{prefix}segment/{index}"))
    }

    pub fn reference(&self) -> Result<MediaRef, StorageError> {
        if self.media.len() > ramflux_protocol::large_attachment::MAX_MANIFEST_BYTES {
            return Err(invalid());
        }
        let reference = MediaRef::decode(&self.media).map_err(|_| invalid())?;
        let raw =
            ramflux_protocol::decode_base64url(&reference.object_id).map_err(|_| invalid())?;
        let object_hex = hex(&raw);
        let manifest_hex = hex(&reference.large_manifest.manifest_id);
        if !((self.object_id == reference.object_id
            && self.manifest_hash == ramflux_protocol::encode_base64url(reference.manifest_digest))
            || (self.object_id == object_hex && self.manifest_hash == manifest_hex))
            || reference.large_manifest.layout().dimensions().map_err(|_| invalid())?.1
                != self.ciphertext_bytes
        {
            return Err(invalid());
        }
        Ok(reference)
    }

    /// Verifies every cipher segment, AEAD, plaintext digest and exact length while streaming.
    pub fn stream(
        &self,
        mut segment: impl FnMut(u32) -> Result<BackupMediaSegment, StorageError>,
        sink: &mut dyn Write,
        mut checkpoint: impl FnMut() -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let reference = self.reference()?;
        let manifest = &reference.large_manifest;
        let object: [u8; 32] = ramflux_protocol::decode_base64url(&reference.object_id)
            .map_err(|_| invalid())?
            .try_into()
            .map_err(|_| invalid())?;
        let mut digest = blake3::Hasher::new();
        let mut written = 0_u64;
        for (index, expected) in manifest.segment_digests.iter().enumerate() {
            checkpoint()?;
            let index = u32::try_from(index).map_err(|_| invalid())?;
            let record = segment(index)?;
            if record.object_id != self.object_id
                || record.manifest_hash != self.manifest_hash
                || record.ciphertext.len() > (SEGMENT_BYTES as usize).div_ceil(3) * 4
            {
                return Err(invalid());
            }
            let cipher =
                ramflux_protocol::decode_base64url(&record.ciphertext).map_err(|_| invalid())?;
            if segment_digest(&cipher).map_err(|_| invalid())? != *expected {
                return Err(invalid());
            }
            let plain =
                open_segment(&self.key, &object, manifest.layout(), u64::from(index), &cipher)
                    .map_err(|_| invalid())?;
            let bytes = plain.as_staging_bytes();
            digest.update(bytes);
            written = written
                .checked_add(u64::try_from(bytes.len()).map_err(|_| invalid())?)
                .ok_or_else(invalid)?;
            sink.write_all(bytes)?;
        }
        checkpoint()?;
        if written != manifest.plaintext_length
            || *digest.finalize().as_bytes() != manifest.plaintext_digest
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::new();
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

impl AccountDb {
    /// Reads a bounded private recovery record. An oversized record is corruption.
    pub fn backup_media_state<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
    ) -> Result<Option<T>, StorageError> {
        let bytes: Option<Vec<u8>> = self.connection.query_row("SELECT CASE WHEN length(state_json)<=?2 THEN state_json END FROM runtime_actor_state WHERE state_kind=?1",params![name,MAX_RECORD],|row|row.get(0)).optional()?;
        bytes
            .map(|bytes| {
                let bytes = Zeroizing::new(bytes);
                Ok(serde_json::from_slice(&bytes)?)
            })
            .transpose()
    }
    /// Enumerates only messages owning media, in bounded pages, without changing live state.
    pub fn backup_media_message_page(&self, after: &str) -> Result<Vec<String>, StorageError> {
        Ok(self.connection.prepare("SELECT DISTINCT m.message_id FROM object_message_reference m JOIN runtime_message_content c USING(message_id) WHERE m.message_id>?1 AND EXISTS(SELECT 1 FROM runtime_actor_state a WHERE a.state_kind='routed/generated-identity/'||m.message_id) ORDER BY m.message_id LIMIT 64")?
            .query_map(params![after], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?)
    }
}

impl BackupDatabase {
    pub(super) fn count_backup_media(
        &self,
        filter: &str,
        join: &str,
        newer: &str,
        report: &mut crate::BackupMergeReport,
    ) -> Result<(), StorageError> {
        let selected = format!("({filter}) AND r.state_kind LIKE 'attachment/recovery/%/metadata'");
        let count = |predicate: &str| -> Result<(u64, u64), StorageError> {
            Ok(self.db.query_row(&format!("SELECT count(*),coalesce(sum(json_extract(CAST(r.state_json AS TEXT),'$.ciphertext_bytes')),0) FROM incoming.runtime_actor_state r WHERE {selected} AND {predicate}"),[],|row|Ok((row.get(0)?,row.get(1)?)))?)
        };
        let (restored, bytes) = count(&format!(
            "NOT EXISTS(SELECT 1 FROM runtime_actor_state l WHERE {join} AND NOT ({newer}))"
        ))?;
        report.restored.attachments += restored;
        report.restored.attachment_bytes += bytes;
        let (kept, bytes) = count(&format!(
            "EXISTS(SELECT 1 FROM runtime_actor_state l WHERE {join} AND NOT ({newer}))"
        ))?;
        report.kept_newer.attachments += kept;
        report.kept_newer.attachment_bytes += bytes;
        Ok(())
    }
    fn backup_media_commitment(&self, media: &BackupMedia) -> Result<String, StorageError> {
        let hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.object.transport.owner.v1",
            &ramflux_protocol::canonical_json_bytes(&(
                &media.object_id,
                &media.manifest_hash,
                &media.message_id,
            ))?,
        );
        let commitment: Option<String> = self.db.query_row("SELECT p.commitment FROM object_retention_payload p JOIN object_retention_reference r USING(commitment) JOIN object_message_reference m USING(reference_hash) WHERE r.reference_hash=?1 AND m.message_id=?2 AND p.wire_id=?3 AND p.manifest_hash=?4 AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=p.commitment)",params![hash,media.message_id,media.object_id,media.manifest_hash],|row|row.get(0)).optional()?;
        let deleted = super::deleted_messages::message_is_deleted_on(&self.db, &media.message_id)?;
        if deleted {
            return Err(invalid());
        }
        commitment.ok_or_else(invalid)
    }

    /// Adds a private recovery copy only under the existing canonical transport owner.
    pub fn put_backup_media_state(
        &self,
        media: &BackupMedia,
        name: &str,
        value: &impl Serialize,
    ) -> Result<(), StorageError> {
        let commitment = self.backup_media_commitment(media)?;
        let metadata = BackupMedia::state_key(&media.message_id, media.index, &media.media)?;
        let prefix = metadata.strip_suffix("metadata").ok_or_else(invalid)?;
        if !name.starts_with(prefix) {
            return Err(invalid());
        }
        let bytes = Zeroizing::new(serde_json::to_vec(value)?);
        if bytes.len() > MAX_RECORD {
            return Err(invalid());
        }
        if let Some(path) = self.db.path() {
            let parent = std::path::Path::new(path).parent().ok_or_else(invalid)?;
            super::backup_database::require_space(
                parent,
                u64::try_from(bytes.len())
                    .map_err(|_| invalid())?
                    .saturating_mul(3)
                    .saturating_add(20 * 1024 * 1024),
            )?;
        }
        let tx = self.db.unchecked_transaction()?;
        self.db.execute(
            "INSERT OR REPLACE INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2)",
            params![name, bytes.as_slice()],
        )?;
        self.db.execute(
            "INSERT OR IGNORE INTO object_payload_actor(commitment,state_kind) VALUES(?1,?2)",
            params![commitment, name],
        )?;
        self.db.execute(
            "INSERT OR IGNORE INTO message_copy_binding(copy_id,message_id) VALUES(?1,?2)",
            params![format!("actor:{name}"), media.message_id],
        )?;
        self.db.execute("INSERT OR IGNORE INTO message_footprint(message_id,kind,locator) VALUES(?1,'actor',?2)",params![media.message_id,name])?;
        tx.commit()?;
        Ok(())
    }

    fn backup_media_state<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
    ) -> Result<T, StorageError> {
        let bytes: Vec<u8> = self.db.query_row("SELECT state_json FROM runtime_actor_state WHERE state_kind=?1 AND length(state_json)<=?2",params![name,MAX_RECORD],|row|row.get(0))?;
        let bytes = Zeroizing::new(bytes);
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub(super) fn verify_backup_media(
        &self,
        archive_only: bool,
        mut progress: impl FnMut(u64, u64) -> Result<(), StorageError>,
    ) -> Result<u64, StorageError> {
        let mut after = String::new();
        let mut verified = 0_u64;
        loop {
            let predicate = if archive_only {
                " AND EXISTS(SELECT 1 FROM incoming.runtime_actor_state i WHERE i.state_kind=r.state_kind)"
            } else {
                ""
            };
            let keys = self.db.prepare(&format!("SELECT state_kind FROM runtime_actor_state r WHERE state_kind LIKE 'attachment/recovery/%/metadata' AND state_kind>?1{predicate} ORDER BY state_kind LIMIT 64"))?
                .query_map([&after],|row|row.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            if keys.is_empty() {
                return Ok(verified);
            }
            for key in keys {
                let media: BackupMedia = self.backup_media_state(&key)?;
                if key != BackupMedia::state_key(&media.message_id, media.index, &media.media)? {
                    return Err(invalid());
                }
                self.backup_media_commitment(&media)?;
                media.stream(
                    |index| self.backup_media_state(&media.segment_key(index)?),
                    &mut std::io::sink(),
                    || progress(verified, 0),
                )?;
                verified = verified.checked_add(1).ok_or_else(invalid)?;
                progress(verified, media.ciphertext_bytes)?;
                after = key;
            }
        }
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A complete native contribution keeps actual display values and authored history together.
use super::{FullDirectHistory, direct_history, direct_source};
use crate::{AccountDb, BackupDatabase, DirectMessageRecord, MessageMetadata, StorageError};
use ramflux_crypto::native_origin::OwnAuthoredCapture;
use ramflux_protocol::custody::DeviceRef;
use rusqlite::{Connection, OptionalExtension as _, params};
use std::io::{Read as _, Write};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"NDR1";
const SENDER_LIMIT: usize = 4096;
const CAPTURE_LIMIT: usize = super::super::raw_inner::MAX_HISTORY_CONTAINER_BYTES;
/// Three fixed length prefixes, the original timestamp, sender, native version and capture.
pub const FULL_DIRECT_RECORD_LIMIT: usize =
    MAGIC.len() + 20 + SENDER_LIMIT + super::FULL_DIRECT_HISTORY_LIMIT + CAPTURE_LIMIT;

/// An original contribution, never an already-normalized B contribution or an authority grant.
pub struct FullDirectRecord {
    history: FullDirectHistory,
    sender: String,
    created_at: i64,
    capture: Option<OwnAuthoredCapture>,
}
fn invalid() -> StorageError {
    StorageError::PairingField("UnsupportedRecord")
}
impl FullDirectRecord {
    /// Preserve a real contributor's projection and actual authored capture.
    /// # Errors
    /// Refuses incomplete evidence, inconsistent captures or unsupported display metadata.
    pub fn from_parts(
        own: &str,
        history: FullDirectHistory,
        projection: &DirectMessageRecord,
        capture: Option<OwnAuthoredCapture>,
    ) -> Result<Self, StorageError> {
        let value = Self {
            history,
            sender: projection.sender_id.clone(),
            created_at: projection.created_at,
            capture,
        };
        let expected = value.projection(own)?;
        if projection.message_id != expected.message_id
            || projection.conversation_id != expected.conversation_id
            || projection.deleted
            || projection.metadata != MessageMetadata::default()
            || (!projection.encrypted_body.is_empty()
                && projection.encrypted_body != value.history.exact_inner())
        {
            return Err(invalid());
        }
        Ok(value)
    }

    /// Validate under the independently authenticated account and retain original display time.
    /// # Errors
    /// Refuses another account, oversized labels, invalid native context or a missing capture.
    pub fn projection(&self, own: &str) -> Result<DirectMessageRecord, StorageError> {
        let version = self.history.verify(own)?;
        if self.created_at < 0 || self.sender.len() > SENDER_LIMIT {
            return Err(invalid());
        }
        super::direct_install::require_capture(&self.history, self.capture.as_ref(), own)?;
        Ok(DirectMessageRecord {
            conversation_id: version.original().conversation_id.clone(),
            message_id: ramflux_protocol::encode_base64url(&version.original().id),
            sender_id: self.sender.clone(),
            encrypted_body: Vec::new(),
            metadata: MessageMetadata::default(),
            deleted: false,
            is_own: version
                .original()
                .author
                .as_ref()
                .is_some_and(|author| author.account_anchor == own),
            created_at: self.created_at,
            receipts: Vec::new(),
        })
    }

    /// Resolve original contributions with B supplied first. Keep its original display values;
    /// choose a whole verified native version and an actual matching authored capture.
    /// # Errors
    /// Refuses native equivocation, different originals or a selected authored version without capture.
    pub fn merge(&self, other: &Self, own: &str) -> Result<Self, StorageError> {
        self.projection(own)?;
        other.projection(own)?;
        let selected = self.history.merge(&other.history, own)?;
        let mut bytes = Zeroizing::new(Vec::new());
        selected.write(&mut *bytes)?;
        let history = FullDirectHistory::read(&bytes, own)?;
        let capture = self
            .capture
            .as_ref()
            .filter(|capture| capture.sent.exact_inner == selected.exact_inner())
            .or_else(|| {
                other
                    .capture
                    .as_ref()
                    .filter(|capture| capture.sent.exact_inner == selected.exact_inner())
            })
            .map(|capture| parse_capture(&direct_history::encode_state(capture)?))
            .transpose()?;
        let value =
            Self { history, sender: self.sender.clone(), created_at: self.created_at, capture };
        value.projection(own)?;
        Ok(value)
    }

    pub(super) fn exact_inner(&self) -> &[u8] {
        self.history.exact_inner()
    }

    pub(super) fn merge_on(
        &self,
        db: &Connection,
        source: &DeviceRef,
    ) -> Result<bool, StorageError> {
        if db.is_autocommit() {
            return Err(StorageError::PairingField("WrongContext"));
        }
        super::direct_install::merge(
            db,
            source,
            &self.history,
            &self.projection(&source.account_anchor)?,
            self.capture.as_ref(),
        )
    }

    /// Apply a result reconstructed solely from retained original contributions in the
    /// caller's private transaction. This can remove a now-absent A-only preferred version.
    /// # Errors
    /// Refuses foreign roots, invalid originals, erasure or unclassified B replay state.
    pub fn project_original_contributions(
        &self,
        private: &BackupDatabase,
        source: &DeviceRef,
    ) -> Result<bool, StorageError> {
        let own = &source.account_anchor;
        let projection = self.projection(own)?;
        let changed = super::direct_install::project_original_contributions(
            &private.db,
            source,
            &self.history,
            &projection,
            self.capture.as_ref(),
        )?;
        if super::super::deleted_messages::message_is_deleted_on(
            &private.db,
            &projection.message_id,
        )? {
            return Ok(false);
        }
        let actual = read_source(&private.db, own, &projection.message_id)?.ok_or_else(invalid)?;
        let mut expected_bytes = Zeroizing::new(Vec::new());
        let mut actual_bytes = Zeroizing::new(Vec::new());
        self.write(own, &mut *expected_bytes)?;
        actual.write(own, &mut *actual_bytes)?;
        if expected_bytes.as_slice() != actual_bytes.as_slice() {
            return Err(StorageError::PairingField("ManifestMismatch"));
        }
        Ok(changed)
    }

    /// Write a bounded private record. The outer owner still authenticates its contribution.
    /// # Errors
    /// Refuses foreign context, invalid parts or output failure.
    pub fn write(&self, own: &str, output: &mut impl Write) -> Result<(), StorageError> {
        self.projection(own)?;
        let mut history = Zeroizing::new(Vec::new());
        self.history.write(&mut *history)?;
        let capture = self.capture.as_ref().map(direct_history::encode_state).transpose()?;
        output.write_all(MAGIC)?;
        output.write_all(&self.created_at.to_be_bytes())?;
        write_part(output, self.sender.as_bytes(), SENDER_LIMIT)?;
        write_part(output, &history, super::FULL_DIRECT_HISTORY_LIMIT)?;
        write_part(output, capture.as_deref().map_or(&[], Vec::as_slice), CAPTURE_LIMIT)?;
        Ok(())
    }

    /// Read the sole complete-record format, checking every part before decoding.
    /// # Errors
    /// Refuses mixed/old formats, extra fields, trailing bytes, wrong accounts or invalid history.
    pub fn read(mut bytes: &[u8], own: &str) -> Result<Self, StorageError> {
        if bytes.len() > FULL_DIRECT_RECORD_LIMIT || take(&mut bytes, MAGIC.len())? != MAGIC {
            return Err(invalid());
        }
        let mut stamp = [0; 8];
        bytes.read_exact(&mut stamp)?;
        let sender = std::str::from_utf8(read_part(&mut bytes, SENDER_LIMIT)?)
            .map_err(|_| invalid())?
            .to_owned();
        let history =
            FullDirectHistory::read(read_part(&mut bytes, super::FULL_DIRECT_HISTORY_LIMIT)?, own)?;
        let encoded = read_part(&mut bytes, CAPTURE_LIMIT)?;
        let capture = if encoded.is_empty() { None } else { Some(parse_capture(encoded)?) };
        if !bytes.is_empty() {
            return Err(invalid());
        }
        let value = Self { history, sender, created_at: i64::from_be_bytes(stamp), capture };
        value.projection(own)?;
        Ok(value)
    }
}

impl AccountDb {
    /// Assemble actual original display/capture fields in the same native source read snapshot.
    /// # Errors
    /// Refuses incomplete/unsupported native history or nonportable projection metadata.
    pub fn read_full_direct_record(
        &self,
        message: &str,
    ) -> Result<Option<FullDirectRecord>, StorageError> {
        let own = self.principal_commitment.clone();
        let message = message.to_owned();
        self.read_snapshot(|| {
            self.connection.call(move |db| Ok(read_source(db, &own, &message)))?
        })
    }
}
impl BackupDatabase {
    /// Project the complete contribution through the existing native transaction owner.
    /// # Errors
    /// Refuses no caller transaction, foreign sources, erasure conflicts or invalid native values.
    pub fn merge_full_direct_record(
        &mut self,
        source: &DeviceRef,
        value: &FullDirectRecord,
    ) -> Result<bool, StorageError> {
        self.merge_full_direct_history(
            source,
            &value.history,
            &value.projection(&source.account_anchor)?,
            value.capture.as_ref(),
        )
    }
}

pub(super) fn read_source(
    db: &Connection,
    own: &str,
    id: &str,
) -> Result<Option<FullDirectRecord>, StorageError> {
    let Some(history) = direct_source::read(db, own, id)? else { return Ok(None) };
    let (sender, created_at): (String, i64) = db.query_row(
        "SELECT CASE WHEN length(CAST(sender_id AS BLOB))<=?2 THEN sender_id END,created_at FROM direct_message_projection WHERE message_id=?1 AND deleted=0 AND is_own IN(0,1) AND metadata_json=?3 AND (length(encrypted_body)=0 OR encrypted_body=(SELECT body FROM runtime_message_content WHERE message_id=?1))",
        params![id, SENDER_LIMIT, serde_json::to_vec(&MessageMetadata::default())?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let raw: Option<Option<Vec<u8>>> = db.query_row(
        "SELECT CASE WHEN typeof(state_json)='blob' AND length(state_json)<=?2 THEN state_json END FROM runtime_actor_state WHERE state_kind=?1",
        params![format!("own-history/capture/{id}"), CAPTURE_LIMIT], |row| row.get(0),
    ).optional()?;
    let capture = match raw {
        None => None,
        Some(None) => return Err(invalid()),
        Some(Some(bytes)) => Some(parse_capture(&Zeroizing::new(bytes))?),
    };
    let value = FullDirectRecord { history, sender, created_at, capture };
    value.projection(own)?;
    Ok(Some(value))
}

fn parse_capture(bytes: &[u8]) -> Result<OwnAuthoredCapture, StorageError> {
    if bytes.is_empty() || bytes.len() > CAPTURE_LIMIT {
        return Err(invalid());
    }
    let capture: OwnAuthoredCapture =
        ramflux_protocol::parse_i_json_secret(bytes).map_err(|_| invalid())?;
    // The actual capture producer and this private frame use the same typed serializer.
    // Re-encoding rejects ignored nested protobuf fields instead of silently dropping them.
    if direct_history::encode_state(&capture)?.as_slice() != bytes {
        return Err(invalid());
    }
    Ok(capture)
}
fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], StorageError> {
    let value = bytes.get(..count).ok_or_else(invalid)?;
    *bytes = bytes.get(count..).ok_or_else(invalid)?;
    Ok(value)
}
fn read_part<'a>(bytes: &mut &'a [u8], limit: usize) -> Result<&'a [u8], StorageError> {
    let mut length = [0; 4];
    bytes.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| invalid())?;
    if length > limit {
        return Err(invalid());
    }
    take(bytes, length)
}
fn write_part(output: &mut impl Write, bytes: &[u8], limit: usize) -> Result<(), StorageError> {
    if bytes.len() > limit {
        return Err(invalid());
    }
    output.write_all(&u32::try_from(bytes.len()).map_err(|_| invalid())?.to_be_bytes())?;
    output.write_all(bytes)?;
    Ok(())
}

// Physical validation extracts only a claim. The semantic owner still supplies the
// authenticated transfer account independently to FullDirectRecord::read.
pub(super) fn payload_account(mut bytes: &[u8]) -> Result<&str, StorageError> {
    if bytes.len() > FULL_DIRECT_RECORD_LIMIT || take(&mut bytes, MAGIC.len())? != MAGIC {
        return Err(invalid());
    }
    take(&mut bytes, 8)?;
    read_part(&mut bytes, SENDER_LIMIT)?;
    direct_history::payload_account(read_part(&mut bytes, super::FULL_DIRECT_HISTORY_LIMIT)?)
}

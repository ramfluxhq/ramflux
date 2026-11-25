// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Copies legitimately readable media into the encrypted backup cut, without live authority.
use super::codes::{
    CODE_CANCELLED, CODE_LAYOUT_INVALID, CODE_NOT_GRANTEE, CODE_SEAL_FAILED, Refusal,
};
use super::{AuthorityPin, Store, bus, handles, import_job, plane::Plane};
use crate::SdkError;
use prost::Message as _;
use ramflux_storage::{AccountDb, BackupDatabase, BackupMedia, BackupMediaSegment};
use std::io::Read as _;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use zeroize::Zeroizing;

/// Only the active device's media read context survives the actor capture, never signing keys.
pub(crate) struct Capture {
    store: Store,
    anchor: String,
    device: String,
    epoch: u64,
    secret: Zeroizing<[u8; 32]>,
    pin: AuthorityPin,
    plane: Option<Arc<dyn Plane>>,
}

impl Capture {
    pub(crate) fn new(
        account: &crate::bus::state::LocalBusAccountState,
        id: &str,
    ) -> Result<Option<Self>, SdkError> {
        let client = &account.client;
        let Some(branch) = client.device_branch.as_ref() else { return Ok(None) };
        if !bus::flag(client)? {
            return Ok(None);
        }
        Ok(Some(Self {
            store: bus::open_store(client, id)?,
            anchor: client.own_account_anchor()?,
            device: branch.device_id.clone(),
            epoch: branch.device_epoch,
            secret: client.attachment_device_secret()?,
            pin: bus::authority(client)?,
            plane: if account.connection.is_some() || client.attachment_plane.is_some() {
                Some(bus::plane_for(account)?)
            } else {
                None
            },
        }))
    }

    fn source(
        &self,
        reader: &AccountDb,
        mid: &str,
        index: u64,
        media: &ramflux_protocol::message::MediaRef,
    ) -> Result<(BackupMedia, Segments), SdkError> {
        let reference = import_job::canonical(media)?;
        let encoded = media.encode_to_vec();
        let (key, wire, manifest, segments) =
            if let Some(prepare) = handles::prepare_at_on(reader, mid, index)? {
                let row = self.store.load(&prepare)?;
                let (key, object) = self.store.open_secret(&row)?;
                if row.object_id != Some(object)
                    || reference.object_id != ramflux_protocol::encode_base64url(object)
                    || row.manifest_hash != Some(reference.large_manifest.manifest_id)
                    || row.segment_digests != reference.large_manifest.segment_digests
                {
                    return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
                }
                (
                    key,
                    super::owner_wire::encode_hex(&object),
                    super::owner_wire::encode_hex(&reference.large_manifest.manifest_id),
                    Segments::Owned(prepare),
                )
            } else {
                let opened = import_job::open_entry(
                    media,
                    &import_job::Importer {
                        account_anchor: &self.anchor,
                        device_id: &self.device,
                        device_epoch: self.epoch,
                        secret: &self.secret,
                    },
                    &import_job::SourcePin {
                        source: &self.pin.source,
                        generation: self.pin.generation,
                        public_key: &self.pin.public_key,
                        now: bus::unix_now()?,
                    },
                )?;
                let key = opened.recovery_key();
                (
                    key,
                    reference.object_id.clone(),
                    ramflux_protocol::encode_base64url(reference.manifest_digest),
                    Segments::Remote(Box::new(opened)),
                )
            };
        let ciphertext_bytes = reference
            .large_manifest
            .layout()
            .dimensions()
            .map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?
            .1;
        Ok((
            BackupMedia {
                object_id: wire,
                manifest_hash: manifest,
                message_id: mid.to_owned(),
                index,
                media: encoded,
                key: *key,
                ciphertext_bytes,
            },
            segments,
        ))
    }
}

enum Segments {
    Owned(String),
    Remote(Box<import_job::Opened>),
}

pub(crate) fn stored(
    reader: &AccountDb,
    mid: &str,
    index: u64,
    encoded: &[u8],
) -> Result<Option<BackupMedia>, SdkError> {
    let key = BackupMedia::state_key(mid, index, encoded)?;
    let Some(media) = reader.backup_media_state::<BackupMedia>(&key)? else { return Ok(None) };
    if media.message_id != mid
        || media.index != index
        || media.media != encoded
        || reader.message_is_deleted(mid)?
    {
        return Err(Refusal::new(CODE_LAYOUT_INVALID).into());
    }
    media.reference()?;
    reader.check_object_access(&media.object_id)?;
    reader.check_object_identity(&media.object_id, &media.manifest_hash)?;
    Ok(Some(media))
}

/// Streams a cut into encrypted, message-owned records. Publication still rechecks erasure.
pub(crate) fn write(
    reader: &AccountDb,
    context: Option<&Capture>,
    db: &BackupDatabase,
    cancel: &AtomicBool,
) -> Result<(), SdkError> {
    let mut after = String::new();
    loop {
        let messages = reader.backup_media_message_page(&after)?;
        if messages.is_empty() {
            return Ok(());
        }
        for mid in messages {
            if cancel.load(Ordering::Acquire) {
                return Err(Refusal::new(CODE_CANCELLED).into());
            }
            for (index, entry) in
                handles::message_media_entries(reader, &mid)?.into_iter().enumerate()
            {
                let index = u64::try_from(index).map_err(|_| Refusal::new(CODE_LAYOUT_INVALID))?;
                // Already recovered records are copied with the ordinary database snapshot.
                if stored(reader, &mid, index, &entry.encode_to_vec())?.is_some() {
                    continue;
                }
                let context =
                    context.ok_or_else(|| SdkError::from(Refusal::new(CODE_NOT_GRANTEE)))?;
                let (media, source) = context.source(reader, &mid, index, &entry)?;
                copy_segments(context, db, &media, &source, cancel)?;
                let key = BackupMedia::state_key(&mid, index, &media.media)?;
                db.put_backup_media_state(&media, &key, &media)?;
            }
            after = mid;
        }
    }
}

fn copy_segments(
    context: &Capture,
    db: &BackupDatabase,
    media: &BackupMedia,
    source: &Segments,
    cancel: &AtomicBool,
) -> Result<(), SdkError> {
    let meter = super::budget::Meter::default();
    let _held = super::budget::memory_metered(
        8 * u64::from(ramflux_protocol::large_attachment::SEGMENT_BYTES),
        &meter,
    )?;
    let mut source_error = None;
    let result = media.stream(
        |index| {
            let key = media.segment_key(index)?;
            let cipher = match source {
                Segments::Owned(prepare) => read_owned(&context.store, prepare, index),
                Segments::Remote(opened) => {
                    context.plane.as_ref().ok_or(Refusal::new(CODE_NOT_GRANTEE)).and_then(|plane| {
                        import_job::fetch_segment(plane.as_ref(), opened, index, &|| Ok(()))
                    })
                }
            }
            .map_err(|error| {
                source_error = Some(error);
                ramflux_storage::StorageError::AuthorizationRejected
            })?;
            let record = BackupMediaSegment {
                object_id: media.object_id.clone(),
                manifest_hash: media.manifest_hash.clone(),
                ciphertext: ramflux_protocol::encode_base64url(&cipher),
            };
            db.put_backup_media_state(media, &key, &record)?;
            Ok(record)
        },
        &mut std::io::sink(),
        || {
            if cancel.load(Ordering::Acquire) {
                Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into())
            } else {
                Ok(())
            }
        },
    );
    if let Some(error) = source_error {
        return Err(error.into());
    }
    result?;
    Ok(())
}

fn read_owned(store: &Store, prepare: &str, index: u32) -> Result<Vec<u8>, Refusal> {
    let file =
        std::fs::File::open(store.dir(prepare).join(super::seal_job::segment_name_of(index)))
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let limit = u64::from(ramflux_protocol::large_attachment::SEGMENT_BYTES);
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    if u64::try_from(bytes.len()).map_err(|_| Refusal::new(CODE_SEAL_FAILED))? > limit {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    Ok(bytes)
}

pub(super) fn stream(
    reader: &AccountDb,
    media: &BackupMedia,
    sink: &mut dyn std::io::Write,
    fenced: &dyn Fn() -> bool,
    meter: &super::budget::Meter,
) -> Result<(), Refusal> {
    let _held = super::budget::memory_metered(
        4 * u64::from(ramflux_protocol::large_attachment::SEGMENT_BYTES),
        meter,
    )?;
    media
        .stream(
            |index| {
                reader
                    .backup_media_state(&media.segment_key(index)?)?
                    .ok_or(ramflux_storage::StorageError::AuthorizationRejected)
            },
            sink,
            || {
                if fenced() {
                    Err(ramflux_storage::StorageError::AuthorizationRejected)
                } else {
                    Ok(())
                }
            },
        )
        .map_err(|_| Refusal::new(if fenced() { CODE_CANCELLED } else { CODE_SEAL_FAILED }))
}

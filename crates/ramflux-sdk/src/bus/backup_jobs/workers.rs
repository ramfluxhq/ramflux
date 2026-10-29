// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Blocking archive workers; only encrypted bytes are staged and only complete output is published.
use super::{
    CapturedAccount,
    format::{self, Metadata, Unpack},
    io::{PartialFile, PrivateDirectory, ProgressIo, check_space},
    service::{BackupJobs, now},
};
use crate::backup::{
    BackupArchivePreview, BackupAttachmentChecks, BackupCategory, BackupFailure, BackupFailureCode,
    BackupJob, BackupJobState, VerifiedBackup, VerifiedBackupStaging,
};
use ramflux_crypto::backup_stream::{
    BackupContext, BackupStreamDecoder, BackupStreamError, encrypt_backup_stream,
};
use ramflux_storage::{AccountDbKey, BackupCounts, BackupDatabase};
use std::{
    io::BufReader,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
};
use zeroize::Zeroizing;
fn failure(code: BackupFailureCode) -> BackupFailure {
    BackupFailure::new(code)
}
fn storage_error(error: ramflux_storage::StorageError) -> BackupFailure {
    let full = error.is_insufficient_space();
    drop(error);
    failure(if full { BackupFailureCode::InsufficientSpace } else { BackupFailureCode::Tampered })
}
fn stream_error(error: BackupStreamError, header: bool) -> BackupFailure {
    match error {
        BackupStreamError::Authentication => failure(if header {
            BackupFailureCode::WrongPassphrase
        } else {
            BackupFailureCode::Tampered
        }),
        BackupStreamError::Io(error) => failure(match error.kind() {
            std::io::ErrorKind::UnexpectedEof => BackupFailureCode::Truncated,
            std::io::ErrorKind::StorageFull => BackupFailureCode::InsufficientSpace,
            std::io::ErrorKind::ConnectionAborted => BackupFailureCode::Interrupted,
            std::io::ErrorKind::InvalidData => BackupFailureCode::Tampered,
            _ => BackupFailureCode::Unreadable,
        }),
        BackupStreamError::Invalid(_) => failure(BackupFailureCode::UnsupportedVersion),
        BackupStreamError::Derivation(_) => failure(BackupFailureCode::WrongPassphrase),
    }
}
impl BackupJobs {
    fn verify_files(
        &self,
        job: &BackupJob,
        db: &BackupDatabase,
        cancel: &Arc<std::sync::atomic::AtomicBool>,
        counts: &BackupCounts,
    ) -> Result<BackupAttachmentChecks, BackupFailure> {
        let checks = db
            .verify_attachments(|items, bytes| {
                if cancel.load(Ordering::Acquire) {
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionAborted).into());
                }
                self.progress(
                    &job.job_id,
                    BackupCategory::Attachments,
                    items,
                    bytes,
                    Some(counts.attachment_bytes),
                );
                Ok(())
            })
            .map_err(storage_error)?;
        let checks = BackupAttachmentChecks {
            verified: checks.verified,
            mismatched: checks.mismatched,
            missing: checks.missing,
            unavailable_at_source: checks.unavailable_at_source,
            local_missing_kept: checks.local_missing_kept,
        };
        self.change(|registry| registry.attachment_checks(&job.job_id, checks.clone()))
            .map_err(|_| failure(BackupFailureCode::Interrupted))?;
        if checks.missing != checks.unavailable_at_source || checks.mismatched > 0 {
            return Err(failure(BackupFailureCode::AttachmentMismatch));
        }
        Ok(checks)
    }

    pub(super) fn write_archive(
        &self,
        job: &BackupJob,
        secret: Zeroizing<String>,
        captured: CapturedAccount,
        allow_missing_attachments: bool,
    ) -> Result<(), BackupFailure> {
        let cancel =
            self.cancellation(&job.job_id).map_err(|_| failure(BackupFailureCode::Interrupted))?;
        let directory =
            self.directory(&job.job_id).map_err(|_| failure(BackupFailureCode::NotWritable))?;
        let mut private = PrivateDirectory { path: directory.clone(), transferred: false };
        let estimate = captured.reader.backup_estimated_bytes().map_err(storage_error)?;
        check_space(&self.root, estimate.saturating_mul(2).saturating_add(20 * 1024 * 1024))?;
        let destination = std::path::Path::new(&job.path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        check_space(destination, estimate.saturating_add(20 * 1024 * 1024))?;
        let database = directory.join("account.db");
        let snapshot = captured
            .reader
            .write_backup_snapshot_cancellable(&database, Arc::clone(&cancel))
            .map_err(|error| {
                if cancel.load(Ordering::Acquire) {
                    failure(BackupFailureCode::Interrupted)
                } else {
                    storage_error(error)
                }
            })?;
        drop(captured.reader);
        self.change(|registry| registry.writing(&job.job_id, snapshot.counts.clone(), now()))
            .map_err(|_| failure(BackupFailureCode::Interrupted))?;
        let db = BackupDatabase::open(&database, &snapshot.key).map_err(storage_error)?;
        db.clear_missing_manifest().map_err(storage_error)?;
        if db.missing_attachment_count().map_err(storage_error)? > 0 {
            if !allow_missing_attachments {
                let failure = self
                    .unavailable_failure(job, directory.clone(), &snapshot.key, &db)
                    .map_err(|_| failure(BackupFailureCode::Interrupted))?;
                private.transferred = true;
                return Err(failure);
            }
            db.allow_missing_attachments().map_err(storage_error)?;
        }
        self.verify_files(job, &db, &cancel, &snapshot.counts)?;
        let missing_count = db.approved_missing_count().map_err(storage_error)?;
        drop(db);
        let output = PathBuf::from(&job.path);
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let metadata = archive_metadata(captured.identity, &database, &snapshot.key)?;
        let size =
            std::fs::metadata(&database).map_err(|_| failure(BackupFailureCode::Unreadable))?.len();
        check_space(parent, size.saturating_add(20 * 1024 * 1024))?;
        let temporary = parent.join(format!(".ramflux-backup-{}.partial", job.job_id));
        super::recovery::remember_partial_output(&directory, &temporary)
            .map_err(|_| failure(BackupFailureCode::NotWritable))?;
        let mut guard = PartialFile { path: temporary.clone(), published: false };
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| failure(BackupFailureCode::NotWritable))?;
        let service = self.clone();
        let id = job.job_id.clone();
        let mut output_io = ProgressIo {
            inner: file,
            cancel: Arc::clone(&cancel),
            bytes: 0,
            space: Some(parent.to_owned()),
            notify: Box::new(move |bytes| {
                service.progress(&id, BackupCategory::Attachments, 0, bytes, Some(size));
            }),
        };
        let mut totals = serde_json::to_value(&snapshot.counts)
            .map_err(|_| failure(BackupFailureCode::Interrupted))?
            .as_object()
            .ok_or_else(|| failure(BackupFailureCode::Interrupted))?
            .iter()
            .map(|(key, value)| (key.clone(), value.as_u64().unwrap_or(0)))
            .collect::<std::collections::BTreeMap<_, _>>();
        totals.insert("database_bytes".into(), size);
        totals.insert("missing_attachments".into(), missing_count);
        let context = BackupContext {
            account_id: metadata.identity.account_id().to_owned(),
            created_at: now(),
            totals,
        };
        let mut input = format::payload(&metadata, &database)
            .map_err(|_| failure(BackupFailureCode::Unreadable))?;
        encrypt_backup_stream(&mut input, &mut output_io, secret.as_bytes(), context)
            .map_err(|error| stream_error(error, false))?;
        drop(secret);
        output_io.inner.sync_all().map_err(|_| failure(BackupFailureCode::NotWritable))?;
        let bytes = output_io.bytes;
        drop(output_io);
        self.publish_archive(job, &cancel, &mut guard, &output, bytes)
    }
    fn publish_archive(
        &self,
        job: &BackupJob,
        cancel: &Arc<std::sync::atomic::AtomicBool>,
        guard: &mut PartialFile,
        output: &std::path::Path,
        bytes: u64,
    ) -> Result<(), BackupFailure> {
        let temporary = &guard.path;
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        // The potentially long NFS/FUSE copy never holds the daemon job-state lock.
        {
            let state = self.state.lock().map_err(|_| failure(BackupFailureCode::Interrupted))?;
            if cancel.load(Ordering::Acquire)
                || state
                    .registry
                    .job(&job.job_id)
                    .map_err(|_| failure(BackupFailureCode::Interrupted))?
                    .state
                    != BackupJobState::Writing
            {
                return Err(failure(BackupFailureCode::Interrupted));
            }
        }
        let directory = self.root.join(format!("job_{}", job.job_id));
        super::publication::publish_cancellable(temporary, output, cancel, &directory).map_err(
            |error| {
                if cancel.load(Ordering::Acquire) {
                    failure(BackupFailureCode::Interrupted)
                } else if error.kind() == std::io::ErrorKind::StorageFull {
                    BackupFailure {
                        needed_bytes: Some(bytes),
                        available_bytes: fs2::available_space(parent).ok(),
                        ..failure(BackupFailureCode::InsufficientSpace)
                    }
                } else {
                    failure(BackupFailureCode::NotWritable)
                }
            },
        )?;
        let mut output_guard = PartialFile { path: output.to_owned(), published: false };
        let _ = std::fs::remove_file(temporary);
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| failure(BackupFailureCode::NotWritable))?;
        let mut state = self.state.lock().map_err(|_| failure(BackupFailureCode::Interrupted))?;
        if cancel.load(Ordering::Acquire)
            || state.cancelling.contains(&job.job_id)
            || state
                .registry
                .job(&job.job_id)
                .map_err(|_| failure(BackupFailureCode::Interrupted))?
                .state
                != BackupJobState::Writing
        {
            return Err(failure(BackupFailureCode::Interrupted));
        }
        let row = state
            .registry
            .written(&job.job_id, bytes, now())
            .map_err(|_| failure(BackupFailureCode::Interrupted))?;
        state.head += 1;
        let seq = state.head;
        state.events.push_back((seq, row));
        output_guard.published = true;
        guard.published = true;
        Ok(())
    }
    pub(super) fn verify_archive(
        &self,
        job: &BackupJob,
        secret: Zeroizing<String>,
    ) -> Result<(), BackupFailure> {
        let cancel =
            self.cancellation(&job.job_id).map_err(|_| failure(BackupFailureCode::Interrupted))?;
        let file =
            std::fs::File::open(&job.path).map_err(|_| failure(BackupFailureCode::Unreadable))?;
        let archive_bytes =
            file.metadata().map_err(|_| failure(BackupFailureCode::Unreadable))?.len();
        let mut input = BufReader::new(file);
        let decoder = BackupStreamDecoder::open(&mut input, secret.as_bytes())
            .map_err(|error| stream_error(error, true))?;
        drop(secret);
        let context = decoder.context().clone();
        let counts = archive_counts(&context)?;
        self.change(|registry| registry.authenticated_totals(&job.job_id, counts.clone()))
            .map_err(|_| failure(BackupFailureCode::Interrupted))?;
        check_space(
            &self.root,
            context
                .totals
                .get("database_bytes")
                .copied()
                .unwrap_or(archive_bytes)
                .saturating_mul(2)
                .saturating_add(20 * 1024 * 1024),
        )?;
        let directory =
            self.directory(&job.job_id).map_err(|_| failure(BackupFailureCode::NotWritable))?;
        let mut guard = PrivateDirectory { path: directory.clone(), transferred: false };
        let path = directory.join("account.db");
        let output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| failure(BackupFailureCode::NotWritable))?;
        let service = self.clone();
        let id = job.job_id.clone();
        let mut unpack = ProgressIo {
            inner: Unpack::new(output),
            cancel: Arc::clone(&cancel),
            bytes: 0,
            space: Some(directory.clone()),
            notify: Box::new(move |bytes| {
                service.progress(&id, BackupCategory::Identity, 0, bytes, Some(archive_bytes));
            }),
        };
        decoder.decrypt(&mut input, &mut unpack).map_err(|error| stream_error(error, false))?;
        let mut metadata =
            unpack.inner.finish().map_err(|_| failure(BackupFailureCode::Truncated))?;
        if context.totals.get("database_bytes").copied()
            != Some(
                std::fs::metadata(&path).map_err(|_| failure(BackupFailureCode::Unreadable))?.len(),
            )
        {
            return Err(failure(BackupFailureCode::Tampered));
        }
        metadata
            .validate(&context.account_id)
            .map_err(|_| failure(BackupFailureCode::RootConflict))?;
        let (master, key) = fresh_staging_keys()?;
        let db = BackupDatabase::open(&path, &AccountDbKey::from_bytes(metadata.database_key))
            .map_err(storage_error)?;
        db.check_integrity().map_err(storage_error)?;
        db.rekey(&key).map_err(storage_error)?;
        metadata.database_key = *key.bytes();
        if db.counts().map_err(storage_error)? != counts {
            return Err(failure(BackupFailureCode::Tampered));
        }
        if db.approved_missing_count().map_err(storage_error)?
            != context.totals.get("missing_attachments").copied().unwrap_or(0)
        {
            return Err(failure(BackupFailureCode::Tampered));
        }
        let checks = self.verify_files(job, &db, &cancel, &counts)?;
        drop(db);
        let preview = self.archive_preview(&metadata, &path, &key, context.created_at)?;
        format::save_metadata(&directory.join("identity.sealed"), &master, &metadata)
            .map_err(|_| failure(BackupFailureCode::NotWritable))?;
        std::fs::File::open(&directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| failure(BackupFailureCode::NotWritable))?;
        let staging = VerifiedBackupStaging::new(directory, *master, now())
            .map_err(|_| failure(BackupFailureCode::Interrupted))?;
        guard.transferred = true;
        self.change(|registry| {
            registry.verified(
                &job.job_id,
                VerifiedBackup { preview, counts, archive_bytes, checks, staging },
                now(),
            )
        })
        .map_err(|_| failure(BackupFailureCode::Interrupted))?;
        Ok(())
    }
    fn archive_preview(
        &self,
        metadata: &Metadata,
        incoming: &std::path::Path,
        key: &AccountDbKey,
        created_at: u64,
    ) -> Result<BackupArchivePreview, BackupFailure> {
        let (id, merge) = if let format::Identity::Native { native } = &metadata.identity {
            let target = self
                .native_restore_target(native)
                .map_err(|_| failure(BackupFailureCode::RootConflict))?;
            let merge = target.is_some();
            (target.unwrap_or_else(|| native.local_account_id.clone()), merge)
        } else {
            (
                metadata.identity.account_id().to_owned(),
                self.check_existing_identity(metadata, incoming, key)?,
            )
        };
        Ok(BackupArchivePreview {
            local_account_id: id,
            account_label: metadata.identity.label(),
            created_at,
            merge,
        })
    }
    pub(super) fn check_existing_identity(
        &self,
        metadata: &Metadata,
        incoming: &std::path::Path,
        key: &AccountDbKey,
    ) -> Result<bool, BackupFailure> {
        if let format::Identity::Native { native } = &metadata.identity {
            return self
                .native_restore_target(native)
                .map(|target| target.is_some())
                .map_err(|_| failure(BackupFailureCode::RootConflict));
        }
        let manifest =
            metadata.identity.legacy().map_err(|_| failure(BackupFailureCode::RootConflict))?;
        let id = &manifest.local_account_id;
        match self.index.account(id) {
            Err(ramflux_storage::StorageError::AccountNotFound(_)) => Ok(false),
            Err(_) => Err(failure(BackupFailureCode::Unreadable)),
            Ok(record) => {
                if record.principal_commitment != manifest.principal_commitment {
                    return Err(failure(BackupFailureCode::RootConflict));
                }
                if crate::custody::account_exists(&self.data_root, id)
                    .map_err(|_| failure(BackupFailureCode::RootConflict))?
                {
                    return Err(failure(BackupFailureCode::RootConflict));
                }
                let local = crate::bus::daemon::read_local_bus_account_manifest(
                    &crate::bus::daemon::local_bus_account_manifest_path(&self.data_root, id),
                )
                .map_err(|_| failure(BackupFailureCode::Unreadable))?;
                if local.root_seed != manifest.root_seed {
                    return Err(failure(BackupFailureCode::RootConflict));
                }
                let path = self.data_root.join(record.db_relative_path);
                let local_key = super::install::existing_key(
                    &self.index,
                    &self.data_root,
                    id,
                    local.account_secret.as_bytes(),
                )
                .map_err(|_| failure(BackupFailureCode::Unreadable))?;
                BackupDatabase::open(&path, &local_key)
                    .map_err(storage_error)?
                    .check_backup_pins(incoming, key)
                    .map_err(|_| failure(BackupFailureCode::RootConflict))?;
                Ok(true)
            }
        }
    }
}

fn fresh_staging_keys() -> Result<(Zeroizing<[u8; 32]>, AccountDbKey), BackupFailure> {
    let master = Zeroizing::new(
        ramflux_crypto::random_32().map_err(|_| failure(BackupFailureCode::Interrupted))?,
    );
    let key = AccountDbKey::from_bytes(ramflux_crypto::blake3_keyed_derive(
        &master,
        b"ramflux.backup.staging.database.v1",
    ));
    Ok((master, key))
}

fn archive_counts(context: &BackupContext) -> Result<BackupCounts, BackupFailure> {
    let counts: BackupCounts = serde_json::from_value(
        serde_json::to_value(&context.totals).map_err(|_| failure(BackupFailureCode::Tampered))?,
    )
    .map_err(|_| failure(BackupFailureCode::UnsupportedVersion))?;
    Ok(counts)
}

fn archive_metadata(
    identity: format::Identity,
    path: &std::path::Path,
    key: &AccountDbKey,
) -> Result<Metadata, BackupFailure> {
    let ca_pem = match &identity {
        format::Identity::Legacy { manifest } => std::fs::read(&manifest.gateway.ca_cert)
            .map_err(|_| failure(BackupFailureCode::Unreadable))?,
        format::Identity::Native { .. } => {
            BackupDatabase::open(path, key)
                .map_err(storage_error)?
                .sanitize_native_backup()
                .map_err(storage_error)?;
            Vec::new()
        }
    };
    let metadata = Metadata { identity, database_key: *key.bytes(), ca_pem };
    metadata
        .validate(metadata.identity.account_id())
        .map_err(|_| failure(BackupFailureCode::RootConflict))?;
    Ok(metadata)
}

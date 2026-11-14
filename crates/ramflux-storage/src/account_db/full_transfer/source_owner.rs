// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private source I/O view shared by preparation and a separately authenticated data stage.
use super::source_scalar::SourceGuard;
use super::{FullTransferStage, stage::context};
use crate::{StorageError, database::Connection};
use ramflux_crypto::custody::pairing::PairingRole;
use std::path::Path;

pub(super) struct SourceContext<'a> {
    pub(super) key: &'a dyn SourceMetadataKey,
    pub(super) connection: &'a Connection,
    pub(super) guard: SourceGuard,
    pub(super) directory: &'a Path,
}
impl FullTransferStage<'_> {
    pub(super) fn reverse_source_context(&self) -> Result<SourceContext<'_>, StorageError> {
        self.require_io()?;
        if self.resume_record()?.role != PairingRole::Responder {
            return Err(context());
        }
        Ok(SourceContext {
            key: &self.key,
            connection: &self.connection,
            guard: SourceGuard::new(self.db, Some(self.source_cancelled.clone())),
            directory: &self.directory,
        })
    }

    pub(super) fn source_context(&self) -> Result<SourceContext<'_>, StorageError> {
        self.db.require_full_stage_unlock()?;
        if self.resume_record()?.role != PairingRole::Initiator {
            return Err(context());
        }
        Ok(SourceContext {
            key: &self.key,
            connection: &self.connection,
            guard: SourceGuard::new(self.db, Some(self.source_cancelled.clone())),
            directory: &self.directory,
        })
    }
}

impl SourceContext<'_> {
    pub(super) fn require_source_live(&self) -> Result<(), StorageError> {
        self.guard.require()
    }
}

/// Only local encrypted metadata access. Neither implementation exports any raw key.
pub(super) trait SourceMetadataKey {
    fn open_source_metadata(&self, path: &Path) -> Result<Connection, StorageError>;
}
impl SourceMetadataKey for super::FullStageKey<'_> {
    fn open_source_metadata(&self, path: &Path) -> Result<Connection, StorageError> {
        self.open_metadata(path)
    }
}

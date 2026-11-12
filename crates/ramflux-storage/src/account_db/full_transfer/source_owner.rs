// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private source I/O view shared by preparation and a separately authenticated data stage.
use super::{FullTransferStage, stage::context};
use crate::{AccountDb, StorageError, database::Connection};
use ramflux_crypto::custody::pairing::PairingRole;
use std::path::Path;

pub(super) struct SourceContext<'a> {
    pub(super) key: &'a super::FullStageKey<'a>,
    pub(super) connection: &'a Connection,
    pub(super) db: &'a AccountDb,
    pub(super) directory: &'a Path,
    pub(super) cancelled: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}
impl FullTransferStage<'_> {
    pub(super) fn source_context(&self) -> Result<SourceContext<'_>, StorageError> {
        self.db.require_full_stage_unlock()?;
        if self.resume_record()?.role != PairingRole::Initiator {
            return Err(context());
        }
        Ok(SourceContext {
            key: &self.key,
            connection: &self.connection,
            db: self.db,
            directory: &self.directory,
            cancelled: Some(self.source_cancelled.clone()),
        })
    }
}

impl SourceContext<'_> {
    pub(super) fn require_source_live(&self) -> Result<(), StorageError> {
        if self
            .cancelled
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
        {
            return Err(StorageError::PairingField("Cancelled"));
        }
        self.db.require_full_stage_unlock()
    }
}

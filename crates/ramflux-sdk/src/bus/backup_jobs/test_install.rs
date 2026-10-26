// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test-only synchronization at generation publication boundaries; no production fault switches.
use super::service::BackupJobs;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum InstallPoint {
    Prepared,
    BeforeCommit,
    Committed,
}
pub(super) type InstallHook =
    Arc<Mutex<Option<Arc<dyn Fn(InstallPoint, &Path) -> std::io::Result<()> + Send + Sync>>>>;
impl BackupJobs {
    pub(super) fn install_checkpoint(
        &self,
        point: InstallPoint,
        path: &Path,
    ) -> Result<(), crate::SdkError> {
        let hook =
            self.install_hook.lock().map_err(|_| super::service::refused("interrupted"))?.clone();
        if let Some(hook) = hook {
            hook(point, path)?;
        }
        Ok(())
    }
}

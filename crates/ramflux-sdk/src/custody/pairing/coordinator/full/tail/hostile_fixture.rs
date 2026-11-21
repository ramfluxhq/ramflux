// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A malicious source changes its own signed manifest before the real epoch seals it.
use super::{PairingActor, Phase, SdkError, SourceManifest, wrong};
pub(super) type ManifestOverride =
    Box<dyn FnOnce(SourceManifest) -> Result<SourceManifest, SdkError> + Send + Sync>;
impl PairingActor {
    pub(crate) async fn replace_unstarted_tail_manifest_for_test(
        &mut self,
        operation: &str,
        replace: ManifestOverride,
    ) -> Result<(), SdkError> {
        self.start_completed_tail().await?;
        let job = self.tail_jobs.get_mut(operation).ok_or_else(wrong)?;
        if job.status.role != "initiator"
            || job.phase != Phase::Prepare
            || job.manifest.is_some()
            || job.manifest_override.is_some()
        {
            return Err(wrong());
        }
        job.manifest_override = Some(replace);
        Ok(())
    }
}

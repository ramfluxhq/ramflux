// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded reverse requests return owned private work or actual durable progress.
use super::{Action, Applied};
use crate::{
    SdkError,
    custody::pairing::{
        FullLocalIoPort, FullReverseManifestDraft,
        full_io::{FullLocalAction, FullLocalResult, wrong},
    },
};
impl FullLocalIoPort {
    async fn reverse_request(&mut self, action: Action) -> Result<Applied, SdkError> {
        let FullLocalResult::Reverse(result) =
            self.request(FullLocalAction::Reverse(action)).await?
        else {
            return Err(wrong());
        };
        Ok(result)
    }
    pub(crate) async fn retained_reverse_manifest(
        &mut self,
    ) -> Result<Option<ramflux_protocol::custody::pairing::full_transfer::SourceManifest>, SdkError>
    {
        let Applied::Current(manifest) = self.reverse_request(Action::Current).await? else {
            return Err(wrong());
        };
        Ok(*manifest)
    }
    /// Pin original B once and release its actual writer before bulk encoding.
    /// # Errors
    /// Refuses another role, a lost frozen cut or changed local scope.
    pub async fn reverse_source_work(
        &mut self,
    ) -> Result<Box<ramflux_storage::FullReverseSourceWork>, SdkError> {
        let Applied::Source(work) = self.reverse_request(Action::PrepareSource).await? else {
            return Err(wrong());
        };
        Ok(work)
    }
    /// Bind original-B encoded work to the same exact scoped manifest signer.
    /// # Errors
    /// Refuses changed stage/digest/unlock or a foreign encoded proof.
    pub async fn reverse_source_draft(
        &mut self,
        draft: ramflux_storage::FullReverseSourceDraft,
    ) -> Result<FullReverseManifestDraft, SdkError> {
        let Applied::Draft(manifest) =
            self.reverse_request(Action::AcceptSource(Box::new(draft))).await?
        else {
            return Err(wrong());
        };
        Ok(FullReverseManifestDraft { manifest, scope: self.scope.clone() })
    }
    /// Read only an exact originally signed B reverse chunk, never a generic source path.
    /// # Errors
    /// Refuses another role, unsigned/foreign metadata or corrupt private bytes.
    pub async fn read_reverse_source_chunk(
        &mut self,
        hash: &str,
        index: u64,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, SdkError> {
        let Applied::Bytes(bytes) =
            self.reverse_request(Action::ReadSource { hash: hash.into(), index }).await?
        else {
            return Err(wrong());
        };
        Ok(bytes)
    }
    /// Retain original-B bytes through A's encrypted fsync-before-receipt owner.
    /// # Errors
    /// Refuses foreign/changed bytes, a stale source or disk failures.
    pub async fn retain_reverse_chunk(
        &mut self,
        hash: &str,
        index: u64,
        bytes: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<Option<u64>, SdkError> {
        let Applied::Prefix(prefix) =
            self.reverse_request(Action::RetainChunk { hash: hash.into(), index, bytes }).await?
        else {
            return Err(wrong());
        };
        Ok(prefix)
    }
    /// Revalidate A's original reverse durable prefix before granting network credit.
    /// # Errors
    /// Refuses foreign manifests, locked writers or failed repaired-prefix persistence.
    pub async fn reverse_prefix(&mut self, hash: &str) -> Result<Option<u64>, SdkError> {
        let Applied::Prefix(prefix) = self.reverse_request(Action::Prefix(hash.into())).await?
        else {
            return Err(wrong());
        };
        Ok(prefix)
    }
    /// Release A's writer before checking the complete authenticated restrictive stream.
    /// # Errors
    /// Refuses wrong role/context, absent slots or an unavailable original unlock.
    pub async fn reverse_validation_work(
        &mut self,
        hash: &str,
    ) -> Result<Box<ramflux_storage::FullReverseValidationWork>, SdkError> {
        let Applied::Validation(work) = self.reverse_request(Action::Validate(hash.into())).await?
        else {
            return Err(wrong());
        };
        Ok(work)
    }
    /// Retain only the exact off-loan input proof; this does not mark semantic verification.
    /// # Errors
    /// Refuses replaced stage/path/unlock or metadata persistence failures.
    pub async fn accept_reverse_input(
        &mut self,
        input: ramflux_storage::FullValidatedReverseInput,
    ) -> Result<(), SdkError> {
        let Applied::InputAccepted =
            self.reverse_request(Action::AcceptInput(Box::new(input))).await?
        else {
            return Err(wrong());
        };
        Ok(())
    }
    /// Commit at most 32 actual A restrictive records; true means the entire input is applied.
    /// # Errors
    /// Refuses unvalidated input, changed A or failed account/progress persistence.
    pub async fn merge_reverse_batch(&mut self, hash: &str) -> Result<bool, SdkError> {
        let Applied::Merged(complete) = self.reverse_request(Action::Merge(hash.into())).await?
        else {
            return Err(wrong());
        };
        Ok(complete)
    }
}

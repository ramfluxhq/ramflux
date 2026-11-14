// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-entry signature cache for a freshly read, completely fingerprinted public account.
use super::StoredAuthority;
use crate::SdkError;
use ramflux_crypto::custody::{VerifiedRecord, verify_record};

#[derive(Default)]
pub(crate) struct PublicAuthorityCache(Option<Box<Entry>>);
struct Entry {
    at: u64,
    fingerprint: [u8; 32],
    record: VerifiedRecord,
}
impl PublicAuthorityCache {
    pub(super) fn verify(
        &mut self,
        stored: &StoredAuthority,
        human: Option<&VerifiedRecord>,
        at: u64,
    ) -> Result<VerifiedRecord, SdkError> {
        let bytes = serde_json::to_vec(&(stored, human.map(VerifiedRecord::envelope)))?;
        let fingerprint = *blake3::hash(&bytes).as_bytes();
        if let Some(record) = self.get(at, &fingerprint) {
            return Ok(record);
        }
        let verified = verify_record(&stored.record, at, stored.compacted_ids.as_deref(), human)?;
        self.remember(at, fingerprint, verified.clone());
        Ok(verified)
    }
    fn get(&self, at: u64, fingerprint: &[u8; 32]) -> Option<VerifiedRecord> {
        let entry = self.0.as_ref()?;
        (entry.at == at && &entry.fingerprint == fingerprint).then(|| entry.record.clone())
    }
    fn remember(&mut self, at: u64, fingerprint: [u8; 32], record: VerifiedRecord) {
        self.0 = Some(Box::new(Entry { at, fingerprint, record }));
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded signature-work reuse for identical public authority at the exact verification time.
use ramflux_crypto::custody::VerifiedRecord;
use std::collections::BTreeMap;
const MAX_AUTHORITIES: usize = 16;
struct Entry {
    at: u64,
    state: [u8; 32],
    record: VerifiedRecord,
}
#[derive(Default)]
pub(crate) struct VerifiedAuthorityCache {
    authorities: BTreeMap<String, Entry>,
    own_manifest: Option<[u8; 32]>,
}
impl VerifiedAuthorityCache {
    pub(crate) fn own_manifest_verified(&self, fingerprint: &[u8; 32]) -> bool {
        self.own_manifest.as_ref() == Some(fingerprint)
    }
    pub(crate) fn remember_own_manifest(&mut self, fingerprint: [u8; 32]) {
        self.own_manifest = Some(fingerprint);
    }
    pub(crate) fn get(&self, anchor: &str, at: u64, state: &[u8; 32]) -> Option<VerifiedRecord> {
        let entry = self.authorities.get(anchor)?;
        (entry.at == at && &entry.state == state).then(|| entry.record.clone())
    }
    pub(crate) fn remember(
        &mut self,
        anchor: &str,
        at: u64,
        state: [u8; 32],
        record: VerifiedRecord,
    ) {
        if self.authorities.len() >= MAX_AUTHORITIES {
            self.authorities.clear();
        }
        self.authorities.insert(anchor.into(), Entry { at, state, record });
    }
}

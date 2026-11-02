// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Monotonic current-head observations are process-local and never restored with account data.
use crate::{RamfluxClient, SdkError, prekey::SdkDeviceManifestResponse};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
const MAX_HEADS: usize = 512;
const FRESH_FOR: Duration = Duration::from_secs(300);
#[derive(Default)]
pub(crate) struct NativeHeadFreshness {
    heads: BTreeMap<String, (String, Instant)>,
}
impl NativeHeadFreshness {
    fn remember(&mut self, root: &str, hash: String, at: Instant) {
        if self.heads.get(root).is_some_and(|(seen, observed)| seen == &hash && *observed > at) {
            return;
        }
        if !self.heads.contains_key(root) && self.heads.len() >= MAX_HEADS {
            let oldest =
                self.heads.iter().min_by_key(|(_, (_, at))| *at).map(|(root, _)| root.clone());
            if let Some(oldest) = oldest {
                self.heads.remove(&oldest);
            }
        }
        self.heads.insert(root.to_owned(), (hash, at));
    }
    fn contains(&self, root: &str, hash: &str, now: Instant) -> bool {
        self.heads.get(root).is_some_and(|(observed, at)| {
            observed == hash && now.checked_duration_since(*at).is_some_and(|age| age <= FRESH_FOR)
        })
    }
}
impl RamfluxClient {
    /// Only a completed current-directory network fetch may call this helper. Own-device
    /// history, archive import, cached manifests and caller-supplied JSON use the evidence-only
    /// persistence helper; none can refresh this process-local authorization clock.
    pub(crate) fn persist_fetched_identity_directory(
        &self,
        manifest: &SdkDeviceManifestResponse,
    ) -> Result<(), SdkError> {
        self.persist_fetched_identity_directory_at(manifest, Instant::now())
    }

    /// A prepared network result retains its conservative fetch-time lower bound while queued.
    /// Caller-supplied, cached or archived manifests must not use this freshness-bearing helper.
    pub(crate) fn persist_fetched_identity_directory_at(
        &self,
        manifest: &SdkDeviceManifestResponse,
        observed_at: Instant,
    ) -> Result<(), SdkError> {
        self.persist_identity_directory(manifest)?;
        if let Some(native) = &manifest.custody {
            let hash = ramflux_protocol::custody::object_hash(&native.publication.record)?;
            self.native_head_freshness.borrow_mut().remember(
                &manifest.principal_commitment,
                hash,
                observed_at,
            );
        }
        Ok(())
    }
    pub(crate) fn invalidate_changed_custody_head(&self, root: &str, hash: &str) {
        let mut cache = self.native_head_freshness.borrow_mut();
        if cache.heads.get(root).is_some_and(|(old, _)| old != hash) {
            cache.heads.remove(root);
        }
    }
    pub(crate) fn require_fresh_custody_head(
        &self,
        root: &str,
        record: &ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>,
    ) -> Result<(), SdkError> {
        let hash = ramflux_protocol::custody::object_hash(record)?;
        if self.native_head_freshness.borrow().contains(root, &hash, Instant::now()) {
            Ok(())
        } else {
            Err(SdkError::InboundPending(
                "native current-head freshness expired; refresh directory".into(),
            ))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn prepared_courier_current_head_clock_retains_fetch_age()
    -> crate::client::native_test_support::TestResult {
        use crate::client::native_test_support::Fixture;
        let local = Fixture::new("courier-freshness-local").await?;
        let remote = Fixture::new("courier-freshness-remote").await?;
        let old =
            Instant::now().checked_sub(FRESH_FOR + Duration::from_secs(1)).ok_or("clock range")?;
        let native = remote.manifest.custody.as_ref().ok_or("native manifest missing")?;
        let root = &remote.manifest.principal_commitment;
        local.client.persist_fetched_identity_directory_at(&remote.manifest, old)?;
        assert!(
            local.client.require_fresh_custody_head(root, &native.publication.record).is_err(),
            "queued public evidence cannot renew the directory permission clock"
        );
        local.client.persist_fetched_identity_directory(&remote.manifest)?;
        local.client.persist_fetched_identity_directory_at(&remote.manifest, old)?;
        assert!(
            local.client.require_fresh_custody_head(root, &native.publication.record).is_ok(),
            "an older queued copy cannot overwrite a newer network observation"
        );
        Ok(())
    }

    #[test]
    fn freshness_is_exact_monotonic_bounded_and_not_recreated_from_an_old_head() {
        let mut cache = NativeHeadFreshness::default();
        let now = Instant::now();
        cache.remember("root", "head".into(), now);
        assert!(cache.contains("root", "head", now + FRESH_FOR));
        assert!(!cache.contains("root", "head", now + FRESH_FOR + Duration::from_nanos(1)));
        assert!(!cache.contains("root", "replacement", now));
        cache.remember("future", "head".into(), now + Duration::from_secs(1));
        assert!(!cache.contains("future", "head", now));
        assert!(!NativeHeadFreshness::default().contains("root", "head", now));
        for index in 0..MAX_HEADS {
            cache.remember(&format!("root-{index}"), "head".into(), now + Duration::from_secs(1));
        }
        assert_eq!(cache.heads.len(), MAX_HEADS);
        assert!(!cache.contains("root", "head", now));
    }
}

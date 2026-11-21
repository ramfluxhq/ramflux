// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Streaming node-boundary/log evidence retains sizes and violation flags, never payloads.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
const FORBIDDEN: [&[u8]; 10] = [
    b"sql/account_mac_bundle",
    b"sql/object_erasure_fence",
    b"census_hash",
    b"manifest_hash",
    b"chunks_root",
    b"portable_records",
    b"source_rows",
    b"\"kind\":\"manifest\"",
    b"\"kind\":\"chunk\"",
    b"\"kind\":\"data_verified\"",
];
#[derive(Default)]
pub(in crate::custody::pairing::component_tests) struct NodeEvidence {
    violated: AtomicBool,
    corrupt_next: AtomicBool,
    corruption_relayed: AtomicUsize,
    sends: AtomicUsize,
    admitted_sends: AtomicUsize,
    bytes: AtomicUsize,
    logs: AtomicUsize,
    roots: Mutex<Option<zeroize::Zeroizing<[[u8; 32]; 2]>>>,
}
impl NodeEvidence {
    pub(in crate::custody::pairing::component_tests) fn corrupt_next_packet(&self) {
        self.corrupt_next.store(true, Ordering::Release);
    }
    pub(super) fn take_corruption(&self) -> bool {
        self.corrupt_next.swap(false, Ordering::AcqRel)
    }
    pub(super) fn relayed_corruption(&self) {
        self.corruption_relayed.fetch_add(1, Ordering::Release);
    }
    pub(in crate::custody::pairing::component_tests) fn admitted_corruption(&self) -> usize {
        self.corruption_relayed.load(Ordering::Acquire)
    }
    pub(super) fn observe(&self, bytes: &[u8]) {
        if FORBIDDEN.iter().any(|needle| bytes.windows(needle.len()).any(|part| part == *needle)) {
            self.violated.store(true, Ordering::Release);
        }
        let Ok(roots) = self.roots.lock() else {
            self.violated.store(true, Ordering::Release);
            return;
        };
        if let Some(roots) = roots.as_ref() {
            for root in roots.iter() {
                let encoded = zeroize::Zeroizing::new(ramflux_protocol::encode_base64url(root));
                if bytes.windows(root.len()).any(|part| part == root)
                    || bytes.windows(encoded.len()).any(|part| part == encoded.as_bytes())
                {
                    self.violated.store(true, Ordering::Release);
                }
            }
        }
    }
    pub(in crate::custody::pairing::component_tests) fn reject_roots(
        &self,
        root: [u8; 32],
        census: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        *self.roots.lock().map_err(|_| "test: private root observation lock")? =
            Some(zeroize::Zeroizing::new([root, census]));
        Ok(())
    }
    pub(super) fn admitted_send(&self) {
        self.admitted_sends.fetch_add(1, Ordering::Release);
    }
    pub(in crate::custody::pairing::component_tests) fn admitted_sends(&self) -> usize {
        self.admitted_sends.load(Ordering::Acquire)
    }
    pub(super) fn sent(&self, bytes: usize) {
        self.sends.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }
    pub(super) fn node<T>(self: &Arc<Self>, work: impl FnOnce() -> T) -> T {
        tracing::dispatcher::with_default(&tracing::Dispatch::new(Logs(self.clone())), work)
    }
    pub(in crate::custody::pairing::component_tests) fn check_persistence(
        &self,
        path: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Read as _;
        let mut file = std::fs::File::open(path)?;
        if file.metadata()?.len() > 64 * 1024 * 1024 {
            return Err("test: node persistence fixture exceeded bounded scan size".into());
        }
        let mut block = [0_u8; 8192];
        let mut window = Vec::with_capacity(8448);
        loop {
            let length = file.read(&mut block)?;
            if length == 0 {
                break;
            }
            window.extend_from_slice(block.get(..length).ok_or("test: bounded persistence block")?);
            self.observe(&window);
            let keep = window.len().saturating_sub(256);
            drop(window.drain(..keep));
        }
        Ok(())
    }
    pub(in crate::custody::pairing::component_tests) fn assert_private(&self) {
        assert!(
            self.sends.load(Ordering::Acquire) > 0,
            "test: no actual encrypted node packets observed"
        );
        assert!(
            self.bytes.load(Ordering::Acquire) > 0,
            "test: node-bound size witness was vacuous"
        );
        assert!(
            self.logs.load(Ordering::Acquire) > 0,
            "test: node relay log subscriber was not installed"
        );
        assert!(
            !self.violated.load(Ordering::Acquire),
            "test: node wire, persistence or relay logs exposed private transfer metadata"
        );
    }
}
struct Logs(Arc<NodeEvidence>);
impl tracing::Subscriber for Logs {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target().contains("pairing_relay")
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        values.record(&mut Visitor(&self.0));
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        self.0.logs.fetch_add(1, Ordering::Relaxed);
        event.record(&mut Visitor(&self.0));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
struct Visitor<'a>(&'a NodeEvidence);
impl tracing::field::Visit for Visitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        self.0.observe(field.name().as_bytes());
        let _ = write!(self, "{value:?}");
    }
}
impl std::fmt::Write for Visitor<'_> {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        self.0.observe(value.as_bytes());
        Ok(())
    }
}

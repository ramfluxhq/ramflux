// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Poll validation noise must not rewrite state, and stream gaps are connection scoped.
use super::support::{Fake, Fixture, TestResult, incoming};
use ramflux_agent_host::{AgentBus, AgentHost, Error, Result, RuleEngine};
use ramflux_sdk::{LocalBusFrame, SurfaceRefusalCode as Code};
use serde_json::Value;
use std::os::unix::fs::MetadataExt;
struct PollBus {
    inner: Fake,
    path: std::path::PathBuf,
    inodes: Vec<u64>,
}
impl AgentBus for PollBus {
    async fn request(&mut self, method: &str, body: Value, op: Option<&str>) -> Result<Value> {
        if method == "message.receive" {
            self.inodes.push(std::fs::metadata(&self.path).map_err(|_| Error::Storage)?.ino());
            return Err(Error::SurfaceRefused(Code::InvalidRequest));
        }
        self.inner.request(method, body, op).await
    }
    async fn next_event(&mut self) -> Result<LocalBusFrame> {
        if self.inodes.len() >= 3 {
            return Err(Error::Bus);
        }
        std::future::pending().await
    }
}
#[tokio::test]
async fn r5_unchanged_poll_refusals_do_not_replace_the_checkpoint_again() -> TestResult {
    let mut f = Fixture::new()?;
    f.config.poll_interval_ms = 50;
    let mut bus =
        PollBus { inner: Fake::default(), path: f.config.state_file.clone(), inodes: vec![] };
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(1), host.run(&mut bus)).await?,
        Err(Error::Bus)
    ));
    assert_eq!(bus.inodes.len(), 3);
    assert_ne!(bus.inodes[0], bus.inodes[1]);
    assert_eq!(bus.inodes[1], bus.inodes[2]);
    assert_eq!(
        host.checkpoint().last_refusal.as_ref().ok_or("refusal")?.reason,
        Code::InvalidRequest
    );
    Ok(())
}
#[tokio::test]
async fn r5_an_unscoped_stream_gap_requests_reconnect_instead_of_being_skipped() -> TestResult {
    let f = Fixture::new()?;
    let mut bus = Fake::default();
    let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
    host.start(&mut bus).await?;
    let mut lagged = incoming(11, false);
    lagged.account_id = None;
    lagged.seq = None;
    lagged.method = "stream.lagged".into();
    assert!(matches!(host.apply(&mut bus, lagged, 2000).await, Err(Error::Resync)));
    assert_eq!(host.checkpoint().cursor, Some(10));
    Ok(())
}

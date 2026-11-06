// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Whole-population issued observations, bounded to four 1,024-target requests.
mod request;
use crate::{GatewaySessionHub, RouterMeshClient};
pub(crate) use request::Requests;
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IssuedSeq {
    pub(crate) target_delivery_id: String,
    pub(crate) incarnation_id: Option<String>,
    pub(crate) inbox_seq: u64,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct IssuedSeqsResponse {
    issued: Vec<IssuedSeq>,
}
use std::{
    collections::BTreeMap,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

pub(crate) fn start(hub: &Arc<GatewaySessionHub>, router: &RouterMeshClient) {
    if hub.probe_started.swap(true, Ordering::AcqRel) {
        return;
    }
    let weak = Arc::downgrade(hub);
    let router = router.clone();
    tokio::spawn(async move {
        let mut last_log = None;
        loop {
            let Some(hub) = weak.upgrade() else {
                return;
            };
            let failed = round(&hub, &router).await;
            drop(hub);
            let now = tokio::time::Instant::now();
            if failed && last_log.is_none_or(|t| now.duration_since(t) >= Duration::from_secs(60)) {
                tracing::warn!("issued observation failed; confirmations reset");
                last_log = Some(now);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

/// The immutable index pins the round's token high-water without copying the population.
/// Replacements are checked by token on application; later registrations start next round.
pub(crate) async fn round(hub: &Arc<GatewaySessionHub>, router: &RouterMeshClient) -> bool {
    let snapshot = hub.snapshot().await;
    let mut tasks = tokio::task::JoinSet::new();
    let mut offset = 0;
    let mut failed = false;
    loop {
        let page = snapshot.page(offset);
        if page.is_empty() {
            break;
        }
        offset += page.len();
        let hub = hub.clone();
        let router = router.clone();
        tasks.spawn(async move {
            let targets: Vec<_> = page.iter().map(|(target, _)| target.clone()).collect();
            let result = request::post(&router, targets.clone(), &hub.probe_requests)
                .await
                .and_then(|reply| decode(&targets, &reply.bytes, reply.mesh_frame))
                .ok();
            for (target, entry) in page {
                hub.probe_observation(
                    &target,
                    entry.token,
                    result.as_ref().and_then(|r| r.get(&target)),
                )
                .await;
            }
            result.is_none()
        });
        if tasks.len() == 4 {
            failed |= tasks.join_next().await.is_none_or(|r| r.unwrap_or(true));
        }
    }
    while let Some(result) = tasks.join_next().await {
        failed |= result.unwrap_or(true);
    }
    failed
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InvalidBatch {
    TargetCount,
    TargetDuplicate,
    TargetEmpty,
    ResultCount,
    ResultTarget,
    ResultDuplicate,
    Incarnation,
}
impl std::fmt::Display for InvalidBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid issued batch: {self:?}")
    }
}
impl std::error::Error for InvalidBatch {}
fn validate(
    targets: &[String],
    response: IssuedSeqsResponse,
) -> Result<BTreeMap<String, IssuedSeq>, InvalidBatch> {
    use InvalidBatch as E;
    if targets.is_empty() || targets.len() > 1024 {
        return Err(E::TargetCount);
    }
    let expected: std::collections::BTreeSet<_> = targets.iter().collect();
    if expected.len() != targets.len() {
        return Err(E::TargetDuplicate);
    }
    if targets.iter().any(String::is_empty) {
        return Err(E::TargetEmpty);
    }
    if response.issued.len() != targets.len() {
        return Err(E::ResultCount);
    }
    let mut result = BTreeMap::new();
    for row in response.issued {
        if !expected.contains(&row.target_delivery_id) {
            return Err(E::ResultTarget);
        }
        if row
            .incarnation_id
            .as_deref()
            .is_some_and(|id| !ramflux_node_core::valid_inbox_incarnation(id))
            || (row.incarnation_id.is_none() && row.inbox_seq != 0)
        {
            return Err(E::Incarnation);
        }
        if result.insert(row.target_delivery_id.clone(), row).is_some() {
            return Err(E::ResultDuplicate);
        }
    }
    Ok(result)
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct IssuedWireResponse {
    status: u16,
    body: IssuedSeqsResponse,
}
fn decode(
    targets: &[String],
    bytes: &[u8],
    mesh_frame: bool,
) -> anyhow::Result<BTreeMap<String, IssuedSeq>> {
    // Validate original bytes with the shared I-JSON policy before constructing typed rows.
    let response = if mesh_frame {
        let wire: IssuedWireResponse = ramflux_protocol::parse_i_json(bytes)?;
        anyhow::ensure!(
            (200..300).contains(&wire.status),
            "issued probe HTTP status {}",
            wire.status
        );
        wire.body
    } else {
        ramflux_protocol::parse_i_json(bytes)?
    };
    Ok(validate(targets, response)?)
}

/// Offered ranges are hints only. They never acknowledge or settle a client inbox.
#[derive(Default)]
pub(crate) struct Coverage {
    pub(crate) prefix: u64,
    ranges: Vec<(u64, u64)>,
    confirmations: u8,
}
impl Coverage {
    pub(crate) fn offered(&mut self, first: u64, last: u64) -> bool {
        if first > last || last <= self.prefix {
            return true;
        }
        self.ranges.push((first, last));
        self.ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(257);
        for (lo, hi) in self.ranges.drain(..) {
            if lo <= self.prefix.saturating_add(1) {
                self.prefix = self.prefix.max(hi);
            } else if let Some(range) = merged.last_mut().filter(|r| lo <= r.1.saturating_add(1)) {
                range.1 = range.1.max(hi);
            } else {
                merged.push((lo, hi));
            }
        }
        if self.prefix >= last {
            self.confirmations = 0;
        }
        let bounded = merged.len() <= 256;
        merged.truncate(256);
        self.ranges = merged;
        bounded
    }
    pub(crate) fn observe(&mut self, issued: Option<u64>) -> Option<(u64, u64)> {
        if let Some(issued) = issued.filter(|s| *s > self.prefix) {
            self.confirmations = self.confirmations.saturating_add(1);
            if self.confirmations >= 2 {
                return Some((self.prefix, issued));
            }
        } else {
            self.confirmations = 0;
        }
        None
    }
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receiving federation charges the actual authenticated node and observed egress prefix.
use super::FederationRedbStore;
use crate::contact_reach::{CostIssuerPeer, ReachError, Result};
use ramflux_protocol::contact_reach::Reason;
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
const RATES: TableDefinition<&str, &[u8]> = TableDefinition::new("contact_cost_peer_rates_v1");
const MAX_ROWS: u64 = 8192;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rate {
    count: u64,
    until: u64,
}
fn storage(error: impl std::fmt::Display) -> ReachError {
    crate::NodeCoreError::Redb(error.to_string()).into()
}
fn refuse(reason: Reason) -> ReachError {
    ReachError::Refused(reason)
}
impl FederationRedbStore {
    /// Charge before calling the issuer router; forwarded bodies never supply a peer identity/IP.
    /// The issuer router independently enforces its global issue rate and challenge hash cap.
    /// # Errors
    /// Refuses invalid TLS roles, exhausted per-node/prefix/global budgets or storage faults.
    pub fn admit_contact_cost(
        &self,
        peer: &crate::MeshPeerIdentity,
        remote: std::net::IpAddr,
        now: u64,
    ) -> Result<()> {
        let peer = CostIssuerPeer::from_tls(peer, remote)?;
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        let now = super::contact_clock::fenced(&tx, now)?;
        let window = now / 60;
        let until = window
            .checked_add(2)
            .and_then(|n| n.checked_mul(60))
            .ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
        let mut rates = tx.open_table(RATES).map_err(storage)?;
        let expired = rates
            .iter()
            .map_err(storage)?
            .take(usize::try_from(MAX_ROWS).map_err(storage)?)
            .map(|entry| {
                let (key, value) = entry.map_err(storage)?;
                let rate: Rate = serde_json::from_slice(value.value()).map_err(storage)?;
                Ok((key.value().to_owned(), rate.until))
            })
            .collect::<Result<Vec<_>>>()?;
        for (key, deadline) in expired {
            if deadline <= now {
                rates.remove(key.as_str()).map_err(storage)?;
            }
        }
        for (scope, value, cap) in
            [("global", "", 1000), ("node", peer.node(), 60), ("prefix", peer.prefix(), 120)]
        {
            let key = serde_json::to_string(&(scope, window, value)).map_err(storage)?;
            let prior = rates
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| serde_json::from_slice::<Rate>(value.value()).map_err(storage))
                .transpose()?;
            if prior.is_none() && rates.len().map_err(storage)? >= MAX_ROWS {
                return Err(refuse(Reason::ForeignCapacity));
            }
            let count = prior
                .map_or(0, |rate| rate.count)
                .checked_add(1)
                .filter(|count| *count <= cap)
                .ok_or_else(|| refuse(Reason::ForeignRateLimited))?;
            rates
                .insert(
                    key.as_str(),
                    ramflux_protocol::canonical_json_bytes(&Rate { count, until })?.as_slice(),
                )
                .map_err(storage)?;
        }
        drop(rates);
        tx.commit().map_err(storage)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

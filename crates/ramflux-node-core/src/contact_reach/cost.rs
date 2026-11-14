// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persisted, bounded challenges consumed by the same writer transaction as first admission.
use super::{
    Result, refuse, storage,
    store::{encoded, row},
};
use crate::{MigrationNode, RouterRedbStore};
use ed25519_dalek::Signer;
use ramflux_protocol::{
    contact_reach::{
        COMMAND_LIFETIME, COST_CONTEXT_DOMAIN, COST_DOMAIN, Challenge, ChallengeRequest, Cost,
        CostPurpose, Reason,
    },
    custody::{self, Envelope as Signed},
};
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition};
#[cfg(test)]
pub(super) mod fault;
use serde::{Deserialize, Serialize};

const CHALLENGES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("contact_reach_challenges_v1");
const ISSUE_RATES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("contact_reach_challenge_rates_v1");
/// TLS-derived source identity and observed node egress prefix; never a forwarded user address.
pub struct CostIssuerPeer {
    node: String,
    prefix: String,
    proxy_budgeted: bool,
}
impl CostIssuerPeer {
    /// Bind challenge budgets to an authenticated federation identity and socket address.
    /// # Errors
    /// Refuses non-federation service identities and inconsistent parsed identity facts.
    pub fn from_tls(peer: &crate::MeshPeerIdentity, remote: std::net::IpAddr) -> Result<Self> {
        let parsed = crate::parse_mesh_spiffe_uri(&peer.spiffe_uri)?;
        ramflux_protocol::contact_reach::validate_node_selector(&parsed.node_id)?;
        if parsed.node_id != peer.node_id
            || parsed.service_id != "ramflux-federation"
            || parsed.service_id != peer.service_id
        {
            return Err(refuse(Reason::ForeignReadRefused));
        }
        let prefix = match remote {
            std::net::IpAddr::V4(ip) => {
                format!("{}/24", std::net::Ipv4Addr::from(u32::from(ip) & 0xffff_ff00))
            }
            std::net::IpAddr::V6(ip) => {
                format!("{}/56", std::net::Ipv6Addr::from(u128::from(ip) & (u128::MAX << 72)))
            }
        };
        Ok(Self { node: peer.node_id.clone(), prefix, proxy_budgeted: false })
    }
    // Only the own-federation issuer hop may use this after charging its authenticated peer.
    pub(crate) fn budgeted_proxy(node: &str) -> Self {
        Self { node: node.into(), prefix: String::new(), proxy_budgeted: true }
    }
    #[must_use]
    pub(crate) fn node(&self) -> &str {
        &self.node
    }
    #[must_use]
    pub(crate) fn prefix(&self) -> &str {
        &self.prefix
    }
    pub(super) fn local(node: &str) -> Self {
        Self { node: node.into(), prefix: format!("local:{node}"), proxy_budgeted: false }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueRate {
    count: u64,
    until: u64,
}
fn charge_issue(tx: &redb::WriteTransaction, peer: &CostIssuerPeer, now: u64) -> Result<()> {
    let window = now / 60;
    let until = window
        .checked_add(2)
        .and_then(|n| n.checked_mul(60))
        .ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
    let mut table = tx.open_table(ISSUE_RATES).map_err(storage)?;
    let expired = table
        .iter()
        .map_err(storage)?
        .take(8192)
        .map(|r| {
            let (key, value) = r.map_err(storage)?;
            Ok((key.value().to_owned(), row::<IssueRate>(value.value())?.until))
        })
        .collect::<Result<Vec<_>>>()?;
    for (key, until) in expired {
        if until <= now {
            table.remove(key.as_str()).map_err(storage)?;
        }
    }
    for (scope, value, cap) in [
        ("global", "", 1000_u64),
        ("node", peer.node.as_str(), 60),
        ("prefix", peer.prefix.as_str(), 120),
    ] {
        if peer.proxy_budgeted && scope != "global" {
            continue;
        }
        let key = serde_json::to_string(&(scope, window, value)).map_err(storage)?;
        let prior = table
            .get(key.as_str())
            .map_err(storage)?
            .map(|v| row::<IssueRate>(v.value()))
            .transpose()?;
        if prior.is_none() && table.len().map_err(storage)? >= 8192 {
            return Err(refuse(Reason::ForeignCapacity));
        }
        let count = prior
            .map_or(0, |r| r.count)
            .checked_add(1)
            .filter(|n| *n <= cap)
            .ok_or_else(|| refuse(Reason::ForeignRateLimited))?;
        table
            .insert(key.as_str(), encoded(&IssueRate { count, until })?.as_slice())
            .map_err(storage)?;
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Issued {
    expires: u64,
    consumed: Option<String>,
}

pub(super) fn consume(
    tx: &redb::WriteTransaction,
    cost: &Cost,
    operation: &str,
    now: u64,
) -> Result<()> {
    let hash = custody::framed_hash(COST_CONTEXT_DOMAIN, &cost.challenge)?;
    let mut table = tx.open_table(CHALLENGES).map_err(storage)?;
    let mut issued: Issued = table
        .get(hash.as_str())
        .map_err(storage)?
        .map(|v| row(v.value()))
        .transpose()?
        .ok_or_else(|| refuse(Reason::CostInvalid))?;
    if issued.expires <= now || issued.consumed.as_ref().is_some_and(|old| old != operation) {
        return Err(refuse(Reason::CostInvalid));
    }
    issued.consumed = Some(operation.into());
    table.insert(hash.as_str(), encoded(&issued)?.as_slice()).map_err(storage)?;
    Ok(())
}

impl RouterRedbStore {
    /// Issue a fresh signed puzzle without allocating authority or reserving a name.
    /// The caller authenticates the source home and applies source-prefix/node issue limits.
    /// # Errors
    /// Refuses malformed purposes and full unexpired challenge storage.
    pub fn reach_issue_cost(
        &self,
        node: &MigrationNode,
        peer: &CostIssuerPeer,
        request: &ChallengeRequest,
        now: u64,
    ) -> Result<Signed<Challenge>> {
        request.validate()?;
        if request.purpose != CostPurpose::Stranger {
            return Err(refuse(Reason::CostInvalid));
        }
        let nonce = ramflux_crypto::random_32()?;
        let (tx, now) = self.begin_reach_write(now)?;
        let recipient =
            request.recipient_root.as_deref().ok_or_else(|| refuse(Reason::CostInvalid))?;
        let home = super::store::home(&tx, recipient).map_err(|error| match error {
            super::ReachError::Refused(_) => refuse(Reason::CostInvalid),
            error => error,
        })?;
        if home.record.home() != (node.node_id(), node.public_key()) {
            return Err(refuse(Reason::CostInvalid));
        }
        let _recipient_authority = super::store::authority(&tx, recipient, now)?;
        charge_issue(&tx, peer, now)?;
        let expires =
            now.checked_add(COMMAND_LIFETIME).ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
        let body = Challenge {
            version: 1,
            issuer: node.node_id().into(),
            purpose: request.purpose,
            source_root: request.source_root.clone(),
            recipient_root: request.recipient_root.clone(),
            operation_hash: request.operation_hash.clone(),
            nonce: ramflux_protocol::encode_base64url(nonce),
            difficulty: u64::from(request.purpose.difficulty()),
            issued_at: now,
            expires_at: expires,
        };
        body.validate()?;
        let signature = ramflux_protocol::encode_base64url(
            node.key.sign(&custody::signing_bytes(COST_DOMAIN, &body)?).to_bytes(),
        );
        let signed = Signed { body, signature };
        let mut table = tx.open_table(CHALLENGES).map_err(storage)?;
        let rows = table
            .iter()
            .map_err(storage)?
            .take(4096)
            .map(|e| {
                let (k, v) = e.map_err(storage)?;
                Ok((k.value().to_owned(), row::<Issued>(v.value())?))
            })
            .collect::<Result<Vec<_>>>()?;
        for (key, issued) in rows {
            if issued.expires.checked_add(60).is_some_and(|e| e <= now) {
                table.remove(key.as_str()).map_err(storage)?;
            }
        }
        if table.len().map_err(storage)? >= 4096 {
            return Err(refuse(Reason::ForeignCapacity));
        }
        table
            .insert(
                custody::framed_hash(COST_CONTEXT_DOMAIN, &signed)?.as_str(),
                encoded(&Issued { expires, consumed: None })?.as_slice(),
            )
            .map_err(storage)?;
        drop(table);
        #[cfg(test)]
        fault::checkpoint(fault::Point::BeforeCommit)?;
        tx.commit()?;
        #[cfg(test)]
        fault::checkpoint(fault::Point::AfterCommit)?;
        Ok(signed)
    }
}

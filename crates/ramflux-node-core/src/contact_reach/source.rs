// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source-home public snapshots contain original evidence and no private owner credentials.
use super::{ReachError, ReachService, Result, refuse, store};
use crate::{RouterCore, RouterRedbStore};
use ed25519_dalek::Signer as _;
use ramflux_protocol::{
    contact_reach::{
        self as wire, Discovery, PeerQueryRequest, PeerQueryResponse, PeerQueryResult,
        PeerQueryResultKind, PeerReply, Query, Reason, Snapshot, SnapshotPayload,
    },
    custody::{self, Envelope as Signed},
    home_migration::{MAX_CHAIN_RECORDS, RecordEvidence, ResolveResult},
};

/// Discovery and peer identity come from the local service configuration/authenticated transport.
/// None is accepted as an owner operation or a replacement supplied by the queried account.
pub trait ReachSourceDocuments: Send + Sync {
    /// Read this node's original signed client/server discoveries from its configured service.
    /// # Errors
    /// Refuses unavailable service identity, deadline expiry and invalid/oversized documents.
    fn read(&self, deadline: std::time::Instant) -> Result<Discovery>;
    /// Read the node's original bounded rotation proofs from the same authenticated service.
    /// # Errors
    /// Refuses missing or invalid continuity documents and exhausted deadlines.
    fn continuity(&self, deadline: std::time::Instant) -> Result<Vec<serde_json::Value>>;
}

#[derive(Clone, Copy)]
pub struct ReachSnapshotContext<'a> {
    pub router: &'a RouterCore,
    pub store: &'a RouterRedbStore,
    pub discovery: &'a Discovery,
    pub continuity: &'a [serde_json::Value],
    pub peer_node: &'a str,
    pub now: u64,
    pub deadline: std::time::Instant,
}
impl ReachService {
    /// Configure only the node's own authenticated discovery source, never an owner-selected URL.
    #[must_use]
    pub fn with_source_documents(
        mut self,
        documents: std::sync::Arc<dyn ReachSourceDocuments>,
    ) -> Self {
        self.source_documents = Some(documents);
        self
    }

    /// Execute a source snapshot after the listener authenticated its own federation proxy.
    /// The federation proxy has already matched `Q.source_node` to the actual peer's TLS node.
    /// # Errors
    /// Malformed requests refuse without guessing correlation; service failures are typed results.
    pub fn public_query_from_proxy(
        &self,
        router: &RouterCore,
        store: &RouterRedbStore,
        request: &PeerQueryRequest,
        now: u64,
    ) -> Result<PeerQueryResponse> {
        request.validate()?;
        let result = (|| {
            if !wire::enabled() {
                return Err(refuse(Reason::ForeignCapabilityMissing));
            }
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_millis(request.remaining_ms);
            let documents =
                self.source_documents.as_ref().ok_or_else(|| refuse(Reason::ForeignUnavailable))?;
            let discovery = documents.read(deadline)?;
            let continuity = documents.continuity(deadline)?;
            self.public_query(
                ReachSnapshotContext {
                    router,
                    store,
                    discovery: &discovery,
                    continuity: &continuity,
                    peer_node: &request.query.source_node,
                    now: now.max(crate::now_unix_seconds()),
                    deadline,
                },
                request,
            )
        })();
        Ok(result.unwrap_or_else(|error| PeerQueryResponse {
            kind: PeerQueryResultKind::QueryResult,
            request_id: request.request_id.clone(),
            result: peer_error(&error),
        }))
    }
    /// Serve the exact public query carrier, including provisional authenticated readers.
    /// Card hashes are correlation, never possession or private-read permission.
    /// # Errors
    /// Malformed input has no guessed correlation; valid queries carry a closed typed result.
    pub fn public_query(
        &self,
        context: ReachSnapshotContext<'_>,
        request: &PeerQueryRequest,
    ) -> Result<PeerQueryResponse> {
        request.validate()?;
        let result = self.public_query_inner(context, &request.query).map_or_else(
            |error| peer_error(&error),
            |reply| PeerQueryResult::Query { reply: Box::new(reply) },
        );
        Ok(PeerQueryResponse {
            kind: PeerQueryResultKind::QueryResult,
            request_id: request.request_id.clone(),
            result,
        })
    }
    fn public_query_inner(
        &self,
        context: ReachSnapshotContext<'_>,
        query: &Query,
    ) -> Result<PeerReply> {
        if !wire::enabled() {
            return Err(refuse(Reason::ForeignCapabilityMissing));
        }
        query.validate()?;
        if query.source_node != context.peer_node || query.target_node != self.node.node_id() {
            return Err(refuse(Reason::ForeignPolicyDenied));
        }
        self.assemble_public_snapshot(context, query)
    }
    fn assemble_public_snapshot(
        &self,
        context: ReachSnapshotContext<'_>,
        query: &Query,
    ) -> Result<PeerReply> {
        let (home, base, records) = history(context.store, query)?;
        let custodian_history = context.store.home_custodian_history(&records)?;
        let manifest = context
            .router
            .ordinary_device_manifest(&query.account_anchor, context.now, context.store)?
            .filter(|manifest| manifest.custody.is_some())
            .ok_or_else(|| refuse(Reason::ForeignReadRefused))?;
        let prekey = query
            .device_ref
            .as_ref()
            .map(|device| {
                context.store.reach_public_prekey(
                    context.router,
                    &self.node,
                    context.peer_node,
                    device,
                    context.now,
                )
            })
            .transpose()?;
        let tx = context.store.begin_write()?;
        let now = store::clock(&tx, context.now)?;
        let authority = store::authority(&tx, &query.account_anchor, now)?;
        let current = store::home(&tx, &query.account_anchor)?;
        let hash = ramflux_protocol::home_migration::record_hash(&current.record)?;
        if current.record.home().0 != self.node.node_id()
            || hash != ramflux_protocol::home_migration::record_hash(&home.home.record)?
            || manifest
                .custody
                .as_ref()
                .is_none_or(|native| native.publication.record != *authority.envelope())
        {
            return Err(refuse(Reason::HomeRollback));
        }
        ramflux_crypto::contact_reach::verify_node_continuity(
            context.continuity,
            ramflux_crypto::contact_reach::NodeContinuityContext {
                node: self.node.node_id(),
                old_key: current.record.home().1,
                current_key: self.node.public_key(),
                minimum_rotated_at: 0,
                now,
            },
        )?;
        let profile = super::profile::public_profile(&tx, &query.account_anchor)?;
        let state = store::load(&tx, &query.account_anchor)?;
        let reach = state.policy.ok_or_else(|| refuse(Reason::ReachPolicyRequired))?;
        ramflux_crypto::contact_reach::verify_retained_policy(&reach, &authority, now)?;
        let payload = SnapshotPayload {
            home,
            discovery: context.discovery.clone(),
            manifest: serde_json::to_value(manifest).map_err(super::storage)?,
            prekey: prekey.map(serde_json::to_value).transpose().map_err(super::storage)?,
            node_continuity: context.continuity.to_vec(),
            reach,
            profile,
            custodian_history,
            directory: None,
        };
        let body = Snapshot {
            version: 1,
            source_node: self.node.node_id().into(),
            target_node: context.peer_node.into(),
            account_anchor: query.account_anchor.clone(),
            request_nonce: query.nonce.clone(),
            request_hash: custody::framed_hash(wire::QUERY_HASH_DOMAIN, query)?,
            payload_hash: custody::framed_hash(wire::PAYLOAD_HASH_DOMAIN, &payload)?,
            issued_at: now,
            expires_at: now.checked_add(60).ok_or_else(|| refuse(Reason::ForeignUnavailable))?,
        };
        let signature = ramflux_protocol::encode_base64url(
            self.node.key.sign(&custody::signing_bytes(wire::SNAPSHOT_DOMAIN, &body)?).to_bytes(),
        );
        let reply = PeerReply { snapshot: Signed { body, signature }, payload };
        ramflux_crypto::contact_reach::verify_peer_reply(
            &reply,
            query,
            self.node.public_key(),
            base.as_ref(),
            now,
        )?;
        if std::time::Instant::now() >= context.deadline {
            return Err(refuse(Reason::ForeignUnavailable));
        }
        tx.commit()?;
        Ok(reply)
    }
}
fn peer_error(error: &ReachError) -> PeerQueryResult {
    let reason = match error {
        ReachError::Refused(reason) => *reason,
        ReachError::Storage(_) => Reason::ForeignStorageUnavailable,
        _ => Reason::ForeignSnapshotInvalid,
    };
    PeerQueryResult::Error {
        reason,
        retry_after_ms: matches!(reason, Reason::ForeignRateLimited | Reason::ForeignSpamLimited)
            .then_some(1000),
        current_revision: None,
    }
}

fn history(
    store: &RouterRedbStore,
    query: &Query,
) -> Result<(ResolveResult, Option<RecordEvidence>, Vec<RecordEvidence>)> {
    let base = query
        .base
        .as_ref()
        .map(|base| store.migration_home_checkpoint(&query.account_anchor, base))
        .transpose()?;
    let home = store.resolve_migration_home(
        &query.account_anchor,
        query.base.as_ref().map(|base| base.hash.as_str()),
        MAX_CHAIN_RECORDS,
    )?;
    let records = base
        .iter()
        .chain(home.predecessors.iter())
        .chain(std::iter::once(&home.home))
        .cloned()
        .collect();
    Ok((home, base, records))
}

#[cfg(test)]
mod tests;

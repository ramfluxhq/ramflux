// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed peer exchanges authenticate node claims independently of service TLS identities.
use crate::{AttestedHome, MigrationNode, MigrationPeer, NodeCoreError, SealedMigration};
use ramflux_crypto::home_migration as crypto;
use ramflux_protocol::{
    custody::framed_hash,
    home_migration::{
        Action, AttestRequest, Authorization, Control, HomeAttestation, NodeCommitDelivery,
        NoncommitFence, PeerQuery, PeerQueryKind, PeerStatus, RecordEvidence, Refusal,
        SKEW_SECONDS, Signed, message_hash,
    },
};
use serde::{Deserialize, Serialize};
fn refused() -> NodeCoreError {
    NodeCoreError::HomeMigration(Refusal::PeeringUnavailable)
}
fn wire(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
fn hash<T: Serialize>(value: &T) -> Result<String, NodeCoreError> {
    framed_hash(ramflux_protocol::domain::CUSTODY_OBJECT_HASH, value).map_err(wire)
}
fn nonce() -> Result<String, NodeCoreError> {
    ramflux_crypto::random_32().map(ramflux_protocol::encode_base64url).map_err(wire)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum MigrationPeerCall {
    Attest { authentication: Signed<PeerQuery>, owner: Box<AttestRequest> },
    AuthorizeRead { authentication: Signed<PeerQuery>, owner: Box<Signed<Control>> },
    Commit { authentication: Signed<NodeCommitDelivery>, sealed: Box<SealedMigration> },
    Status { authentication: Signed<PeerStatus>, authorization: Box<Signed<Authorization>> },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", content = "evidence", rename_all = "snake_case", deny_unknown_fields)]
pub enum MigrationPeerReply {
    Attested(Box<AttestedHome>),
    Authorized(Box<Signed<HomeAttestation>>),
    Committed(Box<RecordEvidence>),
    Fenced(Box<Signed<NoncommitFence>>),
    Refused(Refusal),
}
impl MigrationPeerCall {
    #[must_use]
    pub fn claimed_peer(&self) -> &str {
        match self {
            Self::Attest { authentication, .. } | Self::AuthorizeRead { authentication, .. } => {
                &authentication.body.source_node
            }
            Self::Commit { authentication, .. } => &authentication.body.source_node,
            Self::Status { authentication, .. } => &authentication.body.destination_node,
        }
    }
    #[must_use]
    pub fn audience(&self) -> &str {
        match self {
            Self::Attest { authentication, .. } | Self::AuthorizeRead { authentication, .. } => {
                &authentication.body.audience_node
            }
            Self::Commit { authentication, .. } => &authentication.body.audience_node,
            Self::Status { authentication, .. } => &authentication.body.audience_node,
        }
    }
    /// Validate the independently admitted node and exact action/evidence binding before dispatch.
    /// # Errors
    /// Rejects stale wrappers, substituted node claims, mismatched evidence and another audience.
    pub fn verify(
        &self,
        peer: MigrationPeer<'_>,
        audience: &str,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        if self.claimed_peer() != peer.node_id || self.audience() != audience {
            return Err(refused());
        }
        match self {
            Self::Attest { authentication, owner } => {
                verify_query(authentication, peer, now)?;
                let q = &authentication.body;
                if q.kind != PeerQueryKind::Attest
                    || q.request_hash != hash(owner)?
                    || q.account_anchor != owner.payload.account_anchor
                    || q.migration_id != owner.control.body.migration_id
                    || owner.control.body.audience_node != audience
                    || owner.payload.destination_node != peer.node_id
                {
                    return Err(refused());
                }
            }
            Self::AuthorizeRead { authentication, owner } => {
                verify_query(authentication, peer, now)?;
                let q = &authentication.body;
                if q.kind != PeerQueryKind::AuthorizeRead
                    || q.request_hash != message_hash(owner).map_err(wire)?
                    || q.account_anchor != owner.body.requester.account_anchor
                    || q.migration_id != owner.body.migration_id
                    || owner.body.audience_node != peer.node_id
                    || !matches!(owner.body.action, Action::Status | Action::Resolve)
                {
                    return Err(refused());
                }
            }
            Self::Commit { authentication, sealed } => {
                crypto::verify_node(authentication, peer.node_id, peer.node_key)
                    .map_err(|_| refused())?;
                let d = &authentication.body;
                fresh(d.issued_at, d.expires_at, &d.nonce, now)?;
                let a = &sealed.authorization.body;
                if d.authorization_hash != message_hash(&sealed.authorization).map_err(wire)?
                    || d.offer_hash != message_hash(&sealed.offer).map_err(wire)?
                    || d.seal_hash != message_hash(&sealed.seal).map_err(wire)?
                    || d.admission_evidence_hash != hash(sealed)?
                    || d.account_anchor != a.account_anchor
                    || d.migration_id != a.migration_id
                    || a.destination_node != peer.node_id
                    || a.destination_key != peer.node_key
                    || a.old_node != audience
                {
                    return Err(refused());
                }
            }
            Self::Status { authentication, authorization } => {
                crypto::verify_node(authentication, peer.node_id, peer.node_key)
                    .map_err(|_| refused())?;
                let q = &authentication.body;
                fresh(q.issued_at, q.expires_at, &q.nonce, now)?;
                if q.authorization_hash != message_hash(authorization).map_err(wire)?
                    || q.account_anchor != authorization.body.account_anchor
                    || q.migration_id != authorization.body.migration_id
                    || authorization.body.destination_node != peer.node_id
                    || authorization.body.destination_key != peer.node_key
                    || authorization.body.old_node != audience
                {
                    return Err(refused());
                }
            }
        }
        Ok(())
    }
}
fn fresh(issued: u64, expires: u64, nonce: &str, now: u64) -> Result<(), NodeCoreError> {
    if issued > now.saturating_add(SKEW_SECONDS)
        || expires <= issued
        || expires - issued > 30
        || now > expires.saturating_add(SKEW_SECONDS)
        || !ramflux_protocol::decode_base64url(nonce).is_ok_and(|value| {
            value.len() == 32 && ramflux_protocol::encode_base64url(value) == nonce
        })
    {
        return Err(refused());
    }
    Ok(())
}
fn verify_query(
    query: &Signed<PeerQuery>,
    peer: MigrationPeer<'_>,
    now: u64,
) -> Result<(), NodeCoreError> {
    crypto::verify_node(query, peer.node_id, peer.node_key).map_err(|_| refused())?;
    fresh(query.body.issued_at, query.body.expires_at, &query.body.nonce, now)
}
impl MigrationNode {
    /// Authenticate a relayed owner preflight without granting a peer cancellation rights.
    /// # Errors
    /// Returns bounded serialization, randomness and signing errors.
    pub fn peer_attest_call(
        &self,
        owner: AttestRequest,
        now: u64,
    ) -> Result<MigrationPeerCall, NodeCoreError> {
        let body = self.peer_query(
            PeerQueryInput {
                kind: PeerQueryKind::Attest,
                anchor: &owner.payload.account_anchor,
                id: &owner.control.body.migration_id,
                audience: &owner.control.body.audience_node,
                request_hash: hash(&owner)?,
            },
            now,
        )?;
        Ok(MigrationPeerCall::Attest { authentication: body, owner: Box::new(owner) })
    }
    /// Ask the current home to validate a former-home private read's owner against current authority.
    /// # Errors
    /// Returns bounded serialization, randomness and signing errors.
    pub fn peer_read_call(
        &self,
        audience: &str,
        owner: Signed<Control>,
        now: u64,
    ) -> Result<MigrationPeerCall, NodeCoreError> {
        let body = self.peer_query(
            PeerQueryInput {
                kind: PeerQueryKind::AuthorizeRead,
                anchor: &owner.body.requester.account_anchor,
                id: &owner.body.migration_id,
                audience,
                request_hash: message_hash(&owner).map_err(wire)?,
            },
            now,
        )?;
        Ok(MigrationPeerCall::AuthorizeRead { authentication: body, owner: Box::new(owner) })
    }
    /// Send only immutable sealed admission evidence, binding every byte to the destination node.
    /// # Errors
    /// Rejects another destination or signing failure.
    pub fn peer_commit_call(
        &self,
        sealed: SealedMigration,
        now: u64,
    ) -> Result<MigrationPeerCall, NodeCoreError> {
        let a = &sealed.authorization.body;
        if a.destination_node != self.node_id() || a.destination_key != self.public_key() {
            return Err(refused());
        }
        let authentication = crypto::sign_node(
            NodeCommitDelivery {
                version: 1,
                migration_id: a.migration_id.clone(),
                account_anchor: a.account_anchor.clone(),
                source_node: self.node_id().into(),
                audience_node: a.old_node.clone(),
                authorization_hash: message_hash(&sealed.authorization).map_err(wire)?,
                offer_hash: message_hash(&sealed.offer).map_err(wire)?,
                seal_hash: message_hash(&sealed.seal).map_err(wire)?,
                admission_evidence_hash: hash(&sealed)?,
                nonce: nonce()?,
                issued_at: now,
                expires_at: now.checked_add(30).ok_or_else(refused)?,
            },
            self.node_id(),
            &self.key,
        )
        .map_err(wire)?;
        Ok(MigrationPeerCall::Commit { authentication, sealed: Box::new(sealed) })
    }
    /// Query an immutable authorization outcome with a fresh peer nonce after any lost reply.
    /// # Errors
    /// Rejects another destination and signing errors.
    pub fn peer_status_call(
        &self,
        authorization: Signed<Authorization>,
        now: u64,
    ) -> Result<MigrationPeerCall, NodeCoreError> {
        let a = &authorization.body;
        if a.destination_node != self.node_id() {
            return Err(refused());
        }
        let authentication = crypto::sign_node(
            PeerStatus {
                version: 1,
                account_anchor: a.account_anchor.clone(),
                migration_id: a.migration_id.clone(),
                authorization_hash: message_hash(&authorization).map_err(wire)?,
                audience_node: a.old_node.clone(),
                destination_node: self.node_id().into(),
                nonce: nonce()?,
                issued_at: now,
                expires_at: now.checked_add(30).ok_or_else(refused)?,
            },
            self.node_id(),
            &self.key,
        )
        .map_err(wire)?;
        Ok(MigrationPeerCall::Status { authentication, authorization: Box::new(authorization) })
    }
    fn peer_query(
        &self,
        input: PeerQueryInput<'_>,
        now: u64,
    ) -> Result<Signed<PeerQuery>, NodeCoreError> {
        crypto::sign_node(
            PeerQuery {
                version: 1,
                kind: input.kind,
                account_anchor: input.anchor.into(),
                migration_id: input.id.into(),
                source_node: self.node_id().into(),
                audience_node: input.audience.into(),
                request_hash: input.request_hash,
                nonce: nonce()?,
                issued_at: now,
                expires_at: now.checked_add(30).ok_or_else(refused)?,
            },
            self.node_id(),
            &self.key,
        )
        .map_err(wire)
    }
}
struct PeerQueryInput<'a> {
    kind: PeerQueryKind,
    anchor: &'a str,
    id: &'a str,
    audience: &'a str,
    request_hash: String,
}

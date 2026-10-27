// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner-authenticated peer preflight precedes every new destination reservation.
use crate::{
    AttestMigration, AttestedHome, HomeMigrationService, MigrationAdmission, MigrationPeerReply,
    NodeCoreError, PrepareMigration, home_migration_reply::MigrationReply,
};
use ramflux_crypto::home_migration as crypto;
use ramflux_protocol::{
    custody::{Publication, object_hash},
    home_migration::{
        AttestRequest, Prepare, Refusal, Request, ResolveResult, Response, SKEW_SECONDS, Signed,
        delivery_map_hash, record_hash,
    },
};
fn failure(reason: Refusal) -> NodeCoreError {
    NodeCoreError::HomeMigration(reason)
}
fn wire(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}
impl HomeMigrationService {
    pub(crate) fn attest_owner(
        &self,
        scope: &super::home_migration_service::MigrationExecution<'_>,
        request: &Request,
        owner: &AttestRequest,
    ) -> Result<Response, NodeCoreError> {
        let super::home_migration_service::MigrationExecution { router, store, now, .. } = *scope;
        let source = &owner.control.body.audience_node;
        if owner.payload.destination_node == *source {
            return Err(failure(Refusal::BaseMismatch));
        }
        let home = if source == self.node.node_id() {
            // A direct preflight cannot substitute for B obtaining its own authenticated mesh view.
            self.mesh.peer_key(&owner.payload.destination_node)?;
            router.attest_home_migration(
                store,
                &self.node,
                AttestMigration { request: owner },
                now,
            )?
        } else {
            if owner.payload.destination_node != self.node.node_id() {
                return Err(failure(Refusal::PinMismatch));
            }
            let pin = self.mesh.peer_key(source)?;
            let call = self.node.peer_attest_call(owner.clone(), now)?;
            let started = std::time::Instant::now();
            let home = match self.mesh.exchange(source, &call)? {
                MigrationPeerReply::Attested(home) => *home,
                MigrationPeerReply::Refused(reason) => return Err(failure(reason)),
                _ => return Err(failure(Refusal::EvidenceRequired)),
            };
            let observed = now.saturating_add(started.elapsed().as_secs());
            verify_preflight(&home, owner, &pin, observed)?;
            self.preflight.lock().map_err(wire)?.insert(home.clone(), observed)?;
            home
        };
        MigrationReply {
            attestation: Some(home.attestation),
            resolve_result: Some(ResolveResult { home: home.home, predecessors: vec![] }),
            ..MigrationReply::default()
        }
        .sign(&self.node, &request.control, None, now)
    }
    pub(crate) fn prepare_owner(
        &self,
        scope: &super::home_migration_service::MigrationExecution<'_>,
        request: &Request,
        prepare: &Signed<Prepare>,
    ) -> Result<Response, NodeCoreError> {
        let super::home_migration_service::MigrationExecution {
            router,
            store,
            caller,
            authority,
            now,
        } = *scope;
        let p = &prepare.body;
        if let Some(existing) = store.migration_operation(
            &p.account_anchor,
            &p.migration_id,
            crate::MigrationRole::Destination,
        )? {
            if ramflux_protocol::home_migration::message_hash(&existing.prepare).map_err(wire)?
                != ramflux_protocol::home_migration::message_hash(prepare).map_err(wire)?
            {
                return Err(failure(Refusal::IdempotencyConflict));
            }
            return MigrationReply {
                offer: Some(existing.offer.clone()),
                ..MigrationReply::default()
            }
            .sign(&self.node, &request.control, Some(&existing), now);
        }
        crypto::verify_actor(prepare, authority, now)
            .map_err(|_| failure(Refusal::AuthorityUpdateRequired))?;
        let cached = self.preflight.lock().map_err(wire)?.get(&p.account_anchor, &p.nonce, now)?;
        let publication = Publication {
            record: caller.publication.record.clone(),
            compacted_ids: caller.publication.compacted_ids.clone(),
        };
        if cached.authority != publication
            || cached.attestation.body.previous_home_hash != p.previous_home_hash
            || cached.attestation.body.authority_record_hash != p.authority_record_hash
            || cached.home.record.home().0 != p.old_node
            || request
                .evidence
                .attestation
                .as_ref()
                .is_some_and(|supplied| supplied != &cached.attestation)
        {
            return Err(failure(Refusal::AuthorityUpdateRequired));
        }
        let pin = self.mesh.peer_key(&p.old_node)?;
        if cached.home.record.home() != (p.old_node.as_str(), pin.as_str()) {
            return Err(failure(Refusal::PinMismatch));
        }
        let base = crypto::verify_home_chain(
            &ResolveResult { home: cached.home.clone(), predecessors: vec![] },
            &cached.home,
            now,
        )
        .map_err(|_| failure(Refusal::EvidenceRequired))?;
        self.preflight.lock().map_err(wire)?.charge(&p.account_anchor, now)?;
        let offer = router.admit_home_migration(
            store,
            &self.node,
            MigrationAdmission {
                publication: &caller.publication,
                prepare: PrepareMigration {
                    prepare,
                    attestation: &cached.attestation,
                    base: &base,
                    delivery_map: &cached.delivery_map,
                },
                source: caller.source,
            },
            now,
        )?;
        let op = store
            .migration_operation(
                &p.account_anchor,
                &p.migration_id,
                crate::MigrationRole::Destination,
            )?
            .ok_or_else(|| failure(Refusal::EvidenceRequired))?;
        MigrationReply { offer: Some(offer), ..MigrationReply::default() }.sign(
            &self.node,
            &request.control,
            Some(&op),
            now,
        )
    }
}
fn verify_preflight(
    home: &AttestedHome,
    owner: &AttestRequest,
    pin: &str,
    now: u64,
) -> Result<(), NodeCoreError> {
    let source = &owner.control.body.audience_node;
    crypto::verify_node(&home.attestation, source, pin)
        .map_err(|_| failure(Refusal::PinMismatch))?;
    let a = &home.attestation.body;
    if home.home.record.home() != (source.as_str(), pin)
        || home.home.record.account_anchor() != owner.payload.account_anchor
        || home.authority.record.body.account_anchor != owner.payload.account_anchor
        || a.account_anchor != owner.payload.account_anchor
        || a.audience_node != owner.payload.destination_node
        || a.nonce != owner.payload.nonce
        || a.authority_record_hash != owner.control.body.authority_record_hash
        || a.authority_record_hash != object_hash(&home.authority.record).map_err(wire)?
        || a.previous_home_hash != record_hash(&home.home.record).map_err(wire)?
        || a.delivery_map_hash != delivery_map_hash(&home.delivery_map).map_err(wire)?
        || a.device_set_epoch != home.authority.record.body.device_set_epoch
        || a.issued_at > now.saturating_add(SKEW_SECONDS)
        || a.expires_at <= a.issued_at
        || a.expires_at - a.issued_at > 60
        || now > a.expires_at
    {
        return Err(failure(Refusal::AuthorityUpdateRequired));
    }
    Ok(())
}

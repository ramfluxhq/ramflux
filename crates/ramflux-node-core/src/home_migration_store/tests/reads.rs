// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Former-home private reads cannot reuse stale local authority after destination revocation.
use super::*;
use crate::home_migration_service::MigrationCaller;
use crate::{HomeMigrationMesh, HomeMigrationService, MigrationPeerCall, MigrationPeerReply};
use ramflux_protocol::{
    custody::MigrationPurpose,
    home_migration::{
        ActionPayload, Control, Evidence, OperationPayload, Request, ResolvePayload,
        control_payload_hash,
    },
};
use std::{collections::BTreeMap, sync::Arc};
struct Mesh(BTreeMap<String, Arc<TestNode>>);
impl HomeMigrationMesh for Mesh {
    fn peer_key(&self, peer: &str) -> Result<String, NodeCoreError> {
        self.0
            .get(peer)
            .map(|n| n.node.public_key().to_owned())
            .ok_or_else(|| refusal(Refusal::PeeringUnavailable))
    }
    fn exchange(
        &self,
        peer: &str,
        call: &MigrationPeerCall,
    ) -> Result<MigrationPeerReply, NodeCoreError> {
        let node = self.0.get(peer).ok_or_else(|| refusal(Refusal::PeeringUnavailable))?;
        let key = self.peer_key(call.claimed_peer())?;
        let now = match call {
            MigrationPeerCall::Attest { authentication, .. }
            | MigrationPeerCall::AuthorizeRead { authentication, .. }
            | MigrationPeerCall::Resolve { authentication, .. } => authentication.body.issued_at,
            MigrationPeerCall::Commit { authentication, .. } => authentication.body.issued_at,
            MigrationPeerCall::Status { authentication, .. } => authentication.body.issued_at,
        };
        node.core.handle_migration_peer(
            node.store.as_ref().ok_or_else(|| storage("closed"))?,
            &node.node,
            MigrationPeer { node_id: call.claimed_peer(), node_key: &key },
            call,
            now,
        )
    }
}
fn service(node: &TestNode, peers: Arc<Mesh>) -> TestResult<HomeMigrationService> {
    let n = &node.node;
    Ok(HomeMigrationService::new(
        Arc::new(MigrationNode::new(
            n.record.clone(),
            n.key.to_bytes(),
            MigrationEndpoints {
                gateway_tcp_addr: n.gateway_tcp_addr.clone(),
                federation_endpoint: n.federation_endpoint.clone(),
                discovery_hash: n.discovery_hash.clone(),
                server_record_hash: n.server_record_hash.clone(),
            },
            NOW,
        )?),
        peers,
    ))
}
fn owner_control(
    action: Action,
    payload: ActionPayload,
    id: &str,
    now: u64,
) -> TestResult<Request> {
    let pubn = publication()?;
    let authority = verify_record(&pubn.record, now, None, None)?;
    let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
    let control = Control {
        version: 1,
        action,
        audience_node: "A".into(),
        migration_id: id.into(),
        requester: authority.envelope().body.master_certificate.body.primary_device_ref.clone(),
        authority_record_hash: object_hash(&pubn.record)?,
        payload_hash: control_payload_hash(action, &payload, None)?,
        nonce: hash(98),
        issued_at: now,
        expires_at: now + 60,
    };
    Ok(Request {
        control: crypto::sign_actor(control, &branch, &authority, now)?,
        payload,
        evidence: Evidence::default(),
    })
}
fn caller() -> TestResult<MigrationCaller> {
    Ok(MigrationCaller {
        publication: publication()?,
        purpose: MigrationPurpose::Read,
        source: "127.0.0.1".parse()?,
    })
}
#[test]
fn former_home_private_status_checks_destination_revocation_while_resolve_is_only_public_evidence()
-> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let committed = s.commit(&op)?;
    s.b.store()?.activate_home_migration(
        &s.b.node,
        &ResolveResult { home: committed, predecessors: vec![] },
        NOW + 2,
    )?;
    let a = Arc::new(s.a);
    let b = Arc::new(s.b);
    let peers = Arc::new(Mesh(BTreeMap::from([("A".into(), a.clone()), ("B".into(), b.clone())])));
    let service = service(&a, peers)?;
    let request = owner_control(
        Action::Status,
        ActionPayload::Operation(OperationPayload {
            account_anchor: s.anchor.clone(),
            migration_id: s.authorization.body.migration_id.clone(),
        }),
        &s.authorization.body.migration_id,
        NOW + 2,
    )?;
    let response = service
        .execute(&a.core, a.store()?, request, caller()?, NOW + 2)
        .map_err(|e| format!("status {e:?}"))?;
    assert!(response.backlog_progress.is_some());
    let mut revoked = publication()?;
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([2; 32]));
    revoked.record.body.previous_record_hash = Some(object_hash(&revoked.record)?);
    revoked.record.body.device_set_epoch = ramflux_protocol::custody::encode_epoch(1, 2)?;
    revoked.record.body.issued_at = NOW + 3;
    let mut branch = revoked.record.body.devices[0].branch_certificate.take().ok_or("branch")?.body;
    branch.cert_id = hash(99);
    branch.capabilities = vec!["register".into()];
    revoked.record.body.devices[0].branch_certificate = Some(primary.certify_branch(branch)?);
    revoked.record = primary.sign_record(revoked.record.body)?;
    b.core.publish_custody_record(&revoked, NOW + 3, b.store()?)?;
    let request = owner_control(
        Action::Status,
        ActionPayload::Operation(OperationPayload {
            account_anchor: s.anchor.clone(),
            migration_id: s.authorization.body.migration_id.clone(),
        }),
        &s.authorization.body.migration_id,
        NOW + 3,
    )?;
    assert!(matches!(
        service.execute(&a.core, a.store()?, request, caller()?, NOW + 3),
        Err(ramflux_protocol::custody::CustodyRefusal::HomeMigration {
            reason: Refusal::AuthorityUpdateRequired,
            ..
        })
    ));
    let resolve = owner_control(
        Action::Resolve,
        ActionPayload::Resolve(ResolvePayload {
            target_anchor: s.anchor.clone(),
            after_home_hash: Some(s.base.hash().into()),
            limit: 64,
            old_node_hint: None,
        }),
        &s.authorization.body.migration_id,
        NOW + 3,
    )?;
    let response = service
        .execute(&a.core, a.store()?, resolve, caller()?, NOW + 3)
        .map_err(|e| format!("resolve {e:?}"))?;
    assert!(response.backlog_progress.is_none());
    assert!(response.attestation.is_none());
    assert_eq!(response.resolve_result.ok_or("history")?.home.record.home().0, "B");
    assert_eq!(
        a.core.custody_record(&s.anchor, NOW + 3)?.ok_or("old local authority")?.record,
        publication()?.record
    );
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native durable courier tests preserve safety when transport loses each signed outcome.
use super::*;
use crate::{HomeMigrationMesh, HomeMigrationService, MigrationPeerCall, MigrationPeerReply};
use std::sync::{Arc, Mutex};
struct NativeMesh {
    source: Mutex<TestNode>,
    lose: std::sync::atomic::AtomicBool,
    calls: Mutex<Vec<bool>>,
}
impl HomeMigrationMesh for NativeMesh {
    fn peer_key(&self, node: &str, _deadline: std::time::Instant) -> Result<String, NodeCoreError> {
        if node == "A" { Ok(public(8)) } else { Err(refusal(Refusal::PeeringUnavailable)) }
    }
    fn exchange(
        &self,
        _: &str,
        call: &MigrationPeerCall,
        _deadline: std::time::Instant,
    ) -> Result<MigrationPeerReply, NodeCoreError> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(matches!(call, MigrationPeerCall::Commit { .. }));
        let source = self.source.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = match call {
            MigrationPeerCall::Commit { authentication, .. } => authentication.body.issued_at,
            MigrationPeerCall::Status { authentication, .. } => authentication.body.issued_at,
            _ => return Err(refusal(Refusal::PeeringUnavailable)),
        };
        let result = source.core.handle_migration_peer(
            source.store.as_ref().ok_or_else(|| storage("closed test store"))?,
            &source.node,
            MigrationPeer { node_id: "B", node_key: &public(9) },
            call,
            now,
        )?;
        if self.lose.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(refusal(Refusal::PeeringUnavailable));
        }
        Ok(result)
    }
}
fn service(node: &MigrationNode, mesh: Arc<NativeMesh>) -> TestResult<HomeMigrationService> {
    let node = MigrationNode::new(
        node.record.clone(),
        node.key.to_bytes(),
        MigrationEndpoints {
            gateway_tcp_addr: node.gateway_tcp_addr.clone(),
            federation_endpoint: node.federation_endpoint.clone(),
            discovery_hash: node.discovery_hash.clone(),
            server_record_hash: node.server_record_hash.clone(),
        },
        NOW,
    )?;
    Ok(HomeMigrationService::new(Arc::new(node), mesh))
}
#[test]
fn sealed_courier_survives_crash_and_lost_commit_reply_then_activates_once() -> TestResult {
    let mut s = Scenario::prepared()?;
    s.seal()?;
    s.b.restart()?;
    let mesh = Arc::new(NativeMesh {
        source: Mutex::new(s.a),
        lose: true.into(),
        calls: Mutex::new(vec![]),
    });
    let service = service(&s.b.node, mesh.clone())?;
    assert_eq!(service.courier_tick(s.b.store()?, NOW + 2, 128)?, 1);
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    s.b.restart()?;
    mesh.lose.store(false, std::sync::atomic::Ordering::SeqCst);
    let retry_at =
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Destination,
            )?
            .ok_or("missing courier retry operation after restart")?
            .next_due;
    assert_eq!(service.courier_tick(s.b.store()?, retry_at, 128)?, 1);
    assert!(s.b.store()?.home_migration_target_active(&s.target)?);
    assert_eq!(service.courier_tick(s.b.store()?, NOW + 100, 128)?, 0);
    let op =
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Destination,
            )?
            .ok_or("op")?;
    assert_eq!(op.phase, Phase::Active);
    assert_eq!(op.state_version, 4);
    Ok(())
}
#[test]
fn claimed_courier_recovers_worker_crash_and_never_commits_after_deadline() -> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    assert_eq!(s.b.store()?.claim_migration_courier(NOW + 2, 128)?.len(), 1);
    assert_eq!(s.b.store()?.claim_migration_courier(NOW + 3, 128)?.len(), 0);
    let mesh = Arc::new(NativeMesh {
        source: Mutex::new(s.a),
        lose: false.into(),
        calls: Mutex::new(vec![]),
    });
    let service = service(&s.b.node, mesh.clone())?;
    let deadline = op.seal.as_ref().and_then(|s| s.body.commit_deadline).ok_or("deadline")?;
    assert_eq!(service.courier_tick(s.b.store()?, deadline + 1, 128)?, 1);
    assert_eq!(*mesh.calls.lock().map_err(|_| "calls")?, Vec::<bool>::new());
    let later = crypto::hard_deadline(&s.authorization.body)? + 1;
    assert_eq!(service.courier_tick(s.b.store()?, later, 128)?, 1);
    assert_eq!(*mesh.calls.lock().map_err(|_| "calls")?, vec![false]);
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    assert_eq!(
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Destination
            )?
            .ok_or("op")?
            .phase,
        Phase::Expired
    );
    Ok(())
}
#[test]
fn unresolved_peer_capacity_is_reserved_before_seal_and_released_only_with_signed_outcome()
-> TestResult {
    let s = Scenario::prepared()?;
    let tx = s.b.store()?.migration_db().begin_write()?;
    tx.open_table(BUDGETS)?.insert("sealed-peer/A", 16)?;
    tx.commit()?;
    assert!(matches!(
        s.b.core.seal_home_migration(s.b.store()?, &s.b.node, &s.authorization, NOW + 1),
        Err(NodeCoreError::HomeMigration(Refusal::CapacityRefused))
    ));
    let tx = s.b.store()?.migration_db().begin_write()?;
    tx.open_table(BUDGETS)?.insert("sealed-peer/A", 0)?;
    tx.commit()?;
    s.seal()?;
    s.seal()?;
    let tx = s.b.store()?.migration_db().begin_read()?;
    assert_eq!(tx.open_table(BUDGETS)?.get("sealed-peer/A")?.ok_or("budget")?.value(), 1);
    drop(tx);
    let FenceOutcome::Fenced(fence) = s.a.core.fence_home_authorization(
        s.a.store()?,
        &s.a.node,
        &s.authorization,
        NOW + 2,
        Some(&cancel_request(&s, NOW + 2)?),
    )?
    else {
        return Err("fence".into());
    };
    s.b.store()?.accept_home_noncommit_fence(&fence, &s.anchor, NOW + 2)?;
    let tx = s.b.store()?.migration_db().begin_read()?;
    assert_eq!(tx.open_table(BUDGETS)?.get("sealed-peer/A")?.ok_or("budget")?.value(), 0);
    Ok(())
}

#[test]
fn verification_capacity_cannot_downgrade_an_unknown_commit_outcome() -> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let deadline = op.seal.as_ref().and_then(|seal| seal.body.commit_deadline).ok_or("deadline")?;
    let mesh = Arc::new(NativeMesh {
        source: Mutex::new(s.a),
        lose: false.into(),
        calls: Mutex::new(vec![]),
    });
    let service = service(&s.b.node, mesh.clone())?;
    service.courier_tick(s.b.store()?, deadline + 1, 128)?;
    let permits = (0..16)
        .map(|_| service.node.acquire_migration_verification())
        .collect::<Result<Vec<_>, _>>()?;
    service.courier_tick(s.b.store()?, deadline + 3, 128)?;
    assert_eq!(
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Destination
            )?
            .ok_or("op")?
            .phase,
        Phase::CommitOutcomeUnknown
    );
    assert!(mesh.calls.lock().map_err(|_| "calls")?.is_empty());
    drop(permits);
    Ok(())
}

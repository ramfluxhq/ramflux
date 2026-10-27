// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production redb transitions exercised at lost-reply and pre-commit failure boundaries.
use super::*;
use ramflux_crypto::custody::{SelfSigningKey, verify_record};
use ramflux_protocol::custody::{DeviceSet, object_hash};
use ramflux_protocol::home_migration::ResolveResult;
use serde_json::{Value, json};
use std::path::PathBuf;
use zeroize::Zeroizing;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_700_000_100;
fn hash(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
fn fixture() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../../../ramflux-crypto/tests/fixtures/home_migration_v1.json"
    ))?)
}
fn publication() -> TestResult<crate::CustodyPublication> {
    let v: Value = serde_json::from_str(include_str!(
        "../../../ramflux-crypto/tests/fixtures/custody_v3.json"
    ))?;
    Ok(crate::CustodyPublication {
        record: serde_json::from_value(v["record"].clone())?,
        compacted_ids: None,
    })
}
fn signing(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}
fn public(seed: u8) -> String {
    ramflux_protocol::encode_base64url(signing(seed).verifying_key().to_bytes())
}
struct TestNode {
    path: PathBuf,
    store: Option<RouterRedbStore>,
    core: RouterCore,
    node: MigrationNode,
}
impl TestNode {
    fn new(id: &str, seed: u8, registered: bool) -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!(
            "rf-mig-{}-{}.redb",
            std::process::id(),
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        let store = RouterRedbStore::open_with_wal(&path, path.with_extension("wal"))?;
        let core = RouterCore::new();
        let pubn = publication()?;
        core.publish_custody_record(&pubn, NOW, &store)?;
        if registered {
            let target =
                ramflux_protocol::qualified_device_id(&pubn.record.body.account_anchor, "primary")?;
            // Registration's existing durable prekey row is the source-home marker.
            store.record_custody_prekey(&target, &json!({"test_registration":true}))?;
        }
        let source: RecordEvidence = serde_json::from_value(fixture()?["genesis"].clone())?;
        let mut node = source.node_record.body;
        node.node_id = id.into();
        node.node_signing_public_key = public(seed);
        let record = ramflux_crypto::custody::sign_node_identity_record(&signing(seed), node)?;
        let node = MigrationNode::new(
            record,
            [seed; 32],
            MigrationEndpoints {
                gateway_tcp_addr: "127.0.0.1:9000".into(),
                federation_endpoint: "https://peer.example".into(),
                discovery_hash: hash(19),
                server_record_hash: hash(19),
            },
            NOW,
        )?;
        Ok(Self { path, store: Some(store), core, node })
    }
    fn store(&self) -> TestResult<&RouterRedbStore> {
        self.store.as_ref().ok_or_else(|| "store closed".into())
    }
    fn restart(&mut self) -> TestResult {
        drop(self.store.take());
        let store = RouterRedbStore::open_with_wal(&self.path, self.path.with_extension("wal"))?;
        self.core = store.load_router()?.ok_or("router snapshot")?;
        self.store = Some(store);
        Ok(())
    }
    fn fail_commit(&self) -> TestResult {
        self.store()?.fail_next_migration_commit.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}
impl Drop for TestNode {
    fn drop(&mut self) {
        drop(self.store.take());
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir_all(self.path.with_extension("wal"));
    }
}
struct Scenario {
    a: TestNode,
    b: TestNode,
    base: VerifiedHome,
    authorization: Signed<Authorization>,
    offer: Signed<Offer>,
    anchor: String,
    target: String,
}
impl Scenario {
    fn prepared() -> TestResult<Self> {
        let a = TestNode::new("A", 8, true)?;
        let b = TestNode::new("B", 9, false)?;
        let record = publication()?.record;
        let authority = verify_record(&record, NOW, None, None)?;
        let anchor = record.body.account_anchor.clone();
        let nonce = hash(31);
        let attested = a.core.attest_home_migration(
            a.store()?,
            &a.node,
            AttestMigration { account_anchor: &anchor, destination: "B", nonce: &nonce },
            NOW,
        )?;
        let base = crypto::verify_home_chain(
            &ResolveResult { home: attested.home, predecessors: vec![] },
            &crypto::HomeTrust {
                account_anchor: &anchor,
                node_id: "A",
                node_key: &public(8),
                home_epoch: 0,
                home_hash: None,
            },
            NOW,
        )?;
        let mut prepare: Prepare =
            serde_json::from_value(fixture()?["messages"][0]["signed"]["body"].clone())?;
        prepare.destination_node = "B".into();
        prepare.destination_key = public(9);
        prepare.previous_home_hash = base.hash().into();
        prepare.previous_home_epoch = 0;
        prepare.delivery_map_hash = delivery_map_hash(&attested.delivery_map)?;
        prepare.nonce = nonce;
        prepare.issued_at = NOW;
        prepare.expires_at = NOW + 300;
        let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
        let prepare = crypto::sign_actor(prepare, &branch, &authority, NOW)?;
        let offer = b.core.prepare_home_migration(
            b.store()?,
            &b.node,
            PrepareMigration {
                prepare: &prepare,
                attestation: &attested.attestation,
                base: &base,
                delivery_map: &attested.delivery_map,
            },
            NOW,
        )?;
        let mut auth: Authorization = serde_json::from_value(
            fixture()?["committed_home"]["record"]["authorization"]["body"].clone(),
        )?;
        auth.migration_id = prepare.body.migration_id.clone();
        auth.previous_home_hash = base.hash().into();
        auth.offer_hash = message_hash(&offer)?;
        auth.delivery_map_hash = offer.body.delivery_map_hash.clone();
        auth.issued_at = NOW + 1;
        auth.seal_until = offer.body.accept_until;
        let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([2; 32]));
        let authorization = primary.sign_home_authorization(auth, &branch, &authority, NOW + 1)?;
        let target = attested.delivery_map[0].target_delivery_id.clone();
        Ok(Self { a, b, base, authorization, offer, anchor, target })
    }
    fn seal(&self) -> TestResult<MigrationOperation> {
        self.b.core.seal_home_migration(
            self.b.store()?,
            &self.b.node,
            &self.authorization,
            NOW + 1,
        )?;
        self.b
            .store()?
            .migration_operation(
                &self.anchor,
                &self.authorization.body.migration_id,
                MigrationRole::Destination,
            )?
            .ok_or_else(|| "sealed operation".into())
    }
    fn commit(&self, op: &MigrationOperation) -> TestResult<RecordEvidence> {
        Ok(self.a.core.commit_home_migration(
            self.a.store()?,
            &self.a.node,
            CommitMigration {
                sealed: &op.sealed_evidence()?,
                peer: MigrationPeer { node_id: "B", node_key: &public(9) },
            },
            NOW + 2,
        )?)
    }
    fn verify(&self, record: RecordEvidence) -> TestResult<VerifiedHome> {
        Ok(crypto::verify_home_chain(
            &ResolveResult { home: record, predecessors: vec![] },
            &crypto::HomeTrust {
                account_anchor: &self.anchor,
                node_id: "A",
                node_key: &public(8),
                home_epoch: 0,
                home_hash: Some(self.base.hash()),
            },
            NOW + 2,
        )?)
    }
}
#[test]
fn seal_commit_and_activation_survive_each_lost_reply_without_timer_activation() -> TestResult {
    let mut s = Scenario::prepared()?;
    let op = s.seal()?;
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    s.b.restart()?;
    assert_eq!(
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &op.prepare.body.migration_id,
                MigrationRole::Destination
            )?
            .ok_or("op")?
            .phase,
        Phase::Sealed
    );
    assert!(s.b.store()?.activate_home_migration(&s.b.node, &s.base, NOW + 1).is_err());
    let committed = s.commit(&op)?;
    s.a.restart()?;
    let retry = s.commit(&op)?;
    assert_eq!(retry, committed);
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    let verified = s.verify(committed)?;
    s.b.store()?.activate_home_migration(&s.b.node, &verified, NOW + 2)?;
    s.b.restart()?;
    s.b.store()?.activate_home_migration(&s.b.node, &verified, NOW + 2)?;
    assert!(s.b.store()?.home_migration_target_active(&s.target)?);
    assert_eq!(s.b.store()?.migration_home(&s.anchor)?.ok_or("head")?.record.epoch(), 1);
    assert!(!s.b.store()?.home_migration_blocks_recovery(&s.anchor)?);
    Ok(())
}
#[test]
fn failed_seal_source_commit_and_activation_roll_back_every_table() -> TestResult {
    let s = Scenario::prepared()?;
    s.b.fail_commit()?;
    assert!(
        s.b.core.seal_home_migration(s.b.store()?, &s.b.node, &s.authorization, NOW + 1).is_err()
    );
    assert_eq!(
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Destination
            )?
            .ok_or("op")?
            .phase,
        Phase::Prepared
    );
    assert!(!s.b.store()?.home_migration_blocks_recovery(&s.anchor)?);
    let op = s.seal()?;
    s.a.fail_commit()?;
    assert!(s.commit(&op).is_err());
    assert_eq!(s.a.store()?.migration_home(&s.anchor)?.ok_or("head")?.record.epoch(), 0);
    assert!(
        s.a.store()?
            .migration_operation(&s.anchor, &op.prepare.body.migration_id, MigrationRole::Source)?
            .is_none()
    );
    assert!(!s.a.store()?.home_migration_blocks_recovery(&s.anchor)?);
    let verified = s.verify(s.commit(&op)?)?;
    s.b.fail_commit()?;
    assert!(s.b.store()?.activate_home_migration(&s.b.node, &verified, NOW + 2).is_err());
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    assert!(s.b.store()?.migration_home(&s.anchor)?.is_none());
    s.b.store()?.activate_home_migration(&s.b.node, &verified, NOW + 2)?;
    Ok(())
}
#[test]
fn source_cancellation_fence_is_relayable_and_permanently_beats_late_commit() -> TestResult {
    let mut s = Scenario::prepared()?;
    let op = s.seal()?;
    let result = s.a.core.fence_home_migration(
        s.a.store()?,
        &s.a.node,
        CommitMigration {
            sealed: &op.sealed_evidence()?,
            peer: MigrationPeer { node_id: "B", node_key: &public(9) },
        },
        NOW + 2,
        true,
    )?;
    let FenceOutcome::Fenced(fence) = result else {
        return Err("unexpected commit".into());
    };
    s.a.restart()?;
    assert!(s.commit(&op).is_err());
    s.b.store()?.accept_home_noncommit_fence(&fence, &s.anchor, NOW + 2)?;
    s.b.restart()?;
    assert_eq!(
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &op.prepare.body.migration_id,
                MigrationRole::Destination
            )?
            .ok_or("op")?
            .phase,
        Phase::Expired
    );
    assert_eq!(s.a.store()?.migration_home(&s.anchor)?.ok_or("head")?.record.epoch(), 0);
    Ok(())
}
#[test]
fn proof_index_survives_transient_operation_compaction_and_refuses_a_false_fence() -> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let record = s.commit(&op)?;
    let key = op_key(&s.anchor, &op.prepare.body.migration_id, MigrationRole::Source)?;
    let tx = s.a.store()?.migration_db().begin_write()?;
    tx.open_table(OPS)?.remove(key.as_str())?;
    tx.commit()?;
    let result = s.a.core.fence_home_migration(
        s.a.store()?,
        &s.a.node,
        CommitMigration {
            sealed: &op.sealed_evidence()?,
            peer: MigrationPeer { node_id: "B", node_key: &public(9) },
        },
        NOW + 2,
        true,
    )?;
    let FenceOutcome::Committed(existing) = result else {
        return Err("false fence".into());
    };
    assert_eq!(*existing, record);
    assert_eq!(s.commit(&op)?, record);
    Ok(())
}
#[test]
fn expired_prepares_release_live_admission_budgets_and_clock_rollback_is_refused() -> TestResult {
    let s = Scenario::prepared()?;
    assert_eq!(
        s.b.store()?.cleanup_home_migrations(s.offer.body.accept_until + SKEW_SECONDS + 1)?,
        1
    );
    assert!(
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Destination
            )?
            .is_none()
    );
    let tx = s.b.store()?.migration_db().begin_read()?;
    let budget = tx.open_table(BUDGETS)?;
    assert_eq!(budget.get("live")?.ok_or("budget")?.value(), 0);
    assert_eq!(budget.get(s.anchor.as_str())?.ok_or("budget")?.value(), 0);
    assert_eq!(budget.get("unsealed")?.ok_or("budget")?.value(), 0);
    assert!(s.b.store()?.cleanup_home_migrations(NOW).is_err());
    Ok(())
}
#[test]
fn wrong_destination_and_changed_seal_cannot_activate_even_a_valid_source_proof() -> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let verified = s.verify(s.commit(&op)?)?;
    let evil = TestNode::new("C", 10, false)?;
    assert!(s.b.store()?.activate_home_migration(&evil.node, &verified, NOW + 2).is_err());
    assert!(!s.b.store()?.home_migration_target_active(&s.target)?);
    let tx = s.b.store()?.migration_db().begin_write()?;
    let key = op_key(&s.anchor, &op.prepare.body.migration_id, MigrationRole::Destination)?;
    let mut wrong = op;
    wrong.seal.as_mut().ok_or("seal")?.body.state_version += 1;
    write(&tx, OPS, &key, &wrong)?;
    tx.commit()?;
    assert!(s.b.store()?.activate_home_migration(&s.b.node, &verified, NOW + 2).is_err());
    Ok(())
}

fn recovery_record() -> TestResult<crate::CustodyPublication> {
    use ramflux_crypto::custody::{MasterKey, RecoveryPhrase};
    let current = publication()?;
    let mut body = current.record.body.clone();
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([12; 32]));
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[0; 32])?)?;
    let mut cert = body.master_certificate.body.clone();
    cert.self_signing_public_key = primary.public_key();
    cert.range_index = 2;
    cert.cert_id = hash(44);
    cert.previous_certificate_hash = Some(object_hash(&body.master_certificate)?);
    cert.issued_at = NOW + 2;
    body.master_certificate = master.certify(cert)?;
    body.device_set_epoch = ramflux_protocol::custody::encode_epoch(2, 1)?;
    body.issued_at = NOW + 2;
    body.previous_record_hash = Some(object_hash(&current.record)?);
    let mut branch = body.devices[0].branch_certificate.take().ok_or("branch")?.body;
    branch.master_certificate_hash = object_hash(&body.master_certificate)?;
    body.devices[0].branch_certificate = Some(primary.certify_branch(branch)?);
    let record: Envelope<DeviceSet> = primary.sign_record(body)?;
    Ok(crate::CustodyPublication { record, compacted_ids: None })
}
#[test]
fn primary_recovery_cannot_bypass_pending_guard_through_direct_publication() -> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let replacement = recovery_record()?;
    assert!(matches!(
        s.b.core.publish_custody_record(&replacement, NOW + 2, s.b.store()?),
        Err(NodeCoreError::HomeMigration(Refusal::MigrationInProgress))
    ));
    let record = s.commit(&op)?;
    assert!(matches!(
        s.a.core.publish_custody_record(&replacement, NOW + 2, s.a.store()?),
        Err(NodeCoreError::HomeMigration(Refusal::MigrationInProgress))
    ));
    s.b.store()?.activate_home_migration(&s.b.node, &s.verify(record)?, NOW + 2)?;
    s.b.core.publish_custody_record(&replacement, NOW + 2, s.b.store()?)?;
    assert_eq!(s.b.store()?.migration_home(&s.anchor)?.ok_or("home")?.record.epoch(), 1);
    Ok(())
}

fn competitor(s: &Scenario) -> TestResult<(TestNode, MigrationOperation)> {
    let c = TestNode::new("C", 10, false)?;
    let record = publication()?.record;
    let authority = verify_record(&record, NOW + 1, None, None)?;
    let nonce = hash(40);
    let attested = s.a.core.attest_home_migration(
        s.a.store()?,
        &s.a.node,
        AttestMigration { account_anchor: &s.anchor, destination: "C", nonce: &nonce },
        NOW + 1,
    )?;
    let mut prepare =
        s.b.store()?
            .migration_operation(
                &s.anchor,
                &s.authorization.body.migration_id,
                MigrationRole::Destination,
            )?
            .ok_or("operation")?
            .prepare
            .body;
    prepare.migration_id = hash(40);
    prepare.destination_node = "C".into();
    prepare.destination_key = public(10);
    prepare.nonce = nonce;
    prepare.issued_at = NOW + 1;
    prepare.expires_at = NOW + 301;
    let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
    let prepare = crypto::sign_actor(prepare, &branch, &authority, NOW + 1)?;
    let offer = c.core.prepare_home_migration(
        c.store()?,
        &c.node,
        PrepareMigration {
            prepare: &prepare,
            attestation: &attested.attestation,
            base: &s.base,
            delivery_map: &attested.delivery_map,
        },
        NOW + 1,
    )?;
    let mut auth = s.authorization.body.clone();
    auth.migration_id = prepare.body.migration_id;
    auth.destination_node = "C".into();
    auth.destination_key = public(10);
    auth.offer_hash = message_hash(&offer)?;
    auth.seal_until = offer.body.accept_until;
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([2; 32]));
    let auth = primary.sign_home_authorization(auth, &branch, &authority, NOW + 1)?;
    c.core.seal_home_migration(c.store()?, &c.node, &auth, NOW + 1)?;
    let op = c
        .store()?
        .migration_operation(&s.anchor, &auth.body.migration_id, MigrationRole::Destination)?
        .ok_or("C operation")?;
    Ok((c, op))
}
#[test]
fn concurrent_destinations_from_one_base_can_commit_exactly_one_successor() -> TestResult {
    let s = Scenario::prepared()?;
    let b = s.seal()?;
    let (_c, c) = competitor(&s)?;
    let b = b.sealed_evidence()?;
    let c = c.sealed_evidence()?;
    let store = s.a.store()?;
    let results = std::thread::scope(|scope| -> TestResult<_> {
        let left = scope.spawn(|| {
            s.a.core.commit_home_migration(
                store,
                &s.a.node,
                CommitMigration {
                    sealed: &b,
                    peer: MigrationPeer { node_id: "B", node_key: &public(9) },
                },
                NOW + 2,
            )
        });
        let right = scope.spawn(|| {
            s.a.core.commit_home_migration(
                store,
                &s.a.node,
                CommitMigration {
                    sealed: &c,
                    peer: MigrationPeer { node_id: "C", node_key: &public(10) },
                },
                NOW + 2,
            )
        });
        Ok((
            left.join().map_err(|_| "B commit panicked")?,
            right.join().map_err(|_| "C commit panicked")?,
        ))
    })?;
    assert_eq!(u8::from(results.0.is_ok()) + u8::from(results.1.is_ok()), 1);
    assert_eq!(store.migration_home(&s.anchor)?.ok_or("home")?.record.epoch(), 1);
    Ok(())
}
#[test]
fn source_rejects_a_validly_signed_far_future_offer_without_mutating_the_head() -> TestResult {
    let s = Scenario::prepared()?;
    let mut op = s.seal()?;
    let mut future = op.offer.body.clone();
    future.issued_at += 31_536_000;
    future.accept_until = future.issued_at + 600;
    op.offer = crypto::sign_node(future, "B", &signing(9))?;
    let mut auth = s.authorization.body.clone();
    auth.offer_hash = message_hash(&op.offer)?;
    let record = publication()?.record;
    let authority = verify_record(&record, NOW + 1, None, None)?;
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([2; 32]));
    let branch = ramflux_crypto::create_device_branch("vector.example", "primary", 1, [3; 32]);
    let auth = primary.sign_home_authorization(auth, &branch, &authority, NOW + 1)?;
    let mut seal = op.seal.take().ok_or("seal")?.body;
    seal.authorization_hash = Some(message_hash(&auth)?);
    seal.request_hash = message_hash(&auth)?;
    op.seal = Some(crypto::sign_node(seal, "B", &signing(9))?);
    op.authorization = Some(auth);
    assert!(s.commit(&op).is_err());
    assert_eq!(s.a.store()?.migration_home(&s.anchor)?.ok_or("home")?.record.epoch(), 0);
    Ok(())
}

#[test]
fn recovery_winning_before_source_commit_invalidates_move_and_fence_releases_destination()
-> TestResult {
    let s = Scenario::prepared()?;
    let op = s.seal()?;
    let replacement = recovery_record()?;
    s.a.core.publish_custody_record(&replacement, NOW + 2, s.a.store()?)?;
    assert!(s.commit(&op).is_err());
    let result = s.a.core.fence_home_migration(
        s.a.store()?,
        &s.a.node,
        CommitMigration {
            sealed: &op.sealed_evidence()?,
            peer: MigrationPeer { node_id: "B", node_key: &public(9) },
        },
        NOW + 2,
        true,
    )?;
    let FenceOutcome::Fenced(fence) = result else {
        return Err("unexpected commit".into());
    };
    s.b.store()?.accept_home_noncommit_fence(&fence, &s.anchor, NOW + 2)?;
    s.b.core.publish_custody_record(&replacement, NOW + 2, s.b.store()?)?;
    assert_eq!(s.a.store()?.migration_home(&s.anchor)?.ok_or("head")?.record.epoch(), 0);
    Ok(())
}

mod wal_barrier;

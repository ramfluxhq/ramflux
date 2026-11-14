// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real native primary signatures and verified complete home reads exercise recipient decisions.
//! Source authentication is tested separately; these controls exercise the subsequent policy gate.
use super::*;
use crate::{
    client::native_test_support::{Fixture, TestResult},
    contact_reach::group_test_support::verified_records,
    custody::ReachCommandContext,
};
use ramflux_protocol::{contact_reach as wire, custody};

struct PolicyFixture {
    owner: Fixture,
    route: Route,
    policy: custody::Envelope<wire::ReachPolicy>,
    now: u64,
}
fn digest(byte: u8) -> String {
    ramflux_protocol::encode_base64url([byte; 32])
}

impl PolicyFixture {
    async fn new() -> TestResult<Self> {
        let owner = Fixture::new("reach-policy-owner").await?;
        let peer = Fixture::new("reach-policy-peer").await?;
        let account = owner.client.born_v3_account.as_ref().ok_or("native owner")?;
        let now = crate::custody::network_now()?;
        let root = owner.client.own_account_anchor()?;
        let source = peer.client.own_account_anchor()?;
        let home = digest(24);
        let wire::Operation::Policy { update: policy } = account.prepare_reach_policy(
            owner.vault.as_ref(),
            ReachCommandContext {
                actor: &account.record().body.master_certificate.body.primary_device_ref,
                home_head_hash: &home,
                expected_revision: 0,
                now,
            },
            wire::ReachMode::ContactsOnly,
        )?
        else {
            return Err("initial policy".into());
        };
        let branch = peer.client.device_branch.as_ref().ok_or("peer branch")?;
        let route = Route {
            version: 1,
            source: custody::DeviceRef {
                account_anchor: source.clone(),
                device_id: branch.device_id.clone(),
                device_epoch: branch.device_epoch,
            },
            recipient_root: root.clone(),
            conversation_id: ramflux_protocol::message::dm_scope::derive(&source, &root)?,
            traffic: Traffic::Dm,
            group: None,
            envelope_hash: digest(40),
            authority_head_hash: custody::object_hash(
                peer.client.born_v3_account.as_ref().ok_or("peer")?.record(),
            )?,
            issued_at: now,
            expires_at: now.checked_add(300).ok_or("route expiry")?,
        };
        Ok(Self { owner, route, policy, now })
    }
    fn update(
        &self,
        subject: Subject,
        decision: wire::Decision,
        permissions: Option<wire::Permissions>,
        expected: u64,
    ) -> TestResult<custody::Envelope<wire::Admission>> {
        let account = self.owner.client.born_v3_account.as_ref().ok_or("owner")?;
        let home = digest(24);
        let mut body = account.reach_decision_body(
            &ReachCommandContext {
                actor: &account.record().body.master_certificate.body.primary_device_ref,
                home_head_hash: &home,
                expected_revision: expected,
                now: self.now,
            },
            subject,
            decision,
        )?;
        if decision == wire::Decision::Allow {
            body.permissions = permissions;
            body.grant_until = Some(0);
            body.notice_hash = Some(digest(41));
            body.evidence_hash = Some(digest(42));
        }
        Ok(account.group_primary(self.owner.vault.as_ref())?.sign_reach_admission(
            body,
            account.verified(),
            self.now,
        )?)
    }
    fn install(
        &self,
        update: &custody::Envelope<wire::Admission>,
        records: Vec<StateRecord>,
    ) -> TestResult {
        let mut complete = vec![
            StateRecord::Policy { revision: 1, update: self.policy.clone() },
            StateRecord::AdmissionMeta {
                revision: update
                    .body
                    .expected_revision
                    .checked_add(1)
                    .ok_or("admission revision")?,
                last_update: Some(update.clone()),
            },
        ];
        complete.extend(records);
        self.owner.client.install_reach_state(verified_records(
            &self.owner,
            &digest(24),
            complete,
            self.now,
        )?)?;
        Ok(())
    }
    fn friendship(&self, permissions: wire::Permissions, expected: u64) -> TestResult {
        let subject = Subject::Friendship { root: self.route.source.account_anchor.clone() };
        let update =
            self.update(subject.clone(), wire::Decision::Allow, Some(permissions), expected)?;
        self.install(
            &update,
            vec![StateRecord::Grant {
                subject,
                permissions,
                grant_until: 0,
                update: update.clone(),
            }],
        )
    }
    fn check(&self, traffic: Traffic) -> Result<(), SdkError> {
        let mut route = self.route.clone();
        route.traffic = traffic;
        self.owner.client.require_reach_receive_policy(&route, self.now)
    }
    fn outgoing(&self, traffic: Traffic) -> Result<(), SdkError> {
        self.owner.client.require_reach_outgoing_signal(
            &self.route.source.account_anchor,
            &self.route.conversation_id,
            traffic,
            self.now,
        )
    }
}
fn assert_denied(result: &Result<(), SdkError>) {
    assert!(
        matches!(
            &result,
            Err(SdkError::GeneratedRefused {
                code: crate::error::GeneratedRefusalCode::Authority,
                ..
            })
        ),
        "a verified recipient denial must settle without authorizing application effects: {result:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn cr_future_original_clearance_cannot_remove_a_verified_block() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), future_clearance()).await?
}

async fn future_clearance() -> TestResult {
    let fixture = PolicyFixture::new().await?;
    let subject = Subject::Friendship { root: fixture.route.source.account_anchor.clone() };
    let block = fixture.update(subject.clone(), wire::Decision::Block, None, 2)?;
    fixture.install(
        &block,
        vec![StateRecord::Block { subject: subject.clone(), update: block.clone() }],
    )?;
    let before = fixture.owner.client.group_reach_mirror()?.ok_or("blocked mirror")?;
    let account = fixture.owner.client.born_v3_account.as_ref().ok_or("owner")?;
    let future = fixture.now.checked_add(61).ok_or("future signing time")?;
    let mut body = fixture.update(subject.clone(), wire::Decision::Unblock, None, 3)?.body;
    body.issued_at = future;
    body.expires_at = future.checked_add(300).ok_or("submission deadline")?;
    let unblock = account.group_primary(fixture.owner.vault.as_ref())?.sign_reach_admission(
        body,
        account.verified(),
        future,
    )?;
    ramflux_crypto::contact_reach::verify_admission(
        &unblock,
        account.verified(),
        &digest(24),
        &unblock.body.actor,
        future,
    )?;
    assert!(
        fixture
            .install(
                &unblock,
                vec![StateRecord::Retirement {
                    subject,
                    revision: 4,
                    update: unblock.clone(),
                    group_floor: None,
                }],
            )
            .is_err(),
        "a valid future primary signature cannot authorize clearance in an earlier home snapshot"
    );
    let after = fixture.owner.client.group_reach_mirror()?.ok_or("preserved mirror")?;
    assert_eq!(after.state_hash, before.state_hash, "refusal must preserve the committed mirror");
    assert_eq!(after.restrictions, before.restrictions, "refusal must preserve the signed block");
    assert_denied(&fixture.check(Traffic::Dm));
    refuse_restored_future_clearance(&fixture, &block, &unblock)?;
    Ok(())
}

fn refuse_restored_future_clearance(
    fixture: &PolicyFixture,
    block: &custody::Envelope<wire::Admission>,
    unblock: &custody::Envelope<wire::Admission>,
) -> TestResult {
    let db = fixture.owner.client.account_db()?;
    let before = db.reach_saved_state()?.ok_or("committed block")?;
    let future = StateRecord::Retirement {
        subject: unblock.body.subject.clone(),
        revision: 4,
        update: unblock.clone(),
        group_floor: None,
    };
    let hashes = db.reach_provenance_proof_hashes()?;
    let proof = db
        .reach_provenance_proof(&before.root, hashes.first().ok_or("native proof selector")?)?
        .ok_or("native proof")?;
    let mut signers = wire::record_signers(&future)?;
    for signer in &mut signers {
        signer.proof_hash.clone_from(&proof.proof_hash);
    }
    db.retain_reach_provenance(&before.root, &signers, [Ok(proof)])?;
    db.persist_actor_state(
        crate::contact_reach::restore::KEY,
        &ramflux_storage::ReachRestoreRestrictions {
            root: before.root.clone(),
            records: vec![future],
        },
    )?;
    let error = fixture
        .install(
            block,
            vec![StateRecord::Block { subject: block.body.subject.clone(), update: block.clone() }],
        )
        .err()
        .ok_or("future restored clearance must refuse")?;
    assert!(
        matches!(error.downcast_ref::<SdkError>(), Some(SdkError::Protocol(_)))
            && error.to_string().contains("original signing time"),
        "a valid proof/reference closure must stop at the restored original-time boundary: {error}"
    );
    assert_eq!(
        db.reach_saved_state()?.ok_or("preserved block")?,
        before,
        "refused future restore must leave the entire committed mirror unchanged"
    );
    assert!(
        db.actor_state_exists(crate::contact_reach::restore::KEY)?,
        "the unauthenticated-in-time restore remains pending instead of clearing the block"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cr_receipt_policy_requires_each_original_permission_and_local_setting() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), receipt_policy()).await?
}
async fn receipt_policy() -> TestResult {
    let fixture = PolicyFixture::new().await?;
    assert!(
        matches!(fixture.check(Traffic::Dm), Err(SdkError::InboundPending(_))),
        "an absent own-state mirror cannot synthesize default receiving authority"
    );
    fixture.friendship(wire::Permissions::UNACCEPTED, 1)?;
    assert_denied(&fixture.check(Traffic::ReceiptRead));
    assert_denied(&fixture.outgoing(Traffic::ReceiptRead));
    assert_denied(&fixture.outgoing(Traffic::Typing));
    fixture.owner.client.set_reach_signal_settings(wire::Permissions::ACCEPTED)?;
    assert_denied(&fixture.check(Traffic::ReceiptRead));
    fixture
        .friendship(wire::Permissions { user_delivered: true, read: false, typing: false }, 2)?;
    fixture.check(Traffic::ReceiptDelivered)?;
    fixture.outgoing(Traffic::ReceiptDelivered)?;
    assert_denied(&fixture.check(Traffic::ReceiptRead));
    fixture.owner.client.set_reach_signal_settings(wire::Permissions {
        user_delivered: false,
        read: true,
        typing: true,
    })?;
    assert_denied(&fixture.check(Traffic::ReceiptDelivered));
    assert_denied(&fixture.check(Traffic::ReceiptRead));
    fixture.friendship(wire::Permissions::ACCEPTED, 3)?;
    fixture.check(Traffic::ReceiptRead)?;
    assert_denied(&fixture.check(Traffic::ReceiptDelivered));
    fixture.owner.client.set_reach_signal_settings(wire::Permissions::ACCEPTED)?;
    fixture.check(Traffic::ReceiptDelivered)?;
    fixture.outgoing(Traffic::ReceiptRead)?;
    fixture.outgoing(Traffic::Typing)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cr_recipient_root_denial_survives_complete_snapshot_omission() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), retained_root_denial()).await?
}
async fn retained_root_denial() -> TestResult {
    let fixture = PolicyFixture::new().await?;
    fixture.friendship(wire::Permissions::ACCEPTED, 1)?;
    let subject = Subject::Friendship { root: fixture.route.source.account_anchor.clone() };
    let block = fixture.update(subject.clone(), wire::Decision::Block, None, 2)?;
    fixture.install(&block, vec![StateRecord::Block { subject, update: block.clone() }])?;
    assert_denied(&fixture.check(Traffic::Dm));
    assert_denied(&fixture.check(Traffic::ReceiptRead));
    let unrelated = fixture.update(
        Subject::Friendship { root: digest(43) },
        wire::Decision::Unblock,
        None,
        3,
    )?;
    fixture.install(&unrelated, vec![])?;
    assert_denied(&fixture.check(Traffic::Dm));
    fixture.owner.client.set_reach_signal_settings(wire::Permissions::ACCEPTED)?;
    assert_denied(&fixture.check(Traffic::ReceiptDelivered));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cr_decline_expiry_preserves_revision_floor_without_reviving_old_grants() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), decline_expiry()).await?
}

async fn decline_expiry() -> TestResult {
    let fixture = PolicyFixture::new().await?;
    let subject = Subject::Friendship { root: fixture.route.source.account_anchor.clone() };
    let old = fixture.update(
        subject.clone(),
        wire::Decision::Allow,
        Some(wire::Permissions::ACCEPTED),
        1,
    )?;
    let decline = fixture.update(subject.clone(), wire::Decision::Decline, None, 2)?;
    let until = fixture.now.checked_add(wire::DECLINE_COOLDOWN).ok_or("cooldown overflow")?;
    fixture.install(
        &decline,
        vec![
            StateRecord::Grant {
                subject: subject.clone(),
                permissions: wire::Permissions::ACCEPTED,
                grant_until: 0,
                update: old,
            },
            StateRecord::Decline {
                root: fixture.route.source.account_anchor.clone(),
                until,
                update: decline.clone(),
            },
            StateRecord::Floor {
                subject,
                revision: 3,
                denied: true,
                erase_generation: 3,
                erased: true,
            },
        ],
    )?;
    assert_denied(&fixture.owner.client.require_reach_receive_policy(&fixture.route, until - 1));
    fixture.owner.client.require_reach_receive_policy(&fixture.route, until)?;
    fixture.owner.client.set_reach_signal_settings(wire::Permissions::ACCEPTED)?;
    let projected = fixture.owner.client.conversation_reach(
        &fixture.route.source.account_anchor,
        "peer.example",
        &fixture.route.conversation_id,
        until,
    )?;
    assert_eq!(projected.relationship, wire::Relationship::Unaccepted);
    assert_eq!(projected.permissions, wire::Permissions::UNACCEPTED);
    let mut receipt = fixture.route.clone();
    receipt.traffic = Traffic::ReceiptRead;
    assert_denied(&fixture.owner.client.require_reach_receive_policy(&receipt, until));
    let saved = fixture.owner.client.group_reach_mirror()?.ok_or("retained mirror")?;
    assert!(
        saved.restrictions.values().any(|record| matches!(
            record,
            StateRecord::Floor { revision: 3, erase_generation: 3, erased: true, .. }
        )),
        "expiry cannot remove revision or erasure floors"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cr_signed_root_clearance_survives_mirror_omission_and_older_denial_merge() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), retained_clearance()).await?
}

async fn retained_clearance() -> TestResult {
    let fixture = PolicyFixture::new().await?;
    let subject = Subject::Friendship { root: fixture.route.source.account_anchor.clone() };
    let block = fixture.update(subject.clone(), wire::Decision::Block, None, 2)?;
    let old = vec![
        StateRecord::Block { subject: subject.clone(), update: block.clone() },
        StateRecord::Floor {
            subject: subject.clone(),
            revision: 3,
            denied: true,
            erase_generation: 3,
            erased: true,
        },
    ];
    fixture.install(&block, old.clone())?;
    let unblock = fixture.update(subject.clone(), wire::Decision::Unblock, None, 3)?;
    fixture.install(
        &unblock,
        vec![
            StateRecord::Retirement {
                subject: subject.clone(),
                revision: 4,
                update: unblock.clone(),
                group_floor: None,
            },
            StateRecord::Floor {
                subject: subject.clone(),
                revision: 4,
                denied: false,
                erase_generation: 4,
                erased: true,
            },
        ],
    )?;
    let other = fixture.update(
        Subject::Friendship { root: digest(46) },
        wire::Decision::Unblock,
        None,
        4,
    )?;
    fixture.install(&other, vec![])?;
    let saved = fixture.owner.client.group_reach_mirror()?.ok_or("current mirror")?;
    assert!(
        saved.restrictions.values().any(
            |record| matches!(record, StateRecord::Retirement { update, .. } if update == &unblock)
        ),
        "canonical omission must retain the original signed clearance and its native proof"
    );
    let db = fixture.owner.client.account_db()?;
    assert!(
        db.reach_provenance_reference(
            wire::ObjectKind::Admission,
            &custody::framed_hash(wire::OPERATION_HASH_DOMAIN, &unblock)?,
        )?
        .is_some(),
        "collection must retain the independently saved clearance's exact signer reference"
    );
    assert!(
        db.reach_provenance_reference(
            wire::ObjectKind::Admission,
            &custody::framed_hash(wire::OPERATION_HASH_DOMAIN, &block)?,
        )?
        .is_none(),
        "the legitimately cleared and superseded block must stop occupying signer metadata"
    );
    let merged =
        crate::contact_reach::restrictions::merge_restrictions(saved.restrictions.clone(), &old)?;
    assert!(!merged.values().any(
        |record| matches!(record, StateRecord::Block { subject: peer, .. } if peer == &subject)
    ));
    assert!(merged.values().any(|record| matches!(
        record,
        StateRecord::Floor { denied: false, revision: 4, erase_generation: 4, erased: true, .. }
    )));
    let later = fixture.update(subject.clone(), wire::Decision::Block, None, 5)?;
    let merged = crate::contact_reach::restrictions::merge_restrictions(
        merged,
        &[StateRecord::Block { subject, update: later }],
    )?;
    assert!(merged.values().any(|record| matches!(record, StateRecord::Block { update, .. } if update.body.expected_revision == 5)), "an old signed clearance cannot clear a newer denial");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cr_restored_denials_hold_positive_use_until_originals_verify_atomically() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), restored_denials()).await?
}

async fn restored_denials() -> TestResult {
    let fixture = PolicyFixture::new().await?;
    fixture.friendship(wire::Permissions::ACCEPTED, 1)?;
    let db = fixture.owner.client.account_db()?;
    let before = db.client_record("reach", "state")?.ok_or("pre-denial mirror")?;
    let subject = Subject::Friendship { root: fixture.route.source.account_anchor.clone() };
    let block = fixture.update(subject.clone(), wire::Decision::Block, None, 2)?;
    let restrictions = vec![
        StateRecord::Block { subject: subject.clone(), update: block.clone() },
        StateRecord::Floor {
            subject,
            revision: 3,
            denied: true,
            erase_generation: 3,
            erased: true,
        },
    ];
    fixture.install(&block, restrictions.clone())?;
    let originals =
        crate::contact_reach::provenance::read_pool_for_tests(db, &fixture.route.recipient_root)?
            .ok_or("original proof pool")?;
    // State after a native data merge: live metadata remains local; originals and denials are staged.
    db.persist_client_record("reach", "state", &before)?;
    let staged = serde_json::json!({"root":fixture.route.recipient_root,"records":restrictions});
    db.persist_actor_state(crate::contact_reach::restore::KEY, &staged)?;
    assert!(matches!(fixture.check(Traffic::Dm), Err(SdkError::InboundPending(_))));
    let other = fixture.update(
        Subject::Friendship { root: digest(47) },
        wire::Decision::Unblock,
        None,
        3,
    )?;
    crate::contact_reach::provenance::clear_pool_for_tests(db)?;
    assert!(
        fixture.install(&other, vec![]).is_err(),
        "fresh mirror cannot replace missing original denial evidence"
    );
    assert!(db.actor_state_exists(crate::contact_reach::restore::KEY)?);
    assert_eq!(db.client_record("reach", "state")?.ok_or("mirror after refusal")?, before);
    crate::contact_reach::provenance::write_pool_for_tests(db, &originals)?;
    fixture.install(&other, vec![])?;
    assert!(!db.actor_state_exists(crate::contact_reach::restore::KEY)?);
    assert_denied(&fixture.check(Traffic::Dm));
    // Equal-content refresh must also reconcile a newly imported independent restriction set.
    db.persist_actor_state(crate::contact_reach::restore::KEY, &staged)?;
    fixture.install(&other, vec![])?;
    assert!(!db.actor_state_exists(crate::contact_reach::restore::KEY)?);
    assert_denied(&fixture.check(Traffic::Dm));
    db.persist_actor_state(
        crate::contact_reach::restore::KEY,
        &serde_json::json!({
            "root":fixture.route.recipient_root,"records":[]
        }),
    )?;
    assert!(matches!(fixture.check(Traffic::Dm), Err(SdkError::InboundPending(_))));
    fixture.install(&other, vec![])?;
    assert!(!db.actor_state_exists(crate::contact_reach::restore::KEY)?);
    assert_denied(&fixture.check(Traffic::Dm));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cr_restored_clearance_with_matching_reference_but_bad_signature_stays_pending()
-> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), forged_restored_clearance()).await?
}

async fn forged_restored_clearance() -> TestResult {
    let fixture = PolicyFixture::new().await?;
    let subject = Subject::Friendship { root: fixture.route.source.account_anchor.clone() };
    let block = fixture.update(subject.clone(), wire::Decision::Block, None, 2)?;
    fixture.install(
        &block,
        vec![StateRecord::Block { subject: subject.clone(), update: block.clone() }],
    )?;
    let db = fixture.owner.client.account_db()?;
    let before = db.client_record("reach", "state")?.ok_or("blocked mirror")?;
    let mut forged = fixture.update(subject.clone(), wire::Decision::Unblock, None, 3)?;
    forged.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &custody::signing_bytes(wire::ADMISSION_DOMAIN, &forged.body)?,
        [55; 32],
    );
    let record =
        StateRecord::Retirement { subject, revision: 4, update: forged, group_floor: None };
    let mut pool =
        crate::contact_reach::provenance::read_pool_for_tests(db, &fixture.route.recipient_root)?
            .ok_or("native original proof pool")?;
    let mut references = wire::record_signers(&record)?;
    for reference in &mut references {
        let proof = pool
            .authorities
            .iter()
            .find(|proof| {
                custody::object_hash(&proof.authority.publication.record)
                    .is_ok_and(|head| head == reference.authority_head_hash)
            })
            .ok_or("exact selected original native proof")?;
        reference.proof_hash.clone_from(&proof.proof_hash);
    }
    pool.signers.extend(references);
    pool.signers.sort_by(|left, right| left.order_key().cmp(&right.order_key()));
    crate::contact_reach::provenance::write_pool_for_tests(db, &pool)?;
    db.persist_actor_state(
        crate::contact_reach::restore::KEY,
        &serde_json::json!({"root":fixture.route.recipient_root,"records":[record]}),
    )?;
    let verification = crate::contact_reach::restore::verify(
        db,
        &fixture.route.recipient_root,
        None,
        fixture.now.checked_add(60).ok_or("restore clock window")?,
    );
    assert!(
        matches!(verification, Err(SdkError::Crypto(ramflux_crypto::CryptoError::VerifyFailed))),
        "matching object/proof hashes cannot replace original cryptographic verification"
    );
    assert!(db.actor_state_exists(crate::contact_reach::restore::KEY)?);
    assert_eq!(db.client_record("reach", "state")?.ok_or("blocked after refusal")?, before);
    assert!(matches!(fixture.check(Traffic::Dm), Err(SdkError::InboundPending(_))));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cr_recipient_node_denial_needs_authenticated_source_home() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), node_denial()).await?
}
async fn node_denial() -> TestResult {
    let fixture = PolicyFixture::new().await?;
    fixture.friendship(wire::Permissions::ACCEPTED, 1)?;
    let subject = Subject::Node { node_id: "blocked.example".into() };
    let block = fixture.update(subject.clone(), wire::Decision::Block, None, 2)?;
    fixture.install(&block, vec![StateRecord::Block { subject, update: block.clone() }])?;
    assert!(
        matches!(fixture.check(Traffic::Dm), Err(SdkError::InboundPending(_))),
        "an unknown source home cannot bypass a retained node denial"
    );
    assert!(
        matches!(fixture.check(Traffic::ReceiptRead), Err(SdkError::InboundPending(_))),
        "a true receipt permission cannot replace authenticated home binding"
    );
    Ok(())
}

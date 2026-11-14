// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A real native sibling consumes complete signed snapshots, independently retaining block proof.
use super::super::group_test_support::{install_grant, verified_records};
use super::*;
use crate::{
    client::native_test_support::{Fixture, TestResult},
    custody::ReachCommandContext,
};
use ramflux_protocol::{
    contact_reach::{Admission, Decision, GroupFloor, Operation},
    custody,
};
type SignedAdmission = custody::Envelope<Admission>;

struct Proofs {
    policy: StateRecord,
    grant: SignedAdmission,
    leave: SignedAdmission,
    block: SignedAdmission,
    unblock: SignedAdmission,
    other: SignedAdmission,
    later: SignedAdmission,
}
fn home() -> String {
    ramflux_protocol::encode_base64url([24; 32])
}
fn decision(
    phone: &Fixture,
    subject: Subject,
    decision: Decision,
    revision: u64,
) -> TestResult<SignedAdmission> {
    let account = phone.client.born_v3_account.as_ref().ok_or("primary account")?;
    let head = home();
    let context = ReachCommandContext {
        actor: &account.record().body.master_certificate.body.primary_device_ref,
        home_head_hash: &head,
        expected_revision: revision,
        now: crate::custody::network_now()?,
    };
    let Operation::Admission { update, .. } =
        account.prepare_reach_denial(phone.vault.as_ref(), context, subject, decision)?
    else {
        return Err("primary denial operation".into());
    };
    Ok(update)
}
async fn fixture() -> TestResult<(Fixture, Proofs)> {
    let mut phone = Fixture::new("reach-unblock-phone").await?;
    let sibling = phone.enroll_sibling("reach-unblock-sibling", "second").await?;
    let account_id = phone.client.account_db()?.local_account_id.clone();
    phone.client.born_v3_account = Some(Box::new(crate::custody::load_account(
        &phone.root.0,
        &account_id,
        crate::custody::network_now()?,
    )?));
    let primary = phone
        .client
        .born_v3_account
        .as_ref()
        .ok_or("current primary")?
        .group_primary(phone.vault.as_ref())?;
    let state = phone.client.shared_group_create_with_primary(
        "proof-group",
        "proof-thread",
        None,
        &phone.config.target_delivery_id,
        Some(&primary),
    )?;
    sibling.client.accept_shared_group_state(&state, &sibling.config.target_delivery_id)?;
    install_grant(&phone, &state)?;
    let initial = phone.client.group_reach_mirror()?.ok_or("initial signed state")?;
    let grant = initial
        .records
        .iter()
        .find_map(|record| match record {
            StateRecord::Grant { update, .. } => Some(update.clone()),
            _ => None,
        })
        .ok_or("original grant")?;
    let policy = initial
        .records
        .iter()
        .find(|record| matches!(record, StateRecord::Policy { .. }))
        .cloned()
        .ok_or("original policy")?;
    let subject = grant.body.subject.clone();
    let proofs = Proofs {
        policy,
        grant,
        leave: decision(&phone, subject.clone(), Decision::Revoke, 2)?,
        block: decision(&phone, subject.clone(), Decision::Block, 3)?,
        unblock: decision(&phone, subject, Decision::Unblock, 4)?,
        other: decision(
            &phone,
            Subject::Node { node_id: "other.example".into() },
            Decision::Block,
            5,
        )?,
        later: decision(
            &phone,
            Subject::Node { node_id: "later.example".into() },
            Decision::Block,
            6,
        )?,
    };
    Ok((sibling, proofs))
}
impl Proofs {
    fn records(
        &self,
        control: Option<&SignedAdmission>,
        last: &SignedAdmission,
        nodes: &[&SignedAdmission],
    ) -> TestResult<Vec<StateRecord>> {
        let revision = self
            .leave
            .body
            .expected_revision
            .max(control.map_or(0, |control| control.body.expected_revision))
            .checked_add(1)
            .ok_or("retirement revision overflow")?;
        let Subject::Group { group_epoch, .. } = self.leave.body.subject else {
            return Err("group retirement".into());
        };
        let mut records = vec![
            self.policy.clone(),
            StateRecord::AdmissionMeta {
                revision: last
                    .body
                    .expected_revision
                    .checked_add(1)
                    .ok_or("admission revision overflow")?,
                last_update: Some(last.clone()),
            },
            StateRecord::Retirement {
                subject: self.leave.body.subject.clone(),
                revision,
                update: self.leave.clone(),
                group_floor: Some(Box::new(GroupFloor {
                    floor_epoch: group_epoch,
                    grant: Some(Box::new(self.grant.clone())),
                    roster_header: None,
                    block_control: control.cloned().map(Box::new),
                })),
            },
        ];
        for node in nodes {
            records.push(StateRecord::Block {
                subject: node.body.subject.clone(),
                update: (*node).clone(),
            });
        }
        Ok(records)
    }
}
fn install(sibling: &Fixture, records: Vec<StateRecord>) -> TestResult {
    let verified = verified_records(sibling, &home(), records, crate::custody::network_now()?)?;
    sibling.client.install_reach_state(verified)?;
    Ok(())
}
fn retained(sibling: &Fixture) -> TestResult<GroupFloor> {
    let state = sibling.client.group_reach_mirror()?.ok_or("verified sibling mirror")?;
    state
        .restrictions
        .values()
        .find_map(|record| match record {
            StateRecord::Retirement { group_floor: Some(floor), .. } => {
                Some(floor.as_ref().clone())
            }
            _ => None,
        })
        .ok_or_else(|| "independent retained group proof".into())
}

#[tokio::test]
async fn cr_group_signed_read_clears_only_original_retained_unblock() -> TestResult {
    let (sibling, proofs) = fixture().await?;
    install(&sibling, proofs.records(Some(&proofs.block), &proofs.block, &[])?)?;
    let blocked = retained(&sibling)?;
    assert!(blocked.blocked(), "the real sibling retains the original primary-signed block");
    install(&sibling, proofs.records(None, &proofs.other, &[&proofs.other])?)?;
    assert!(
        retained(&sibling)?.blocked(),
        "a complete correctly home-signed snapshot omitting the clearance cannot clear the block"
    );
    install(
        &sibling,
        proofs.records(Some(&proofs.unblock), &proofs.later, &[&proofs.other, &proofs.later])?,
    )?;
    let cleared = retained(&sibling)?;
    assert!(!cleared.blocked(), "only the higher-revision original signed unblock clears it");
    assert_eq!(cleared.floor_epoch, blocked.floor_epoch, "clearance never lowers the signed floor");
    assert_eq!(
        cleared.block_control.as_deref(),
        Some(&proofs.unblock),
        "the sibling retains the exact signed clearance rather than inferring it from the home manifest"
    );
    let state = sibling.client.group_reach_mirror()?.ok_or("cleared state")?;
    assert!(
        state.records.iter().any(|record| matches!(record,
        StateRecord::AdmissionMeta { last_update: Some(update), .. } if update == &proofs.later)),
        "an unrelated admission replaced last_update before the sibling received the clearance"
    );
    assert!(
        !state.records.iter().any(|record| matches!(record, StateRecord::Grant { .. })),
        "the retirement's signed grant remains proof and is never installed as permission"
    );
    let older = proofs.records(Some(&proofs.block), &proofs.block, &[])?;
    let restored = super::super::restrictions::merge_restored(state.restrictions, &older)?;
    assert!(restored.values().any(|record| matches!(record,
        StateRecord::Retirement { group_floor: Some(floor), .. }
        if floor.floor_epoch == cleared.floor_epoch && floor.block_control.as_deref() == Some(&proofs.unblock)
    )), "restoring older original group evidence cannot drop a newer signed clearance or F");
    Ok(())
}

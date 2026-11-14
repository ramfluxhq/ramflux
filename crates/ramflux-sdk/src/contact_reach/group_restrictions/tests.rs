// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independent floor merge controls; full signature verification precedes this pure reducer.
use super::*;
use ramflux_protocol::{
    contact_reach::{Admission, Decision, GroupFloor, Subject},
    custody::{DeviceRef, Envelope as Signed},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn digest(n: u8) -> String {
    ramflux_protocol::encode_base64url([n; 32])
}
fn update(decision: Decision, revision: u64, epoch: u64) -> Signed<Admission> {
    Signed {
        body: Admission {
            version: 2,
            operation_id: digest(2),
            recipient_root: digest(1),
            home_head_hash: digest(3),
            expected_revision: revision,
            subject: Subject::Group {
                group_id: "group".into(),
                conversation_id: "signed-thread".into(),
                genesis_hash: digest(4),
                group_epoch: epoch,
                membership_hash: digest(5),
            },
            decision,
            permissions: None,
            grant_until: None,
            authority_head_hash: digest(6),
            master_certificate_hash: digest(7),
            actor: DeviceRef {
                account_anchor: digest(1),
                device_id: "phone".into(),
                device_epoch: 1,
            },
            notice_hash: None,
            evidence_hash: None,
            issued_at: 100,
            expires_at: 400,
        },
        signature: ramflux_protocol::encode_base64url([8; 64]),
    }
}
fn record(control: Option<Signed<Admission>>, floor_epoch: u64) -> StateRecord {
    let update = update(Decision::Revoke, 1, floor_epoch);
    let revision = control.as_ref().map_or(2, |control| control.body.expected_revision + 1);
    StateRecord::Retirement {
        subject: update.body.subject.clone(),
        revision,
        update,
        group_floor: Some(Box::new(GroupFloor {
            floor_epoch,
            grant: None,
            roster_header: None,
            block_control: control.map(Box::new),
        })),
    }
}
fn floor(record: &StateRecord) -> Result<&GroupFloor, SdkError> {
    if let StateRecord::Retirement { group_floor: Some(floor), .. } = record {
        Ok(floor)
    } else {
        Err(SdkError::ReachRefused(Reason::ForeignSnapshotInvalid))
    }
}
#[test]
fn cr_group_retained_unblock_merge_model() -> TestResult {
    let blocked = record(Some(update(Decision::Block, 2, 1)), 100);
    for omitted_or_stale in
        [record(None, 100), record(Some(update(Decision::Unblock, 1, 500)), 100)]
    {
        let merged = merge(Some(&blocked), &omitted_or_stale)?;
        assert!(
            floor(&merged)?.blocked(),
            "an omitted or lower-revision clearance cannot remove an independently retained signed block"
        );
        assert_eq!(
            floor(&merged)?.floor_epoch,
            100,
            "the block control never changes the retirement floor"
        );
    }
    let unblocked = merge(Some(&blocked), &record(Some(update(Decision::Unblock, 4, 500)), 100))?;
    assert!(
        !floor(&unblocked)?.blocked(),
        "a same-binding higher-revision signed unblock is the applicable clearance"
    );
    assert_eq!(
        floor(&unblocked)?.floor_epoch,
        100,
        "even a high epoch in the unblock is excluded from the floor formula"
    );
    let later_leave = merge(Some(&unblocked), &record(None, 101))?;
    assert_eq!(
        floor(&later_leave)?.block_control.as_ref().map(|control| control.body.decision),
        Some(Decision::Unblock),
        "clearance remains retained through a later retirement and unrelated command history"
    );
    assert_eq!(
        floor(&later_leave)?.floor_epoch,
        101,
        "the later signed retirement may advance but never lower the independent floor"
    );
    assert!(
        matches!(
            merge(Some(&later_leave), &record(None, 100)),
            Err(SdkError::ReachRefused(Reason::HomeRollback))
        ),
        "a higher transport snapshot cannot lower the signed group floor"
    );
    Ok(())
}
#[test]
fn cr_group_conflicting_control_revision_fences_model() {
    let blocked = record(Some(update(Decision::Block, 2, 1)), 100);
    let conflicting = record(Some(update(Decision::Unblock, 2, 1)), 100);
    assert!(
        matches!(
            merge(Some(&blocked), &conflicting),
            Err(SdkError::ReachRefused(Reason::HomeFork))
        ),
        "two different signed controls at the same revision cannot select a permissive interpretation"
    );
}

fn grant(epoch: u64) -> StateRecord {
    let mut update = update(Decision::Allow, 4, epoch);
    update.body.permissions = Some(ramflux_protocol::contact_reach::Permissions::UNACCEPTED);
    update.body.grant_until = Some(0);
    update.body.notice_hash = Some(digest(12));
    update.body.evidence_hash = Some(digest(5));
    StateRecord::Grant {
        subject: update.body.subject.clone(),
        permissions: ramflux_protocol::contact_reach::Permissions::UNACCEPTED,
        grant_until: 0,
        update,
    }
}

#[test]
fn cr_group_snapshot_binding_is_bijective_and_deny_wins() -> TestResult {
    let retired = record(None, 100);
    verify_bindings(&[retired.clone(), grant(101)])?;
    assert!(
        verify_bindings(&[retired.clone(), grant(100)]).is_err(),
        "a live grant must exceed its retained floor"
    );
    assert!(
        verify_bindings(&[record(Some(update(Decision::Block, 2, 1)), 100), grant(101)]).is_err(),
        "a retained active block forbids even a higher-epoch allow"
    );
    for (group, conversation, genesis) in [
        ("group", "other-thread", digest(4)),
        ("other-group", "signed-thread", digest(4)),
        ("other-group", "other-thread", digest(4)),
        ("group", "signed-thread", digest(9)),
    ] {
        let mut forged = grant(101);
        if let StateRecord::Grant {
            subject: Subject::Group { group_id, conversation_id, genesis_hash, .. },
            ..
        } = &mut forged
        {
            *group_id = group.into();
            *conversation_id = conversation.into();
            *genesis_hash = genesis;
        }
        assert!(
            matches!(
                verify_bindings(&[retired.clone(), forged]),
                Err(SdkError::ReachRefused(Reason::ReachRouteInvalid))
            ),
            "home transport signatures cannot rebind group, conversation or genesis"
        );
    }
    Ok(())
}

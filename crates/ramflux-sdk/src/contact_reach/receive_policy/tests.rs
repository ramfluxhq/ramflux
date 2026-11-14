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

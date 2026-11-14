// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::client::native_test_support::{Fixture, TestResult};

#[tokio::test]
async fn cr_primary_required_rejects_linked_actor_even_with_primary_vault() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut phone = Fixture::new("reach-primary-phone").await?;
        let linked = phone.enroll_sibling("reach-primary-linked", "linked").await?;
        let account = linked.client.born_v3_account.as_ref().ok_or("linked authority")?;
        let primary = &account.record().body.master_certificate.body.primary_device_ref;
        let identity = linked.client.owned_device_identity()?;
        let actor = DeviceRef {
            account_anchor: identity.root_commitment().into(),
            device_id: identity.device_id().into(),
            device_epoch: 1,
        };
        let home = ramflux_protocol::encode_base64url([23; 32]);
        let now = crate::custody::network_now()?;
        for actor in [&actor, primary] {
            let context =
                ReachCommandContext { actor, home_head_hash: &home, expected_revision: 0, now };
            let result = account.prepare_reach_policy(
                phone.vault.as_ref(),
                context,
                ReachMode::ContactsOnly,
            );
            assert!(
                matches!(result, Err(SdkError::PairingCode("PrimaryRequired"))),
                "a linked installation cannot borrow a primary vault or claim the primary actor"
            );
        }
        let phone_account = phone.client.born_v3_account.as_ref().ok_or("phone authority")?;
        let context = ReachCommandContext {
            actor: &phone_account.record().body.master_certificate.body.primary_device_ref,
            home_head_hash: &home,
            expected_revision: 0,
            now,
        };
        let operation = phone_account.prepare_reach_policy(
            phone.vault.as_ref(),
            context,
            ReachMode::ContactsOnly,
        )?;
        assert!(
            matches!(operation, Operation::Policy { update } if update.body.revision == 1
            && update.body.mode == ReachMode::ContactsOnly),
            "the actual primary installation can sign the explicit default-off setup policy"
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}

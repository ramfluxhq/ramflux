// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real signed mirrors and encrypted account clocks; receive/source phase coverage is separate.
use super::*;
use crate::{client::native_test_support::TestResult, contact_reach::group_test_support};

#[tokio::test(flavor = "current_thread")]
async fn cr_reach_install_refuses_an_expired_verified_lease_after_clock_rollback() -> TestResult {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let (owner, peer, _) = group_test_support::roster_fixture().await?;
        let before = peer.client.group_reach_mirror()?.ok_or("current signed mirror")?;
        let now = crate::custody::network_now()?;
        let verified = group_test_support::verified_records(
            &peer,
            &before.home_head_hash,
            before.records.clone(),
            now,
        )?;
        let floor = verified.manifest.expires_at.checked_add(1).ok_or("lease boundary")?;
        let db = peer.client.account_db()?;
        peer.client.conversation_reach(
            owner.client.owned_device_identity()?.root_commitment(),
            "peer.example",
            "roster-thread",
            floor,
        )?;
        assert!(
            matches!(peer.client.install_reach_state(verified), Err(SdkError::Protocol(_))),
            "a previously verified lease cannot outlive the independently committed UTC floor"
        );
        let after = peer.client.group_reach_mirror()?.ok_or("unchanged signed mirror")?;
        assert_eq!(
            ramflux_protocol::canonical_json_bytes(&after)?,
            ramflux_protocol::canonical_json_bytes(&before)?,
            "expired install cannot partially refresh home binding or original permission records"
        );
        assert!(
            db.reach_fenced_now(now)? >= floor,
            "the rejected install cannot lower the separately committed observation"
        );
        Ok(())
    })
    .await?
}

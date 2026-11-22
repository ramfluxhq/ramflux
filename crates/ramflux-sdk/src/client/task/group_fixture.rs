// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native signed membership for Task authorization and signer-isolation regressions.
use crate::RamfluxClient;
use crate::client::native_test_support::{
    Fixture, TestResult, activation_send::tests::publish_layer_four,
};
use ramflux_protocol::{GroupStateChange, SharedGroupRole};

pub(super) struct GroupFixture {
    pub human: RamfluxClient,
    pub agent: RamfluxClient,
    pub other: RamfluxClient,
}

pub(super) async fn fixture(with_other: bool, name: &str) -> TestResult<GroupFixture> {
    let mut human =
        Box::pin(Fixture::with_principal("task-human", "human-device", "human")).await?;
    let mut agent =
        Box::pin(Fixture::with_principal("task-agent", "agent-device", "agent")).await?;
    let mut other =
        Box::pin(Fixture::with_principal("task-other", &format!("{name}-device"), name)).await?;
    for fixture in [&mut human, &mut agent, &mut other] {
        Box::pin(publish_layer_four(fixture)).await?;
    }
    for local in [&human, &agent, &other] {
        for peer in [&human, &agent, &other] {
            local.client.persist_observed_identity_directory_now(&peer.manifest)?;
        }
    }
    let human = human.into_bus();
    let agent = agent.into_bus();
    let other = other.into_bus();
    human.client.fixture_group_create("group", "group-thread", None, "human-device")?;
    let mut state = human.client.fixture_group_change(
        "group",
        "human-device",
        GroupStateChange::Add {
            member: agent.client.fixture_group_actor("agent-device")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    if with_other {
        state = human.client.fixture_group_change(
            "group",
            "human-device",
            GroupStateChange::Add {
                member: other.client.fixture_group_actor(&format!("{name}-device"))?.identity,
                role: SharedGroupRole::Member,
            },
        )?;
        other.client.fixture_accept_group_state(&state, &format!("{name}-device"))?;
    }
    agent.client.fixture_accept_group_state(&state, "agent-device")?;
    Ok(GroupFixture { human: human.client, agent: agent.client, other: other.client })
}

/// Corrupt only the unsigned cache to model a stale projection beneath signed native state.
pub(super) fn skew_projection(client: &RamfluxClient, epoch: u64) -> TestResult {
    use std::fmt::Write as _;
    let _material = client.native_bus_fixture.as_ref().ok_or("native fixture")?;
    let account = &client.account_db()?.local_account_id;
    let vault = client.vault_secret_source()?.vault_secret(account)?;
    let wrapped = client.account_index()?.load_wrapped_db_key(account)?.ok_or("database key")?;
    let key = ramflux_storage::unwrap_with_vault_secret(
        &crate::client::account::account_db_key_encryption_key(
            &vault,
            b"native fixture data passphrase",
        )?,
        &wrapped,
    )?;
    let db = rusqlite::Connection::open(&client.account_db()?.path)?;
    let mut hex = zeroize::Zeroizing::new(String::with_capacity(64));
    for byte in key.bytes() {
        write!(&mut *hex, "{byte:02x}")?;
    }
    db.execute_batch(&format!("PRAGMA key=\"x'{}'\";", hex.as_str()))?;
    db.execute("INSERT OR REPLACE INTO group_member_projection(group_id, member_principal_id, member_id, role, joined_epoch, active, updated_at) VALUES ('group','ghost','ghost','member',?1,1,0)", [i64::try_from(epoch)?])?;
    Ok(())
}

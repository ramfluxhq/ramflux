// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native signed group history shared by the membership-witness regressions.
use crate::RamfluxClient;
use crate::client::native_test_support::{Fixture, TestResult, bus};
use ramflux_protocol::{GroupStateChange, SharedGroupRole};

pub(super) struct GroupFixture {
    pub human: RamfluxClient,
    pub agent: RamfluxClient,
    pub sibling: RamfluxClient,
}

pub(super) async fn fixture(excluded_epoch: bool) -> TestResult<GroupFixture> {
    let mut human = Fixture::with_principal("history-human", "human-device", "human").await?;
    crate::client::native_test_support::activation_send::tests::publish_layer_four(&mut human)
        .await?;
    let agent = Fixture::with_principal("history-agent", "agent-device", "agent").await?;
    let mut agent = agent.into_bus();
    let sibling = bus::sibling(&mut agent, "history-sibling", "agent2-device").await?;
    let native = Fixture::take_bus(&mut agent)?;
    native.accept_peer(&human)?;
    human.accept_peer(&native)?;
    agent = native.into_bus();
    let human = human.into_bus();
    sibling.client.persist_observed_identity_directory_now(
        &human.client.native_bus_fixture.as_ref().ok_or("human material")?.manifest,
    )?;
    let genesis =
        agent.client.fixture_group_create("group", "group-thread", None, "agent-device")?;
    sibling.client.fixture_accept_group_state(&genesis, "agent2-device")?;
    if excluded_epoch {
        let excluded = Fixture::with_principal("history-excluded", "excluded-device", "excluded")
            .await?
            .into_bus();
        for client in [&agent.client, &sibling.client] {
            client.persist_observed_identity_directory_now(
                &excluded.client.native_bus_fixture.as_ref().ok_or("excluded material")?.manifest,
            )?;
        }
        let state = agent.client.fixture_group_change(
            "group",
            "agent-device",
            GroupStateChange::Add {
                member: excluded.client.fixture_group_actor("excluded-device")?.identity,
                role: SharedGroupRole::Member,
            },
        )?;
        sibling.client.fixture_accept_group_state(&state, "agent2-device")?;
        let state = agent.client.fixture_group_change(
            "group",
            "agent-device",
            GroupStateChange::Remove {
                root_commitment: excluded.client.own_account_anchor()?,
                device_id: "excluded-device".into(),
            },
        )?;
        sibling.client.fixture_accept_group_state(&state, "agent2-device")?;
    }
    let state = agent.client.fixture_group_change(
        "group",
        "agent-device",
        GroupStateChange::Add {
            member: human.client.fixture_group_actor("human-device")?.identity,
            role: SharedGroupRole::Member,
        },
    )?;
    human.client.fixture_accept_group_state(&state, "human-device")?;
    sibling.client.fixture_accept_group_state(&state, "agent2-device")?;
    Ok(GroupFixture { human: human.client, agent: agent.client, sibling: sibling.client })
}

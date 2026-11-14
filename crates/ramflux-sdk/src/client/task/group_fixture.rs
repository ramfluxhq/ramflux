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
            local.client.persist_fetched_identity_directory(&peer.manifest)?;
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

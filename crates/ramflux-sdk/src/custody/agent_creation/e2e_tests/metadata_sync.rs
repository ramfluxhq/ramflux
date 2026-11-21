// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Replication of the agent record between the two roots of one human (AGENT-IDENTITY-01 E3, E6,
//! `agent_record_metadata_sync`). Real: the phone and the paired desktop native fixtures with their
//! own record stores, the own-device outbox (`own_device_copy`), the real `RouterCore` between the
//! devices (`OwnRouter::route`), the own-device receive path and the apply rule by `EventOrder`.
//! Fixture: the initial `U` record is written on the desktop by `seed_for_test` (the completing
//! desktop writes it in E2); the other device gets its record only from the metadata packets.
//! Nothing sleeps: every change takes an explicit `now`. The fixture builders run their own
//! runtime, so each test builds the fixture first and runs only the routing on its own runtime.
use super::super::test_support::{OwnRouter, Pair, TestResult, now, pair};
use crate::SdkError;
use crate::agent_record::{StoredAgentRecord, metadata_of, seed_for_test};
use crate::client::RamfluxClient;
use ramflux_protocol::encode_base64url;
use ramflux_protocol::message::{AgentAccessPolicy, AgentPersona};

fn persona(name: &str) -> AgentPersona {
    AgentPersona {
        name: name.into(),
        avatar: String::new(),
        responsibility: "answers the owner's questions".into(),
    }
}

fn access(dm: &str) -> AgentAccessPolicy {
    AgentAccessPolicy { dm: dm.into(), group_inviters: "owner".into(), allowed_humans: Vec::new() }
}

/// The stored record of `agent` on the root of `client`.
fn stored(client: &RamfluxClient, agent: &str) -> TestResult<StoredAgentRecord> {
    client.agent_record_store()?.load(agent)?.ok_or_else(|| "test: the replica is missing".into())
}

/// Runs one routing scenario on its own current-thread runtime (the fixtures are built outside it).
fn on_runtime(scenario: impl std::future::Future<Output = TestResult>) -> TestResult {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(scenario)
}

#[test]
fn agent_record_metadata_sync_edits_reach_the_other_root_in_order() -> TestResult {
    let mut pair: Pair = pair("metadata-order")?;
    let router = OwnRouter::new()?;
    let agent = encode_base64url([8_u8; 32]);
    let at = now()?;
    let author = pair.laptop.client.own_device_ref()?;
    let seeded = seed_for_test(&pair.laptop.client.agent_record_store()?, &agent, &author, at)?;
    on_runtime(async {
        // The desktop changes the persona; the phone has no record yet and creates it from the packet.
        let first = pair.laptop.client.agent_persona_edit(
            &agent,
            &seeded.identity,
            persona("second"),
            Some(true),
            at,
        )?;
        router.route(&mut pair.laptop, &mut pair.phone, 1).await?;
        assert_eq!(stored(&pair.phone.client, &agent)?.persona.name, "second");
        assert_eq!(stored(&pair.phone.client, &agent)?.identity, first.identity);

        // The desktop then changes the access; the phone applies the newer identity.
        let second = pair.laptop.client.agent_access_set(
            &agent,
            &first.identity,
            access("contacts"),
            Some(true),
            at,
        )?;
        router.route(&mut pair.laptop, &mut pair.phone, 2).await?;
        assert_eq!(stored(&pair.phone.client, &agent)?.access.dm, "contacts");

        // The phone edits from the identity it holds, and the desktop applies it.
        let phone_base = stored(&pair.phone.client, &agent)?.identity;
        assert_eq!(phone_base, second.identity, "both roots hold the same identity");
        let reply = pair.phone.client.agent_persona_edit(
            &agent,
            &phone_base,
            persona("third"),
            Some(true),
            at,
        )?;
        router.route(&mut pair.phone, &mut pair.laptop, 3).await?;
        assert_eq!(stored(&pair.laptop.client, &agent)?.persona.name, "third");
        assert_eq!(stored(&pair.laptop.client, &agent)?.identity, reply.identity);
        Ok(())
    })
}

#[test]
fn agent_record_metadata_sync_refuses_stale_bases_bad_policy_and_unconfirmed_edits() -> TestResult {
    let mut pair: Pair = pair("metadata-refusals")?;
    let router = OwnRouter::new()?;
    let agent = encode_base64url([9_u8; 32]);
    let at = now()?;
    let author = pair.laptop.client.own_device_ref()?;
    let seeded = seed_for_test(&pair.laptop.client.agent_record_store()?, &agent, &author, at)?;
    on_runtime(async {
        let edited = pair.laptop.client.agent_persona_edit(
            &agent,
            &seeded.identity,
            persona("current"),
            Some(true),
            at,
        )?;
        router.route(&mut pair.laptop, &mut pair.phone, 1).await?;

        // The old identity no longer matches the stored one.
        let stale = pair.laptop.client.agent_persona_edit(
            &agent,
            &seeded.identity,
            persona("stale"),
            Some(true),
            at,
        );
        assert!(matches!(stale, Err(SdkError::AgentCreationRefused("stale_base"))), "stale base");
        // A policy outside the closed shapes is refused and nothing is written.
        let invalid = pair.laptop.client.agent_access_set(
            &agent,
            &edited.identity,
            access("everyone"),
            Some(true),
            at,
        );
        assert!(
            matches!(invalid, Err(SdkError::AgentCreationRefused("access_policy_invalid"))),
            "invalid access"
        );
        // Without a confirmation nothing is written either.
        let unconfirmed = pair.laptop.client.agent_persona_edit(
            &agent,
            &edited.identity,
            persona("unconfirmed"),
            None,
            at,
        );
        assert!(
            matches!(unconfirmed, Err(SdkError::AgentCreationRefused("confirmation_required"))),
            "unconfirmed"
        );
        assert_eq!(stored(&pair.laptop.client, &agent)?.persona.name, "current");
        assert_eq!(stored(&pair.phone.client, &agent)?.persona.name, "current");
        Ok(())
    })
}

#[test]
fn agent_record_metadata_sync_retirement_is_final_on_both_roots() -> TestResult {
    let mut pair: Pair = pair("metadata-retire")?;
    let router = OwnRouter::new()?;
    let agent = encode_base64url([10_u8; 32]);
    let at = now()?;
    let author = pair.laptop.client.own_device_ref()?;
    let seeded = seed_for_test(&pair.laptop.client.agent_record_store()?, &agent, &author, at)?;
    on_runtime(async {
        let edited = pair.laptop.client.agent_persona_edit(
            &agent,
            &seeded.identity,
            persona("before retirement"),
            Some(true),
            at,
        )?;
        router.route(&mut pair.laptop, &mut pair.phone, 1).await?;
        let older = metadata_of(&edited);

        let retired = pair.laptop.client.agent_retire(&agent, &edited.identity, Some(true), at)?;
        assert_eq!(retired.lifecycle, "X", "the desktop retires the identity");
        router.route(&mut pair.laptop, &mut pair.phone, 2).await?;
        assert_eq!(stored(&pair.phone.client, &agent)?.lifecycle, "X", "the phone retires too");

        // A replayed older packet does not resurrect the identity.
        let replayed = pair.phone.client.receive_agent_metadata(&older)?;
        assert!(!replayed, "an older packet is ignored");
        assert_eq!(stored(&pair.phone.client, &agent)?.lifecycle, "X", "still retired");
        // A retired record refuses every later edit.
        let edit = pair.phone.client.agent_persona_edit(
            &agent,
            &retired.identity,
            persona("after"),
            Some(true),
            at,
        );
        assert!(matches!(edit, Err(SdkError::AgentCreationRefused("agent_retired"))), "retired");
        Ok(())
    })
}

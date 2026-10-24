// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Foreign updates are refused before the local producer can build a hashless delta carrier.
use super::*;
use crate::bus::runtime_tests;
use crate::client::surface::SurfaceSender;
use ramflux_protocol::{A2uiConversationCommand as C, CreateSurfaceCommand, SurfaceType};
use std::sync::{Arc, atomic::AtomicBool};
#[test]
fn non_author_send_is_typed_before_delta_hash_construction()
-> Result<(), Box<dyn std::error::Error>> {
    let root = runtime_tests::root("surface-author-preflight");
    let author = runtime_tests::account(
        &root.join("author"),
        "author",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let reader = runtime_tests::account(
        &root.join("reader"),
        "reader",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let create = crate::SurfaceSendRequest::event(
        "thread",
        1,
        &C::CreateSurface(CreateSurfaceCommand {
            surface_id: "surface".into(),
            surface_type: SurfaceType::StatusPanel,
            catalog: "basic".into(),
            catalog_version: "1".into(),
            fallback_text: "safe".into(),
            fallback_markdown: None,
            components: vec![json!({"id":"result","text":""})],
            data_model: serde_json::Map::default(),
            allowed_actions: Vec::new(),
        }),
    )?;
    let body: Send = serde_json::from_value(serde_json::to_value(&create)?)?;
    let raw = ramflux_protocol::decode_base64url(&create.wire_base64)?;
    let carrier = prepare_carrier(&author.client, &body, PayloadKind::Event, &raw, "surface")?;
    reader.client.persist_root_verified_directory(
        &crate::client::identity_authority::test_support::public_manifest(&author.client)?,
    )?;
    reader.client.account_db()?.persist_client_record(
        "conversation",
        "thread",
        &json!({"kind":"direct","participants":["reader","author"]}),
    )?;
    let outcome = reader
        .client
        .project_surface_message(
            "thread",
            "create",
            SurfaceSender {
                principal: "author",
                device: "device-author",
                envelope_id: "create",
                expires_at: None,
                group_epoch: None,
            },
            &carrier.bytes()?,
            false,
        )?
        .ok_or("projection")?;
    assert!(outcome.accepted);
    let before = reader.client.surface_get("surface", 0, None)?;
    let update = crate::SurfaceSendRequest::event(
        "thread",
        2,
        &C::DeleteSurface(ramflux_protocol::DeleteSurfaceCommand {
            surface_id: "surface".into(),
            reason: None,
        }),
    )?;
    let body: Send = serde_json::from_value(serde_json::to_value(&update)?)?;
    let raw = ramflux_protocol::decode_base64url(&update.wire_base64)?;
    let error = prepare_carrier(&reader.client, &body, PayloadKind::Event, &raw, "surface")
        .err()
        .ok_or("foreign carrier produced")?;
    assert_eq!(crate::bus::io::local_bus_error_body(&error).code, "not_author");
    assert_eq!(reader.client.surface_get("surface", 0, None)?, before);
    assert_eq!(reader.client.account_db()?.actor_state_usage("own-device/send/")?.0, 0);
    drop(reader);
    drop(author);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn group_roster_without_seed_refuses_surface_in_the_unreceived_conversation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = runtime_tests::root("surface-group-before-seed");
    let owner = runtime_tests::account(
        &root.join("owner"),
        "owner",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let agent = runtime_tests::account(
        &root.join("agent"),
        "agent",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    owner.client.create_group("group", "device-owner")?;
    owner.client.persist_root_verified_directory(
        &crate::client::identity_authority::test_support::public_manifest(&agent.client)?,
    )?;
    owner.client.add_group_member(
        "group",
        agent.client.owned_device_identity()?.storage_key(),
        "member",
    )?;
    let join = owner.client.create_signed_group_member_join_event(
        "group",
        "device-owner",
        "device-agent",
        "member",
        &owner.client.surface_local_root_commitment()?,
    )?;
    agent.client.persist_root_verified_directory(
        &crate::client::identity_authority::test_support::public_manifest(&owner.client)?,
    )?;
    let branch = owner.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    agent.client.apply_bootstrap_group_member_join_event(
        &join,
        "device-owner",
        &ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes()),
    )?;
    assert_eq!(agent.client.group_state("group")?.members.len(), 2);
    assert!(
        agent.client.account_db()?.client_record("conversation", "group_thread_k2b")?.is_none()
    );
    let mut state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.join("bus.sock"), root.join("agent")),
        accounts: BTreeMap::from([("agent".into(), agent)]),
        active_account_id: Some("agent".into()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let event = crate::SurfaceSendRequest::event(
        "group_thread_k2b",
        1,
        &C::CreateSurface(CreateSurfaceCommand {
            surface_id: "surface-group".into(),
            surface_type: SurfaceType::StatusPanel,
            catalog: "basic".into(),
            catalog_version: "1".into(),
            fallback_text: "Working".into(),
            fallback_markdown: None,
            components: vec![json!({"id":"result","text":""})],
            data_model: serde_json::Map::default(),
            allowed_actions: Vec::new(),
        }),
    )?;
    let request = LocalBusFrame::request(
        "surface-create",
        Some("agent".into()),
        "surface",
        "surface.send",
        serde_json::to_value(event)?,
    );
    let error = dispatch_surface_inner(&request, &mut state)
        .await
        .err()
        .ok_or("surface was authored before its conversation arrived")?;
    assert!(error.to_string().contains("surface requires an existing conversation"), "{error}");
    eprintln!(
        "native fixture reproduction: account=agent conversation=group_thread_k2b roster=2 error={error}"
    );
    assert_eq!(state.accounts["agent"].client.surface_get("surface-group", 0, None)?, Value::Null);
    drop(state);
    drop(owner);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

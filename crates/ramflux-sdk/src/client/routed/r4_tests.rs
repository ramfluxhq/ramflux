// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! State ordering, sender namespace and confirmed-session recovery regressions.
use super::review::{Inbox, pool, trust};
use super::*;

fn bootstrap(
    sender: &Fixture,
    receiver: &Fixture,
    id: &str,
) -> Result<GatewayInboxEntry, SdkError> {
    super::r5::fresh(sender, receiver, id)
}

#[tokio::test]
async fn simultaneous_verified_bootstraps_converge_and_retire_x3dh_after_peer_confirmation()
-> Result<(), SdkError> {
    let mut alice = Fixture::native("alice", 41).await?;
    let mut bob = Fixture::native("bob", 61).await?;
    alice.client.establish_friend_link(
        "friend",
        &alice.client.own_account_anchor()?,
        &bob.client.own_account_anchor()?,
    )?;
    bob.client.establish_friend_link(
        "friend",
        &bob.client.own_account_anchor()?,
        &alice.client.own_account_anchor()?,
    )?;
    let a = bootstrap(&alice, &bob, "alice-initial")?;
    let b = bootstrap(&bob, &alice, "bob-initial")?;
    let mut ae = GatewaySessionEngine::with_test_transport(alice.config()?, Box::new(NoNetwork));
    let mut be = GatewaySessionEngine::with_test_transport(bob.config()?, Box::new(NoNetwork));
    alice.client.apply_routed_entry(&mut ae, &pool()?, &b).await?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &a).await?;
    let active_a = alice
        .client
        .active_pair(
            &alice.client.local_device_identity("alice")?,
            &alice.client.device_identity(&fixture_peer_reference(&alice.client, "bob")?)?,
        )?
        .ok_or_else(|| invalid("pair"))?
        .0
        .session_id;
    let active_b = bob
        .client
        .active_pair(
            &bob.client.local_device_identity("bob")?,
            &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
        )?
        .ok_or_else(|| invalid("pair"))?
        .0
        .session_id;
    assert_eq!(active_a, active_b);
    let reply = super::r5::seal(
        &alice,
        &bob,
        super::r5::native_outgoing(&alice, &bob, "reply-a")?,
        b"reply",
    )?;
    bob.client.apply_routed_entry(&mut be, &pool()?, &reply).await?;
    let reply = super::r5::seal(
        &bob,
        &alice,
        super::r5::native_outgoing(&bob, &alice, "reply-b")?,
        b"reply",
    )?;
    alice.client.apply_routed_entry(&mut ae, &pool()?, &reply).await?;
    let next = super::r5::seal(
        &alice,
        &bob,
        super::r5::native_outgoing(&alice, &bob, "confirmed")?,
        b"next",
    )?;
    assert!(decode(&next.envelope)?.x3dh.is_none());
    assert!(decode(&next.envelope)?.ciphertext.ratchet_public_key.is_some());
    bob.client.apply_routed_entry(&mut be, &pool()?, &next).await?;
    let (_, _, _) = bob.client.send_pair_session_from_url(
        &bob.client.local_device_identity("bob")?,
        &super::r5::native_outgoing(&bob, &alice, "next")?,
        None,
    )?;
    let snapshot = serde_json::to_value(
        bob.client
            .active_pair(
                &bob.client.local_device_identity("bob")?,
                &bob.client.device_identity(&fixture_peer_reference(&bob.client, "alice")?)?,
            )?
            .ok_or_else(|| invalid("pair"))?
            .0
            .snapshot(),
    )?;
    assert!(snapshot["dh_ratchet_step"].as_u64().is_some_and(|step| step > 0));
    Ok(())
}

#[tokio::test]
async fn legacy_a2i_refusal_has_no_ack_or_persistent_effects_across_reopen() -> Result<(), SdkError>
{
    let alice = Fixture::native_named("alice", 41).await?;
    let mut bob = Fixture::native_named("bob", 61).await?;
    trust(&bob, &alice)?;
    let entry = generated_delivery(&alice, &bob, "closed-a2i", "supported Message")?.entry;
    let (mut engine, writes) = Inbox::engine(bob.config()?, vec![entry])?;
    bob.client.account_db()?.install_receive_ledger_schema()?;
    let before = bob.client.account_db()?.durable_rows_for_test()?;
    assert!(bob.client.receive_a2i_control_events(&mut engine, 16).await.is_ok());
    assert!(
        bob.client.account_db()?.durable_rows_for_test()? == before,
        "closed API changed durable state"
    );
    bob.client.active_account_db = None;
    bob.client.unlock_account("bob", b"native fixture data passphrase")?;
    let reopened = bob.client.account_db()?.durable_rows_for_test()?;
    assert!(bob.client.receive_a2i_control_events(&mut engine, 16).await.is_ok());
    assert!(
        bob.client.account_db()?.durable_rows_for_test()? == reopened,
        "closed API changed reopened state"
    );
    assert_eq!(bob.client.account_db()?.list_actor_states::<A2iControlEvent>("a2i/")?.len(), 0);
    assert_eq!(writes.lock().map_err(|_| invalid("mutex"))?.len(), 0);
    assert_eq!(bob.client.gateway_receive_cursor(&engine.config.target_delivery_id)?, 0);
    Ok(())
}

#[tokio::test]
async fn retained_a2i_rows_cannot_be_exposed_or_acknowledged_after_reopen() -> Result<(), SdkError>
{
    let alice = Fixture::new("alice", 41)?;
    let mut bob = Fixture::new("bob", 61)?;
    trust(&bob, &alice)?;
    let root = alice.client.surface_local_root_commitment()?;
    let source = bob.client.device_identity_for_root(&root, "alice")?;
    let retained = A2iControlEvent {
        source_principal_id: Some("alice".into()),
        source_principal_commitment: Some(root),
        event_id: "ack-event".into(),
        event_type: "a2i.control".into(),
        source_device_id: "alice".into(),
        target_device_id: "bob".into(),
        control_domain: "message".into(),
        action: "test".into(),
        subject_base64: String::new(),
        created_at: 1,
        acknowledged: false,
    };
    let key = crate::client::routed::control::a2i_key(&source, &retained.event_id)?;
    bob.client.account_db()?.persist_actor_state(&key, &retained)?;
    for method in ["a2i.list", "a2i.list_pending"] {
        let request = LocalBusFrame::request("cached", None, "a2i", method, serde_json::json!({}));
        let listed =
            crate::bus::test_account_reader_request(bob.client.account_db()?, request).await?;
        assert_eq!(listed["events"].as_array().map(Vec::len), Some(1));
        assert_eq!(listed["events"][0]["acknowledged"], false);
    }
    let config = bob.config()?;
    let own_root = bob.client.surface_local_root_commitment()?;
    let mut account = crate::bus::state::LocalBusAccountState::disconnected(
        std::mem::take(&mut bob.client),
        config,
        own_root,
    );
    account.pending_a2i.insert(key, retained);
    let mut state = crate::bus::state::LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(bob.root.join("bus.sock"), &bob.root),
        accounts: BTreeMap::from([("bob".to_owned(), account)]),
        active_account_id: Some("bob".to_owned()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let ack = LocalBusFrame::request(
        "ack",
        Some("bob".into()),
        "a2i",
        "a2i.acknowledge",
        serde_json::json!({"event_id":"ack-event"}),
    );
    let acked = crate::bus::dispatch::a2i::dispatch_a2i_bus_request(&ack, &mut state).await?;
    assert_eq!(acked.response_body["acknowledged"], true);
    {
        let account = state.accounts.get("bob").ok_or_else(|| invalid("account"))?;
        assert!(account.pending_a2i.values().any(|row| row.acknowledged));
        assert_eq!(
            account.client.a2i_events_json(true)?["events"].as_array().map(Vec::len),
            Some(0)
        );
    }
    let append = LocalBusFrame::request(
        "append",
        Some("bob".into()),
        "a2i",
        "a2i.append",
        serde_json::json!({"event_id":"ack-event"}),
    );
    assert!(
        crate::bus::dispatch::a2i::dispatch_a2i_bus_request(&append, &mut state).await.is_err()
    );
    let account = state.accounts.get("bob").ok_or_else(|| invalid("account"))?;
    let stored = account.client.account_db()?.list_actor_states::<A2iControlEvent>("a2i/")?;
    assert_eq!(stored.len(), 1);
    assert!(stored[0].acknowledged);
    Ok(())
}

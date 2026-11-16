// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native authority runs the ordinary group invitation, sender-key and removal paths.
use crate::client::native_test_support::{Fixture, TestResult};
use ramflux_protocol::group_state::GroupStateChange;
#[tokio::test(flavor = "current_thread")]
async fn native_group_admission_message_replay_and_removal_use_real_authority() -> TestResult {
    crate::client::native_test_support::watchdog::within(async {
        use ramflux_protocol::message as g;
        let alice = Fixture::with_device("native-group-owner", "owner-device").await?;
        let mut bob = Fixture::with_device("native-group-member", "member-device").await?;
        alice.accept_peer(&bob)?;
        bob.accept_peer(&alice)?;
        let owner = alice.client.owned_device_identity()?;
        let member = bob.client.owned_device_identity()?;
        let primary = alice
            .client
            .born_v3_account
            .as_ref()
            .ok_or("native account")?
            .group_primary(alice.vault.as_ref())?;
        alice.client.shared_group_create_with_primary(
            "native-group",
            "native-group-thread",
            None,
            &alice.config.target_delivery_id,
            Some(&primary),
        )?;
        let state = alice.client.shared_group_change_with_primary(
            "native-group",
            &alice.config.target_delivery_id,
            GroupStateChange::Add {
                member: bob.client.owned_group_actor(&bob.config.target_delivery_id)?.identity,
                role: ramflux_protocol::SharedGroupRole::Member,
            },
            Some(&primary),
        )?;
        bob.client.accept_shared_group_state(&state, &bob.config.target_delivery_id)?;
        let snapshot = alice.client.shared_group_packet_for_recipient(&state, &member)?;
        let directory = crate::client::native_test_support::directory::Directory::new(vec![
            alice.manifest.clone(),
            bob.manifest.clone(),
        ])
        .await?;
        directory.configure(&mut bob);
        bob.receive(alice.seal_inner_to(&bob, &snapshot)?, 1).await?;
        assert!(directory.requests() > 0, "native snapshot must refresh actual issuer authority");
        let identity = alice.client.allocate_generated_identity(
            "native-group-thread",
            crate::client::generated_identity::now_ms(),
            false,
        )?;
        let logical = ramflux_protocol::encode_base64url(&identity.id);
        let exact = alice.client.encrypt_generated_group_inner(
            "native-group",
            owner.device_id(),
            identity,
            &g::Message { text: "native group message".into(), ..Default::default() },
        )?;
        let envelope = alice.seal_inner_to(&bob, &exact)?;
        bob.receive(envelope.clone(), 2).await?;
        bob.receive(envelope, 2).await?;
        assert_eq!(
            bob.client.account_db()?.message_content(&logical)?,
            Some(exact),
            "actual native group receive must retain the authenticated sealed Inner"
        );
        assert_one_decrypted_group_message(&bob.client)?;
        assert_generated_history(&bob.client)?;
        let removed = alice.client.shared_group_change_with_primary(
            "native-group",
            &alice.config.target_delivery_id,
            GroupStateChange::Remove {
                root_commitment: member.root_commitment().into(),
                device_id: member.device_id().into(),
            },
            Some(&primary),
        )?;
        bob.client.accept_shared_group_state(&removed, &bob.config.target_delivery_id)?;
        assert!(
            removed.view().effective_role(member.root_commitment(), member.device_id()).is_none(),
            "the native removal must retire the member"
        );
        assert_removed_sender(&alice, &bob)?;
        Ok(())
    })
    .await?
}

fn assert_removed_sender(alice: &Fixture, bob: &Fixture) -> TestResult {
    use ramflux_protocol::message as g;
    let member = bob.client.owned_device_identity()?;
    let denied = bob.client.allocate_generated_identity(
        "native-group-thread",
        crate::client::generated_identity::now_ms(),
        false,
    )?;
    assert!(
        bob.client
            .encrypt_generated_group_inner(
                "native-group",
                member.device_id(),
                denied,
                &g::Message { text: "removed sender".into(), ..Default::default() }
            )
            .is_err(),
        "a removed native member cannot produce a new group message"
    );
    assert!(
        alice.client.identity_root.is_none() && bob.client.identity_root.is_none(),
        "this integration must use native custody rather than legacy root authority"
    );
    Ok(())
}

#[tokio::test]
async fn native_shared_group_create_add_rename_and_remove_use_custody_authority() -> TestResult {
    let alice = Fixture::with_device("native-shared-owner", "owner-device").await?;
    let bob = Fixture::with_device("native-shared-member", "member-device").await?;
    alice.client.persist_fetched_identity_directory(&bob.manifest)?;
    bob.client.persist_fetched_identity_directory(&alice.manifest)?;
    let owner = alice.client.owned_device_identity()?;
    let member = bob.client.owned_device_identity()?;
    let primary = alice
        .client
        .born_v3_account
        .as_deref()
        .ok_or("native owner")?
        .group_primary(alice.vault.as_ref())?;
    let initial = alice.client.shared_group_create_with_primary(
        "native-shared-group",
        "native-shared-thread",
        Some("Native group".into()),
        owner.storage_key(),
        Some(&primary),
    )?;
    assert_eq!(initial.creator().identity.root_commitment, owner.root_commitment());
    assert!(initial.creator().native_authority.is_some());
    assert!(alice.client.identity_root.is_none());
    let member_identity = bob.client.owned_group_actor(member.storage_key())?.identity;
    let added = alice.client.shared_group_change_with_primary(
        "native-shared-group",
        owner.storage_key(),
        GroupStateChange::Add {
            member: member_identity,
            role: ramflux_protocol::group_state::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    assert!(added.view().effective_role(member.root_commitment(), member.device_id()).is_some());
    let renamed = alice.client.shared_group_change_with_primary(
        "native-shared-group",
        owner.storage_key(),
        GroupStateChange::SetName { name: "Renamed native group".into() },
        Some(&primary),
    )?;
    assert_eq!(renamed.view().name.as_deref(), Some("Renamed native group"));
    let removed = alice.client.shared_group_change_with_primary(
        "native-shared-group",
        owner.storage_key(),
        GroupStateChange::Remove {
            root_commitment: member.root_commitment().into(),
            device_id: member.device_id().into(),
        },
        Some(&primary),
    )?;
    assert!(removed.view().effective_role(member.root_commitment(), member.device_id()).is_none());
    assert!(alice.client.identity_root.is_none());
    Ok(())
}

fn assert_one_decrypted_group_message(client: &crate::RamfluxClient) -> TestResult {
    use ramflux_protocol::message as g;
    let page = client.generated_message_page("native-group-thread", None, 10)?;
    let chats: Vec<_> = page
        .messages
        .iter()
        .filter(|row| {
            !matches!(
                row.state.as_ref(),
                Some(g::message_update::State::Content(content))
                    if matches!(content.value.as_ref(), Some(g::content::Value::Service(_)))
            )
        })
        .collect();
    assert_eq!(chats.len(), 1, "group replay must not duplicate the durable projection");
    let Some(g::message_update::State::Content(content)) =
        chats.first().and_then(|row| row.state.as_ref())
    else {
        return Err("test: decrypted group projection missing".into());
    };
    assert!(
        matches!(content.value.as_ref(), Some(g::content::Value::Message(value))
            if value.text == "native group message" && value.sealed_group.is_none()),
        "the native group reader must project the actual decrypted plaintext"
    );
    Ok(())
}

fn assert_generated_history(client: &crate::RamfluxClient) -> TestResult {
    let frame = crate::LocalBusFrame::request(
        "history",
        None,
        "group",
        "group.history",
        serde_json::json!({"group_id":"native-group", "conversation_id":"native-group-thread", "limit":10}),
    );
    let before = client.account_db()?.journal_bounds()?.head_seq;
    let body = crate::bus::dispatch::group::history::read(client, &frame)?;
    let rows = body["messages"].as_array().ok_or("native group history rows")?;
    let chats: Vec<_> = rows.iter().filter(|row| row["kind"] != "service").collect();
    let [row] = chats.as_slice() else {
        return Err("native group history must contain one received message".into());
    };
    assert_eq!(
        row["text"], "native group message",
        "group.history must render actual decrypted typed content"
    );
    assert!(
        body.get("decrypted_messages").is_none(),
        "group.history must not expose the retired raw plaintext projection"
    );
    let encoded = serde_json::to_string(&body)?;
    assert!(
        !encoded.contains("erasureNonce") && !encoded.contains("sealedGroup"),
        "the public group reader must not expose private revision entropy or group ciphertext"
    );
    assert_eq!(
        client.account_db()?.journal_bounds()?.head_seq,
        before,
        "stored group history must perform no receive or authority writes"
    );
    Ok(())
}

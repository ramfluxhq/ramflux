// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Provisional contact recovery, stronger pin protection, and metadata preservation.
use super::cards::Origin;
use super::*;
fn client(s: &LocalBusDaemonState) -> Result<&RamfluxClient, SdkError> {
    Ok(&s.accounts.get("alice").ok_or_else(|| invalid("alice"))?.client)
}
async fn card(s: &mut LocalBusDaemonState) -> Result<String, SdkError> {
    call(s, "bob", "contact.card.export", json!({})).await?["card"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("card"))
}
async fn lying_lookup()
-> Result<(Fixture, Fixture, Fixture, Directory, Origin, LocalBusDaemonState, String), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let fake = Fixture::new("bob", 71)?;
    let d = Directory::new(&a, &b).await?;
    let real = super::super::r9::manifest(&b)?;
    d.records.lock().map_err(|_| invalid("mutex"))?[1] = super::super::r9::manifest(&fake)?;
    d.records.lock().map_err(|_| invalid("mutex"))?.push(real);
    let origin = Origin::new(&d).await?;
    let mut s = state(&mut a, &mut b, &d)?;
    origin.configure(&mut s, "alice")?;
    origin.configure(&mut s, "bob")?;
    let added = call(&mut s, "alice", "contact.add", json!({"principal_id":"bob"})).await?;
    assert_eq!(added["contact"]["root_source"], "lookup");
    let old =
        added["contact"]["root_commitment"].as_str().ok_or_else(|| invalid("root"))?.to_owned();
    Ok((a, b, fake, d, origin, s, old))
}
#[tokio::test]
async fn genuine_card_replaces_a_lying_lookup_only_after_confirmation_and_retires_the_old_session()
-> Result<(), SdkError> {
    let (mut a, mut b, fake, _d, _origin, mut s, old) = lying_lookup().await?;
    a.client =
        std::mem::take(&mut s.accounts.get_mut("alice").ok_or_else(|| invalid("account"))?.client);
    let local = a.client.owned_device_identity()?;
    let fake_identity = fake.client.owned_device_identity()?;
    seal(&a, &fake, message("old-session", "thread"), b"old")?;
    assert!(a.client.active_pair(&local, &fake_identity)?.is_some());
    s.accounts.get_mut("alice").ok_or_else(|| invalid("account"))?.client =
        std::mem::take(&mut a.client);
    let signed = card(&mut s).await?;
    let proposed = call(&mut s, "alice", "contact.add", json!({"card":signed}))
        .await
        .err()
        .ok_or_else(|| invalid("missing confirmation"))?;
    let error = crate::bus::io::local_bus_error_body(&proposed);
    assert_eq!(error.reason_code.as_deref(), Some("root_replacement_confirmation_required"));
    let details = error.details.ok_or_else(|| invalid("missing comparison"))?;
    assert_eq!(details["previous_root_commitment"], old);
    let real = s.accounts.get("bob").ok_or_else(|| invalid("bob"))?.principal_commitment.clone();
    assert_eq!(details["proposed_root_commitment"], real);
    assert_eq!(client(&s)?.contact_entry("bob")?["root_commitment"], old);
    assert!(client(&s)?.active_pair(&local, &fake_identity)?.is_some());
    let stale = call(
        &mut s,
        "alice",
        "contact.add",
        json!({"card":signed,"replace_provisional_root":"different-old-root"}),
    )
    .await
    .err()
    .ok_or_else(|| invalid("stale confirmation accepted"))?;
    assert!(matches!(stale, SdkError::ContactInput(crate::ContactReason::RootConflict)));
    let fixed =
        call(&mut s, "alice", "contact.add", json!({"card":signed,"replace_provisional_root":old}))
            .await?;
    assert_eq!(fixed["contact"]["root_commitment"], real);
    assert_eq!(fixed["contact"]["root_source"], "card");
    assert_eq!(fixed["contact"]["reachable"], true);
    assert_eq!(fixed["contact"]["verified"], false);
    assert!(client(&s)?.active_pair(&local, &fake_identity)?.is_none());
    let db = client(&s)?.account_db()?;
    assert!(db.client_record("commitment", &old)?.is_none());
    assert_eq!(
        db.device_directory_entry("bob")?.ok_or_else(|| invalid("directory"))?.principal_commitment,
        real
    );
    assert!(db.journal_after(0,256)?.iter().any(|e|e.topic=="safety.changed" && e.body["reason"]=="provisional_root_replaced"));
    a.client =
        std::mem::take(&mut s.accounts.get_mut("alice").ok_or_else(|| invalid("alice"))?.client);
    b.client = std::mem::take(&mut s.accounts.get_mut("bob").ok_or_else(|| invalid("bob"))?.client);
    let first = seal(&a, &b, message("genuine-first", "thread"), b"to the real bob")?;
    assert_eq!(b.client.open_routed(&first, "bob")?.body.as_slice(), b"to the real bob");
    a.client.active_account_db.take();
    a.client.unlock_account("alice", b"routed-test")?;
    assert_eq!(a.client.contact_entry("bob")?["root_source"], "card");
    assert_eq!(a.client.contact_entry("bob")?["root_commitment"], real);
    Ok(())
}
#[tokio::test]
async fn out_of_band_safety_preview_is_non_mutating_and_confirmation_promotes_the_genuine_root()
-> Result<(), SdkError> {
    let (_a, _b, _fake, _d, _origin, mut s, old) = lying_lookup().await?;
    let root = s.accounts.get("bob").ok_or_else(|| invalid("bob"))?.principal_commitment.clone();
    let body = json!({"principal_id":"bob","contact_identity_commitment":root});
    let preview = call(&mut s, "alice", "contact.safety_number", body.clone()).await?;
    assert_eq!(preview["safety_number"].as_array().map(Vec::len), Some(12));
    assert_eq!(client(&s)?.contact_entry("bob")?["root_commitment"], old);
    assert!(matches!(
        call(&mut s, "alice", "contact.verify", body).await,
        Err(SdkError::ContactConfirmationRequired(_))
    ));
    let verified=call(&mut s,"alice","contact.verify",json!({"principal_id":"bob","contact_identity_commitment":root,"replace_provisional_root":old})).await?;
    assert_eq!(verified["safety_number"], preview["safety_number"]);
    let set = client(&s)?.observed_device_set(&root)?.ok_or_else(|| invalid("verified set"))?;
    assert_eq!(
        client(&s)?
            .account_db()?
            .load_actor_state::<String>(&format!("identity/safety_verified_set/{root}"))?,
        Some(crate::client::identity_authority::set_fingerprint(&set)?),
        "confirmed contact resolution persists the authority stamp"
    );
    assert_eq!(client(&s)?.contact_entry("bob")?["root_source"], "verified");
    assert_eq!(
        client(&s)?
            .account_db()?
            .client_record("identity", "bob")?
            .ok_or_else(|| invalid("identity"))?["root_source"],
        "verified"
    );
    assert_eq!(client(&s)?.contact_entry("bob")?["verified"], true);
    assert_eq!(client(&s)?.contact_entry("bob")?["root_commitment"], root);
    let db = client(&s)?.account_db()?;
    let record = db.contact_verification(&root)?.ok_or_else(|| invalid("verification"))?;
    db.observe_contact_key_state(ramflux_storage::ContactKeyObservation {
        contact_identity_commitment: &root,
        safety_number_hash: "changed",
        device_set_hash: &record.verified_device_set_hash,
        lineage_head: &record.verified_lineage_head,
        change_event_id: "changed-root",
        seen_at: now_unix_timestamp(),
    })?;
    let identity = db.client_record("identity", "bob")?.ok_or_else(|| invalid("identity"))?;
    assert_eq!(identity["root_source"], "verified");
    assert!(
        client(&s)?.contact_replacement(&identity, "bob", "different-root", Some(&root)).is_err()
    );
    Ok(())
}
#[tokio::test]
async fn card_and_manually_verified_roots_refuse_replacement_even_with_confirmation()
-> Result<(), SdkError> {
    for verified in [false, true] {
        let (_a, _b, _fake, _d, _origin, mut s, old) = lying_lookup().await?;
        if verified {
            call(&mut s, "alice", "contact.verify", json!({"contact_identity_commitment":old}))
                .await?;
        } else {
            let db = client(&s)?.account_db()?;
            let mut identity =
                db.client_record("identity", "bob")?.ok_or_else(|| invalid("identity"))?;
            identity["root_source"] = json!("card");
            db.persist_client_record("identity", "bob", &identity)?;
        }
        let signed = card(&mut s).await?;
        let err = call(
            &mut s,
            "alice",
            "contact.add",
            json!({"card":signed,"replace_provisional_root":old}),
        )
        .await
        .err()
        .ok_or_else(|| invalid("strong pin replaced"))?;
        assert!(matches!(err, SdkError::ContactInput(crate::ContactReason::RootConflict)));
        assert_eq!(client(&s)?.contact_entry("bob")?["root_commitment"], old);
    }
    Ok(())
}
#[tokio::test]
async fn a_card_preserves_existing_local_display_and_kind_even_when_signed_fields_are_null()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let d = Directory::new(&a, &b).await?;
    let origin = Origin::new(&d).await?;
    let mut s = state(&mut a, &mut b, &d)?;
    origin.configure(&mut s, "alice")?;
    origin.configure(&mut s, "bob")?;
    client(&s)?.account_db()?.persist_client_record(
        "identity",
        "bob",
        &json!({"display_name":"My own label","kind_asserted":"human"}),
    )?;
    let signed = card(&mut s).await?;
    let body = crate::parse_contact_card(&signed, now_unix_timestamp())?;
    assert!(body.display_name.is_none());
    assert!(body.kind_asserted.is_none());
    let added = call(&mut s, "alice", "contact.add", json!({"card":signed})).await?;
    assert_eq!(added["contact"]["display_name"], "My own label");
    assert_eq!(added["contact"]["kind_asserted"], "human");
    Ok(())
}

#[tokio::test]
async fn a_rejected_contact_resolution_keeps_the_group_key_change_observation()
-> Result<(), SdkError> {
    let (_a, _b, fake, _d, _origin, mut s, _old) = lying_lookup().await?;
    let original = super::super::r9::manifest(&fake)?;
    client(&s)?.create_group("pinned", "alice")?;
    client(&s)?.add_group_member(
        "pinned",
        fake.client.owned_device_identity()?.storage_key(),
        "member",
    )?;
    let db = client(&s)?.account_db()?;
    db.persist_group_member_device_key(
        "pinned",
        &RamfluxClient::device_identity_from_manifest(&original, "bob")?,
        &original.devices[0].branch_public_key,
    )?;
    db.bind_group_member_key_identity(
        "pinned",
        &RamfluxClient::device_identity_from_manifest(&original, "bob")?,
        "bob",
        &original.principal_commitment,
        &original.devices[0].branch_public_key,
    )?;
    let link = client(&s)?.friend_links()?[0].link_id.clone();
    client(&s)?.remove_friend_link(&link, "both")?;
    let signed = card(&mut s).await?;
    assert!(call(&mut s, "alice", "contact.add", json!({"card":signed})).await.is_err());
    let db = client(&s)?.account_db()?;
    let group = db.client_record("group", "pinned")?.ok_or_else(|| invalid("group"))?;
    assert_eq!(group["safety_change"]["reason"], "pinned_group_member_key_changed");
    assert!(db.journal_after(0, 128)?.iter().any(|e| e.topic == "safety.changed"));
    assert!(client(&s)?.friend_links()?.iter().all(|link| link.state != "accepted"));
    assert_eq!(
        db.client_record("device", "bob")?.ok_or_else(|| invalid("device"))?["signing_public_key"],
        original.devices[0].branch_public_key
    );
    Ok(())
}
#[tokio::test]
async fn principal_add_and_accept_use_the_same_link_id_for_both_sides() -> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let d = Directory::new(&a, &b).await?;
    let mut s = state(&mut a, &mut b, &d)?;
    call(&mut s, "alice", "contact.add", json!({"principal_id":"bob"})).await?;
    call(&mut s, "bob", "contact.accept", json!({"principal_id":"alice"})).await?;
    let alice = client(&s)?.friend_links()?;
    let bob = s.accounts.get("bob").ok_or_else(|| invalid("bob"))?.client.friend_links()?;
    assert_eq!(alice.len(), 1);
    assert_eq!(bob.len(), 1);
    assert_eq!(alice[0].link_id, bob[0].link_id);
    assert_eq!(alice[0].requester_id, bob[0].requester_id);
    assert_eq!(alice[0].target_id, bob[0].target_id);
    Ok(())
}
#[tokio::test]
async fn legacy_friend_requests_bind_participants_to_the_authenticated_sender_before_accept()
-> Result<(), SdkError> {
    for forged in [true, false] {
        let a = Fixture::new("alice", 21)?;
        let mut b = Fixture::new("bob", 31)?;
        super::super::review::trust(&b, &a)?;
        b.client.establish_friend_link("prior-friend", "alice", "bob")?;
        let mut message = message("legacy-control", "history");
        let bundle = b.client.load_x3dh_private_state(&b.client.owned_device_identity()?)?.bundle;
        let (mut session, header) =
            a.client.create_send_dm_session_from_bundle(&message, "bob", bundle, "alice")?;
        let body = serde_json::to_vec(
            &json!({"type":"friend.requested","link_id":"incoming-request","requester":if forged{"carol"}else{"alice"},"target":"bob"}),
        )?;
        let ciphertext = session.encrypt(&body, dm_associated_data("history"))?;
        message.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
            source_principal_commitment: Some(
                a.client.owned_device_identity()?.root_commitment().into(),
            ),
            schema: "ramflux.sdk.dm_x3dh_envelope.v1".into(),
            version: 1,
            x3dh: header.clone(),
            ciphertext,
        })?;
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: "bob".into(),
            envelope: gateway_direct_message_envelope(&a.config()?, &message, None)?,
        };
        let receiving = b.client.load_or_create_recv_dm_session("history", header.as_ref())?;
        b.client.send_direct_message("history", "old-history", "alice", b"prior bound thread")?;
        b.client.persist_dm_session("history", "old-history", "recv", &receiving)?;
        let mut engine =
            GatewaySessionEngine::with_test_transport(b.config()?, Box::new(NoNetwork));
        let result = b
            .client
            .receive_legacy_entry(
                &mut engine,
                &super::super::review::pool()?,
                entry,
                crate::client::dm::LegacyReceive {
                    conversation_id: "history",
                    auto_fetch_attachments: false,
                    relay_service_key_base64: None,
                },
            )
            .await;
        if forged {
            assert!(result?.is_none());
            assert_eq!(b.client.gateway_receive_cursor("bob")?, 1);
            valid_delivery_after_rejected_control(&a, &mut b, &mut engine, &mut session).await?;
            assert!(!b.client.friend_links()?.iter().any(|l| l.link_id == "incoming-request"));
        } else {
            result?;
            let link = b.client.account_db()?.friend_link("incoming-request")?;
            assert_eq!(link.requester_id, "alice");
            assert_eq!(link.state, "pending");
        }
    }
    Ok(())
}

#[tokio::test]
async fn invalid_directory_signatures_return_a_typed_manifest_error_without_a_contact()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let d = Directory::new(&a, &b).await?;
    d.records.lock().map_err(|_| invalid("mutex"))?[1].devices[0].branch_proof.signature =
        ramflux_protocol::encode_base64url([0; 64]);
    let mut s = state(&mut a, &mut b, &d)?;
    let error = call(&mut s, "alice", "contact.add", json!({"principal_id":"bob"}))
        .await
        .err()
        .ok_or_else(|| invalid("invalid manifest accepted"))?;
    let body = crate::bus::io::local_bus_error_body(&error);
    assert_eq!(body.code, "ValidationFailed");
    assert_eq!(body.reason_code.as_deref(), Some("manifest_invalid"));
    assert_eq!(client(&s)?.friend_links()?.len(), 0);
    assert!(client(&s)?.account_db()?.client_record("identity", "bob")?.is_none());
    Ok(())
}

async fn valid_delivery_after_rejected_control(
    a: &Fixture,
    b: &mut Fixture,
    engine: &mut GatewaySessionEngine,
    session: &mut ramflux_crypto::DmSession,
) -> Result<(), SdkError> {
    let mut next = super::super::message("legacy-next", "history");
    next.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
        source_principal_commitment: Some(
            a.client.owned_device_identity()?.root_commitment().into(),
        ),
        schema: "ramflux.sdk.dm_x3dh_envelope.v1".into(),
        version: 1,
        x3dh: None,
        ciphertext: session.encrypt(b"after rejected control", dm_associated_data("history"))?,
    })?;
    let next = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 2,
        target_delivery_id: "bob".into(),
        envelope: gateway_direct_message_envelope(&a.config()?, &next, None)?,
    };
    let delivered = b
        .client
        .receive_legacy_entry(
            engine,
            &super::super::review::pool()?,
            next,
            crate::client::dm::LegacyReceive {
                conversation_id: "history",
                auto_fetch_attachments: false,
                relay_service_key_base64: None,
            },
        )
        .await?;
    assert!(delivered.is_some());
    assert_eq!(b.client.gateway_receive_cursor("bob")?, 2);

    Ok(())
}

#[tokio::test]
async fn unknown_friend_removed_is_quarantined_and_the_next_legacy_message_arrives()
-> Result<(), SdkError> {
    let a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    super::super::review::trust(&b, &a)?;
    b.client.establish_friend_link("prior-friend", "alice", "bob")?;
    let mut message = message("legacy-control", "history");
    let bundle = b.client.load_x3dh_private_state(&b.client.owned_device_identity()?)?.bundle;
    let (mut session, header) =
        a.client.create_send_dm_session_from_bundle(&message, "bob", bundle, "alice")?;
    let body = serde_json::to_vec(
        &json!({"type":"friend.removed","link_id":"incoming-request","requester":"alice","target":"bob"}),
    )?;
    let ciphertext = session.encrypt(&body, dm_associated_data("history"))?;
    message.encrypted_body = serde_json::to_vec(&SdkDmEncryptedEnvelope {
        source_principal_commitment: Some(
            a.client.owned_device_identity()?.root_commitment().into(),
        ),
        schema: "ramflux.sdk.dm_x3dh_envelope.v1".into(),
        version: 1,
        x3dh: header.clone(),
        ciphertext,
    })?;
    let entry = GatewayInboxEntry {
        forwarded: false,
        inbox_seq: 1,
        target_delivery_id: "bob".into(),
        envelope: gateway_direct_message_envelope(&a.config()?, &message, None)?,
    };
    let receiving = b.client.load_or_create_recv_dm_session("history", header.as_ref())?;
    b.client.send_direct_message("history", "old-history", "alice", b"prior bound thread")?;
    b.client.persist_dm_session("history", "old-history", "recv", &receiving)?;
    let mut engine = GatewaySessionEngine::with_test_transport(b.config()?, Box::new(NoNetwork));
    let result = b
        .client
        .receive_legacy_entry(
            &mut engine,
            &super::super::review::pool()?,
            entry,
            crate::client::dm::LegacyReceive {
                conversation_id: "history",
                auto_fetch_attachments: false,
                relay_service_key_base64: None,
            },
        )
        .await;
    assert!(result?.is_none());
    assert_eq!(b.client.gateway_receive_cursor("bob")?, 1);
    assert!(
        b.client
            .account_db()?
            .journal_after(0, 128)?
            .iter()
            .any(|event| event.body["error_code"] == "legacy_control_rejected")
    );
    valid_delivery_after_rejected_control(&a, &mut b, &mut engine, &mut session).await?;
    assert!(!b.client.friend_links()?.iter().any(|l| l.link_id == "incoming-request"));
    Ok(())
}

#[tokio::test]
async fn directory_refresh_preserves_card_locator_and_verified_provenance() -> Result<(), SdkError>
{
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let d = Directory::new(&a, &b).await?;
    let origin = Origin::new(&d).await?;
    let mut s = state(&mut a, &mut b, &d)?;
    origin.configure(&mut s, "alice")?;
    origin.configure(&mut s, "bob")?;
    let signed = card(&mut s).await?;
    let added = call(&mut s, "alice", "contact.add", json!({"card":signed})).await?;
    let node = added["contact"]["node"].clone();
    assert!(!node.is_null());
    let manifest = d
        .records
        .lock()
        .map_err(|_| invalid("directory"))?
        .iter()
        .find(|record| record.principal_id == "bob")
        .cloned()
        .ok_or_else(|| invalid("bob manifest"))?;
    for source in ["card", "verified"] {
        if source == "verified" {
            call(
                &mut s,
                "alice",
                "contact.verify",
                json!({"contact_identity_commitment":manifest.principal_commitment}),
            )
            .await?;
        }
        client(&s)?.persist_root_verified_directory(&manifest)?;
        let db = client(&s)?.account_db()?;
        let identity = db.client_record("identity", "bob")?.ok_or_else(|| invalid("identity"))?;
        assert_eq!(identity["root_source"], source);
        assert_eq!(identity["node"], node);
        assert!(client(&s)?.contact_replacement(&identity, "bob", "different-root", None).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn directory_refresh_without_profile_preserves_card_asserted_kind() -> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let d = Directory::new(&a, &b).await?;
    let origin = Origin::new(&d).await?;
    let mut s = state(&mut a, &mut b, &d)?;
    origin.configure(&mut s, "alice")?;
    origin.configure(&mut s, "bob")?;
    let mut body = crate::parse_contact_card(&card(&mut s).await?, now_unix_timestamp())?;
    body.kind_asserted = Some("bot".into());
    let seed = s
        .accounts
        .get("bob")
        .ok_or_else(|| invalid("bob"))?
        .client
        .identity_root
        .as_ref()
        .ok_or(SdkError::IdentityRootMissing)?
        .signing_key
        .to_bytes();
    let (signed, _) = crate::contact_card::encode_contact_card(body, seed, now_unix_timestamp())?;
    let added = call(&mut s, "alice", "contact.add", json!({"card":signed})).await?;
    assert_eq!(added["contact"]["kind_asserted"], "bot");
    assert_eq!(added["contact"]["kind_verified"], false);
    let manifest = d
        .records
        .lock()
        .map_err(|_| invalid("directory"))?
        .iter()
        .find(|record| record.principal_id == "bob")
        .cloned()
        .ok_or_else(|| invalid("bob manifest"))?;
    assert!(manifest.signed_device_set.as_ref().is_some_and(|record| record.profile.is_none()));
    client(&s)?.persist_root_verified_directory(&manifest)?;
    let contact = client(&s)?.contact_entry("bob")?;
    assert_eq!(contact["kind_asserted"], "bot");
    assert_eq!(contact["kind_verified"], false);
    assert_eq!(contact["root_source"], "card");
    Ok(())
}

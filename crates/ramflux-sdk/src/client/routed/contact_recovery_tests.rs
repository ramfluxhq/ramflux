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
    let mut a = Fixture::native_named("alice", 21).await?;
    let mut b = Fixture::native_same_home(&a, "bob").await?;
    let fake = Fixture::native_named("bob", 71).await?;
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
async fn native_card_cannot_override_an_existing_anchor_or_retire_its_pair() -> Result<(), SdkError>
{
    let (mut a, _b, fake, _d, _origin, mut s, old) = lying_lookup().await?;
    a.client =
        std::mem::take(&mut s.accounts.get_mut("alice").ok_or_else(|| invalid("account"))?.client);
    let local = a.client.owned_device_identity()?;
    let remote = fake.client.owned_device_identity()?;
    generated_delivery(&a, &fake, "pinned-session", "pinned native content")?;
    let before = a.client.persisted_pair_snapshot(&local, &remote)?;
    s.accounts.get_mut("alice").ok_or_else(|| invalid("account"))?.client =
        std::mem::take(&mut a.client);
    let signed = card(&mut s).await?;
    for confirmation in [None, Some(old.as_str())] {
        let mut body = json!({"card":signed});
        if let Some(root) = confirmation {
            body["replace_provisional_root"] = json!(root);
        }
        let error = call(&mut s, "alice", "contact.add", body)
            .await
            .err()
            .ok_or_else(|| invalid("native anchor replaced"))?;
        assert!(
            matches!(error, SdkError::ContactInput(crate::ContactReason::AnchorMismatch)),
            "{error:?}"
        );
        assert_eq!(client(&s)?.contact_entry("bob")?["root_commitment"], old);
        assert_eq!(client(&s)?.persisted_pair_snapshot(&local, &remote)?, before);
    }
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
    let current = client(&s)?.native_safety_number(&root)?;
    assert_eq!(current.algorithm_version, 2);
    assert_eq!(
        current.verification_state, "verified",
        "native safety confirmation must retain its current authority stamp"
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
        assert!(matches!(err, SdkError::ContactInput(crate::ContactReason::AnchorMismatch)));
        assert_eq!(client(&s)?.contact_entry("bob")?["root_commitment"], old);
    }
    Ok(())
}
#[tokio::test]
async fn a_native_card_refreshes_certified_profile_and_preserves_local_metadata()
-> Result<(), SdkError> {
    let mut a = Fixture::native_named("alice", 21).await?;
    let mut b = Fixture::native_same_home(&a, "bob").await?;
    let d = Directory::new(&a, &b).await?;
    let origin = Origin::new(&d).await?;
    let mut s = state(&mut a, &mut b, &d)?;
    origin.configure(&mut s, "alice")?;
    origin.configure(&mut s, "bob")?;
    client(&s)?.account_db()?.persist_client_record(
        "identity",
        "bob",
        &json!({"display_name":"Old unsigned cache","kind_asserted":"human","local_note":"My own label"}),
    )?;
    let signed = card(&mut s).await?;
    let body = crate::parse_contact_card(&signed, now_unix_timestamp())?;
    assert_eq!(body.version, 3);
    assert_eq!(body.kind_asserted.as_deref(), Some("human"));
    let added = call(&mut s, "alice", "contact.add", json!({"card":signed})).await?;
    assert_eq!(
        added["contact"]["display_name"],
        body.display_name.as_deref().ok_or_else(|| invalid("certified display name"))?
    );
    assert_eq!(added["contact"]["kind_asserted"], "human");
    assert_eq!(added["contact"]["kind_verified"], true);
    assert_eq!(
        client(&s)?
            .account_db()?
            .client_record("identity", "bob")?
            .ok_or_else(|| invalid("cached identity"))?["local_note"],
        "My own label"
    );
    Ok(())
}

#[tokio::test]
async fn a_rejected_native_card_preserves_signed_group_authority_and_contact_pin()
-> Result<(), SdkError> {
    let (a, _b, fake, _d, _origin, mut s, old) = lying_lookup().await?;
    let owner = client(&s)?;
    let native = a.native.as_ref().ok_or_else(|| invalid("native vault"))?;
    let primary = owner
        .born_v3_account
        .as_ref()
        .ok_or(SdkError::CustodySetupInvalid)?
        .group_primary(native.vault.as_ref())?;
    let target = owner.owned_device_identity()?.storage_key().to_owned();
    owner.shared_group_create_with_primary(
        "pinned",
        "pinned-thread",
        None,
        &target,
        Some(&primary),
    )?;
    let state = owner.shared_group_change_with_primary(
        "pinned",
        &target,
        ramflux_protocol::GroupStateChange::Add {
            member: fake.client.owned_group_actor(&fake.config()?.target_delivery_id)?.identity,
            role: ramflux_protocol::SharedGroupRole::Member,
        },
        Some(&primary),
    )?;
    let signed = card(&mut s).await?;
    let error = call(&mut s, "alice", "contact.add", json!({"card":signed}))
        .await
        .err()
        .ok_or_else(|| invalid("pinned root replaced"))?;
    assert!(
        matches!(error, SdkError::ContactInput(crate::ContactReason::AnchorMismatch)),
        "{error:?}"
    );
    assert_eq!(
        client(&s)?
            .account_db()?
            .shared_group_state("pinned")?
            .ok_or_else(|| invalid("pinned group"))?
            .snapshot(),
        state.snapshot()
    );
    assert_eq!(client(&s)?.contact_entry("bob")?["root_commitment"], old);
    assert_eq!(client(&s)?.contact_entry("bob")?["root_source"], "lookup");
    Ok(())
}
#[tokio::test]
async fn principal_add_and_accept_use_the_same_link_id_for_both_sides() -> Result<(), SdkError> {
    let mut a = Fixture::native_named("alice", 21).await?;
    let mut b = Fixture::native_same_home(&a, "bob").await?;
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
async fn invalid_directory_signatures_return_a_typed_manifest_error_without_a_contact()
-> Result<(), SdkError> {
    let mut a = Fixture::native_named("alice", 21).await?;
    let mut b = Fixture::native_same_home(&a, "bob").await?;
    let d = Directory::new(&a, &b).await?;
    d.records
        .lock()
        .map_err(|_| invalid("mutex"))?
        .get_mut(1)
        .ok_or_else(|| invalid("peer publication"))?
        .custody
        .as_mut()
        .ok_or_else(|| invalid("native authority"))?
        .publication
        .record
        .signature = ramflux_protocol::encode_base64url([0; 64]);
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

#[tokio::test]
async fn directory_refresh_preserves_card_locator_and_verified_provenance() -> Result<(), SdkError>
{
    let mut a = Fixture::native_named("alice", 21).await?;
    let mut b = Fixture::native_same_home(&a, "bob").await?;
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
async fn directory_refresh_preserves_native_certified_kind_and_card_locator() -> Result<(), SdkError>
{
    let mut a = Fixture::native_named("alice", 21).await?;
    let mut b = Fixture::native_same_home(&a, "bob").await?;
    let d = Directory::new(&a, &b).await?;
    let origin = Origin::new(&d).await?;
    let mut s = state(&mut a, &mut b, &d)?;
    origin.configure(&mut s, "alice")?;
    origin.configure(&mut s, "bob")?;
    let signed = card(&mut s).await?;
    let added = call(&mut s, "alice", "contact.add", json!({"card":signed})).await?;
    let manifest = d
        .records
        .lock()
        .map_err(|_| invalid("directory"))?
        .iter()
        .find(|record| record.principal_id == "bob")
        .cloned()
        .ok_or_else(|| invalid("bob manifest"))?;
    assert!(manifest.custody.is_some(), "kind must come from actual certified native authority");
    client(&s)?.persist_root_verified_directory(&manifest)?;
    let contact = client(&s)?.contact_entry("bob")?;
    assert_eq!(contact["kind_asserted"], "human");
    assert_eq!(contact["kind_asserted"], added["contact"]["kind_asserted"]);
    assert_eq!(contact["node"], added["contact"]["node"]);
    assert_eq!(contact["root_source"], "card");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn retired_json_friend_controls_remain_message_text_without_side_effects()
-> Result<(), SdkError> {
    for text in [br#"{"type":"friend.requested","link_id":"incoming-request","requester":"mallory","target":"bob"}"#.as_slice(), br#"{"type":"friend.removed","link_id":"unknown-link"}"#.as_slice()] {
        super::super::review::native_text::roundtrip(text, false).await?;
    }
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Adversarial contact admission, retention, selectors and consent races.
use super::*;
use crate::client::identity_authority::HeadUse;
pub(super) fn root(state: &LocalBusDaemonState, who: &str) -> Result<String, SdkError> {
    Ok(account(state, who)?.owned_device_identity()?.root_commitment().into())
}
pub(super) async fn outbound(
    state: &mut LocalBusDaemonState,
    directory: &Directory,
) -> Result<GatewayInboxEntry, SdkError> {
    contact(state, "alice", "contact.add", json!({"principal_id":"bob"})).await?;
    frames(directory)?.into_iter().next().ok_or_else(|| invalid("request"))
}
#[tokio::test]
async fn contact02_r2_unsigned_junk_cannot_spend_the_genuine_request_budget() -> Result<(), SdkError>
{
    crate::client::native_test_support::watchdog::within(
        contact02_r2_unsigned_junk_cannot_spend_the_genuine_request_budget_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn contact02_r2_unsigned_junk_cannot_spend_the_genuine_request_budget_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 31)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 41)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let valid = outbound(&mut state, &directory).await?;
    let mut junk = valid.clone();
    junk.envelope.signed.signature = "invalid".into();
    let receiver = state.accounts.get("bob").ok_or_else(|| invalid("bob"))?;
    for _ in 0..120 {
        assert!(
            receiver
                .client
                .contact_request_candidate(&receiver.gateway_config, &junk)
                .await
                .is_err()
        );
    }
    deliver(&mut state, "bob", &valid).await?;
    assert_eq!(
        contact(&mut state, "bob", "contact.requests.list", json!({})).await?["requests"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    Ok(())
}
#[tokio::test]
async fn contact02_r2_short_expiry_and_chosen_request_ids_are_not_valid_wire_controls()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        contact02_r2_short_expiry_and_chosen_request_ids_are_not_valid_wire_controls_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn contact02_r2_short_expiry_and_chosen_request_ids_are_not_valid_wire_controls_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 51)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 61)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = outbound(&mut state, &directory).await?;
    let manifest = directory
        .records
        .lock()
        .map_err(|_| invalid("directory lock"))?
        .first()
        .cloned()
        .ok_or_else(|| invalid("source manifest"))?;
    account(&state, "bob")?.persist_observed_identity_directory_now(&manifest)?;
    let opened = account(&state, "bob")?.open_routed(&entry, "bob")?;
    account(&state, "bob")?.verify_contact_control(&entry, &opened.routing, &opened.body)?;
    let original = crate::client::contact_requests::native_tests::decoded_consent(&opened.body)
        .map_err(|e| invalid(&e.to_string()))?;
    let native = a.native.as_ref().ok_or_else(|| invalid("native source"))?;
    let public = native
        .manifest
        .custody
        .as_ref()
        .ok_or_else(|| invalid("native manifest"))?
        .publication
        .record
        .body
        .master_certificate
        .body
        .self_signing_public_key
        .clone();
    let primary = native.vault.primary_for_public_key(&public)?;
    for short_lifetime in [true, false] {
        let mut control = original.clone();
        if short_lifetime {
            control.body.expires_at = control.body.issued_at + 60;
        } else {
            control.body.request_id = ramflux_protocol::encode_base64url([9; 32]);
        }
        // A genuine management signer signs invalid semantics deliberately.
        control.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_protocol::custody::signing_bytes(
                ramflux_protocol::domain::CONTACT_REQUEST_V2,
                &control.body,
            )?,
            *primary.vault_seed(),
        );
        let payload = crate::client::generated_control::control_from_payload(
            ramflux_protocol::message::control::Payload::ContactControl(
                ramflux_protocol::message::ContactControl {
                    consent: Some(ramflux_protocol::message::NativeContactConsent {
                        canonical: ramflux_protocol::canonical_json_bytes(&control)?,
                    }),
                },
            ),
        )?;
        let original_inner =
            <ramflux_protocol::message::Inner as prost::Message>::decode(opened.body.as_slice())
                .map_err(|_| invalid("original native Inner"))?;
        let identity = original_inner.identity.ok_or_else(|| invalid("original identity"))?;
        let exact = RamfluxClient::encode_generated_inner(
            identity,
            &ramflux_protocol::message::Content {
                value: Some(ramflux_protocol::message::content::Value::Control(payload)),
            },
        )?;
        assert!(
            account(&state, "bob")?
                .verify_contact_control(&entry, &opened.routing, &exact)
                .is_err(),
            "a primary signer cannot choose expiry or another selector as its request ID"
        );
    }
    Ok(())
}
#[tokio::test]
async fn contact02_r2_persists_a_compact_request_and_prunes_closed_requester_authority()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        contact02_r2_persists_a_compact_request_and_prunes_closed_requester_authority_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn contact02_r2_persists_a_compact_request_and_prunes_closed_requester_authority_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 71)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 81)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let source = root(&state, "alice")?;
    account(&state, "bob")?.account_db()?.append_journal(
        "legacy-preview",
        "contact.requested",
        &json!({"preview":"old private body","note":"old note","safety_number":["1"]}),
        now_unix_timestamp(),
        Some(&source),
    )?;
    pending(&mut state, &directory).await?;
    let source = root(&state, "alice")?;
    let row = account(&state, "bob")?
        .account_db()?
        .contact_request(&source, "inbound")?
        .ok_or_else(|| invalid("row"))?;
    assert!(
        row.request_json.len() < 1024,
        "the request must not retain the signed manifest/control"
    );
    contact(&mut state, "bob", "contact.decline", json!({"request_id":row.request_id})).await?;
    account(&state, "bob")?.account_db()?.decide_contact_request(
        &source,
        "inbound",
        &row.request_id,
        "declined",
        now_unix_timestamp() - 7200,
    )?;
    account(&state, "bob")?.account_db()?.remove_actor_state("contact-request/maintenance-next")?;
    contact(&mut state, "bob", "contact.requests.list", json!({})).await?;
    for event in account(&state, "bob")?.account_db()?.journal_after(0, 128)? {
        if event.topic == "contact.requested" {
            assert!(event.body.get("preview").is_none());
            assert!(event.body.get("note").is_none());
            assert!(event.body.get("safety_number").is_none());
        }
    }
    assert!(account(&state, "bob")?.account_db()?.contact_request(&source, "inbound")?.is_none());
    assert!(account(&state, "bob")?.account_db()?.client_record("identity", "alice")?.is_none());
    assert!(
        account(&state, "bob")?
            .account_db()?
            .load_actor_state::<Value>(&format!("identity/manifest-root/{source}"))?
            .is_none()
    );
    Ok(())
}
#[tokio::test]
async fn contact02_r2_exhausted_reply_items_cannot_roll_back_a_new_auto_accept_receipt()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        contact02_r2_exhausted_reply_items_cannot_roll_back_a_new_auto_accept_receipt_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn contact02_r2_exhausted_reply_items_cannot_roll_back_a_new_auto_accept_receipt_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 91)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 101)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let a_root = root(&state, "alice")?;
    let b_root = root(&state, "bob")?;
    let receiver = account(&state, "bob")?;
    receiver.set_contact_request_policy("auto_accept")?;
    let now = now_unix_timestamp();
    for i in 0_u8..128 {
        let id = ramflux_protocol::encode_base64url([i; 32]);
        let key = format!(
            "contact-request/send/{}",
            ramflux_protocol::hash_base64url(
                "ramflux.contact_request.delivery.v1",
                format!("{a_root}:{id}:Accept").as_bytes()
            )
        );
        receiver.account_db()?.persist_actor_state(&key,&json!({"kind":"accept","request_id":id,"requester_root":a_root,"target_root":b_root,"peer_root":a_root,"note":null,"expires_at":now+604_800,"issued_at":now,"nonce":ramflux_protocol::encode_base64url([i;32]),"attempts":8,"next_at":now+60,"delivered":[]}))?;
    }
    let entry = outbound(&mut state, &directory).await?;
    deliver(&mut state, "bob", &entry).await?;
    assert!(account(&state, "bob")?.friend_link_peer_is_accepted(&a_root)?);
    assert!(
        account(&state, "bob")?
            .account_db()?
            .list_actor_states::<Value>("contact-request/send/")?
            .len()
            <= 4
    );
    Ok(())
}
#[tokio::test]
async fn contact02_r2_readding_a_pending_request_retries_delivery() -> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        contact02_r2_readding_a_pending_request_retries_delivery_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn contact02_r2_readding_a_pending_request_retries_delivery_body() -> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 111)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 121)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let first = outbound(&mut state, &directory).await?;
    let target = root(&state, "bob")?;
    let source = root(&state, "alice")?;
    let row = account(&state, "alice")?
        .account_db()?
        .contact_request(&target, "outbound")?
        .ok_or_else(|| invalid("request"))?;
    let metadata: Value = serde_json::from_slice(&row.request_json)?;
    let key = format!(
        "contact-request/send/{}",
        ramflux_protocol::hash_base64url(
            "ramflux.contact_request.delivery.v1",
            format!("{target}:{}:Request", row.request_id).as_bytes()
        )
    );
    account(&state,"alice")?.account_db()?.persist_actor_state(&key,&json!({"kind":"request","request_id":row.request_id,"requester_root":source,"target_root":target,"peer_root":target,"note":metadata["note"],"expires_at":row.expires_at,"issued_at":metadata["issued_at"],"nonce":metadata["nonce"],"attempts":8,"next_at":now_unix_timestamp()+3600,"delivered":[]}))?;
    contact(&mut state, "alice", "contact.add", json!({"principal_id":"bob"})).await?;
    let entries = frames(&directory)?;
    assert_eq!(entries.len(), 1);
    assert_ne!(entries[0].envelope.envelope_id, first.envelope.envelope_id);
    Ok(())
}
#[tokio::test]
async fn contact02_r2_root_selector_cannot_match_an_attackers_request_id() -> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        contact02_r2_root_selector_cannot_match_an_attackers_request_id_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn contact02_r2_root_selector_cannot_match_an_attackers_request_id_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 131)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 141)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let victim = root(&state, "alice")?;
    let own = root(&state, "bob")?;
    let attacker = ramflux_protocol::encode_base64url([42; 32]);
    for (root, id, name) in
        [(&victim, "victim-request", "victim"), (&attacker, victim.as_str(), "attacker")]
    {
        account(&state,"bob")?.account_db()?.persist_contact_request(&ramflux_storage::ContactRequestRecord {contact_identity_commitment:root.clone(),direction:"inbound".into(),request_id:id.into(),principal_id:name.into(),link_id:format!("link-{name}"),state:"pending".into(),request_json:serde_json::to_vec(&json!({"note":null,"nonce":ramflux_protocol::encode_base64url([1;32]),"issued_at":now_unix_timestamp()}))?,expires_at:now_unix_timestamp()+604_800,updated_at:now_unix_timestamp()})?;
        account(&state, "bob")?.record_pending_friend_link(&format!("link-{name}"), root, &own)?;
    }
    let response =
        contact(&mut state, "bob", "contact.decline", json!({"root_commitment":victim})).await?;
    assert_eq!(response["principal_id"], "victim");
    assert_eq!(
        account(&state, "bob")?
            .account_db()?
            .contact_request(&attacker, "inbound")?
            .ok_or_else(|| invalid("attacker"))?
            .state,
        "pending"
    );
    Ok(())
}
#[tokio::test]
async fn contact02_r2_expiry_between_admission_and_projection_cannot_publish_content()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        contact02_r2_expiry_between_admission_and_projection_cannot_publish_content_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn contact02_r2_expiry_between_admission_and_projection_cannot_publish_content_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 151)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 161)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    pending(&mut state, &directory).await?;
    message(&mut state, "expiry-race").await?;
    let entry = frames(&directory)?.into_iter().next().ok_or_else(|| invalid("message"))?;
    let client = account(&state, "bob")?;
    let mut opened = client.open_routed(&entry, "bob")?;
    opened.routing.message_id = client.projection_id(&entry, &opened.routing)?;
    client.contact_route_gate(&entry, &opened.routing, &opened.body)?;
    let source = root(&state, "alice")?;
    let row = client
        .account_db()?
        .contact_request(&source, "inbound")?
        .ok_or_else(|| invalid("request"))?;
    client.account_db()?.decide_contact_request(
        &source,
        "inbound",
        &row.request_id,
        "expired",
        now_unix_timestamp(),
    )?;
    assert!(
        client
            .project_accepted_contact_message_at(
                &opened.routing,
                &entry,
                &opened.body,
                None,
                entry.envelope.created_at
            )
            .is_err()
    );
    assert_eq!(client.direct_messages("request-thread")?.len(), 0);
    Ok(())
}

#[tokio::test]
async fn contact02_r2_budget_backpressure_keeps_gateway_ciphertext_and_redrives_without_blocking_dm()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(contact02_r2_budget_backpressure_keeps_gateway_ciphertext_and_redrives_without_blocking_dm_body())
        .await.map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn contact02_r2_budget_backpressure_keeps_gateway_ciphertext_and_redrives_without_blocking_dm_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 171)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 181)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = outbound(&mut state, &directory).await?;
    let source = root(&state, "alice")?;
    {
        let receiver = account(&state, "bob")?;
        receiver.set_contact_request_policy("auto_accept")?;
        for _ in 0..120 {
            assert!(receiver.account_db()?.charge_contact_request(
                "bootstrap-attempts",
                120,
                3600,
                now_unix_timestamp()
            )?);
        }
    }
    let (mut dm, conversation) = known_peer_traffic(&mut state, &directory).await?;
    dm.inbox_seq = 2;
    *directory.incoming.lock().map_err(|_| invalid("inbox"))? = vec![entry.clone(), dm];
    crate::bus::sync_driver::run(state.accounts.get_mut("bob").ok_or_else(|| invalid("bob"))?)
        .await?;
    assert_eq!(account(&state, "bob")?.direct_messages(&conversation)?.len(), 1);
    assert_eq!(
        directory.incoming.lock().map_err(|_| invalid("inbox"))?.len(),
        1,
        "quota refusal must not ACK/discard the contact control"
    );
    let db = account(&state, "bob")?.account_db()?;
    let key = account(&state, "bob")?.inbox_admission_key(&entry)?;
    assert!(
        !db.has_inbox_retry(&key)?,
        "30-second generic retries cannot wait out an hourly quota"
    );
    let mut pressure = db
        .load_actor_state::<Value>("contact-admission/backpressure")?
        .ok_or_else(|| invalid("backpressure metadata"))?;
    pressure["next_at"] = json!(now_unix_timestamp() - 1);
    db.persist_actor_state("contact-admission/backpressure", &pressure)?;
    assert!(db.charge_contact_request(
        "bootstrap-attempts",
        120,
        3600,
        now_unix_timestamp() + 3601
    )?);
    crate::bus::sync_driver::run(state.accounts.get_mut("bob").ok_or_else(|| invalid("bob"))?)
        .await?;
    assert_eq!(directory.incoming.lock().map_err(|_| invalid("inbox"))?.len(), 0);
    assert_eq!(
        account(&state, "bob")?
            .account_db()?
            .contact_request(&source, "inbound")?
            .ok_or_else(|| invalid("accepted request"))?
            .state,
        "accepted"
    );
    assert_eq!(account(&state, "bob")?.direct_messages(&conversation)?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn contact02_r2_full_active_queue_defers_the_reply_without_rolling_back_consent()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        contact02_r2_full_active_queue_defers_the_reply_without_rolling_back_consent_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn contact02_r2_full_active_queue_defers_the_reply_without_rolling_back_consent_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 191)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 201)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let source = root(&state, "alice")?;
    let target = root(&state, "bob")?;
    let now = now_unix_timestamp();
    {
        let receiver = account(&state, "bob")?;
        receiver.set_contact_request_policy("auto_accept")?;
        for n in 0_u8..128 {
            let peer = ramflux_protocol::encode_base64url([n; 32]);
            let id = format!("queued-{n}");
            receiver.account_db()?.persist_contact_request(
                &ramflux_storage::ContactRequestRecord {
                    contact_identity_commitment: peer.clone(),
                    direction: "inbound".into(),
                    request_id: id.clone(),
                    principal_id: format!("peer-{n}"),
                    link_id: id.clone(),
                    state: "accepted".into(),
                    request_json: b"{}".to_vec(),
                    expires_at: now + 604_800,
                    updated_at: now,
                },
            )?;
            let key = format!(
                "contact-request/send/{}",
                ramflux_protocol::hash_base64url(
                    "ramflux.contact_request.delivery.v1",
                    format!("{peer}:{id}:Accept").as_bytes()
                )
            );
            receiver.account_db()?.persist_actor_state(&key,&json!({"kind":"accept","request_id":id,"requester_root":peer,"target_root":target,"peer_root":peer,"note":null,"expires_at":now+604_800,"issued_at":now,"nonce":"nonce","attempts":0,"next_at":now+3600,"delivered":[]}))?;
        }
    }
    let entry = outbound(&mut state, &directory).await?;
    deliver(&mut state, "bob", &entry).await?;
    let receiver = account(&state, "bob")?;
    assert!(receiver.friend_link_peer_is_accepted(&source)?);
    let db = receiver.account_db()?;
    let row = db.contact_request(&source, "inbound")?.ok_or_else(|| invalid("request"))?;
    assert_eq!(serde_json::from_slice::<Value>(&row.request_json)?["needs_reply"], "accept");
    assert!(db.actor_state_exists(
        &receiver.authenticated_committed_key(HeadUse::NewAuthorization, &entry)?
    )?);
    let peer = ramflux_protocol::encode_base64url([0; 32]);
    let key = format!(
        "contact-request/send/{}",
        ramflux_protocol::hash_base64url(
            "ramflux.contact_request.delivery.v1",
            format!("{peer}:queued-0:Accept").as_bytes()
        )
    );
    db.remove_actor_state(&key)?;
    flush(&mut state, "bob").await?;
    let row = account(&state, "bob")?
        .account_db()?
        .contact_request(&source, "inbound")?
        .ok_or_else(|| invalid("request"))?;
    assert!(serde_json::from_slice::<Value>(&row.request_json)?.get("needs_reply").is_none());
    assert_eq!(
        account(&state, "bob")?
            .account_db()?
            .list_actor_states::<Value>("contact-request/send/")?
            .len(),
        127
    );
    assert_eq!(frames(&directory)?.len(), 1, "deferred acceptance was submitted");
    Ok(())
}

#[tokio::test]
async fn contact02_r2_retired_authority_floors_are_bounded_and_reject_rollback()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        contact02_r2_retired_authority_floors_are_bounded_and_reject_rollback_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn contact02_r2_retired_authority_floors_are_bounded_and_reject_rollback_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 211)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 221)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    pending(&mut state, &directory).await?;
    let receiver = account(&state, "bob")?;
    let source = root(&state, "alice")?;
    let native = a.native.as_ref().ok_or_else(|| invalid("source native vault"))?;
    let mut manifest = native.manifest.clone();
    let record = manifest
        .custody
        .as_ref()
        .ok_or_else(|| invalid("native authority"))?
        .publication
        .record
        .clone();
    let primary = native
        .vault
        .primary_for_public_key(&record.body.master_certificate.body.self_signing_public_key)?;
    let mut next = record.body.clone();
    next.device_set_epoch += 1;
    next.previous_record_hash = Some(ramflux_protocol::custody::object_hash(&record)?);
    next.profile.display_name = "verified successor".into();
    let successor = primary.sign_record(next.clone())?;
    let now = now_unix_timestamp();
    let db = receiver.account_db()?;
    assert!(db.retain_contact_request_authority_floor(
        &source,
        successor.body.device_set_epoch,
        &ramflux_protocol::custody::object_hash(&successor)?,
        now + 604_800,
        now,
    )?);
    assert!(
        receiver.remember_contact_request_cache(&manifest).is_err(),
        "a lower signed native head cannot roll back the retained floor"
    );
    next.profile.display_name = "conflicting successor".into();
    manifest.custody.as_mut().ok_or_else(|| invalid("native authority"))?.publication.record =
        primary.sign_record(next)?;
    assert!(
        receiver.remember_contact_request_cache(&manifest).is_err(),
        "a genuinely signed same-epoch fork must also fail"
    );
    db.write_transaction(|| -> Result<(), SdkError> {
        for n in 0..4095 {
            assert!(db.retain_contact_request_authority_floor(
                &format!("floor-{n}"),
                1,
                "hash",
                now + 60,
                now
            )?);
        }
        assert!(!db.retain_contact_request_authority_floor(
            "overflow",
            1,
            "hash",
            now + 60,
            now
        )?);
        Ok(())
    })?;
    assert!(db.retain_contact_request_authority_floor(
        "overflow",
        1,
        "hash",
        now + 120,
        now + 61
    )?);
    Ok(())
}

#[tokio::test]
async fn contact02_r2_held_surface_expiry_starts_at_release_and_creates_its_thread()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        contact02_r2_held_surface_expiry_starts_at_release_and_creates_its_thread_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn contact02_r2_held_surface_expiry_starts_at_release_and_creates_its_thread_body()
-> Result<(), SdkError> {
    use crate::client::surface::{Carrier, ControlKind, PayloadKind};
    use ramflux_protocol::message as g;
    use ramflux_protocol::{A2uiConversationCommand as C, StreamAppendCommand};
    let mut a = Box::pin(Fixture::native_named("alice", 231)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 241)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    pending(&mut state, &directory).await?;
    let conversation = direct_thread(&state)?;
    account(&state, "alice")?.set_offline_retention_secs(3600)?;
    let append = ramflux_protocol::encode_a2ui_conversation_event(
        &conversation,
        2,
        &C::StreamAppend(StreamAppendCommand {
            surface_id: "held".into(),
            component_id: "stream".into(),
            text_delta: "hello".into(),
            final_: false,
        }),
    )?;
    let carrier = account(&state, "alice")?.sign_surface_carrier(Carrier {
        typed: None,
        schema: ramflux_protocol::domain::SURFACE_CARRIER.into(),
        content_type: "surface".into(),
        posted_at: None,
        updated_at: None,
        payload_kind: PayloadKind::Event,
        conversation_id: conversation.clone(),
        surface_id: "held".into(),
        message_id: "held-v2".into(),
        sender_principal_id: "alice".into(),
        sender_device_id: "alice".into(),
        author_principal_id: "alice".into(),
        wire_base64: ramflux_protocol::encode_base64url(&append),
        signature: String::new(),
        snapshot: Some(held_surface_hash(&conversation, &append)?),
    })?;
    let delivery =
        account(&state, "alice")?.surface_control_packet(&carrier, ControlKind::Peer, None)?;
    let content = g::Content {
        value: Some(g::content::Value::Surface(g::Surface {
            payload: Some(g::surface::Payload::Delivery(delivery.to_generated()?)),
        })),
    };
    let peer = root(&state, "bob")?;
    let recipient = ramflux_protocol::qualified_device_id(&peer, "bob")?;
    let request = request(
        "alice",
        "message.submit",
        json!({
            "content": content, "conversation_id": conversation, "message_id":"held-surface",
            "envelope_id":"held-surface", "source_principal_id":"alice","sender_id":"alice",
            "recipient_device_id":"bob","recipient_principal_commitment":peer,
            "target_delivery_id":recipient,"encrypted_body_base64":"",
            "created_at":now_unix_timestamp()-120,"ttl":3600,
        }),
    );
    let (outbound, _) = tokio::sync::mpsc::channel(8);
    let connection = crate::bus::state::LocalBusConnectionState::new(1, outbound);
    crate::bus::dispatch::message::dispatch_message_bus_request(&request, &mut state, &connection)
        .await?;
    let entry = frames(&directory)?.into_iter().next().ok_or_else(|| invalid("surface"))?;
    deliver(&mut state, "bob", &entry).await?;
    let source = root(&state, "alice")?;
    let at = now_unix_timestamp();
    contact(&mut state, "bob", "contact.accept", json!({"root_commitment":source})).await?;
    let receiver = account(&state, "bob")?;
    let pending = receiver.account_db()?.list_actor_states::<Value>("surface/pending/")?;
    assert_eq!(pending.len(), 1, "future surface is held for its missing create");
    let [pending] = pending.as_slice() else {
        return Err(invalid("one held Surface expected"));
    };
    assert!(
        pending["wire_expires_at"].as_i64().is_some_and(|expiry| expiry >= at + 3600),
        "the held Surface retention starts at consent release: {pending}",
    );
    let committed = receiver
        .account_db()?
        .load_actor_state::<crate::client::routed::committed::Committed>(
            &receiver.authenticated_committed_key(HeadUse::NewAuthorization, &entry)?,
        )?
        .ok_or_else(|| invalid("held Surface receipt missing"))?;
    assert_eq!(
        committed.entry.envelope, entry.envelope,
        "consent release must preserve the exact authenticated envelope and its original clock",
    );
    assert!(receiver.account_db()?.client_record("conversation", &conversation)?.is_some());
    assert_eq!(receiver.direct_messages(&conversation)?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn contact02_r2_requester_cache_cannot_supply_the_pin_for_legacy_name_consent()
-> Result<(), SdkError> {
    crate::client::native_test_support::watchdog::within(
        contact02_r2_requester_cache_cannot_supply_the_pin_for_legacy_name_consent_body(),
    )
    .await
    .map_err(|_| invalid("test: native contact admission exceeded its watchdog"))?
}

async fn contact02_r2_requester_cache_cannot_supply_the_pin_for_legacy_name_consent_body()
-> Result<(), SdkError> {
    let mut a = Box::pin(Fixture::native_named("alice", 23)).await?;
    let mut b = Box::pin(Fixture::native_named("bob", 33)).await?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    account(&state, "bob")?.account_db()?.establish_friend_link("legacy-name", "bob", "alice")?;
    pending(&mut state, &directory).await?;
    message(&mut state, "requires-root-consent").await?;
    let entry = frames(&directory)?.into_iter().next().ok_or_else(|| invalid("message"))?;
    assert!(deliver(&mut state, "bob", &entry).await?.plaintext.is_none());
    let receiver = account(&state, "bob")?;
    assert_eq!(receiver.direct_messages("request-thread")?.len(), 0);
    assert!(receiver.pending_contact_root(&root(&state, "alice")?)?);
    assert_eq!(receiver.account_db()?.contact_message_count(&root(&state, "alice")?)?, 1);
    Ok(())
}

async fn known_peer_traffic(
    bus_state: &mut LocalBusDaemonState,
    directory: &Directory,
) -> Result<(GatewayInboxEntry, String), SdkError> {
    let mut carol = Box::pin(Fixture::native_named("carol", 17)).await?;
    let mut unused_peer = Box::pin(Fixture::native_named("bob", 27)).await?;
    let manifest = carol.manifest()?;
    directory.records.lock().map_err(|_| invalid("directory"))?.push(manifest.clone());
    let mut other = state(&mut carol, &mut unused_peer, directory)?;
    let account = other.accounts.remove("carol").ok_or_else(|| invalid("known source"))?;
    bus_state.accounts.insert("carol".into(), account);
    let bob_manifest = directory
        .records
        .lock()
        .map_err(|_| invalid("directory"))?
        .iter()
        .find(|row| row.principal_id == "bob")
        .cloned()
        .ok_or_else(|| invalid("known receiver manifest"))?;
    let source_root = manifest.principal_commitment.clone();
    let peer_root = bob_manifest.principal_commitment.clone();
    let conversation = ramflux_protocol::message::dm_scope::derive(&source_root, &peer_root)
        .map_err(|_| invalid("known direct scope"))?;
    let receiver = bus_state.accounts.get("bob").ok_or_else(|| invalid("receiver"))?;
    receiver.client.persist_observed_identity_directory_now(&manifest)?;
    receiver.client.establish_friend_link("known-peer", &source_root, &peer_root)?;
    let source = bus_state.accounts.get_mut("carol").ok_or_else(|| invalid("source"))?;
    source.client.persist_observed_identity_directory_now(&bob_manifest)?;
    source.client.establish_friend_link("known-peer", &source_root, &peer_root)?;
    let device = bob_manifest.devices.first().ok_or_else(|| invalid("peer device"))?;
    let message = GatewayDirectMessage {
        conversation_id: conversation.clone(),
        message_id: "known-traffic".into(),
        envelope_id: "known-traffic".into(),
        source_principal_id: "carol".into(),
        sender_id: source.gateway_config.device_id.clone(),
        recipient_device_id: Some(device.device_id.clone()),
        recipient_principal_commitment: Some(peer_root),
        target_delivery_id: device.target_delivery_id.clone(),
        encrypted_body: Vec::new(),
        created_at: now_unix_timestamp(),
        ttl: 3600,
    };
    let mut engine = source.session_client().await?;
    let sent = source
        .client
        .send_plaintext_direct_message_via_gateway(
            &mut engine,
            message,
            b"ordinary traffic behind stranger admission pressure",
        )
        .await;
    source.install_test_session(engine);
    sent?;
    let entry = frames(directory)?.into_iter().next().ok_or_else(|| invalid("known DM frame"))?;
    Ok((entry, conversation))
}

fn held_surface_hash(
    conversation: &str,
    append: &[u8],
) -> Result<crate::client::surface::SnapshotProof, SdkError> {
    use ramflux_protocol::{
        A2uiConversationCommand as C, A2uiConversationEvent as E, CreateSurfaceCommand,
        SurfaceState, SurfaceType,
    };
    let create = ramflux_protocol::encode_a2ui_conversation_event(
        conversation,
        1,
        &C::CreateSurface(CreateSurfaceCommand {
            surface_id: "held".into(),
            surface_type: SurfaceType::StatusPanel,
            catalog: "basic".into(),
            catalog_version: "1".into(),
            fallback_text: "Working".into(),
            fallback_markdown: None,
            components: vec![json!({"id":"stream","text":""})],
            data_model: serde_json::Map::default(),
            allowed_actions: vec![],
        }),
    )?;
    let state = SurfaceState::default()
        .apply(&E::from_wire_bytes(&create)?)
        .map_err(|_| invalid("create"))?
        .apply(&E::from_wire_bytes(append)?)
        .map_err(|_| invalid("append"))?;
    Ok(crate::client::surface::SnapshotProof {
        wire_base64: String::new(),
        checkpoint_base64: String::new(),
        surface_hash: state.hash().map(str::to_owned),
        metadata: None,
        author_device_id: "alice".into(),
    })
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Admission flood, deferred retry, retained consent and isolated cleanup regressions.
use super::*;
fn reset_maintenance(client: &RamfluxClient) -> Result<(), SdkError> {
    client.account_db()?.remove_actor_state("contact-request/maintenance-next")?;
    Ok(())
}
fn signed_copy(
    state: &LocalBusDaemonState,
    source: &GatewayInboxEntry,
    seq: u64,
) -> Result<GatewayInboxEntry, SdkError> {
    let mut entry = source.clone();
    entry.inbox_seq = seq;
    entry.envelope.envelope_id = format!("contact-r3-{seq}");
    entry.envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
        account(state, "alice")?.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        &entry.envelope,
    )?;
    Ok(entry)
}
async fn sync(state: &mut LocalBusDaemonState) -> Result<(), SdkError> {
    crate::bus::sync_driver::run(state.accounts.get_mut("bob").ok_or_else(|| invalid("bob"))?)
        .await?;
    Ok(())
}
#[tokio::test]
async fn contact02_r3_sender_exhaustion_is_acked_without_manifest_fetch_and_next_root_is_admitted()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 31)?;
    let mut b = Fixture::new("bob", 41)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let valid = r2::outbound(&mut state, &directory).await?;
    let root = r2::root(&state, "alice")?;
    for _ in 0..32 {
        assert!(account(&state, "bob")?.account_db()?.charge_contact_request(
            &format!("bootstrap:{root}"),
            32,
            3600,
            now_unix_timestamp()
        )?);
    }
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    let flood =
        (1..=48).map(|seq| signed_copy(&state, &valid, seq)).collect::<Result<Vec<_>, _>>()?;
    *directory.incoming.lock().map_err(|_| invalid("inbox"))? = flood;
    sync(&mut state).await?;
    assert_eq!(
        directory.incoming.lock().map_err(|_| invalid("inbox"))?.len(),
        0,
        "sender exhaustion must ACK the entire flood"
    );
    assert_eq!(
        directory.manifest_fetches.load(Ordering::SeqCst),
        before,
        "known exhausted sender must not fetch authority"
    );
    let mut c = Fixture::new("carol", 51)?;
    let mut d = Fixture::new("bob", 41)?;
    directory
        .records
        .lock()
        .map_err(|_| invalid("records"))?
        .push(super::super::super::r9::manifest(&c)?);
    let mut other = super::super::state(&mut c, &mut d, &directory)?;
    let carol = other.accounts.remove("carol").ok_or_else(|| invalid("carol"))?;
    state.accounts.insert("carol".into(), carol);
    contact(&mut state, "carol", "contact.add", json!({"principal_id":"bob"})).await?;
    let mut genuine =
        frames(&directory)?.into_iter().next().ok_or_else(|| invalid("genuine request"))?;
    genuine.inbox_seq = 49;
    *directory.incoming.lock().map_err(|_| invalid("inbox"))? = vec![genuine];
    sync(&mut state).await?;
    assert!(account(&state, "bob")?.pending_contact_root(&r2::root(&state, "carol")?)?);
    Ok(())
}
#[tokio::test]
async fn contact02_r3_global_pressure_keeps_one_root_envelope_and_removes_due_retry()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 71)?;
    let mut b = Fixture::new("bob", 81)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = r2::outbound(&mut state, &directory).await?;
    let receiver = account(&state, "bob")?;
    for _ in 0..120 {
        assert!(receiver.account_db()?.charge_contact_request(
            "bootstrap-attempts",
            120,
            3600,
            now_unix_timestamp()
        )?);
    }
    let key = receiver.inbox_admission_key(&entry)?;
    receiver.account_db()?.defer_inbox_entry(
        &key,
        &serde_json::to_vec(&entry)?,
        now_unix_timestamp() - 3,
    )?;
    let flood =
        (1..=40).map(|seq| signed_copy(&state, &entry, seq)).collect::<Result<Vec<_>, _>>()?;
    // Include the actual retry packet as the earliest inbox entry.
    let mut flood = flood;
    flood[0] = entry.clone();
    *directory.incoming.lock().map_err(|_| invalid("inbox"))? = flood;
    let before = directory.manifest_fetches.load(Ordering::SeqCst);
    sync(&mut state).await?;
    assert_eq!(
        directory.incoming.lock().map_err(|_| invalid("inbox"))?.len(),
        1,
        "only one ciphertext per deferred root"
    );
    assert!(
        !account(&state, "bob")?.account_db()?.has_inbox_retry(&key)?,
        "the paced replay floor must own retry"
    );
    let after = directory.manifest_fetches.load(Ordering::SeqCst);
    assert!(after - before <= 1, "extra root envelopes triggered manifest fetches");
    sync(&mut state).await?;
    assert_eq!(
        directory.manifest_fetches.load(Ordering::SeqCst),
        after,
        "no hot loop while waiting for replay"
    );
    for _ in 0..34 {
        let db = account(&state, "bob")?.account_db()?;
        let mut pressure = db
            .load_actor_state::<Value>("contact-admission/backpressure")?
            .ok_or_else(|| invalid("pressure"))?;
        pressure["next_at"] = json!(0);
        db.persist_actor_state("contact-admission/backpressure", &pressure)?;
        sync(&mut state).await?;
        assert_eq!(
            directory.incoming.lock().map_err(|_| invalid("inbox"))?.len(),
            1,
            "global-pressure replay spent the sender quota"
        );
    }
    Ok(())
}
#[tokio::test]
async fn contact02_r3_non_replay_deferral_inside_active_scan_keeps_its_floor()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 91)?;
    let mut b = Fixture::new("bob", 101)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = r2::outbound(&mut state, &directory).await?;
    let receiver = account(&state, "bob")?;
    for _ in 0..120 {
        assert!(receiver.account_db()?.charge_contact_request(
            "bootstrap-attempts",
            120,
            3600,
            now_unix_timestamp()
        )?);
    }
    receiver.account_db()?.persist_actor_state("contact-admission/backpressure",&json!({"floor":1,"next_at":0,"expires_at":now_unix_timestamp()+3600,"scan":{"cursor":2,"until":2,"pending":null,"future":null}}))?;
    *directory.incoming.lock().map_err(|_| invalid("inbox"))? = vec![entry];
    sync(&mut state).await?;
    let pressure = account(&state, "bob")?
        .account_db()?
        .load_actor_state::<Value>("contact-admission/backpressure")?
        .ok_or_else(|| invalid("lost replay floor"))?;
    assert_eq!(pressure["floor"], 1);
    Ok(())
}
#[tokio::test]
async fn contact02_r3_pruned_decline_fences_session_control_and_outbound_retries()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 111)?;
    let mut b = Fixture::new("bob", 121)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    let entry = r2::outbound(&mut state, &directory).await?;
    let source = r2::root(&state, "alice")?;
    let target = r2::root(&state, "bob")?;
    let manifest = directory.records.lock().map_err(|_| invalid("records"))?[0].clone();
    account(&state, "bob")?.persist_identity_directory(&manifest)?;
    let opened = account(&state, "bob")?.open_routed(&entry, "bob")?;
    let control: contact_requests::Control = serde_json::from_slice(&opened.body)?;
    deliver(&mut state, "bob", &entry).await?;
    let receiver = account(&state, "bob")?;
    receiver.account_db()?.fence_contact_request(
        &source,
        "declined",
        now_unix_timestamp() + 3600,
    )?;
    receiver.account_db()?.remove_contact_request(&source, "inbound", &control.body.request_id)?;
    assert!(
        receiver.apply_contact_control(&control).is_err(),
        "ordinary authenticated pair control bypassed fence"
    );
    assert!(receiver.contact_request_admission(&entry).is_err());
    receiver.account_db()?.fence_contact_request(&source, "declined", now_unix_timestamp() - 1)?;
    let mut old = control.clone();
    old.body.issued_at -= 172_800;
    old.body.expires_at -= 172_800;
    old.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::canonical_json_bytes(
            &json!({"domain":"ramflux.contact_request.v1","body":old.body}),
        )?,
        account(&state, "alice")?
            .identity_root
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .signing_key
            .to_bytes(),
    );
    receiver.verify_contact_control(&entry, &opened.routing, &serde_json::to_vec(&old)?)?;
    assert!(
        receiver.apply_contact_control(&old).is_err(),
        "old signed request replayed after cooldown"
    );
    receiver.account_db()?.fence_contact_request(&source, "blocked", 0)?;
    assert!(receiver.apply_contact_control(&control).is_err(), "pruned block was bypassed");

    let sender = account(&state, "alice")?;
    sender.account_db()?.remove_contact_request(&target, "outbound", &control.body.request_id)?;
    sender.account_db()?.persist_client_record(
        "contact_request_status",
        &target,
        &json!({"state":"declined","updated_at":now_unix_timestamp()-7200}),
    )?;
    assert!(!sender.contact_request_retryable(&target)?);
    let peer = directory.records.lock().map_err(|_| invalid("records"))?[1].clone();
    assert!(
        sender.stage_contact_request(&peer, "re-add", None).is_err(),
        "pruned declined status must prevent re-add before cooldown"
    );
    Ok(())
}
#[tokio::test]
async fn contact02_r3_cleanup_is_paced_and_bad_retirement_does_not_block_later_rows()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 131)?;
    let mut b = Fixture::new("bob", 141)?;
    let directory = Directory::new(&a, &b).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    pending(&mut state, &directory).await?;
    let source = r2::root(&state, "alice")?;
    let client = account(&state, "bob")?;
    let db = client.account_db()?;
    let mut bad = db.contact_request(&source, "inbound")?.ok_or_else(|| invalid("request"))?;
    bad.state = "expired".into();
    bad.updated_at = now_unix_timestamp() - 7200;
    db.remove_contact_request(&source, "inbound", &bad.request_id)?;
    db.persist_contact_request(&bad)?;
    // Missing current manifest causes retirement's qualified device lookup to fail.
    db.remove_actor_state(&format!("identity/manifest-root/{source}"))?;
    db.remove_actor_state("identity/manifest/alice")?;
    let mut healthy = bad.clone();
    healthy.direction = "outbound".into();
    healthy.contact_identity_commitment = "healthy-retirement".into();
    healthy.request_id = "healthy-request".into();
    db.persist_contact_request(&healthy)?;
    reset_maintenance(client)?;
    client.maintain_contact_requests()?;
    assert!(
        db.contact_request("healthy-retirement", "outbound")?.is_none(),
        "one bad row blocked healthy retirement"
    );
    assert!(db.contact_request(&source, "inbound")?.is_some());
    db.append_journal(
        "after-migration",
        "contact.requested",
        &json!({"preview":"sentinel for proving no second scan"}),
        now_unix_timestamp(),
        None,
    )?;
    reset_maintenance(client)?;
    client.maintain_contact_requests()?;
    assert!(
        db.journal_after(0, 128)?
            .iter()
            .any(|e| e.body["preview"] == "sentinel for proving no second scan"),
        "legacy redaction was rerun on a hot path"
    );
    Ok(())
}

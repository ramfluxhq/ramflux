// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual signed snapshot and Native advancement exercise retained ingress source floors.
use super::*;
#[test]
fn cr_ingress_source_floor_refuses_old_verified_snapshot_without_allocating_new_trust() -> TestResult
{
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("source-floor.redb");
    let (store, f) = initialize(&path)?;
    let peer = crate::contact_reach::source::tests::verified_source()?;
    let trust_key = key(&f.root, peer.root())?;
    {
        let tx = store.begin_write()?;
        require_ingress_peer(&tx, &f.root, &peer)?;
        assert!(
            tx.open_table(TRUST)?.get(trust_key.as_str())?.is_none(),
            "checking unsolicited evidence must not allocate a permanent source pin"
        );
        adopt_ingress_peer(&tx, &f.root, &peer)?;
        tx.commit()?;
    }
    let mut branch = peer
        .authority()
        .envelope()
        .body
        .devices
        .first()
        .and_then(|device| device.branch_certificate.as_ref())
        .ok_or("current primary branch")?
        .body
        .clone();
    branch.device_id = "new-sibling".into();
    branch.cert_id = digest(90);
    branch.branch_signing_public_key = ramflux_crypto::public_key_base64url_from_seed([91; 32]);
    let next = f.key.enroll_device(peer.authority(), f.key.certify_branch(branch)?, NOW + 1)?;
    let next = ramflux_crypto::custody::verify_record(&next, NOW + 1, None, None)?;
    let saved = {
        let tx = store.begin_write()?;
        let mut previous: AdoptedPeer =
            row(tx.open_table(TRUST)?.get(trust_key.as_str())?.ok_or("adopted source")?.value())?;
        previous.authority_pins.observe(&next)?;
        let saved = encoded(&previous)?;
        tx.open_table(TRUST)?.insert(trust_key.as_str(), saved.as_slice())?;
        tx.commit()?;
        saved
    };
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    let tx = store.begin_write()?;
    assert!(
        require_ingress_peer(&tx, &f.root, &peer).is_err(),
        "a still-valid original snapshot cannot bypass a newer independently retained Native head"
    );
    assert_eq!(
        tx.open_table(TRUST)?.get(trust_key.as_str())?.ok_or("retained source")?.value(),
        saved,
        "refusal cannot lower or replace the retained floor"
    );
    Ok(())
}

fn own_submission(
    peer: &ramflux_crypto::contact_reach::VerifiedPeer,
    traffic: ramflux_protocol::contact_reach::Traffic,
) -> TestResult<Submission> {
    use ramflux_protocol::{DeliveryClass, Ext, Priority, SignatureAlg, SignedFields};
    let root = peer.root();
    let actor = peer.authority().envelope().body.master_certificate.body.primary_device_ref.clone();
    let branch = ramflux_crypto::create_device_branch(
        peer.node(),
        &actor.device_id,
        actor.device_epoch,
        [3; 32],
    );
    let certificate = peer.authority().authorize(&actor, "sync", NOW)?;
    let ciphertext = digest(92);
    let mut envelope = ramflux_protocol::Envelope {
        schema: "ramflux.envelope.v2".into(),
        version: 2,
        domain: "ramflux.envelope.v2".into(),
        ext: Ext::default(),
        signed: SignedFields {
            signing_key_id: format!("{root}#{}", actor.device_id),
            signature_alg: SignatureAlg::Ed25519,
            signature: String::new(),
        },
        envelope_id: format!("own-home-{traffic:?}"),
        source_principal_id: peer.authority().envelope().body.principal_id.clone(),
        source_device_id: actor.device_id.clone(),
        target_delivery_id: ramflux_protocol::qualified_device_id(root, &actor.device_id)?,
        routing_set_id: None,
        delivery_class: DeliveryClass::Message,
        priority: Priority::Normal,
        ttl: 3600,
        created_at: i64::try_from(NOW)?,
        payload_hash: ramflux_protocol::hash_base64url(
            ramflux_protocol::domain::ENVELOPE,
            ciphertext.as_bytes(),
        ),
        encrypted_payload: ciphertext,
        delivery_mode: Some("durable".into()),
        collapse_tag: Some(digest(93)),
        report_commitment: Some(digest(94)),
    };
    envelope.ext.ext.insert("source_root_commitment".into(), root.into());
    envelope.ext.ext.insert("source_device_authority".into(), serde_json::json!({
        "custody_authority":{"publication":{"record":peer.authority().envelope(),"compacted_ids":null},"custodian_publication":null},
        "root_public_key":null,"signed_device_set":null,"principal_id":envelope.source_principal_id,
        "device_id":actor.device_id,"device_epoch":actor.device_epoch,
        "branch_public_key":certificate.branch_signing_public_key,
        "target_delivery_id":envelope.target_delivery_id,"revoked":false,
    }));
    envelope.signed.signature =
        ramflux_crypto::sign_protocol_object_with_device_branch(&branch, &envelope)?;
    let route = ramflux_crypto::contact_reach::sign_route(
        ramflux_protocol::contact_reach::Route {
            version: 1,
            source: actor,
            recipient_root: root.into(),
            conversation_id: "own-thread".into(),
            traffic,
            group: None,
            envelope_hash: custody::framed_hash(
                ramflux_protocol::contact_reach::ENVELOPE_HASH_DOMAIN,
                &envelope,
            )?,
            authority_head_hash: custody::object_hash(peer.authority().envelope())?,
            issued_at: NOW,
            expires_at: NOW + 3600,
        },
        &branch,
    )?;
    let submission = Submission { route, envelope, cost: None };
    ramflux_crypto::contact_reach::verify_current_source_submission(
        &submission,
        peer.authority(),
        NOW,
    )?;
    Ok(submission)
}

#[test]
fn cr_own_copy_and_self_sync_cannot_cross_a_competing_signed_home() -> TestResult {
    let _profile = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let dir = tempfile::TempDir::new()?;
    let (store, f) = initialize(&dir.path().join("own-home.redb"))?;
    let node = super::costs::issuer(&store, &f)?;
    let peer = crate::contact_reach::source::tests::verified_source()?;
    assert_eq!(peer.root(), f.root, "this control must use the SAME actual Native account");
    for traffic in [
        ramflux_protocol::contact_reach::Traffic::OwnCopy,
        ramflux_protocol::contact_reach::Traffic::SelfSync,
    ] {
        let submission = own_submission(&peer, traffic)?;
        let result = store.reach_admit(&node, &peer, &submission, NOW);
        assert!(
            matches!(
                result,
                Err(crate::contact_reach::ReachError::Refused(Reason::ForeignReadRefused))
            ),
            "a genuinely signed competing home cannot use own-account traffic labels to bypass current receiving home: {result:?}"
        );
    }
    assert!(store.reach_account(&f.root)?.is_none(), "refusal must not create policy or grants");
    Ok(())
}

#[test]
fn cr_own_copy_and_self_sync_admit_only_the_current_same_home() -> TestResult {
    let _profile = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
    let dir = tempfile::TempDir::new()?;
    let path = dir.path().join("current-own-home.redb");
    let (store, mut f) = initialize(&path)?;
    let peer = crate::contact_reach::source::tests::verified_source()?;
    // This fresh fixture's independently verified recipient head is the source's exact head.
    let evidence = peer.home().evidence();
    let tx = store.begin_write()?;
    tx.open_table(HEADS)?.insert(f.root.as_str(), encoded(evidence)?.as_slice())?;
    tx.commit()?;
    let node = crate::MigrationNode::new(
        evidence.node_record.clone(),
        [8; 32],
        crate::MigrationEndpoints {
            gateway_tcp_addr: "snapshot.example:443".into(),
            federation_endpoint: "https://snapshot.example".into(),
            discovery_hash: digest(95),
            server_record_hash: digest(96),
        },
        NOW,
    )?;
    f.home = peer.home().hash().into();
    store.reach_owner_commit(owner(&f), &policy(&f, 97, 0, ReachMode::ContactsOnly)?, NOW)?;
    let mut sequences = Vec::with_capacity(2);
    for traffic in [
        ramflux_protocol::contact_reach::Traffic::OwnCopy,
        ramflux_protocol::contact_reach::Traffic::SelfSync,
    ] {
        let submission = own_submission(&peer, traffic)?;
        let admitted = store.reach_admit(&node, &peer, &submission, NOW)?;
        assert_eq!(
            admitted.class,
            crate::contact_reach::ReachClass::Accepted,
            "current same-home sync authority belongs to the accepted reserve"
        );
        assert_eq!(
            admitted.placement,
            ramflux_protocol::contact_reach::Placement::Direct,
            "current own-device transport must retain direct placement"
        );
        sequences.push(admitted.seq);
        let repeated = store.reach_admit(&node, &peer, &submission, NOW)?;
        assert!(repeated.duplicate, "an unchanged current same-home retry must remain idempotent");
        assert_eq!(repeated.seq, admitted.seq, "retry must not reserve a second payload");
    }
    let OperationResult::Strangers { entries, .. } =
        store.reach_pending_page(owner(&f), 0, 16, &[], NOW)?
    else {
        return Err("bounded transfer page".into());
    };
    for entry in &entries {
        assert!(
            entry.reach.node_report_receipt.is_some(),
            "the current profile owns an actual signed node receipt"
        );
        assert_delivery_size(entry)?;
    }
    assert_eq!(accepted_entries(&store)?, 2, "both sealed target copies own pending charges");
    let first = *sequences.first().ok_or("first staged delivery")?;
    let second = *sequences.get(1).ok_or("second staged delivery")?;
    store.reach_pending_page(owner(&f), 0, 16, &[first], NOW)?;
    store.reach_pending_page(owner(&f), 0, 16, &[first], NOW)?;
    assert_eq!(
        accepted_entries(&store)?,
        1,
        "repeated transfer ACK releases only its own charge once"
    );
    drop(store);
    let store = RouterRedbStore::open_without_wal(&path)?;
    assert_eq!(accepted_entries(&store)?, 1, "pending ownership survives reopen");
    store.reach_pending_page(owner(&f), 0, 16, &[second], NOW)?;
    store.reach_pending_page(owner(&f), 0, 16, &[second], NOW)?;
    assert_eq!(
        accepted_entries(&store)?,
        0,
        "the final transfer releases the remaining charge exactly once"
    );
    Ok(())
}

fn accepted_entries(store: &RouterRedbStore) -> TestResult<u64> {
    let tx = store.begin_write()?;
    let table =
        tx.open_table(redb::TableDefinition::<&str, &[u8]>::new("contact_reach_counters_v1"))?;
    let row = table.get("accepted-global")?.ok_or("accepted pending counter")?;
    if row.value().len() > 256 {
        return Err("pending counter exceeded bounded fixture metadata".into());
    }
    let value: serde_json::Value = serde_json::from_slice(row.value())?;
    value.get("entries").and_then(serde_json::Value::as_u64).ok_or_else(|| "pending entries".into())
}

fn assert_delivery_size(entry: &ramflux_protocol::contact_reach::StrangerEntry) -> TestResult {
    let wire_entry = crate::InboxEntry {
        inbox_seq: u64::MAX,
        target_delivery_id: entry.envelope.target_delivery_id.clone(),
        envelope: entry.envelope.clone(),
        reach: Some(Box::new(entry.reach.clone())),
    };
    // Existing downstream bounds use conservative maximum-width integer placeholders.
    // This is a byte oracle, not a claim that those placeholders form an admissible frame.
    let incarnation = "f".repeat(32);
    let frames = [
        serde_json::json!({"frame_type":"deliver","entry":wire_entry}),
        serde_json::json!({"frame_type":"deliver","incarnation_id":incarnation,
            "entry":wire_entry,"retain_until":i64::MIN}),
        serde_json::json!({"frame_type":"entry","incarnation_id":incarnation,
            "record":{"entry":wire_entry,"retain_until":i64::MIN}}),
    ];
    let largest = frames
        .iter()
        .map(|frame| serde_json::to_vec(frame).map(|bytes| bytes.len()))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or("downstream frames")?;
    assert_eq!(
        crate::single_reach_delivery_frame_size(&entry.envelope, &entry.reach)?,
        largest,
        "actual report receipt and explicit nulls must count in the exact largest downstream frame"
    );
    let without_receipt = Submission {
        envelope: entry.envelope.clone(),
        route: entry.reach.route.clone(),
        cost: entry.reach.cost.clone(),
    };
    assert!(
        crate::single_reach_entry_frame_size(&without_receipt)? < largest,
        "the sender preflight cannot account for the receiving home's later signed receipt"
    );
    Ok(())
}

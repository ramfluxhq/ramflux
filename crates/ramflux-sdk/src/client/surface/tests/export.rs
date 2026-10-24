// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Peer-driven export regressions and validated same-root checkpoint replication.
use super::*;
#[test]
fn peer_without_snapshot_proof_exports_and_restores_its_validated_checkpoint() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let exported = f.human.own_surface_history_export(None)?;
    assert_eq!(exported.checkpoints.len(), 1);
    assert!(!exported.metadata.truncated);
    assert!(exported.metadata.skipped.is_empty());
    let mut replica = client(&f.root.join("replica"), "human", 35)?;
    replica.create_device_branch("human", "human-two", 1, [37; 32]);
    replica.import_owned_surface_checkpoints(&exported.checkpoints)?;
    let expected = f.human.surface_get("s", 0, None)?;
    let actual = replica.surface_get("s", 0, None)?;
    for field in ["snapshot", "version", "surface_hash", "closed", "fallback_text"] {
        assert_eq!(actual[field], expected[field]);
    }
    let mut damaged = serde_json::to_value(&exported.checkpoints[0])?;
    damaged["version"] = json!(99);
    let damaged = serde_json::from_value(damaged)?;
    replica.import_owned_surface_checkpoints(&[damaged])?;
    let conflict = replica.surface_get("s", 0, None)?;
    assert_eq!(conflict["snapshot"], actual["snapshot"]);
    assert_eq!(conflict["surface_hash"], actual["surface_hash"]);
    assert_eq!(conflict["out_of_sync"], true);
    Ok(())
}
#[test]
fn sixty_five_peer_surfaces_export_a_marked_window_and_page_the_oldest() -> TestResult {
    let f = Fixture::new()?;
    let mut own_content = snapshot();
    own_content.surface_id = "own".into();
    let mut own =
        carrier(&f.human, PayloadKind::Event, "own", &event(1, C::CreateSurface(snapshot()))?)?;
    own.wire_base64 = ramflux_protocol::encode_base64url(event(1, C::CreateSurface(own_content))?);
    own.surface_id = "own".into();
    own.author_principal_id = "human".into();
    own = f.human.sign_surface_carrier(own)?;
    assert!(project(&f.human, &own, "own")?.accepted);
    for i in 0..65 {
        let mut content = snapshot();
        content.surface_id = format!("s{i}");
        let mut signed = carrier(
            &f.author,
            PayloadKind::Event,
            &format!("create-{i}"),
            &event(1, C::CreateSurface(snapshot()))?,
        )?;
        signed.surface_id = format!("s{i}");
        signed.wire_base64 =
            ramflux_protocol::encode_base64url(event(1, C::CreateSurface(content))?);
        signed = f.author.sign_surface_carrier(signed)?;
        assert!(project(&f.human, &signed, &signed.message_id)?.accepted);
    }
    let exported = f.human.own_surface_history_export(None)?;
    assert!(exported.metadata.truncated);
    assert_eq!(exported.checkpoints.len(), 64);
    assert!(
        exported
            .checkpoints
            .iter()
            .any(|c| serde_json::to_value(c).is_ok_and(|v| v["record"]["surface_id"] == "own"))
    );
    assert_eq!(serde_json::to_value(&exported.checkpoints[0])?["record"]["surface_id"], "s2");
    let all = f.human.own_surface_history_pages()?;
    assert_eq!(all.len(), 2);
    assert_eq!(all.iter().map(|p| p.checkpoints.len()).sum::<usize>(), 66);
    let older = f.human.own_surface_history_export(exported.metadata.next_before)?;
    assert!(!older.metadata.truncated);
    assert_eq!(older.checkpoints.len(), 2);
    assert_eq!(serde_json::to_value(&older.checkpoints[0])?["record"]["surface_id"], "s0");
    let recorded: Value =
        f.human.account_db()?.load_actor_state("surface/export_metadata")?.ok_or("metadata")?;
    assert_eq!(recorded["truncated"], false);
    Ok(())
}
#[test]
fn one_hundred_twenty_eight_actions_do_not_abort_export_or_silently_use_a_hundred_row_cap()
-> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    for version in 1..=128 {
        if version > 1 {
            let signed = carrier(
                &f.author,
                PayloadKind::Event,
                &format!("v{version}"),
                &event(
                    version,
                    C::StreamAppend(StreamAppendCommand {
                        surface_id: "s".into(),
                        component_id: "stream".into(),
                        text_delta: String::new(),
                        final_: false,
                    }),
                )?,
            )?;
            assert!(project(&f.author, &signed, &signed.message_id)?.accepted);
        }
        let hash =
            f.author.surface_get("s", 0, None)?["surface_hash"].as_str().ok_or("hash")?.to_owned();
        let signed = action(&f.human, &format!("decision-{version}"), version, &hash)?;
        assert!(project(&f.author, &signed, &signed.message_id)?.accepted);
    }
    let reference =
        f.author.surface_get("s", 0, None)?["surface_ref"].as_str().ok_or("ref")?.to_owned();
    let prefix = key("actions", &reference) + "/";
    assert_eq!(
        f.author.account_db()?.surface_recent_records::<Value>(&prefix, None, 129)?.len(),
        128
    );
    let exported = f.author.own_surface_history_export(None)?;
    assert_eq!(exported.checkpoints.len(), 1);
    // This fixture has only verified key records, without forwardable full directory manifests.
    // Every retained decision is examined and its explicit omission is recorded, including 101..128.
    assert_eq!(exported.metadata.skipped.get("action_attestation_unavailable"), Some(&128));
    assert!(!exported.metadata.truncated);
    cache_human_manifest(&f)?;
    let with_trust = f.author.own_surface_history_export(None)?;
    assert_eq!(with_trust.controls.len(), 128);
    assert!(with_trust.metadata.skipped.is_empty());
    assert!(!with_trust.metadata.truncated);
    Ok(())
}

fn cache_human_manifest(f: &Fixture) -> TestResult {
    let root = f.human.identity_root.as_ref().ok_or("root")?;
    let branch = f.human.device_branch.as_ref().ok_or("device")?;
    let root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let principal_commitment = crate::identity_root_public_key_commitment(&root_public_key)?;
    let branch_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    let branch_proof = ramflux_crypto::authorize_device_branch(
        root,
        branch,
        "ramflux-node",
        vec!["device.delivery.bind".into()],
        1_700_000_000,
        4_000_000_000,
    )?;
    let identity = ramflux_crypto::X25519KeyPair::from_seed([44; 32]);
    let signed = ramflux_crypto::X25519KeyPair::from_seed([45; 32]);
    let prekey_bundle =
        ramflux_crypto::create_prekey_bundle(branch, &identity, "signed-key", &signed, None, None)?;
    let manifest = crate::prekey::SdkDeviceManifestResponse {
        principal_id: "human".into(),
        principal_commitment: principal_commitment.clone(),
        root_public_key,
        devices: vec![crate::prekey::SdkDeviceManifestEntry {
            principal_id: "human".into(),
            principal_commitment: principal_commitment.clone(),
            device_id: branch.device_id.clone(),
            device_epoch: 1,
            branch_public_key,
            target_delivery_id: "target-human".into(),
            branch_proof,
            prekey_bundle,
            branch_authorized_event_id: "device.branch_authorized:human-device:1".into(),
        }],
    };
    RamfluxClient::verify_device_manifest_json(
        serde_json::to_value(&manifest)?,
        &principal_commitment,
    )?;
    f.author.account_db()?.persist_actor_state("identity/manifest/human", &manifest)?;
    Ok(())
}

#[test]
fn placeholders_never_displace_validated_export_and_expire() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let before = serde_json::to_value(f.human.own_surface_history_export(None)?)?;
    for i in 0..64 {
        let mut held = carrier(
            &f.author,
            PayloadKind::Event,
            &format!("held-{i}"),
            &event(1, C::CreateSurface(snapshot()))?,
        )?;
        held.wire_base64 = ramflux_protocol::encode_base64url(event(
            3,
            C::StreamAppend(StreamAppendCommand {
                surface_id: format!("unknown-{i}"),
                component_id: "stream".into(),
                text_delta: "future".into(),
                final_: false,
            }),
        )?);
        held.surface_id = format!("unknown-{i}");
        held = f.author.sign_surface_carrier(held)?;
        assert!(project(&f.human, &held, &held.message_id)?.queued);
    }
    assert_eq!(serde_json::to_value(f.human.own_surface_history_export(None)?)?, before);
    let db = f.human.account_db()?;
    for (key, mut pending) in
        db.surface_record_page::<Value>("surface/pending/", "surface/pending/", 65)?
    {
        pending["expires_at"] = json!(0);
        db.persist_actor_state(&key, &pending)?;
    }
    f.human.expire_surface_pending()?;
    assert_eq!(db.surface_recent_records::<Value>("directory/surface/", None, 129)?.len(), 1);
    assert_eq!(serde_json::to_value(f.human.own_surface_history_export(None)?)?, before);
    Ok(())
}
#[test]
fn divergent_checkpoint_does_not_abort_honest_surface_and_retries_are_idempotent() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let original = f.human.own_surface_history_export(None)?.checkpoints.remove(0);
    let mut content = snapshot();
    content.surface_id = "honest".into();
    let mut honest =
        carrier(&f.author, PayloadKind::Event, "honest", &event(1, C::CreateSurface(snapshot()))?)?;
    honest.wire_base64 = ramflux_protocol::encode_base64url(event(1, C::CreateSurface(content))?);
    honest.surface_id = "honest".into();
    honest = f.author.sign_surface_carrier(honest)?;
    assert!(project(&f.human, &honest, "honest")?.accepted);
    let exported = f.human.own_surface_history_export(None)?;
    let mut replica = client(&f.root.join("conflict-replica"), "human", 35)?;
    replica.create_device_branch("human", "human-two", 1, [37; 32]);
    replica.import_owned_surface_checkpoints(std::slice::from_ref(&original))?;
    let mut corrupt = serde_json::to_value(&original)?;
    corrupt["surface_hash"] = json!("divergent-content");
    let corrupt = serde_json::from_value(corrupt)?;
    let mut items = vec![corrupt];
    items.extend(
        exported.checkpoints.into_iter().filter(|v| {
            serde_json::to_value(v).is_ok_and(|v| v["record"]["surface_id"] == "honest")
        }),
    );
    for _ in 0..2 {
        replica.import_owned_surface_checkpoints(&items)?;
    }
    assert_eq!(replica.surface_get("honest", 0, None)?["version"], 1);
    let preserved = replica.surface_get("s", 0, None)?;
    assert_eq!(preserved["version"], 1);
    assert_eq!(preserved["out_of_sync"], true);
    assert_eq!(
        replica
            .account_db()?
            .surface_history_page::<Value>("surface/import_skip/", "surface/import_skip/", 65)?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn repeated_checkpoint_retains_the_original_signed_history_entry() -> TestResult {
    let f = Fixture::new()?;
    create(&f)?;
    let owned = f.human.export_owned_surface_checkpoint(
        &f.human.resolve_surface_reference("s", None, None)?.ok_or("reference")?,
    )?;
    let reference = owned.record.surface_id.clone();
    let scope = f.human.resolve_surface_reference(&reference, None, None)?.ok_or("scope")?;
    let history_key = format!("{}/{:020}", super::super::key("history", &scope), owned.version);
    let before: Value = f.human.account_db()?.load_actor_state(&history_key)?.ok_or("history")?;
    assert!(before["carrier"].is_object());
    f.human.import_owned_surface_checkpoints(&[owned])?;
    assert_eq!(f.human.account_db()?.load_actor_state::<Value>(&history_key)?, Some(before));
    Ok(())
}

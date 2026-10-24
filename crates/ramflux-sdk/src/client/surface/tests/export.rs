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
    assert!(replica.import_owned_surface_checkpoints(&[damaged]).is_err());
    assert_eq!(replica.surface_get("s", 0, None)?, actual);
    Ok(())
}
#[test]
fn sixty_five_peer_surfaces_export_a_marked_window_and_page_the_oldest() -> TestResult {
    let f = Fixture::new()?;
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
    assert_eq!(serde_json::to_value(&exported.checkpoints[0])?["record"]["surface_id"], "s1");
    let older = f.human.own_surface_history_export(exported.metadata.next_before)?;
    assert!(!older.metadata.truncated);
    assert_eq!(older.checkpoints.len(), 1);
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

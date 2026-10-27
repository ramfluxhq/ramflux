// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable public heads survive restart without replacing independently held credentials.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use crate::custody::load_account;
fn authority(fixture: &Fixture) -> TestResult<CustodyAuthority> {
    let native = fixture.manifest.custody.as_ref().ok_or("native")?;
    Ok(CustodyAuthority {
        publication: native.publication.clone(),
        custodian_publication: native.custodian_publication.clone(),
    })
}
#[tokio::test]
async fn native_own_head_survives_restart_with_credentials_and_registration_state_intact()
-> TestResult {
    let fixture = Fixture::new("native-own-publication").await?;
    let now = crate::custody::network_now()?;
    let root = &fixture.root.0;
    let id = fixture.client.account_db()?.local_account_id.clone();
    let path = root.join("custody_accounts").join(&id).join("authority.json");
    let mut original = load_account(root, &id, now)?;
    // Exercise the persistence transition only; this test does not create a network session.
    original.mark_live(root)?;
    let before: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    let mut next = authority(&fixture)?;
    let primary = fixture.vault.primary_for_public_key(
        &next.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = next.publication.record.body.clone();
    body.previous_record_hash =
        Some(ramflux_protocol::custody::object_hash(&next.publication.record)?);
    body.device_set_epoch += 1;
    body.profile.display_name = "A current public name".into();
    next.publication.record = primary.sign_record(body)?;
    assert_eq!(accept_publication(root, &id, &next, now)?, PinOutcome::Advanced);
    assert_eq!(accept_publication(root, &id, &next, now)?, PinOutcome::Unchanged);
    assert!(accept_publication(root, &id, &authority(&fixture)?, now).is_err());
    let reloaded = load_account(root, &id, now)?;
    assert_eq!(reloaded.publication(), next.publication);
    assert_eq!(reloaded.state(), crate::custody::CreationState::Live);
    reloaded.credentials(fixture.vault.as_ref(), "primary", now)?;
    let after: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    for field in [
        "primary_vault_ref",
        "branch_vault_ref",
        "local_device_id",
        "vault_class",
        "custody_v3_observed",
    ] {
        assert_eq!(after[field], before[field]);
    }
    for field in ["root_seed", "device_seed", "phrase", "master_seed", "self_signing_seed"] {
        assert!(after.get(field).is_none());
    }
    Ok(())
}
#[tokio::test]
async fn native_owned_file_floor_blocks_stale_cache_before_metadata_is_updated() -> TestResult {
    let fixture = Fixture::new("native-own-floor").await?;
    let now = crate::custody::network_now()?;
    let mut next = authority(&fixture)?;
    let primary = fixture.vault.primary_for_public_key(
        &next.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let identity = fixture.client.owned_device_identity()?;
    let current = fixture
        .client
        .current_custody_authority(identity.root_commitment(), now)?
        .ok_or("current")?;
    next.publication.record = primary.revoke_device(&current, "primary", now)?;
    // A gateway reconnect can update the public file before the account actor cache.
    accept_publication(
        &fixture.root.0,
        fixture.client.account_db()?.local_account_id.as_str(),
        &next,
        now,
    )?;
    let error = fixture
        .client
        .require_current_device_authorization(&identity)
        .err()
        .ok_or("stale grant")?;
    assert!(error.to_string().contains("own custody cache is behind the durable authority floor"));
    let reloaded =
        load_account(&fixture.root.0, &fixture.client.account_db()?.local_account_id, now)?;
    assert!(reloaded.credentials(fixture.vault.as_ref(), "primary", now).is_err());
    Ok(())
}
#[tokio::test]
async fn native_own_equivocation_is_durable_and_cannot_reuse_cached_permissions() -> TestResult {
    let fixture = Fixture::new("native-own-fence").await?;
    let mut native = fixture.manifest.custody.as_ref().ok_or("native")?.clone();
    let primary = fixture.vault.primary_for_public_key(
        &native.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = native.publication.record.body.clone();
    body.profile.display_name = "Same epoch conflict".into();
    native.publication.record = primary.sign_record(body)?;
    let now = crate::custody::network_now()?;
    assert!(
        fixture
            .client
            .observe_custody_manifest(&native, &fixture.manifest.principal_commitment, now)
            .is_err()
    );
    assert!(
        load_account(&fixture.root.0, &fixture.client.account_db()?.local_account_id, now).is_err()
    );
    assert!(
        fixture
            .client
            .require_current_device_authorization(&fixture.client.owned_device_identity()?)
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn native_own_checkpoint_payload_is_retained_across_publication_and_live_marking()
-> TestResult {
    let fixture = Fixture::new("native-own-checkpoint").await?;
    let mut next = authority(&fixture)?;
    let now = crate::custody::network_now()?;
    let primary = fixture.vault.primary_for_public_key(
        &next.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = next.publication.record.body.clone();
    body.previous_record_hash =
        Some(ramflux_protocol::custody::object_hash(&next.publication.record)?);
    body.device_set_epoch += 1;
    let names = vec!["permanently-retired".to_owned()];
    let checkpoint = ramflux_protocol::custody::RevokedCheckpoint {
        schema: ramflux_protocol::domain::CUSTODY_REVOKED_CHECKPOINT.into(),
        version: 1,
        account_anchor: body.account_anchor.clone(),
        master_certificate_hash: ramflux_protocol::custody::object_hash(&body.master_certificate)?,
        device_set_epoch: body.device_set_epoch,
        previous_checkpoint_hash: None,
        list_hash: ramflux_protocol::custody::framed_hash(
            ramflux_protocol::domain::CUSTODY_REVOKED_LIST,
            &names,
        )?,
        count: 1,
        compacted_before: now.saturating_sub(7_776_000),
        issued_at: now,
    };
    let signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::custody::signing_bytes(
            ramflux_protocol::domain::CUSTODY_REVOKED_CHECKPOINT,
            &checkpoint,
        )?,
        *primary.vault_seed(),
    );
    body.revoked_device_checkpoint =
        Some(ramflux_protocol::custody::Envelope { body: checkpoint, signature });
    next.publication.record = primary.sign_record(body)?;
    next.publication.compacted_ids = Some(names);
    let id = &fixture.client.account_db()?.local_account_id;
    accept_publication(&fixture.root.0, id, &next, now)?;
    let mut reloaded = load_account(&fixture.root.0, id, now)?;
    assert_eq!(reloaded.publication(), next.publication);
    reloaded.mark_live(&fixture.root.0)?;
    assert_eq!(load_account(&fixture.root.0, id, now)?.publication(), next.publication);
    Ok(())
}

#[tokio::test]
async fn native_fenced_authority_preserves_data_unlock_without_granting_credentials() -> TestResult
{
    let fixture = Fixture::new("native-fenced-data").await?;
    let id = fixture.client.account_db()?.local_account_id.clone();
    fixture.client.append_event("before-fence", "test.data", b"readable after fencing")?;
    let mut conflict = authority(&fixture)?;
    let primary = fixture.vault.primary_for_public_key(
        &conflict.publication.record.body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = conflict.publication.record.body.clone();
    body.profile.display_name = "Conflicting same-epoch name".into();
    conflict.publication.record = primary.sign_record(body)?;
    let now = crate::custody::network_now()?;
    assert_eq!(accept_publication(&fixture.root.0, &id, &conflict, now)?, PinOutcome::Fenced);
    drop(fixture.client);
    let mut reopened = crate::RamfluxClient::new();
    reopened.open_account_index(&fixture.root.0)?;
    assert!(reopened.unlock_account(&id, b"wrong passphrase").is_err());
    reopened.unlock_account(&id, b"native fixture data passphrase")?;
    assert_eq!(reopened.event_body("before-fence")?, Some(b"readable after fencing".to_vec()));
    let data = reopened.born_v3_account.as_ref().ok_or("native data")?;
    assert!(data.authority_blocked());
    assert_eq!(data.state(), crate::custody::CreationState::NetworkingPending);
    assert!(data.credentials(fixture.vault.as_ref(), "primary", now).is_err());
    assert!(reopened.initialize_born_v3_branch("primary", fixture.vault.clone()).await.is_err());
    assert!(matches!(reopened.require_legacy_networking(), Err(SdkError::NetworkingPending)));
    assert!(reopened.identity_root.is_none());
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Manual safety verification upgrades without inventing authenticated kind or forgetting stamps.
use super::*;
use crate::client::contact_verification::{MIGRATION_MARKER, migrate_legacy_contact_verifications};
use serde_json::json;

fn directory_request(account: &str) -> LocalBusFrame {
    LocalBusFrame::request(
        "directory",
        Some(account.into()),
        "client",
        "identity.directory",
        json!({}),
    )
}

#[tokio::test]
async fn legacy_card_synthetic_verification_agrees_across_views_without_authenticating_kind()
-> TestResult {
    let owner = Actor::new("owner", "phone", 81, 82, 1)?;
    let mut peer = Actor::new("peer", "peer", 83, 84, 1)?;
    let root = owner.manifest()?.principal_commitment;
    let own_root = peer.manifest()?.principal_commitment;
    peer.client.establish_friend_link("contact", &own_root, &root)?;
    peer.client.account_db()?.persist_client_record(
        "identity",
        "owner",
        &json!({
            "principal_id":"owner", "contact_identity_commitment":root, "display_name":"Owner",
            "root_source":"card", "device_set_hash":"legacy-card-device-hash",
        }),
    )?;
    assert!(peer.client.observed_device_set(&root)?.is_none());
    assert_eq!(
        peer.client.mark_contact_safety_verified(&root, "peer")?.verification_state,
        "verified"
    );
    let stamp_key = format!("identity/safety_verified_set/{root}");
    assert!(peer.client.account_db()?.load_actor_state::<String>(&stamp_key)?.is_none());
    assert_eq!(peer.client.contact_safety_number(&root)?.verification_state, "verified");
    assert!(peer.client.verified_principal_kind("owner")?.is_none());
    assert_eq!(peer.client.contact_entry("owner")?["verified"], true);
    assert_eq!(peer.client.contact_entry("owner")?["kind_verified"], false);
    peer.reopen()?;
    assert_eq!(peer.client.contact_safety_number(&root)?.verification_state, "verified");
    let db = peer.client.account_db()?;
    let result = crate::bus::test_account_reader_request(db, directory_request(&peer.id)).await?;
    let row = result["identities"]
        .as_array()
        .ok_or("identities")?
        .iter()
        .find(|r| r["principal_id"] == "owner")
        .ok_or("owner")?;
    assert_eq!(row["safety_state"], "verified");
    assert_eq!(row["verified"], true);
    assert_eq!(row["kind_verified"], false);
    assert!(db.load_actor_state::<String>(&stamp_key)?.is_none());
    Ok(())
}

#[tokio::test]
async fn legacy_verification_is_baselined_before_the_first_query_only_directory_read() -> TestResult
{
    for matches in [true, false] {
        let owner = Actor::new("owner", "phone", 85, 86, 1)?;
        let mut peer = Actor::new("peer", "peer", 87, 88, 1)?;
        let manifest = with_profile(&owner, owner.manifest()?, "Owner", 1, 1)?;
        observe(&peer.client, &manifest)?;
        let db = peer.client.account_db()?;
        let identity = db.client_record("identity", "owner")?.ok_or("identity")?;
        let current_hash = identity["device_set_hash"].as_str().ok_or("hash")?;
        db.mark_contact_verified(ramflux_storage::ContactVerificationUpdate {
            contact_identity_commitment: &manifest.principal_commitment,
            safety_number_hash: "legacy-safety",
            device_set_hash: if matches { current_hash } else { "old-device-hash" },
            lineage_head: "legacy-lineage",
            verified_at: 1,
            verified_by_device_id: "peer",
        })?;
        // Simulate an account written before the migration marker existed.
        db.remove_actor_state(MIGRATION_MARKER)?;
        let stamp_key = format!("identity/safety_verified_set/{}", manifest.principal_commitment);
        assert!(db.load_actor_state::<String>(&stamp_key)?.is_none());
        assert!(!db.is_query_only()?);
        let query = db.open_reader()?;
        assert!(query.is_query_only()?);
        assert!(query.persist_actor_state("must-stay-read-only", &true).is_err());
        let mut reader = RamfluxClient::new();
        reader.active_account_db = Some(query);
        assert_eq!(
            reader.contact_safety_verification_state(
                &manifest.principal_commitment,
                Some(current_hash)
            )?,
            "verification_stale"
        );
        assert!(db.load_actor_state::<String>(&stamp_key)?.is_none());
        drop(reader);
        peer.reopen()?;
        let db = peer.client.account_db()?;
        assert_eq!(db.load_actor_state::<bool>(MIGRATION_MARKER)?, Some(true));
        let result =
            crate::bus::test_account_reader_request(db, directory_request(&peer.id)).await?;
        let row = result["identities"]
            .as_array()
            .ok_or("identities")?
            .iter()
            .find(|r| r["principal_id"] == "owner")
            .ok_or("owner")?;
        let expected = if matches { "verified" } else { "verification_stale" };
        assert_eq!(row["safety_state"], expected);
        assert_eq!(row["verified"], matches);
        assert_eq!(row["kind_verified"], true);
        assert_eq!(
            peer.client.contact_safety_verification_state(
                &manifest.principal_commitment,
                Some(current_hash)
            )?,
            expected
        );
        let stamp = db.load_actor_state::<String>(&stamp_key)?;
        if matches {
            assert_eq!(
                stamp,
                Some(set_fingerprint(manifest.signed_device_set.as_ref().ok_or("set")?)?)
            );
            assert_eq!(peer.client.verified_principal_kind("owner")?, Some(PrincipalKind::Human));
        } else {
            assert!(stamp.is_none(), "a device-hash mismatch must not acquire a migration stamp");
            assert!(peer.client.verified_principal_kind("owner")?.is_none());
        }
    }
    Ok(())
}

fn legacy_record(client: &RamfluxClient, manifest: &SdkDeviceManifestResponse) -> TestResult {
    let db = client.account_db()?;
    let row = db.client_record("identity", &manifest.principal_id)?.ok_or("identity")?;
    db.mark_contact_verified(ramflux_storage::ContactVerificationUpdate {
        contact_identity_commitment: &manifest.principal_commitment,
        safety_number_hash: "legacy-safety",
        device_set_hash: row["device_set_hash"].as_str().ok_or("hash")?,
        lineage_head: "legacy-lineage",
        verified_at: 1,
        verified_by_device_id: "peer",
    })?;
    Ok(())
}

#[test]
fn confirmed_safety_commit_writes_authority_before_any_later_read() -> TestResult {
    let owner = Actor::new("owner", "phone", 101, 102, 1)?;
    let peer = Actor::new("peer", "peer", 103, 104, 1)?;
    let manifest = with_profile(&owner, owner.manifest()?, "Owner", 1, 1)?;
    let own = peer.manifest()?;
    observe(&peer.client, &manifest)?;
    observe(&peer.client, &own)?;
    peer.client.establish_friend_link(
        "contact",
        &own.principal_commitment,
        &manifest.principal_commitment,
    )?;
    let safety = peer.client.contact_safety_number(&manifest.principal_commitment)?;
    let own_material = crate::client::contact::contact_safety_material_from_manifest(&own)?;
    let material = crate::client::contact::contact_safety_material_from_manifest(&manifest)?;
    let key = format!("identity/safety_verified_set/{}", manifest.principal_commitment);
    let db = peer.client.account_db()?;
    assert!(db.load_actor_state::<String>(&key)?.is_none());
    peer.client.commit_contact_safety(&safety, &own_material, &material, "peer")?;
    let stamp = set_fingerprint(manifest.signed_device_set.as_ref().ok_or("set")?)?;
    assert_eq!(
        db.load_actor_state::<String>(&key)?,
        Some(stamp.clone()),
        "confirmation writer must persist authority without reading a contact view"
    );
    let retired = Actor::new("owner", "retired", 101, 105, 1)?;
    let changed = with_revoked_device(&owner, &manifest, &retired)?;
    observe(&peer.client, &changed)?;
    assert_eq!(
        peer.client.contact_safety_number(&manifest.principal_commitment)?.contact_device_set_hash,
        safety.contact_device_set_hash
    );
    assert_eq!(
        peer.client.contact_safety_number(&manifest.principal_commitment)?.verification_state,
        "verification_stale"
    );
    assert_eq!(db.load_actor_state::<String>(&key)?, Some(stamp));
    Ok(())
}

#[tokio::test]
async fn sealed_migration_never_absorbs_new_unstamped_records_or_rescans_on_reader_start()
-> TestResult {
    let owner = Actor::new("owner", "phone", 111, 112, 1)?;
    let peer = Actor::new("peer", "peer", 113, 114, 1)?;
    let manifest = with_profile(&owner, owner.manifest()?, "Owner", 1, 1)?;
    let db = peer.client.account_db()?;
    assert_eq!(db.load_actor_state::<bool>(MIGRATION_MARKER)?, Some(true));
    observe(&peer.client, &manifest)?;
    legacy_record(&peer.client, &manifest)?;
    let row = db.client_record("identity", "owner")?.ok_or("identity")?;
    let key = format!("identity/safety_verified_set/{}", manifest.principal_commitment);
    assert_eq!(
        peer.client.contact_safety_verification_state(
            &manifest.principal_commitment,
            row["device_set_hash"].as_str()
        )?,
        "verification_stale"
    );
    migrate_legacy_contact_verifications(db)?;
    assert!(db.load_actor_state::<String>(&key)?.is_none());
    assert_eq!(peer.client.contact_entry("owner")?["verified"], false);
    let directory =
        crate::bus::test_account_reader_request(db, directory_request(&peer.id)).await?;
    let owner_row = directory["identities"]
        .as_array()
        .ok_or("identities")?
        .iter()
        .find(|r| r["principal_id"] == "owner")
        .ok_or("owner")?;
    assert_eq!(owner_row["safety_state"], "verification_stale");
    assert!(db.load_actor_state::<String>(&key)?.is_none());
    // A later malformed authority would fail the old full scan. Sealed startup must not scan it.
    db.persist_actor_state(
        &record_key(&manifest.principal_commitment),
        &json!({"invalid":"authority"}),
    )?;
    let messages = crate::bus::test_account_reader_request(
        db,
        LocalBusFrame::request(
            "messages",
            Some(peer.id.clone()),
            "client",
            "message.list",
            json!({"conversation_id":"empty"}),
        ),
    )
    .await?;
    assert_eq!(messages["messages"].as_array().map(Vec::len), Some(0));
    assert_eq!(db.load_actor_state::<bool>(MIGRATION_MARKER)?, Some(true));
    Ok(())
}

#[derive(Clone, Default)]
struct MigrationLogs(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
impl tracing::Subscriber for MigrationLogs {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, "{field}={value:?} ");
            }
        }
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(fields.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn legacy_unlock_skips_corrupt_contact_warns_once_and_migrates_healthy_contact() -> TestResult {
    let alpha = Actor::new("alpha", "phone", 121, 122, 1)?;
    let beta = Actor::new("beta", "phone", 123, 124, 1)?;
    let mut peer = Actor::new("peer", "peer", 125, 126, 1)?;
    let a = with_profile(&alpha, alpha.manifest()?, "Alpha", 1, 1)?;
    let b = with_profile(&beta, beta.manifest()?, "Beta", 1, 1)?;
    for manifest in [&a, &b] {
        observe(&peer.client, manifest)?;
        legacy_record(&peer.client, manifest)?;
    }
    peer.client.account_db()?.remove_actor_state(MIGRATION_MARKER)?;
    peer.client.account_db()?.persist_actor_state(
        &record_key(&b.principal_commitment),
        &json!({"record-body-canary":"invalid"}),
    )?;
    let logs = MigrationLogs::default();
    tracing::subscriber::with_default(logs.clone(), || peer.reopen())?;
    let db = peer.client.account_db()?;
    assert_eq!(db.load_actor_state::<bool>(MIGRATION_MARKER)?, Some(true));
    assert_eq!(
        db.load_actor_state::<String>(&format!(
            "identity/safety_verified_set/{}",
            a.principal_commitment
        ))?,
        Some(set_fingerprint(a.signed_device_set.as_ref().ok_or("set")?)?)
    );
    assert!(
        db.load_actor_state::<String>(&format!(
            "identity/safety_verified_set/{}",
            b.principal_commitment
        ))?
        .is_none()
    );
    let healthy = db.client_record("identity", "alpha")?.ok_or("alpha")?;
    assert_eq!(
        peer.client.contact_safety_verification_state(
            &a.principal_commitment,
            healthy["device_set_hash"].as_str()
        )?,
        "verified"
    );
    assert!(matches!(
        peer.client.contact_safety_verification_state(&b.principal_commitment, Some("hash")),
        Err(SdkError::Storage(ramflux_storage::StorageError::Serde(_)))
    ));
    assert!(matches!(
        peer.client.verified_principal_kind("beta"),
        Err(SdkError::Storage(ramflux_storage::StorageError::Serde(_)))
    ));
    tracing::subscriber::with_default(logs.clone(), || peer.reopen())?;
    let entries = logs.0.lock().map_err(|_| "log lock")?;
    let warnings = entries
        .iter()
        .filter(|e| e.contains("skipping legacy contact verification migration"))
        .collect::<Vec<_>>();
    assert_eq!(warnings.len(), 1, "{entries:?}");
    assert!(warnings[0].contains("contact_id=\"beta\""));
    assert!(warnings[0].contains("error_class=\"record_decode\""));
    assert!(!warnings[0].contains("record-body-canary"));
    Ok(())
}

fn merge_verification_reader(
    source: &Actor,
    target: &Actor,
    native_data_only: bool,
) -> Result<RamfluxClient, Box<dyn std::error::Error>> {
    use ramflux_storage::{AccountDb, AccountIndex, BackupDatabase};
    let archive = source.path.join("archive.db");
    let saved = source.client.account_db()?.write_backup_snapshot(&archive)?;
    let staging = target.path.join("merged.db");
    let copied = target.client.account_db()?.write_backup_snapshot(&staging)?;
    let mut merged = BackupDatabase::open(&staging, &copied.key)?;
    if native_data_only {
        merged.merge_native_backup(&archive, &saved.key, || Ok(()))?;
    } else {
        merged.merge_backup(&archive, &saved.key, || Ok(()))?;
    }
    drop(merged);
    // Reopen the production merge's durable generation and use the SDK verification reader.
    let installed = AccountIndex::open(target.path.join("installed"))?;
    let row = installed.create_account("peer", "peer")?;
    std::fs::copy(&staging, installed.root().join(row.db_relative_path))?;
    let db = AccountDb::open(&installed, "peer", &copied.key)?;
    let mut reader = RamfluxClient::new();
    reader.active_account_db = Some(db);
    Ok(reader)
}

#[test]
fn markerless_backup_merge_baselines_only_winning_imported_verified_rows() -> TestResult {
    // Full legacy merge, modern full merge, and data-only merge use the real encrypted merger.
    for mode in ["legacy", "marked", "native", "stamped"] {
        let owner = Actor::new("owner", "phone", 131, 132, 1)?;
        let other = Actor::new("other", "phone", 133, 134, 1)?;
        let conflict = Actor::new("conflict", "phone", 137, 138, 1)?;
        let source = Actor::new("peer", "peer", 135, 136, 1)?;
        let target = Actor::new("peer", "peer", 135, 136, 1)?;
        let incoming = with_profile(&owner, owner.manifest()?, "Owner", 1, 1)?;
        let unrelated = with_profile(&other, other.manifest()?, "Other", 1, 1)?;
        let rejected = with_profile(&conflict, conflict.manifest()?, "Conflict", 1, 1)?;
        observe(&source.client, &incoming)?;
        legacy_record(&source.client, &incoming)?;
        for client in [&source.client, &target.client] {
            observe(client, &rejected)?;
            legacy_record(client, &rejected)?;
        }
        let row =
            target.client.account_db()?.client_record("identity", "conflict")?.ok_or("conflict")?;
        target.client.account_db()?.mark_contact_verified(
            ramflux_storage::ContactVerificationUpdate {
                contact_identity_commitment: &rejected.principal_commitment,
                safety_number_hash: "local-newer",
                device_set_hash: row["device_set_hash"].as_str().ok_or("hash")?,
                lineage_head: "local",
                verified_at: 999,
                verified_by_device_id: "peer",
            },
        )?;
        if mode != "marked" {
            source.client.account_db()?.remove_actor_state(MIGRATION_MARKER)?;
        }
        observe(&target.client, &unrelated)?;
        legacy_record(&target.client, &unrelated)?;
        // An existing stamp survives even when another imported verification wins.
        let preserved = "identity/safety_verified_set/preserved-root";
        source.client.account_db()?.persist_actor_state(preserved, &"incoming-stamp")?;
        target.client.account_db()?.persist_actor_state(preserved, &"local-stamp")?;
        let imported_stamp =
            format!("identity/safety_verified_set/{}", incoming.principal_commitment);
        if mode == "stamped" {
            target
                .client
                .account_db()?
                .persist_actor_state(&imported_stamp, &"previous-authority")?;
        }
        let reader = merge_verification_reader(&source, &target, mode == "native")?;
        let db = reader.account_db()?;
        assert_eq!(db.load_actor_state::<bool>(MIGRATION_MARKER)?, Some(true));
        assert_eq!(db.load_actor_state::<String>(preserved)?.as_deref(), Some("local-stamp"));
        assert!(
            db.load_actor_state::<String>(&format!(
                "identity/safety_verified_set/{}",
                unrelated.principal_commitment
            ))?
            .is_none()
        );
        let local = db.client_record("identity", "other")?.ok_or("other")?;
        assert_eq!(
            reader.contact_safety_verification_state(
                &unrelated.principal_commitment,
                local["device_set_hash"].as_str()
            )?,
            "verification_stale"
        );
        assert!(
            db.load_actor_state::<String>(&format!(
                "identity/safety_verified_set/{}",
                rejected.principal_commitment
            ))?
            .is_none(),
            "a losing imported row cannot baseline the local winner"
        );
        assert_eq!(
            db.contact_verification(&rejected.principal_commitment)?
                .ok_or("verification")?
                .verified_at,
            999
        );
        if mode == "stamped" {
            assert_eq!(
                db.load_actor_state::<String>(&imported_stamp)?.as_deref(),
                Some("previous-authority")
            );
        }
        let imported = db.client_record("identity", "owner")?;
        if mode == "native" {
            assert!(imported.is_none());
        } else {
            let imported = imported.ok_or("imported")?;
            assert_eq!(
                reader.contact_safety_verification_state(
                    &incoming.principal_commitment,
                    imported["device_set_hash"].as_str()
                )?,
                if mode == "legacy" { "verified" } else { "verification_stale" }
            );
        }
    }
    Ok(())
}

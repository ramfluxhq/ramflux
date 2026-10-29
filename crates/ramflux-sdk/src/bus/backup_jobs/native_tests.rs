// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native archives use the production job path without loading primary or branch credentials.
use super::{
    format,
    tests::{call, finished},
};
use crate::{
    bus::{actor::AccountInitializer, supervisor::Supervisor},
    custody::tests::{Root, TestVault, create},
    prelude::*,
};
use serde_json::json;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const LOCAL_SECRET: &str = "independent local data passphrase";
const ARCHIVE_SECRET: &str = "independent archive passphrase";

fn initialize(root: &Path, index: AccountIndex) -> Result<LocalBusAccountState, SdkError> {
    let mut client = RamfluxClient::new();
    client.account_index = Some(index);
    client.open_account_index(root)?;
    client.unlock_account("account", LOCAL_SECRET.as_bytes())?;
    let native = client.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
    let anchor = native.record().body.account_anchor.clone();
    let endpoint = GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse().map_err(|_| SdkError::CustodySetupInvalid)?,
        gateway_addr: "127.0.0.1:1".parse().map_err(|_| SdkError::CustodySetupInvalid)?,
        server_name: "localhost".into(),
        ca_cert: PathBuf::new(),
        principal_id: native.record().body.principal_id.clone(),
        device_id: "primary".into(),
        target_delivery_id: client.owned_device_identity()?.storage_key().into(),
        prekey_http_url: None,
    };
    let gateway = GatewaySessionConfig::auto(endpoint).with_born_v3_account(native);
    Ok(LocalBusAccountState::disconnected(client, gateway, anchor))
}
fn supervisor(root: &Path) -> Result<Rc<Supervisor>, SdkError> {
    let config = LocalBusConfig::new(root.join("bus.sock"), root);
    let path = root.to_owned();
    let initializer: AccountInitializer = Box::new(move |index| initialize(&path, index));
    Supervisor::from_initializers(
        &config,
        vec![("account".into(), initializer)],
        Some("account".into()),
    )
}
async fn make_archive(supervisor: &Supervisor, path: &Path) -> TestResult {
    let row = call(
        supervisor,
        "account.backup.create",
        Some("account"),
        json!({"output_path":path,"passphrase":ARCHIVE_SECRET}),
    )
    .await?;
    finished(
        supervisor,
        row["job"]["job_id"].as_str().ok_or("job")?,
        crate::backup::BackupJobState::Done,
    )
    .await?;
    Ok(())
}
async fn verify(supervisor: &Supervisor, path: &Path) -> TestResult<String> {
    let row = call(
        supervisor,
        "account.restore.verify",
        None,
        json!({"input_path":path,"passphrase":ARCHIVE_SECRET}),
    )
    .await?;
    let id = row["job"]["job_id"].as_str().ok_or("job")?.to_owned();
    finished(supervisor, &id, crate::backup::BackupJobState::Verified).await?;
    Ok(id)
}
fn archive_with_different_local_origin(source: &Path, output: &Path) -> TestResult {
    use ramflux_crypto::backup_stream::{BackupStreamDecoder, encrypt_backup_stream};
    let mut file = std::io::BufReader::new(std::fs::File::open(source)?);
    let decoder = BackupStreamDecoder::open(&mut file, ARCHIVE_SECRET.as_bytes())?;
    let mut context = decoder.context().clone();
    let snapshot = source.with_extension("origin-snapshot.db");
    let mut unpack = format::Unpack::new(std::fs::File::create(&snapshot)?);
    decoder.decrypt(&mut file, &mut unpack)?;
    let mut metadata = unpack.finish()?;
    let format::Identity::Native { native } = &mut metadata.identity else {
        return Err("native archive".into());
    };
    native.local_account_id = "previous-installation-local-id".into();
    context.account_id.clone_from(&native.local_account_id);
    let mut payload = format::payload(&metadata, &snapshot)?;
    encrypt_backup_stream(
        &mut payload,
        &mut std::fs::File::create(output)?,
        ARCHIVE_SECRET.as_bytes(),
        context,
    )?;
    drop(payload);
    std::fs::remove_file(snapshot)?;
    Ok(())
}
fn advance_authority(
    root: &Path,
    vault: &TestVault,
) -> TestResult<ramflux_protocol::custody::CustodyManifest> {
    let account = crate::custody::load_account(root, "account", crate::custody::network_now()?)?;
    let primary = vault.primary_for_public_key(
        &account.record().body.master_certificate.body.self_signing_public_key,
    )?;
    let mut body = account.record().body.clone();
    body.previous_record_hash = Some(ramflux_protocol::custody::object_hash(account.record())?);
    body.device_set_epoch = body.device_set_epoch.checked_add(1).ok_or("epoch")?;
    body.profile.display_name = "Current installation name".into();
    let publication = ramflux_protocol::custody::Publication {
        record: primary.sign_record(body)?,
        compacted_ids: None,
    };
    crate::custody::accept_publication(
        root,
        "account",
        &ramflux_protocol::custody::CustodyAuthority {
            publication: publication.clone(),
            custodian_publication: None,
        },
        crate::custody::network_now()?,
    )?;
    Ok(ramflux_protocol::custody::CustodyManifest {
        publication,
        custodian_publication: None,
        devices: Vec::new(),
    })
}

fn restored_data_assertions(
    root: &Path,
    authority: &[u8],
    wrapping: &ramflux_storage::WrappedAccountDbKey,
    expected_floor: u64,
) -> TestResult {
    assert_eq!(std::fs::read(root.join("custody_accounts/account/authority.json"))?, authority);
    let mut restored = RamfluxClient::new();
    restored.open_account_index(root)?;
    assert!(restored.unlock_account("account", ARCHIVE_SECRET.as_bytes()).is_err());
    restored.unlock_account("account", LOCAL_SECRET.as_bytes())?;
    let after = restored.account_index()?.load_wrapped_db_key("account")?.ok_or("wrapped key")?;
    assert_eq!(after.nonce, wrapping.nonce);
    assert_eq!(after.wrapped_key, wrapping.wrapped_key);
    let native = restored.born_v3_account.as_ref().ok_or("native")?;
    assert_eq!(native.record().body.profile.display_name, "Current installation name");
    assert_eq!(
        restored.custody_epoch_floor(&native.record().body.account_anchor)?,
        Some(expected_floor)
    );
    let db = restored.account_db()?;
    assert_eq!(db.message_content("history")?, Some(b"inbound history".to_vec()));
    assert_eq!(
        db.load_actor_state::<serde_json::Value>("identity/custody/test")?,
        Some(json!({"revision":8,"fenced":true}))
    );
    assert!(!db.actor_state_exists("dm-pair/active/imported")?);
    assert!(db.actor_state_exists("backup/inactive-pair/imported")?);
    assert!(restored.identity_root.is_none());
    assert!(restored.device_branch.is_none());
    assert!(!root.join("local_bus_accounts/account.json").exists());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn native_backup_merge_keeps_independent_authority_credentials_and_history() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let root = Root::new()?;
            let vault = TestVault::default();
            let account = create(&root.0, "account", &vault, crate::custody::network_now()?)?;
            let mut client = RamfluxClient::new();
            client.open_account_index(&root.0)?;
            client.seal_new_account_data(
                "account",
                &account.record().body.account_anchor,
                LOCAL_SECRET.as_bytes(),
            )?;
            client.unlock_account("account", LOCAL_SECRET.as_bytes())?;
            client.observe_custody_manifest(
                &ramflux_protocol::custody::CustodyManifest {
                    publication: account.publication(),
                    custodian_publication: None,
                    devices: Vec::new(),
                },
                &account.record().body.account_anchor,
                crate::custody::network_now()?,
            )?;
            client.account_db()?.store_message_content("thread", "history", b"inbound history")?;
            client
                .account_db()?
                .persist_actor_state("identity/custody/test", &json!({"revision":1}))?;
            client.account_db()?.persist_actor_state("dm-pair/active/imported", &"imported")?;
            client
                .account_db()?
                .persist_actor_state("dm-pair/session/imported", &json!({"counter":1}))?;
            drop(client);
            let source = supervisor(&root.0)?;
            let archive = root.0.join("data.rfb");
            make_archive(&source, &archive).await?;
            source.shutdown().await?;
            let changed_origin = root.0.join("different-origin.rfb");
            archive_with_different_local_origin(&archive, &changed_origin)?;
            let archive = changed_origin;
            let current = advance_authority(&root.0, &vault)?;
            let expected_floor = current.publication.record.body.device_set_epoch;
            let mut live = RamfluxClient::new();
            live.open_account_index(&root.0)?;
            live.unlock_account("account", LOCAL_SECRET.as_bytes())?;
            live.observe_custody_manifest(
                &current,
                &current.publication.record.body.account_anchor,
                crate::custody::network_now()?,
            )?;
            live.account_db()?.persist_actor_state(
                "identity/custody/test",
                &json!({"revision":8,"fenced":true}),
            )?;
            live.account_db()?.remove_actor_state("dm-pair/active/imported")?;
            live.account_db()?.remove_actor_state("dm-pair/session/imported")?;
            let authority = std::fs::read(root.0.join("custody_accounts/account/authority.json"))?;
            let wrapping_before =
                live.account_index()?.load_wrapped_db_key("account")?.ok_or("wrapped key")?;
            drop(live);
            vault.fail.store(true, std::sync::atomic::Ordering::SeqCst);
            let locked = Supervisor::new(LocalBusConfig::new(root.0.join("locked.sock"), &root.0))?;
            let locked_id = verify(&locked, &archive).await?;
            assert!(matches!(
                call(&locked, "account.restore.install", None, json!({"job_id":locked_id})).await,
                Err(SdkError::AccountDbNotUnlocked)
            ));
            finished(&locked, &locked_id, crate::backup::BackupJobState::Verified).await?;
            locked.shutdown().await?;
            let target = supervisor(&root.0)?;
            let id = verify(&target, &archive).await?;
            let rows = target.backup_jobs.jobs()?;
            assert_eq!(rows["jobs"][0]["archive"]["local_account_id"], "account");
            call(&target, "account.restore.install", None, json!({"job_id":id})).await?;
            finished(&target, &id, crate::backup::BackupJobState::Done).await?;
            target.shutdown().await?;
            restored_data_assertions(&root.0, &authority, &wrapping_before, expected_floor)?;
            Ok(())
        }))
        .await
}

#[test]
fn native_metadata_is_public_evidence_without_a_manifest_or_vault_reference() -> TestResult {
    let root = Root::new()?;
    let vault = TestVault::default();
    let account = create(&root.0, "account", &vault, crate::custody::network_now()?)?;
    let mut client = RamfluxClient::new();
    client.born_v3_account = Some(Box::new(account));
    let identity = super::capture_identity(&client, &root.0, "account")?;
    let metadata = format::Metadata { identity, database_key: [42; 32], ca_pem: Vec::new() };
    let bytes = serde_json::to_vec(&metadata)?;
    let decoded: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert!(decoded.get("native").is_some());
    assert!(decoded.get("manifest").is_none());
    for field in [
        "root_seed",
        "device_seed",
        "account_secret",
        "vault_ref",
        "vault_class",
        "branch_vault",
        "primary_vault",
    ] {
        assert!(!String::from_utf8_lossy(&bytes).contains(field), "native metadata leaked {field}");
    }
    let read: format::Metadata = serde_json::from_slice(&bytes)?;
    read.validate("account")?;
    let mut ambiguous = decoded;
    ambiguous["manifest"] = json!({"root_seed":[0,1,2]});
    assert!(serde_json::from_value::<format::Metadata>(ambiguous).is_err());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn native_fresh_restore_refuses_networking_even_with_a_primary_available() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let root = Root::new()?;
            let vault = std::sync::Arc::new(TestVault::default());
            let account =
                create(&root.0, "account", vault.as_ref(), crate::custody::network_now()?)?;
            let public =
                account.record().body.master_certificate.body.self_signing_public_key.clone();
            let mut client = RamfluxClient::new();
            client.open_account_index(&root.0)?;
            client.seal_new_account_data(
                "account",
                &account.record().body.account_anchor,
                LOCAL_SECRET.as_bytes(),
            )?;
            drop(client);
            let source = supervisor(&root.0)?;
            let archive = root.0.join("fresh.rfb");
            make_archive(&source, &archive).await?;
            source.shutdown().await?;
            let target_root = Root::new()?;
            let mut config = LocalBusConfig::new(target_root.0.join("bus.sock"), &target_root.0);
            config.custody_vault = Some(vault.clone());
            let target = Supervisor::new(config)?;
            assert_eq!(vault.primary_for_public_key(&public)?.public_key(), public);
            let id = verify(&target, &archive).await?;
            call(&target, "account.restore.install", None, json!({"job_id":id})).await?;
            let row = finished(&target, &id, crate::backup::BackupJobState::Failed).await?;
            assert_eq!(
                row.error.ok_or("missing typed refusal")?.code,
                crate::backup::BackupFailureCode::NetworkingPending
            );
            assert_eq!(target.index.known_account_ids()?, Vec::<String>::new());
            assert!(!target_root.0.join("custody_accounts").exists());
            assert_eq!(vault.primary_for_public_key(&public)?.public_key(), public);
            target.shutdown().await?;
            Ok(())
        }))
        .await
}

#[test]
fn native_restore_origin_id_cannot_select_a_different_installed_identity() -> TestResult {
    let root = Root::new()?;
    let vault = TestVault::default();
    let own = create(&root.0, "approved", &vault, crate::custody::network_now()?)?;
    let foreign = create(&root.0, "archive-origin", &vault, crate::custody::network_now()?)?;
    let identity = super::native::DataIdentity {
        schema: "ramflux.backup.native_data.v1".into(),
        local_account_id: "archive-origin".into(),
        authority: ramflux_protocol::custody::CustodyAuthority {
            publication: own.publication(),
            custodian_publication: None,
        },
    };
    let jobs = super::BackupJobs::new(&root.0, AccountIndex::open(&root.0)?)?;
    assert_eq!(jobs.native_restore_target(&identity)?, Some("approved".into()));
    assert_eq!(
        crate::custody::load_account(&root.0, "archive-origin", crate::custody::network_now()?)?
            .record(),
        foreign.record()
    );
    Ok(())
}

#[path = "native_recovery_tests.rs"]
mod recovery_tests;

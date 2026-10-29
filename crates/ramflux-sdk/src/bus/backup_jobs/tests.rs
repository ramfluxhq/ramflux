// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production job workflow against real encrypted account databases, without containers.
use crate::backup::{BackupJob, BackupJobState};
use crate::bus::{actor::AccountInitializer, supervisor::Supervisor};
use crate::prelude::*;
use serde_json::json;
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[derive(Clone, Copy)]
struct Scale {
    messages: usize,
    contacts: usize,
    groups: usize,
    file_bytes: Option<usize>,
}
const SMALL: Scale = Scale { messages: 6, contacts: 1, groups: 1, file_bytes: None };
fn initialized_at_scale(
    root: &Path,
    index: AccountIndex,
    scale: Scale,
) -> Result<LocalBusAccountState, SdkError> {
    let seed = [41; 32];
    let principal = "alice";
    let device = "alice-device";
    let mut client = RamfluxClient::new();
    client.account_index = Some(index);
    let root_identity = client.create_identity_root(principal, seed);
    let commitment =
        ramflux_crypto::identity_root_commitment(&root_identity.signing_key.verifying_key());
    client.create_device_branch(principal, device, 1, [42; 32]);
    client.open_account_index(root)?;
    client.create_account("alice", &commitment)?;
    client.unlock_account("alice", b"account-test-secret")?;
    client.object_store.set_cache_capacity(1);
    for n in 0..scale.contacts {
        client.account_db()?.establish_friend_link(
            &format!("friend-{n}"),
            &commitment,
            &format!("peer-root-{n}"),
        )?;
    }
    for n in 0..scale.messages {
        client.send_direct_message("thread", &format!("m{n}"), device, b"ciphertext")?;
        client.account_db()?.store_message_content(
            "thread",
            &format!("m{n}"),
            format!("message {n}").as_bytes(),
        )?;
    }
    for n in 0..scale.groups {
        client.create_group(&format!("group-{n}"), device)?;
    }
    if let Some(size) = scale.file_bytes {
        for n in 0..2 {
            client.put_encrypted_object(
                &format!("large-{n}"),
                &vec![
                    u8::try_from(n).map_err(|_| SdkError::LocalBus("fixture byte".into()))?;
                    size
                ],
            )?;
        }
    }
    client.put_encrypted_object("file", b"complete attachment bytes")?;
    // Evict large fixture payloads before measuring or running the archive workflow.
    client.object_store.replace_persisted(Vec::new(), BTreeMap::new());
    std::fs::create_dir_all(root)?;
    std::fs::write(root.join("ca.pem"), b"test CA placeholder; never connected")?;
    let endpoint = GatewayQuicEndpointConfig {
        bind_addr: "127.0.0.1:0".parse().map_err(|_| SdkError::LocalBus("address".into()))?,
        gateway_addr: "127.0.0.1:1".parse().map_err(|_| SdkError::LocalBus("address".into()))?,
        server_name: "test-gateway".into(),
        ca_cert: root.join("ca.pem"),
        principal_id: principal.into(),
        device_id: device.into(),
        target_delivery_id: "target".into(),
        prekey_http_url: None,
    };
    write_local_bus_account_manifest(
        root,
        &LocalBusPersistedAccount {
            label: Some("Alice".into()),
            kind: Some("human".into()),
            activation_pending: false,
            node_id: None,
            node_tcp_addr: None,
            node_relay: None,
            schema: "ramflux.local_bus.account_manifest.v1".into(),
            local_account_id: "alice".into(),
            principal_id: principal.into(),
            principal_commitment: commitment.clone(),
            device_id: device.into(),
            target_delivery_id: "target".into(),
            account_secret: "account-test-secret".into(),
            root_seed: seed,
            device_seed: [42; 32],
            client_mode: LocalBusClientMode::AttendedCli,
            gateway: endpoint.clone(),
            devices: vec![LocalBusDeviceRecord {
                device_id: device.into(),
                device_epoch: 1,
                target_delivery_id: "target".into(),
                capability_scope: vec![],
                is_local: true,
            }],
        },
    )?;
    let gateway = GatewaySessionConfig::auto(endpoint).with_owned_device(
        client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
        client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.clone(),
    )?;
    Ok(LocalBusAccountState::disconnected(client, gateway, commitment))
}
fn source_supervisor(root: &Path, scale: Scale) -> Result<Rc<Supervisor>, SdkError> {
    let config = LocalBusConfig::new(root.join("bus.sock"), root);
    let source = root.to_owned();
    let initialize: AccountInitializer =
        Box::new(move |index| initialized_at_scale(&source, index, scale));
    Supervisor::from_initializers(&config, vec![("alice".into(), initialize)], Some("alice".into()))
}
pub(super) async fn finished(
    supervisor: &Supervisor,
    id: &str,
    state: BackupJobState,
) -> Result<BackupJob, SdkError> {
    tokio::time::timeout(
        Duration::from_secs(if cfg!(target_os = "macos") { 90 } else { 3600 }),
        async {
            loop {
                let rows = supervisor.backup_jobs.jobs()?;
                let rows: Vec<BackupJob> = serde_json::from_value(rows["jobs"].clone())?;
                let row = rows
                    .into_iter()
                    .find(|row| row.job_id == id)
                    .ok_or_else(|| SdkError::LocalBus("job missing".into()))?;
                if row.state == state {
                    return Ok(row);
                }
                if row.state == BackupJobState::Failed {
                    return Err(SdkError::LocalBus(format!("job failed: {:?}", row.error)));
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        },
    )
    .await
    .map_err(|_| SdkError::LocalBus("job deadline".into()))?
}
#[tokio::test(flavor = "current_thread")]
async fn full_archive_verifies_before_install_and_restores_history_groups_and_files() -> TestResult
{
    Box::pin(round_trip(SMALL)).await
}
#[tokio::test(flavor = "current_thread")]
#[ignore = "dedicated large-data QA; requires 12 GiB disk and 4 GiB memory; never run on developer machines"]
async fn large_backup_restores_ten_thousand_messages_one_thousand_contacts_two_hundred_groups_and_gibibyte_files()
-> TestResult {
    if cfg!(target_os = "macos") {
        return Err("large backup acceptance runs on QA only".into());
    }
    Box::pin(round_trip(Scale {
        messages: 10_000,
        contacts: 1_100,
        groups: 200,
        file_bytes: Some(512 * 1024 * 1024),
    }))
    .await
}
async fn round_trip(scale: Scale) -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let source_root = crate::bus::runtime_tests::root("full-backup-source");
            let restored_root = crate::bus::runtime_tests::root("full-backup-target");
            let source = source_supervisor(&source_root, scale)?;
            let (outbound, _) = mpsc::channel(64);
            let mut connection = LocalBusConnectionState::new(7, outbound);
            connection.attended_account_id = Some("alice".into());
            let archive = source_root.join("account.rfb");
            let secret = "generated-backup-recovery-secret";
            let response = source
                .request(
                    LocalBusFrame::request(
                        "create",
                        Some("alice".into()),
                        "account",
                        "account.backup.create",
                        json!({"output_path":archive,"passphrase":secret}),
                    ),
                    &connection,
                )
                .await?;
            let id = response.body["job"]["job_id"].as_str().ok_or("job id")?;
            let backup = finished(&source, id, BackupJobState::Done).await?;
            assert_eq!(backup.counts.as_ref().map(|c| c.messages), Some(scale.messages as u64));
            assert!(archive.exists());
            let target = Supervisor::new(LocalBusConfig::new(
                restored_root.join("bus.sock"),
                &restored_root,
            ))?;
            target.daemon_attended.borrow_mut().insert(7);
            let verify = target
                .request(
                    LocalBusFrame::request(
                        "verify",
                        None,
                        "account",
                        "account.restore.verify",
                        json!({"input_path":archive,"passphrase":secret}),
                    ),
                    &connection,
                )
                .await?;
            let id = verify.body["job"]["job_id"].as_str().ok_or("restore id")?;
            let verified = finished(&target, id, BackupJobState::Verified).await?;
            assert_eq!(
                verified.attachments.as_ref().map(|a| a.verified),
                Some(if scale.file_bytes.is_some() { 3 } else { 1 })
            );
            assert_eq!(verified.counts.as_ref().map(|c| c.contacts), Some(scale.contacts as u64));
            assert_eq!(verified.counts.as_ref().map(|c| c.groups), Some(scale.groups as u64));
            assert!(
                target.index.known_account_ids()?.is_empty(),
                "verification must not install an account"
            );
            let install = target
                .request(
                    LocalBusFrame::request(
                        "install",
                        None,
                        "account",
                        "account.restore.install",
                        json!({"job_id":id}),
                    ),
                    &connection,
                )
                .await?;
            assert_eq!(
                (
                    &response.body["job"]["state"],
                    &verify.body["job"]["state"],
                    &install.body["job"]["state"]
                ),
                (&json!("preparing"), &json!("verifying"), &json!("installing"))
            );
            finished(&target, id, BackupJobState::Done).await?;
            // A standalone SDK reopen owns a writer; stop the daemon's writer/readers first.
            target.shutdown().await?;
            let restored = check_restored(&restored_root, scale)?;
            if scale.file_bytes.is_none() {
                merge_existing_source(&source, &source_root, &archive, secret).await?;
            }
            source.shutdown().await?;
            drop(restored);
            drop(source);
            drop(target);
            std::fs::remove_dir_all(source_root)?;
            std::fs::remove_dir_all(restored_root)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        }))
        .await
}

fn check_restored(restored_root: &Path, scale: Scale) -> Result<RamfluxClient, SdkError> {
    let mut restored = RamfluxClient::new();
    restored.object_store.set_cache_capacity(8);
    restored.open_account_index(restored_root)?;
    restored.unlock_account("alice", b"account-test-secret")?;
    assert_eq!(restored.direct_messages("thread")?.len(), scale.messages);
    assert_eq!(restored.account_db()?.friend_links()?.len(), scale.contacts);
    assert_eq!(restored.groups()?.len(), scale.groups);
    assert_eq!(restored.decrypt_object("file")?, b"complete attachment bytes");
    assert_eq!(
        restored.account_db()?.load_actor_state::<bool>("backup/reestablishing")?,
        Some(true)
    );
    Ok(restored)
}

pub(super) async fn call(
    supervisor: &Supervisor,
    method: &str,
    account: Option<&str>,
    body: serde_json::Value,
) -> Result<serde_json::Value, SdkError> {
    let (outbound, _) = mpsc::channel(64);
    let mut connection = LocalBusConnectionState::new(88, outbound);
    connection.attended_account_id = Some("alice".into());
    Ok(supervisor
        .request(
            LocalBusFrame::request(method, account.map(str::to_owned), "account", method, body),
            &connection,
        )
        .await?
        .body)
}
#[tokio::test(flavor = "current_thread")]
async fn failed_verification_and_cancellation_leave_existing_accounts_and_output_untouched()
-> TestResult {
    LocalSet::new()
        .run_until(async {
            let root = crate::bus::runtime_tests::root("backup-failures");
            let supervisor = source_supervisor(&root, SMALL)?;
            let archive = root.join("archive.rfb");
            let secret = "test archive secret";
            let original = archive_while_reading(&supervisor, &archive, secret).await?;
            let mut tampered = original.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            let altered = root.join("altered.rfb");
            std::fs::write(&altered, tampered)?;
            let truncated = root.join("truncated.rfb");
            std::fs::write(&truncated, &original[..original.len() - 7])?;
            let original_record = supervisor.index.account("alice")?;
            for (input, password, code) in [
                (&archive, "incorrect", "wrong_passphrase"),
                (&altered, secret, "tampered"),
                (&truncated, secret, "truncated"),
            ] {
                let verify = call(
                    &supervisor,
                    "account.restore.verify",
                    None,
                    json!({"input_path":input,"passphrase":password}),
                )
                .await?;
                let id = verify["job"]["job_id"].as_str().ok_or("id")?;
                let failed = finished(&supervisor, id, BackupJobState::Failed).await?;
                assert_eq!(serde_json::to_value(failed.error)?["code"], code);
                assert_eq!(
                    supervisor.index.account("alice")?.db_relative_path,
                    original_record.db_relative_path
                );
                let read = call(
                    &supervisor,
                    "message.read",
                    Some("alice"),
                    json!({"conversation_id":"thread"}),
                )
                .await?;
                assert!(read.to_string().contains("m5"));
            }
            rejects_identity_replacement_and_rollback(&supervisor, &root, &archive, secret).await?;
            let verify = call(
                &supervisor,
                "account.restore.verify",
                None,
                json!({"input_path":archive,"passphrase":secret}),
            )
            .await?;
            let id = verify["job"]["job_id"].as_str().ok_or("id")?;
            let cancelled =
                call(&supervisor, "account.backup.cancel", None, json!({"job_id":id})).await?;
            assert_eq!(cancelled["job"]["state"], "cancelled");
            assert!(!root.join("backup_jobs").join(format!("job_{id}")).exists());
            assert_eq!(std::fs::read(&archive)?, original);
            let duplicate = call(
                &supervisor,
                "account.backup.create",
                Some("alice"),
                json!({"output_path":archive,"passphrase":secret}),
            )
            .await?;
            let id = duplicate["job"]["job_id"].as_str().ok_or("id")?;
            let failed = finished(&supervisor, id, BackupJobState::Failed).await?;
            assert_eq!(serde_json::to_value(failed.error)?["code"], "not_writable");
            assert_eq!(std::fs::read(&archive)?, original);
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn entry_page_job_subscription_replays_rows_after_its_ack_and_refuses_other_daemon_topics()
-> TestResult {
    LocalSet::new().run_until(async {
        let root=crate::bus::runtime_tests::root("backup-job-stream");
        let supervisor=Supervisor::new(LocalBusConfig::new(root.join("bus.sock"),&root))?;
        let (outbound,mut incoming)=mpsc::channel(16);
        let connection=LocalBusConnectionState::new(99,outbound);
        let row=supervisor.backup_jobs.start(crate::backup::BackupJobKind::Backup,"archive".into())?;
        let request=LocalBusFrame::request("subscribe",None,"stream","subscription.open",json!({"topics":["account.backup.job.changed"],"since_seq":0,"attended_frontend":true}));
        supervisor.subscribe_backup_stream(request.clone(),&connection).await?;
        let ack=incoming.recv().await.ok_or("ack")?;assert_eq!(ack.ok,Some(true));
        let event=tokio::time::timeout(Duration::from_secs(2),incoming.recv()).await?.ok_or("event")?;
        assert_eq!(event.account_id,None);assert_eq!(event.method,"account.backup.job.changed");assert_eq!(event.body["job_id"],row.job_id);assert_eq!(event.seq,Some(1));
        let bad=LocalBusFrame::request("bad",None,"stream","subscription.open",json!({"topics":["message.received"]}));
        assert!(supervisor.subscribe_backup_stream(bad,&connection).await.is_err());
        supervisor.backup_jobs.change(|registry|registry.writing(&row.job_id,ramflux_storage::BackupCounts::default(),super::service::now()))?;
        let (outbound,mut replay)=mpsc::channel(16);let connection=LocalBusConnectionState::new(100,outbound);
        let mut request=request;request.body["since_seq"]=json!(1);
        supervisor.subscribe_backup_stream(request,&connection).await?;
        assert_eq!(replay.recv().await.ok_or("ack")?.ok,Some(true));
        let event=tokio::time::timeout(Duration::from_secs(2),replay.recv()).await?.ok_or("event")?;
        assert_eq!(event.body["state"],"writing");assert_eq!(event.seq,Some(2));
        supervisor.shutdown().await?;drop(supervisor);std::fs::remove_dir_all(root)?;Ok::<(),Box<dyn std::error::Error>>(())
    }).await
}

async fn rejects_identity_replacement_and_rollback(
    supervisor: &Supervisor,
    root: &Path,
    archive: &Path,
    secret: &str,
) -> TestResult {
    let original =
        read_local_bus_account_manifest(&local_bus_account_manifest_path(root, "alice"))?;
    for rollback in [true, false] {
        let mut local = original.clone();
        if rollback {
            local.devices[0].device_epoch += 1;
        } else {
            local.root_seed[0] ^= 1;
        }
        write_local_bus_account_manifest(root, &local)?;
        let verify = call(
            supervisor,
            "account.restore.verify",
            None,
            json!({"input_path":archive,"passphrase":secret}),
        )
        .await?;
        let id = verify["job"]["job_id"].as_str().ok_or("job id")?;
        if rollback {
            assert!(
                finished(supervisor, id, BackupJobState::Verified)
                    .await?
                    .archive
                    .ok_or("archive")?
                    .merge
            );
            call(supervisor, "account.backup.cancel", None, json!({"job_id":id})).await?;
        } else {
            let failed = finished(supervisor, id, BackupJobState::Failed).await?;
            assert_eq!(serde_json::to_value(failed.error)?["code"], "root_conflict");
        }
    }
    write_local_bus_account_manifest(root, &original)?;
    Ok(())
}

async fn archive_while_reading(
    supervisor: &Supervisor,
    archive: &Path,
    secret: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let create = call(
        supervisor,
        "account.backup.create",
        Some("alice"),
        json!({"output_path":archive,"passphrase":secret}),
    )
    .await?;
    let concurrent = tokio::time::timeout(
        Duration::from_secs(2),
        call(supervisor, "message.read", Some("alice"), json!({"conversation_id":"thread"})),
    )
    .await??;
    assert!(
        concurrent.to_string().contains("m5"),
        "archive workers must not hold the account actor"
    );
    finished(supervisor, create["job"]["job_id"].as_str().ok_or("id")?, BackupJobState::Done)
        .await?;
    let original = std::fs::read(archive)?;
    Ok(original)
}

async fn merge_existing_source(
    source: &Supervisor,
    root: &Path,
    archive: &Path,
    secret: &str,
) -> TestResult {
    let verify = call(
        source,
        "account.restore.verify",
        None,
        json!({"input_path":archive,"passphrase":secret}),
    )
    .await?;
    let id = verify["job"]["job_id"].as_str().ok_or("job id")?;
    let preview = finished(source, id, BackupJobState::Verified).await?;
    assert!(preview.archive.as_ref().is_some_and(|a| a.merge));
    call(source, "account.restore.install", None, json!({"job_id":id})).await?;
    let done = finished(source, id, BackupJobState::Done).await?;
    assert_eq!(done.kept_newer.as_ref().map(|c| c.messages), Some(6));
    assert_eq!(done.kept_newer.as_ref().map(|c| c.attachments), Some(1));
    source.shutdown().await?;
    let mut client = RamfluxClient::new();
    client.open_account_index(root)?;
    client.unlock_account("alice", b"account-test-secret")?;
    assert_eq!(client.direct_messages("thread")?.len(), 6);
    assert_eq!(client.decrypt_object("file")?, b"complete attachment bytes");
    assert_eq!(client.account_db()?.load_actor_state::<bool>("backup/reestablishing")?, None);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn agent_accounts_cannot_list_or_start_human_backup_jobs() -> TestResult {
    LocalSet::new().run_until(async {
        let root=crate::bus::runtime_tests::root("backup-agent-denied");
        let supervisor=source_supervisor(&root,SMALL)?;
        let mut manifest=read_local_bus_account_manifest(&local_bus_account_manifest_path(&root,"alice"))?;
        manifest.kind=Some("agent".into());manifest.client_mode=LocalBusClientMode::HeadlessAi;
        write_local_bus_account_manifest(&root,&manifest)?;
        assert!(call(&supervisor,"account.backup.jobs",Some("alice"),json!({})).await.is_err());
        assert!(call(&supervisor,"account.backup.create",Some("alice"),json!({"output_path":root.join("never.rfb"),"passphrase":"never persist this test secret"})).await.is_err());
        assert_eq!(call(&supervisor,"account.backup.jobs",None,json!({})).await?["jobs"],json!([]));
        supervisor.shutdown().await?;drop(supervisor);std::fs::remove_dir_all(root)?;Ok::<(),Box<dyn std::error::Error>>(())
    }).await
}

#[tokio::test(flavor = "current_thread")]
async fn r2_older_epoch_archive_merges_without_rolling_back_live_identity() -> TestResult {
    LocalSet::new()
        .run_until(async {
            let root = crate::bus::runtime_tests::root("backup-older-merge");
            let supervisor = source_supervisor(&root, SMALL)?;
            let archive = root.join("old.rfb");
            let secret = "archive regression secret";
            archive_while_reading(&supervisor, &archive, secret).await?;
            let mut local =
                read_local_bus_account_manifest(&local_bus_account_manifest_path(&root, "alice"))?;
            local.devices[0].device_epoch += 1;
            write_local_bus_account_manifest(&root, &local)?;
            let row = call(
                &supervisor,
                "account.restore.verify",
                None,
                json!({"input_path":archive,"passphrase":secret}),
            )
            .await?;
            let id = row["job"]["job_id"].as_str().ok_or("job")?;
            assert!(
                finished(&supervisor, id, BackupJobState::Verified)
                    .await?
                    .archive
                    .ok_or("archive")?
                    .merge
            );
            call(&supervisor, "account.restore.install", None, json!({"job_id":id})).await?;
            finished(&supervisor, id, BackupJobState::Done).await?;
            let kept =
                read_local_bus_account_manifest(&local_bus_account_manifest_path(&root, "alice"))?;
            assert_eq!(kept.devices, local.devices);
            supervisor.shutdown().await?;
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn r2_successful_merge_reclaims_the_replaced_database_generation() -> TestResult {
    LocalSet::new()
        .run_until(async {
            let root = crate::bus::runtime_tests::root("backup-reclaim");
            let supervisor = source_supervisor(&root, SMALL)?;
            let archive = root.join("all.rfb");
            let secret = "archive cleanup regression";
            archive_while_reading(&supervisor, &archive, secret).await?;
            for _ in 0..2 {
                let old = root.join(supervisor.index.account("alice")?.db_relative_path);
                assert!(old.exists());
                let row = call(
                    &supervisor,
                    "account.restore.verify",
                    None,
                    json!({"input_path":archive,"passphrase":secret}),
                )
                .await?;
                let id = row["job"]["job_id"].as_str().ok_or("job")?;
                finished(&supervisor, id, BackupJobState::Verified).await?;
                call(&supervisor, "account.restore.install", None, json!({"job_id":id})).await?;
                finished(&supervisor, id, BackupJobState::Done).await?;
                assert!(
                    !old.exists(),
                    "committed replacement must reclaim its old encrypted database"
                );
                assert!(root.join(supervisor.index.account("alice")?.db_relative_path).exists());
            }
            supervisor.shutdown().await?;
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn r2_create_fetches_missing_files_then_requires_explicit_authenticated_omissions()
-> TestResult {
    LocalSet::new().run_until(Box::pin(async {
        let root=crate::bus::runtime_tests::root("backup-unavailable");
        let config=LocalBusConfig::new(root.join("bus.sock"),&root);let source=root.clone();
        let initialize:AccountInitializer=Box::new(move|index|{
            let state=initialized_at_scale(&source,index,SMALL)?;
            for n in 0..65 {
                let id=format!("lost-{n:03}");
                state.client.account_db()?.persist_actor_state(&format!("attachment/reference/{id}"),&json!({"reference":{
                    "schema":"ramflux.sdk.dm_attachment_ref.v1","version":1,"object_id":id,
                    "manifest_hash":format!("manifest-{n}"),"plaintext_hash":format!("plain-{n}"),"cipher_size":16,"chunk_size":32,
                    "total_chunks":1,"relay_endpoint":"https://relay.invalid","key_slot":{
                    "schema":"ramflux.sdk.object_key_slot.dm.v1","version":1,"object_id":id,
                    "conversation_id":"slot","recipient_device_id":"alice-device","x3dh":null,
                    "ciphertext":{"session_id":"slot","counter":0,"nonce":[0,0,0,0,0,0,0,0,0,0,0,0],"ciphertext":[]}
                }}}))?;
            }
            Ok(state)
        });
        let supervisor=Supervisor::from_initializers(&config,vec![("alice".into(),initialize)],Some("alice".into()))?;
        let archive=root.join("missing.rfb");let secret="explicit missing regression";
        let request=json!({"output_path":archive,"passphrase":secret});
        let row=call(&supervisor,"account.backup.create",Some("alice"),request.clone()).await?;
        let id=row["job"]["job_id"].as_str().ok_or("job")?;
        let failed=finished(&supervisor,id,BackupJobState::Failed).await?;
        let failure=serde_json::to_value(failed.error)?;
        assert_eq!(failure["code"],"attachments_unavailable");
        assert_eq!(failure["unavailable_count"],65);
        assert_eq!(failure["unavailable_attachments"].as_array().ok_or("list")?.len(),64);
        assert!(!archive.exists());
        let page=call(&supervisor,"account.backup.jobs",None,json!({"job_id":id,"missing_after":failure["unavailable_next_cursor"]})).await?;
        assert_eq!(page["unavailable_attachments"],json!(["lost-064"]));
        let captured=supervisor.account_actor("alice").ok_or("actor")?.capture_backup().await?;
        for selector in ["lost-000","lost-064"] {
            let operation=format!("backup-fetch:{id}:{}",ramflux_protocol::hash_base64url("ramflux.backup.fetch.v1",selector.as_bytes()));
            let fetched:serde_json::Value=captured.reader.load_actor_state(&format!("attachment/operation/{operation}"))?.ok_or("backup fetch was not attempted")?;
            assert_eq!(fetched["operation_id"],operation);
            assert_eq!(fetched["transfer_state"],"failed");
        }
        drop(captured);
        let mut explicit=request;explicit["allow_missing_attachments"]=json!(true);
        let row=call(&supervisor,"account.backup.create",Some("alice"),explicit).await?;
        finished(&supervisor,row["job"]["job_id"].as_str().ok_or("job")?,BackupJobState::Done).await?;
        let target_root=crate::bus::runtime_tests::root("backup-unavailable-target");
        let target=Supervisor::new(LocalBusConfig::new(target_root.join("bus.sock"),&target_root))?;
        let row=call(&target,"account.restore.verify",None,json!({"input_path":archive,"passphrase":secret})).await?;
        let id=row["job"]["job_id"].as_str().ok_or("job")?;
        let verified=finished(&target,id,BackupJobState::Verified).await?;
        assert_eq!(serde_json::to_value(verified.attachments)?["unavailable_at_source"],65);
        call(&target,"account.restore.install",None,json!({"job_id":id})).await?;
        let done=finished(&target,id,BackupJobState::Done).await?;
        assert_eq!(serde_json::to_value(done.attachments)?["missing"],65);
        target.shutdown().await?;supervisor.shutdown().await?;
        std::fs::remove_dir_all(root)?;std::fs::remove_dir_all(target_root)?;Ok(())
    })).await
}

mod r3;

#[test]
fn r8_backup_actor_uses_the_manifests_current_branch_epoch() -> TestResult {
    let root = crate::bus::runtime_tests::root("backup-actor-epoch");
    let index = AccountIndex::open(&root)?;
    let account = initialized_at_scale(
        &root,
        index,
        Scale { messages: 0, contacts: 0, groups: 0, file_bytes: None },
    )?;
    let mut local =
        read_local_bus_account_manifest(&local_bus_account_manifest_path(&root, "alice"))?;
    local.devices[0].device_epoch = 7;
    let branch = super::install::backup_device_branch(&local);
    assert_eq!(branch.device_epoch, 7);
    assert_eq!(
        branch.signing_key.verifying_key(),
        account.client.device_branch.as_ref().ok_or("branch")?.signing_key.verifying_key()
    );
    drop(account);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

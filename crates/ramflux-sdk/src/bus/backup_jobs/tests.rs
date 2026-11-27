// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Production job workflow against real encrypted account databases, without containers.
use crate::backup::{BackupFailureCode, BackupJob, BackupJobState};
use crate::bus::{actor::AccountInitializer, supervisor::Supervisor};
use crate::prelude::*;
use serde_json::json;
use std::sync::Arc;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WRITER_CHILD: &str = "client::account::tests::account_writer_sdk_process_fixture";
const WRITER_ROOT_ENV: &str = "RAMFLUX_SDK_WRITER_TEST_ROOT";

struct WriterChild(std::process::Child);

impl Drop for WriterChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn held_writer(root: &Path) -> TestResult<WriterChild> {
    let mut child = WriterChild(
        std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", WRITER_CHILD, "--nocapture"])
            .env(WRITER_ROOT_ENV, root)
            .stdin(std::process::Stdio::null())
            .spawn()?,
    );
    let ready = root.join("sdk-writer-ready");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        assert!(child.0.try_wait()?.is_none(), "writer child exited before readiness");
        assert!(std::time::Instant::now() < deadline, "writer child startup timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(child)
}

fn busy_error(index: &AccountIndex) -> TestResult<ramflux_storage::StorageError> {
    match index.acquire_account_writer("acct") {
        Err(error @ ramflux_storage::StorageError::AccountWriterBusy(_)) => Ok(error),
        Err(error) => Err(format!("unexpected writer error: {error}").into()),
        Ok(_) => Err("child writer should retain account ownership".into()),
    }
}

#[test]
fn account_busy_is_retryable_and_typed_for_restore_check_and_install() -> TestResult {
    let root = crate::bus::runtime_tests::root("backup-account-busy");
    let index = AccountIndex::open(&root)?;
    index.create_account("acct", "principal")?;
    let holder = held_writer(&root)?;

    let restore_check = super::workers::storage_error(&busy_error(&index)?);
    assert_eq!(restore_check.code, crate::backup::BackupFailureCode::AccountBusy);
    assert!(restore_check.retryable);
    assert_eq!(restore_check.message.as_deref(), Some("account in use by another process"));

    let jobs = super::BackupJobs::new(&root, index.clone())?;
    let job = jobs.start(crate::backup::BackupJobKind::Restore, "archive.rfb".into())?;
    jobs.fail_install(&job.job_id, &SdkError::Storage(busy_error(&index)?));
    let rows: Vec<BackupJob> = serde_json::from_value(jobs.jobs()?["jobs"].clone())?;
    let failed = rows.into_iter().find(|row| row.job_id == job.job_id).ok_or("job")?;
    let failure = failed.error.ok_or("failure")?;
    assert_eq!(failure.code, crate::backup::BackupFailureCode::AccountBusy);
    assert!(failure.retryable);
    assert_eq!(failure.message.as_deref(), Some("account in use by another process"));
    assert_eq!(serde_json::to_value(failure)?["code"], "account_busy");

    drop(holder);
    Ok(())
}

#[derive(Clone, Copy)]
struct Scale {
    messages: usize,
    contacts: usize,
}
const SMALL: Scale = Scale { messages: 6, contacts: 1 };
const FIXTURE_ACCOUNT: &str = "alice";
/// A native custody account with data sealed under the production local-code wrap.
fn initialized_at_scale(
    root: &Path,
    index: AccountIndex,
    scale: Scale,
) -> Result<LocalBusAccountState, SdkError> {
    let vault = crate::custody::tests::TestVault::default();
    let account = crate::custody::tests::create(
        root,
        FIXTURE_ACCOUNT,
        &vault,
        crate::custody::network_now()?,
    )
    .map_err(|error| SdkError::LocalBus(format!("fixture custody: {error}")))?;
    let mut sealing = RamfluxClient::new();
    sealing.open_account_index(root)?;
    sealing.seal_new_account_data(
        FIXTURE_ACCOUNT,
        &account.record().body.account_anchor,
        super::native_tests::LOCAL_SECRET.as_bytes(),
    )?;
    drop(sealing);
    let mut state = super::native_tests::initialize_account(root, index, FIXTURE_ACCOUNT)?;
    let client = &mut state.client;
    client.object_store.set_cache_capacity(1);
    for n in 0..scale.contacts {
        client.account_db()?.establish_friend_link(
            &format!("friend-{n}"),
            "alice-root",
            &format!("peer-root-{n}"),
        )?;
    }
    for n in 0..scale.messages {
        client.send_direct_message("thread", &format!("m{n}"), "alice-device", b"ciphertext")?;
        client.account_db()?.store_message_content(
            "thread",
            &format!("m{n}"),
            format!("message {n}").as_bytes(),
        )?;
    }
    client.put_encrypted_object("file", b"complete attachment bytes")?;
    // Evict fixture payloads before running the archive workflow.
    client.object_store.replace_persisted(Vec::new(), BTreeMap::new());
    Ok(state)
}
fn bind_fixture_attachment(
    client: &RamfluxClient,
    selector: &str,
    message: &str,
    value: &serde_json::Value,
) -> Result<(), SdkError> {
    let reference = &value["reference"];
    let wire = reference["object_id"]
        .as_str()
        .ok_or_else(|| SdkError::LocalBus("fixture object id".into()))?;
    let manifest = reference["manifest_hash"]
        .as_str()
        .ok_or_else(|| SdkError::LocalBus("fixture manifest".into()))?;
    let hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.attachment.reference.v1",
        &ramflux_protocol::canonical_json_bytes(reference)?,
    );
    let db = client.account_db()?;
    db.write_transaction(||->Result<(),SdkError>{
        db.register_object_reference(ramflux_storage::ObjectReferenceAdmission::FreshMessage, &ramflux_storage::ObjectReferenceOwner {reference_hash:&hash,wire_id:wire,manifest_hash:manifest,selector,message_id:message,reference:value,metadata:&json!({"message_id":message,"manifest_hash":manifest,"direction":"incoming"})})?;
        db.persist_actor_state(&format!("attachment/reference/{selector}"),value)?;
        Ok(())
    })
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
async fn backup_archive_corrupted_mac_is_tampered() -> TestResult {
    LocalSet::new()
        .run_until(async {
            let root = crate::bus::runtime_tests::root("backup-archive-mac");
            let supervisor = source_supervisor(&root, SMALL)?;
            let archive = root.join("archive.rfb");
            let secret = "test archive secret";
            let mut bytes = archive_while_reading(&supervisor, &archive, secret).await?;
            let last = bytes.last_mut().ok_or("empty archive")?;
            *last ^= 1;
            std::fs::write(&archive, bytes)?;
            let verify = call(
                &supervisor,
                "account.restore.verify",
                None,
                json!({"input_path":archive,"passphrase":secret}),
            )
            .await?;
            let id = verify["job"]["job_id"].as_str().ok_or("id")?;
            let failed = finished(&supervisor, id, BackupJobState::Failed).await?;
            assert_eq!(failed.error.ok_or("failure")?.code, BackupFailureCode::Tampered);
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn failed_verification_and_cancellation_leave_existing_accounts_and_output_untouched()
-> TestResult {
    Box::pin(LocalSet::new().run_until(async {
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
            let read = call(&supervisor, "contact.list", Some("alice"), json!({})).await?;
            assert!(
                read.to_string().contains("friend-0"),
                "failed restore changed existing contacts"
            );
        }
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
    }))
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
        call(supervisor, "contact.list", Some("alice"), json!({})),
    )
    .await??;
    assert!(
        concurrent.to_string().contains("friend-0"),
        "archive workers must not hold the account actor"
    );
    finished(supervisor, create["job"]["job_id"].as_str().ok_or("id")?, BackupJobState::Done)
        .await?;
    let original = std::fs::read(archive)?;
    Ok(original)
}

#[tokio::test(flavor = "current_thread")]
async fn failed_install_with_a_healthy_reopen_clears_stale_restore_state() -> TestResult {
    LocalSet::new()
        .run_until(async {
            let root = crate::bus::runtime_tests::root("backup-failed-install-reopen");
            let supervisor = source_supervisor(&root, SMALL)?;
            let archive = root.join("failed-install.rfb");
            let secret = "failed install reopen regression";
            archive_while_reading(&supervisor, &archive, secret).await?;
            let row = call(
                &supervisor,
                "account.restore.verify",
                None,
                json!({"input_path":archive,"passphrase":secret}),
            )
            .await?;
            let id = row["job"]["job_id"].as_str().ok_or("job")?;
            finished(&supervisor, id, BackupJobState::Verified).await?;
            supervisor.mark_restore_failed("alice", "wrong_passphrase");
            *supervisor.backup_jobs.install_hook.lock().map_err(|_| "hook")? =
                Some(Arc::new(|point, _| {
                    if point == super::test_install::InstallPoint::Prepared {
                        return Err(std::io::Error::other("injected install failure"));
                    }
                    Ok(())
                }));
            call(&supervisor, "account.restore.install", None, json!({"job_id":id})).await?;
            finished(&supervisor, id, BackupJobState::Failed).await?;
            let status = call(&supervisor, "account.status", Some("alice"), json!({})).await?;
            assert_eq!(status["local_account_id"], "alice");
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
            {
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
                bind_fixture_attachment(&state.client,&id,"m0",&json!({"reference":{
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
        let row=call(&supervisor,"account.restore.verify",None,json!({"input_path":archive,"passphrase":secret})).await?;
        let id=row["job"]["job_id"].as_str().ok_or("job")?;
        let verified=finished(&supervisor,id,BackupJobState::Verified).await?;
        assert_eq!(serde_json::to_value(verified.attachments)?["unavailable_at_source"],65);
        supervisor.shutdown().await?;
        std::fs::remove_dir_all(root)?;Ok(())
    })).await
}

mod r3;

// Mutation: retain the failed-backup diagnostic snapshot after its account erasure generation changes.
#[tokio::test(flavor = "current_thread")]
async fn backup_erasure_discards_retained_diagnostic_snapshot_and_key() -> TestResult {
    LocalSet::new().run_until(Box::pin(async {
        let root = crate::bus::runtime_tests::root("backup-diagnostic-erasure");
        let config = LocalBusConfig::new(root.join("bus.sock"), &root);
        let source = root.clone();
        let initialize: AccountInitializer = Box::new(move |index| {
            let state = initialized_at_scale(&source, index, SMALL)?;
            let db = state.client.account_db()?;
            let (object, _) = db.load_object::<ramflux_sync::EncryptedObject>("file")?
                .ok_or_else(|| SdkError::LocalBus("diagnostic fixture attachment missing".into()))?;
            db.register_object_reference(ramflux_storage::ObjectReferenceAdmission::FreshMessage, &ramflux_storage::ObjectReferenceOwner {
                reference_hash: "diagnostic-reference", wire_id: &object.object_id,
                manifest_hash: &object.manifest_hash, selector: "file", message_id: "m0",
                reference: &json!({"object_id":"file","manifest_hash":object.manifest_hash}),
                metadata: &json!({"message_id":"m0"}),
            })?;
            Ok(state)
        });
        let supervisor = Supervisor::from_initializers(&config,
            vec![("alice".into(), initialize)], Some("alice".into()))?;
        call(&supervisor, "account.status", Some("alice"), json!({})).await?;
        let captured = supervisor.account_actor("alice").ok_or("actor")?.capture_backup().await?;
        let jobs = &supervisor.backup_jobs;
        let job = jobs.start(crate::backup::BackupJobKind::Backup, root.join("unused.rfb").to_string_lossy().into_owned())?;
        let directory = jobs.directory(&job.job_id)?;
        let path = directory.join("account.db");
        let snapshot = captured.reader.write_backup_snapshot(&path)?;
        let db = ramflux_storage::BackupDatabase::open(&path, &snapshot.key)?;
        jobs.unavailable_failure(&job, directory.clone(), &snapshot.key, &db, &captured)?;
        drop(db);
        drop(snapshot);
        drop(captured);
        assert!(path.is_file());
        assert!(jobs.diagnostics.lock().map_err(|_|"diagnostics")?.contains_key(&job.job_id));
        let (outbound, _events) = mpsc::channel(8);
        let mut connection = LocalBusConnectionState::new(1, outbound);
        connection.attended_account_id = Some("alice".into());
        supervisor.request(LocalBusFrame::request("erase", Some("alice".into()), "message", "message.delete", json!({"conversation_id":"thread","message_id":"m0","delete_scope":"local"})), &connection).await?;
        assert!(!jobs.diagnostics.lock().map_err(|_|"diagnostics")?.contains_key(&job.job_id));
        assert!(!directory.exists());
        supervisor.shutdown().await?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    })).await
}

#[tokio::test(flavor = "current_thread")]
async fn backup_create_refuses_short_and_blocklisted_passphrases() -> TestResult {
    LocalSet::new()
        .run_until(async {
            let root = crate::bus::runtime_tests::root("backup-create-refused");
            let supervisor = source_supervisor(&root, Scale { messages: 0, contacts: 0 })?;
            let archive = root.join("refused.rfb");
            for (passphrase, code) in
                [("aaaaaaaaaaaaaa", "too_short"), ("films+pic+galeries", "too_common")]
            {
                let Err(error) = call(
                    &supervisor,
                    "account.backup.create",
                    Some("alice"),
                    json!({"output_path": &archive, "passphrase": passphrase}),
                )
                .await
                else {
                    return Err("test: refused backup passphrase was accepted".into());
                };
                let body = crate::bus::io::local_bus_error_body(&error);
                assert_eq!(body.code, code, "test: backup create refusal code was {}", body.code);
                assert!(
                    body.reason_code.is_none(),
                    "test: backup create refusal carried a reason code"
                );
                assert!(!archive.exists(), "test: a refused backup created an archive");
            }
            assert_eq!(
                supervisor.backup_jobs.jobs()?["jobs"],
                json!([]),
                "test: a refused backup wrote a job row"
            );
            supervisor.shutdown().await?;
            drop(supervisor);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[path = "tests/selector_normalization.rs"]
pub(super) mod selector_normalization_tests;

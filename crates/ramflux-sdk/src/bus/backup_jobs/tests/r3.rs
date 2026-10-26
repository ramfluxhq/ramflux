// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Install/cleanup races and merge-local attachment isolation through real daemon jobs.
use super::*;
use crate::bus::backup_jobs::test_install::InstallPoint;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

async fn archive_and_verify(
    supervisor: &Supervisor,
    root: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let archive = root.join("complete.rfb");
    let secret = "review restore regression";
    archive_while_reading(supervisor, &archive, secret).await?;
    let row = call(
        supervisor,
        "account.restore.verify",
        None,
        json!({"input_path":archive,"passphrase":secret}),
    )
    .await?;
    let id = row["job"]["job_id"].as_str().ok_or("job")?.to_owned();
    finished(supervisor, &id, BackupJobState::Verified).await?;
    Ok(id)
}
#[tokio::test(flavor = "current_thread")]
async fn r3_a_slow_install_survives_repeated_periodic_cleanup_ticks() -> TestResult {
    LocalSet::new()
        .run_until(async {
            let root = crate::bus::runtime_tests::root("backup-install-ticks");
            let supervisor = source_supervisor(&root, SMALL)?;
            let id = archive_and_verify(&supervisor, &root).await?;
            let ready = Arc::new(AtomicBool::new(false));
            let release = Arc::new(AtomicBool::new(false));
            let started = ready.clone();
            let permit = release.clone();
            *supervisor.backup_jobs.install_hook.lock().map_err(|_| "hook")? =
                Some(Arc::new(move |point, _| {
                    if point == InstallPoint::BeforeCommit {
                        started.store(true, Ordering::Release);
                        let until = std::time::Instant::now() + Duration::from_secs(15);
                        while !permit.load(Ordering::Acquire) {
                            if std::time::Instant::now() > until {
                                return Err(std::io::ErrorKind::TimedOut.into());
                            }
                            std::thread::sleep(Duration::from_millis(2));
                        }
                    }
                    Ok(())
                }));
            call(&supervisor, "account.restore.install", None, json!({"job_id":id})).await?;
            tokio::time::timeout(Duration::from_secs(15), async {
                while !ready.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await?;
            let generation = root.join(format!("accounts/alice/generation_{id}"));
            let mut intact = true;
            for _ in 0..6 {
                supervisor.backup_jobs.force_periodic_cleanup();
                intact &= generation.join("account.db").exists();
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
            release.store(true, Ordering::Release);
            finished(&supervisor, &id, BackupJobState::Done).await?;
            assert!(intact, "cleanup touched the pre-commit generation");
            supervisor.shutdown().await?;
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn r3_merge_preserves_local_undownloaded_references_and_reports_them_separately() -> TestResult
{
    Box::pin(LocalSet::new().run_until(async{
        let root=crate::bus::runtime_tests::root("backup-local-missing");let supervisor=source_supervisor(&root,SMALL)?;
        let archive=root.join("complete.rfb");let secret="review local missing regression";
        archive_while_reading(&supervisor,&archive,secret).await?;
        supervisor.account_actor("alice").ok_or("actor")?.stop().await?;supervisor.remove_backup_actor("alice");
        let mut client=RamfluxClient::new();client.open_account_index(&root)?;client.unlock_account("alice",b"account-test-secret")?;
        let reference=json!({"reference":{"object_id":"local-pending","manifest_hash":"unavailable-local-hash","plaintext_hash":"unavailable-plain-hash"}});
        client.account_db()?.persist_actor_state("attachment/reference/local-pending",&reference)?;drop(client);
        let actor=supervisor.new_backup_actor("alice")?;let (outbound,_events)=mpsc::channel(16);
        actor.request(crate::bus::actor::AccountCommand{backup:None,request:LocalBusFrame::request("unlock",Some("alice".into()),"account","account.unlock",json!({"passphrase":"account-test-secret"})),connection_id:1,topics:BTreeSet::new(),attended:true,nodes:None,outbound,reply:None}).await?;
        let row=call(&supervisor,"account.restore.verify",None,json!({"input_path":archive,"passphrase":secret})).await?;
        let id=row["job"]["job_id"].as_str().ok_or("job")?;finished(&supervisor,id,BackupJobState::Verified).await?;
        call(&supervisor,"account.restore.install",None,json!({"job_id":id})).await?;
        let done=finished(&supervisor,id,BackupJobState::Done).await?;
        assert_eq!(serde_json::to_value(done.attachments)?["local_missing_kept"],1);
        let captured=supervisor.account_actor("alice").ok_or("actor")?.capture_backup().await?;
        assert_eq!(captured.reader.load_actor_state::<serde_json::Value>("attachment/reference/local-pending")?,Some(reference));
        assert_eq!(captured.reader.backup_missing_page("")?,vec!["local-pending"]);drop(captured);
        supervisor.shutdown().await?;std::fs::remove_dir_all(root)?;Ok(())
    })).await
}

#[tokio::test(flavor = "current_thread")]
async fn r3_fetch_phase_reports_items_before_the_single_snapshot_capture() -> TestResult {
    LocalSet::new().run_until(async{
        let root=crate::bus::runtime_tests::root("backup-fetch-progress");let config=LocalBusConfig::new(root.join("bus.sock"),&root);let source=root.clone();
        let initialize:AccountInitializer=Box::new(move|index|{
            let account=initialized_at_scale(&source,index,SMALL)?;
            account.client.account_db()?.persist_actor_state("attachment/reference/missing",&json!({"reference":{"object_id":"missing","manifest_hash":"missing","plaintext_hash":"missing"}}))?;Ok(account)
        });
        let supervisor=Supervisor::from_initializers(&config,vec![("alice".into(),initialize)],Some("alice".into()))?;
        let row=call(&supervisor,"account.backup.create",Some("alice"),json!({"output_path":root.join("missing.rfb"),"passphrase":"fetch progress regression"})).await?;
        finished(&supervisor,row["job"]["job_id"].as_str().ok_or("job")?,BackupJobState::Failed).await?;
        assert_eq!(supervisor.account_actor("alice").ok_or("actor")?.backup_capture_count(),1,"fetch must finish before opening the only backup snapshot");
        assert!(supervisor.backup_jobs.state.lock().map_err(|_|"state")?.events.iter().any(|(_,row)|row.state==BackupJobState::Preparing && row.progress.items_total==Some(1) && row.progress.items_done==1));
        supervisor.shutdown().await?;std::fs::remove_dir_all(root)?;Ok(())
    }).await
}

#[tokio::test(flavor = "current_thread")]
async fn r3_precommit_crash_child() -> TestResult {
    let Some(root) = std::env::var_os("RAMFLUX_BACKUP_R3_CRASH_ROOT") else { return Ok(()) };
    let root = PathBuf::from(root);
    LocalSet::new()
        .run_until(async {
            let supervisor = source_supervisor(&root, SMALL)?;
            let id = archive_and_verify(&supervisor, &root).await?;
            let observed = root.clone();
            *supervisor.backup_jobs.install_hook.lock().map_err(|_| "hook")? =
                Some(Arc::new(move |point, _| {
                    if point == InstallPoint::BeforeCommit {
                        std::fs::write(observed.join("precommit-ready"), b"ready")?;
                        let until = std::time::Instant::now() + Duration::from_secs(30);
                        while !observed.join("allow-commit").exists() {
                            if std::time::Instant::now() > until {
                                return Err(std::io::ErrorKind::TimedOut.into());
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        }
                    } else if point == InstallPoint::Committed {
                        std::fs::write(observed.join("committed-ready"), b"ready")?;
                        loop {
                            std::thread::park_timeout(Duration::from_secs(1));
                        }
                    }
                    Ok(())
                }));
            call(&supervisor, "account.restore.install", None, json!({"job_id":id})).await?;
            tokio::time::timeout(Duration::from_secs(30), async {
                while !root.join("precommit-ready").exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await?;
            for _ in 0..6 {
                supervisor.backup_jobs.force_periodic_cleanup();
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
            std::fs::write(root.join("allow-commit"), b"commit")?;
            std::future::pending::<TestResult>().await
        })
        .await
}
struct CrashProcess(std::process::Child);
impl Drop for CrashProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn r3_crash_after_cleanup_ticks_and_commit_leaves_the_account_openable() -> TestResult {
    let root = crate::bus::runtime_tests::root("backup-crash-commit");
    std::fs::create_dir_all(&root)?;
    let log = std::fs::File::create(root.join("child.log"))?;
    let mut child = CrashProcess(
        std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "bus::backup_jobs::tests::r3::r3_precommit_crash_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RAMFLUX_BACKUP_R3_CRASH_ROOT", &root)
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?,
    );
    let until = std::time::Instant::now() + Duration::from_secs(90);
    while !root.join("committed-ready").exists() {
        if child.0.try_wait()?.is_some() {
            return Err("install child exited before commit; see child.log".into());
        }
        if std::time::Instant::now() > until {
            return Err("install child commit deadline; see child.log".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill()?;
    child.0.wait()?;
    let index = AccountIndex::open(&root)?;
    let jobs = super::super::service::BackupJobs::new(&root, index.clone())?;
    let selected = root.join(index.account("alice")?.db_relative_path);
    assert!(selected.exists());
    let mut client = RamfluxClient::new();
    client.open_account_index(&root)?;
    client.unlock_account("alice", b"account-test-secret")?;
    assert_eq!(client.direct_messages("thread")?.len(), SMALL.messages);
    assert_eq!(client.decrypt_object("file")?, b"complete attachment bytes");
    drop(client);
    drop(jobs);
    drop(index);
    drop(child);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

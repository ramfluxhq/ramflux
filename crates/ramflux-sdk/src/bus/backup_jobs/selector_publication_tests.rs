// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-serialized publication authorization orders private erasures.
use super::test_install::InstallPoint;
use crate::{
    custody::tests::{Root, TestVault, create},
    prelude::*,
};
use ramflux_storage::{ObjectReferenceAdmission, ObjectReferenceOwner, ObjectWrite};
use serde_json::json;
use std::sync::{Arc, Mutex};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const LOCAL_SECRET: &str = "independent local data passphrase";
const ARCHIVE_SECRET: &str = "independent archive passphrase";
const ALIAS: &str = "private-publication-alias";

fn guard<T, E>(result: Result<T, E>, message: &str) -> Result<T, std::io::Error> {
    assert!(result.is_ok(), "{message}");
    result.map_err(|_| std::io::Error::other(message.to_owned()))
}

struct Fixture {
    root: Root,
    payload_only: bool,
    reader: ramflux_storage::AccountDb,
    hold: Option<ramflux_storage::PreSendObjectHold>,
    wire: String,
    manifest: String,
}
impl Fixture {
    fn new(payload_only: bool) -> TestResult<Self> {
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
        let db = client.account_db()?;
        let mut donor = ramflux_sync::ObjectStore::new();
        let object = donor.put_encrypted_object("publication-wire", b"publication-private-body")?;
        let key = donor.object_key(&object.object_id)?;
        let hold = if payload_only {
            db.retain_object(
                &object.object_id,
                &object.manifest_hash,
                ramflux_storage::ObjectRetention::PreSend { expires_at: i64::MAX },
            )?;
            None
        } else {
            for (message, selector, hash) in [
                ("survivor", object.object_id.as_str(), "wire-reference"),
                ("removed", ALIAS, "alias-reference"),
            ] {
                db.send_direct_message("thread", message, "peer", b"body")?;
                db.register_object_reference(ObjectReferenceAdmission::FreshMessage, &ObjectReferenceOwner {
                    reference_hash: hash, wire_id: &object.object_id, manifest_hash: &object.manifest_hash,
                    selector, message_id: message, reference: &json!({"object_id":object.object_id,"manifest_hash":object.manifest_hash}), metadata: &json!({}),
                })?;
            }
            db.persist_actor_state(&format!("attachment/reference/{ALIAS}"), &json!({"reference":{"object_id":object.object_id,"manifest_hash":object.manifest_hash}}))?;
            db.set_object_tombstoned(ALIAS)?;
            None
        };
        db.upsert_object(&ObjectWrite {
            object_id: &object.object_id,
            manifest_hash: &object.manifest_hash,
            nonce: &object.nonce,
            ciphertext: &object.ciphertext,
            plaintext_hash: &object.plaintext_hash,
            tombstoned: false,
            backup_excluded: false,
            content_key: Some(&key),
            object: &object,
            updated_at: 1,
        })?;
        let reader = db.open_reader()?;
        drop(client);
        Ok(Self {
            root,
            payload_only,
            reader,
            hold,
            wire: object.object_id,
            manifest: object.manifest_hash,
        })
    }
    fn supervisor(&mut self) -> TestResult<Rc<crate::bus::supervisor::Supervisor>> {
        let config = LocalBusConfig::new(self.root.0.join("bus.sock"), &self.root.0);
        let root = self.root.0.clone();
        let wire = self.wire.clone();
        let manifest = self.manifest.clone();
        let payload_only = self.payload_only;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let initial: crate::bus::actor::AccountInitializer = Box::new(move |index| {
            let state = super::native_tests::initialize(&root, index)?;
            let hold = if payload_only {
                Some(state.client.account_db()?.pre_send_object_hold(&wire, &manifest)?)
            } else {
                None
            };
            sender.send(hold).map_err(|_| SdkError::LocalBus("fixture receiver dropped".into()))?;
            Ok(state)
        });
        let supervisor = crate::bus::supervisor::Supervisor::from_initializers(
            &config,
            vec![("account".into(), initial)],
            Some("account".into()),
        )?;
        self.hold = guard(
            receiver.recv_timeout(Duration::from_secs(120)),
            "actor fixture initialization timed out",
        )?;
        supervisor.start_test_event_router();
        Ok(supervisor)
    }
    async fn erase(&mut self, supervisor: &crate::bus::supervisor::Supervisor) -> TestResult {
        if let Some(hold) = self.hold.take() {
            hold.release()?;
            assert!(matches!(
                self.reader.check_object_identity(&self.wire, &self.manifest),
                Err(ramflux_storage::StorageError::ObjectErased)
            ));
        } else {
            let (outbound, _events) = mpsc::channel(8);
            let mut connection = LocalBusConnectionState::new(1, outbound);
            connection.attended_account_id = Some("account".into());
            supervisor.request(LocalBusFrame::request("delete", Some("account".into()), "message", "message.delete", json!({"conversation_id":"thread","message_id":"removed","delete_scope":"local"})), &connection).await?;
            assert!(matches!(
                self.reader.check_object_access(ALIAS),
                Err(ramflux_storage::StorageError::ObjectErased)
            ));
            self.reader.check_object_access(&self.wire)?;
            assert_eq!(
                self.reader
                    .direct_message_by_id("survivor")?
                    .map(|message| (message.encrypted_body, message.deleted)),
                Some((b"body".to_vec(), false))
            );
            assert!(!self.reader.actor_state_exists(&format!("attachment/reference/{ALIAS}"))?);
        }
        Ok(())
    }
}

fn archive_counts(path: &Path, alias_present: bool) -> TestResult<ramflux_storage::BackupCounts> {
    use ramflux_crypto::backup_stream::BackupStreamDecoder;
    let mut file = std::io::BufReader::new(std::fs::File::open(path)?);
    let decoder = BackupStreamDecoder::open(&mut file, ARCHIVE_SECRET.as_bytes())?;
    let snapshot = path.with_extension("snapshot");
    let mut unpack = super::format::Unpack::new(std::fs::File::create(&snapshot)?);
    decoder.decrypt(&mut file, &mut unpack)?;
    let metadata = unpack.finish()?;
    let key = ramflux_storage::AccountDbKey::from_bytes(metadata.database_key);
    let db = ramflux_storage::BackupDatabase::open(&snapshot, &key)?;
    let counts = db.counts()?;
    drop(db);
    let restored = Root::new()?;
    let source = AccountIndex::open(path.parent().ok_or("archive parent")?)?;
    let index = AccountIndex::open(&restored.0)?;
    let account =
        index.create_account("account", &source.account("account")?.principal_commitment)?;
    let target = restored.0.join(account.db_relative_path);
    std::fs::create_dir_all(target.parent().ok_or("database parent")?)?;
    std::fs::copy(&snapshot, target)?;
    let reader = ramflux_storage::AccountDb::open(&index, "account", &key)?;
    if alias_present {
        assert!(reader.load_object::<serde_json::Value>(ALIAS)?.is_some(), "archive alias row");
    } else {
        assert!(matches!(
            reader.load_object::<serde_json::Value>(ALIAS),
            Err(ramflux_storage::StorageError::ObjectErased)
        ));
    }
    assert_eq!(reader.actor_state_exists(&format!("attachment/reference/{ALIAS}"))?, alias_present);
    assert_eq!(
        reader
            .direct_message_by_id("survivor")?
            .map(|message| (message.encrypted_body, message.deleted)),
        Some((b"body".to_vec(), false))
    );
    drop(reader);
    std::fs::remove_file(snapshot)?;
    Ok(counts)
}

type ArchiveWorker = tokio::task::JoinHandle<Result<(), crate::backup::BackupFailure>>;

fn start_archive(
    jobs: &super::BackupJobs,
    captured: super::CapturedAccount,
    path: &Path,
) -> Result<(crate::backup::BackupJob, ArchiveWorker), SdkError> {
    let job =
        jobs.start(crate::backup::BackupJobKind::Backup, path.to_string_lossy().into_owned())?;
    let service = jobs.clone();
    let work = job.clone();
    let worker = tokio::task::spawn_blocking(move || {
        service.write_archive(
            &work,
            zeroize::Zeroizing::new(ARCHIVE_SECRET.into()),
            captured,
            false,
        )
    });
    Ok((job, worker))
}

fn assert_refused_job(
    jobs: &super::BackupJobs,
    id: &str,
    failure: crate::backup::BackupFailure,
) -> TestResult {
    assert_eq!(failure.code, crate::backup::BackupFailureCode::ObjectErased);
    jobs.fail(id, failure);
    let rows: Vec<crate::backup::BackupJob> = serde_json::from_value(jobs.jobs()?["jobs"].clone())?;
    let failed = rows.iter().find(|row| row.job_id == id).ok_or("failed job")?;
    assert_eq!(failed.state, crate::backup::BackupJobState::Failed);
    assert_eq!(
        failed.error.as_ref().ok_or("failure code")?.code,
        crate::backup::BackupFailureCode::ObjectErased
    );
    Ok(())
}

async fn race(payload_only: bool, authorization_first: bool) -> TestResult {
    let mut fixture = Fixture::new(payload_only)?;
    let supervisor = fixture.supervisor()?;
    let actor = supervisor.account_actor("account").ok_or("actor")?;
    let captured = guard(
        tokio::time::timeout(Duration::from_secs(120), actor.capture_backup()).await,
        "account backup capture timed out",
    )??;
    let before = fixture.reader.privacy_erasure_generation()?;
    let fences = fixture.reader.object_erasure_generation()?;
    let (started, ready) = tokio::sync::oneshot::channel();
    let started = Mutex::new(Some(started));
    let (release, resume) = std::sync::mpsc::sync_channel(1);
    let resume = Mutex::new(resume);
    *supervisor.backup_jobs.install_hook.lock().map_err(|_| "hook")? =
        Some(Arc::new(move |point, path| {
            let selected = if authorization_first {
                InstallPoint::ArchiveAuthorized
            } else {
                InstallPoint::BeforeArchiveAuthorization
            };
            if point == selected {
                assert!(path.is_file(), "encrypted archive must be staged before the race");
                if let Some(started) =
                    started.lock().map_err(|_| std::io::Error::other("checkpoint sender"))?.take()
                {
                    started.send(()).map_err(|()| std::io::Error::other("race driver dropped"))?;
                    guard(
                        resume
                            .lock()
                            .map_err(|_| std::io::Error::other("checkpoint receiver"))?
                            .recv_timeout(Duration::from_secs(120)),
                        "export release timed out",
                    )?;
                }
            }
            Ok(())
        }));
    let path = fixture.root.0.join("publication.rfb");
    let (job, worker) = start_archive(&supervisor.backup_jobs, captured, &path)?;
    let stage = supervisor.backup_jobs.root.join(format!("job_{}", job.job_id));
    guard(
        tokio::time::timeout(Duration::from_secs(120), ready).await,
        "export checkpoint timed out",
    )??;
    fixture.erase(&supervisor).await?;
    assert!(fixture.reader.privacy_erasure_generation()? > before);
    if !payload_only {
        assert_eq!(
            fixture.reader.object_erasure_generation()?,
            fences,
            "alias death must not add a payload fence"
        );
    }
    release.send(())?;
    let result = guard(
        tokio::time::timeout(Duration::from_secs(120), worker).await,
        "archive worker timed out",
    )??;
    if authorization_first {
        result.map_err(|failure| format!("archive failure: {failure:?}"))?;
        assert_eq!(
            archive_counts(&path, true)?.attachments,
            2,
            "authorized external copy keeps the pre-delete alias and live payload"
        );
        let next = fixture.root.0.join("next.rfb");
        let captured = guard(
            tokio::time::timeout(Duration::from_secs(120), actor.capture_backup()).await,
            "account backup capture timed out",
        )??;
        let (_, worker) = start_archive(&supervisor.backup_jobs, captured, &next)?;
        guard(
            tokio::time::timeout(Duration::from_secs(120), worker).await,
            "next archive worker timed out",
        )??
        .map_err(|failure| format!("archive failure: {failure:?}"))?;
        assert_eq!(
            archive_counts(&next, false)?.attachments,
            1,
            "next export omits the deleted alias"
        );
    } else {
        let failure = result.err().ok_or("stale export must be refused")?;
        assert_refused_job(&supervisor.backup_jobs, &job.job_id, failure)?;
        assert!(!path.exists());
    }
    assert!(!fixture.root.0.join(format!(".ramflux-backup-{}.partial", job.job_id)).exists());
    assert!(!stage.exists(), "private snapshot and its staged key must be discarded");
    *supervisor.backup_jobs.install_hook.lock().map_err(|_| "hook")? = None;
    supervisor.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn e13_alias_only_delete_overtakes_paused_export() -> TestResult {
    LocalSet::new().run_until(Box::pin(race(false, false))).await
}
#[tokio::test(flavor = "current_thread")]
async fn e13_payload_only_erasure_overtakes_paused_export() -> TestResult {
    LocalSet::new().run_until(Box::pin(race(true, false))).await
}
#[tokio::test(flavor = "current_thread")]
async fn e13_authorization_first_then_delete() -> TestResult {
    LocalSet::new().run_until(Box::pin(race(false, true))).await
}
#[tokio::test(flavor = "current_thread")]
async fn e13_generation_increases_independent_of_fence_count() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut fixture = Fixture::new(false)?;
            let supervisor = fixture.supervisor()?;
            let generation = fixture.reader.privacy_erasure_generation()?;
            let fences = fixture.reader.object_erasure_generation()?;
            fixture.erase(&supervisor).await?;
            assert!(fixture.reader.privacy_erasure_generation()? > generation);
            assert_eq!(fixture.reader.object_erasure_generation()?, fences);
            supervisor.shutdown().await?;
            Ok(())
        }))
        .await
}

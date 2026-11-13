// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual selected `SQLCipher` owner stays local while bounded work waits off-loan.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Fixture {
    _root: tempfile::TempDir,
    db: AccountDb,
    writer: LocalWriterPort,
    service: PairingLocalWriterService,
}
fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let index = AccountIndex::open(root.path())?;
    index.create_account("source", "principal")?;
    let db = AccountDb::open(
        &index,
        "source",
        &ramflux_storage::AccountDbKey::derive("source", b"frontend test key"),
    )?;
    let scope = Arc::new(Scope {
        root: std::fs::canonicalize(root.path())?,
        account: "source".into(),
        anchor: "principal".into(),
        path: std::fs::canonicalize(&db.path)?,
        unlock: db.full_local_unlock_guard()?,
        runtime: Arc::new(FullRuntimeCancel::default()),
        work: Arc::new(tokio::sync::Notify::new()),
    });
    scope.require_db(&db)?;
    let (sender, receiver) = mpsc::channel(1);
    let writer =
        LocalWriterPort { scope: scope.clone(), sender, admission: Arc::new(Semaphore::new(1)) };
    Ok(Fixture { _root: root, db, writer, service: PairingLocalWriterService { scope, receiver } })
}
#[tokio::test(start_paused = true)]
async fn pairing_frontend_writer_keeps_actual_owner_and_rejects_busy_foreign_and_cancelled_work()
-> TestResult {
    crate::bus::credentials::contract_tests::deadline(Box::pin(async {
        let mut fixture = fixture()?;
        let signal = fixture.service.work_signal();
        let (generation, applied) = tokio::join!(
            fixture
                .writer
                .request(|db| Ok(db.pairing_floor()?.map_or(1, |row| row.next_generation))),
            async {
                signal.notified().await;
                assert!(
                    matches!(
                        fixture.writer.request(|_| Ok(())).await,
                        Err(SdkError::PairingCode("Busy"))
                    ),
                    "test: another callback bypassed single-work admission"
                );
                assert!(
                    fixture.db.pairing_floor()?.is_none(),
                    "test: queued work changed the ordinary writer before service"
                );
                fixture.service.try_apply(&fixture.db)?;
                Ok::<(), Box<dyn std::error::Error>>(())
            }
        );
        applied?;
        assert_eq!(generation?, 1, "test: actual frontend callback read another generation owner");
        refuse_foreign(&fixture.writer, &mut fixture.service).await?;
        let used = Arc::new(AtomicBool::new(false));
        let worker = used.clone();
        let signal = fixture.service.work_signal();
        let (cancelled, ()) = tokio::join!(
            fixture.writer.request(move |_| {
                worker.store(true, Ordering::Release);
                Ok(())
            }),
            async {
                signal.notified().await;
                fixture.writer.scope.runtime.stop();
            }
        );
        assert!(
            matches!(cancelled, Err(SdkError::PairingCode("Retired"))),
            "test: root stop did not wake pending local request"
        );
        fixture.service.try_apply(&fixture.db)?;
        assert!(!used.load(Ordering::Acquire), "test: retired callback touched the actual writer");
        Ok(())
    }))
    .await
}
async fn refuse_foreign(
    writer: &LocalWriterPort,
    service: &mut PairingLocalWriterService,
) -> TestResult {
    let root = tempfile::tempdir()?;
    let index = AccountIndex::open(root.path())?;
    index.create_account("source", "principal")?;
    let db = AccountDb::open(
        &index,
        "source",
        &ramflux_storage::AccountDbKey::derive("source", b"different frontend key"),
    )?;
    let used = Arc::new(AtomicBool::new(false));
    let worker = used.clone();
    let signal = service.work_signal();
    let (foreign, applied) = tokio::join!(
        writer.request(move |_| {
            worker.store(true, Ordering::Release);
            Ok(())
        }),
        async {
            signal.notified().await;
            service.try_apply(&db)
        }
    );
    assert!(applied?, "test: foreign callback was never refused");
    assert!(
        matches!(foreign, Err(SdkError::PairingCode("WrongContext"))),
        "test: another selected store satisfied the local writer scope"
    );
    assert!(!used.load(Ordering::Acquire), "test: refused foreign callback executed");
    Ok(())
}

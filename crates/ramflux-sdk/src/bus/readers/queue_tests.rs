// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reader admission refuses only after both independently held worker queues fill.

use super::*;

#[tokio::test]
async fn reader_queue_full_refuses_without_blocking() -> Result<(), Box<dyn std::error::Error>> {
    let root = crate::bus::runtime_tests::root("reader-queue-bound");
    let index = AccountIndex::open(&root)?;
    index.create_account("a", "root")?;
    let key = ramflux_storage::AccountDbKey::generate()?;
    let db = AccountDb::open(&index, "a", &key)?;
    let readers = AccountReaders::start(&db, None)?;
    let mut releases = Vec::new();
    for worker in &readers.senders {
        let (entered, observed) = std::sync::mpsc::sync_channel(1);
        let (release, held) = std::sync::mpsc::channel();
        worker.try_send(ReadCommand::Hold { entered, release: held })?;
        observed.recv_timeout(Duration::from_secs(5))?;
        releases.push(release);
    }
    let mut answers = Vec::new();
    for _ in 0..128 {
        let (reply, answer) = oneshot::channel();
        readers.enqueue(ReadCommand::MissingAttachments(reply))?;
        answers.push(answer);
    }
    let start = std::time::Instant::now();
    let overflow =
        tokio::time::timeout(Duration::from_secs(1), readers.backup_missing_references()).await;
    // Release every held worker before asserting so a failing mutation leaves no blocked thread.
    for release in releases {
        let _ = release.send(());
    }
    assert!(matches!(
        overflow,
        Ok(Err(SdkError::Transport(
            ramflux_transport::TransportError::BackpressureRejected { .. }
        )))
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    for answer in answers {
        assert_eq!(answer.await??.total, 0);
    }
    readers.stop().await;
    drop(readers);
    drop(db);
    drop(index);
    Ok(())
}

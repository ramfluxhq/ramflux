// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
use std::{fs, io::Cursor, sync::Arc};
fn spec(bytes: &[u8]) -> BackendSegment {
    let domain = b"ramflux.attachment.segment.cipher.v1";
    let mut input = u32::try_from(domain.len()).unwrap().to_be_bytes().to_vec();
    input.extend(domain);
    input.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
    input.extend(bytes);
    BackendSegment {
        object: [1; 32],
        manifest: [2; 32],
        generation: 1,
        index: 0,
        length: u64::try_from(bytes.len()).unwrap(),
        chunk: 524_288,
        digest: *blake3::hash(&input).as_bytes(),
    }
}
fn checkpoint(db: &redb::Database) -> serde_json::Value {
    let tx = db.begin_read().unwrap();
    let table = tx.open_table(SEGMENTS).unwrap();
    let (_, v) = table.iter().unwrap().next().unwrap().unwrap();
    serde_json::from_slice(v.value()).unwrap()
}
#[test]
fn large_local_backend_range_commit_is_durable() {
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "rf-backend-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("db");
    let files = root.join("files");
    let db = Arc::new(redb::Database::create(&path).unwrap());
    let tx = db.begin_write().unwrap();
    install(&tx).unwrap();
    tx.commit().unwrap();
    let backend = LocalAttachmentBackend::open(Arc::clone(&db), [3; 32], &files).unwrap();
    let bytes = vec![71; 524_305];
    let spec = spec(&bytes);
    assert!(backend.commit(&spec).is_err());
    assert!(backend.write_chunk(&spec, 1, &mut Cursor::new(&bytes)).is_err());
    assert!(backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..10])).is_err());
    assert_eq!(checkpoint(&db)["bits"], 0);
    backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..524_288])).unwrap();
    assert_eq!(checkpoint(&db)["bits"], 1);
    assert!(!checkpoint(&db)["committed"].as_bool().unwrap());
    assert!(backend.commit(&spec).is_err());
    backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..524_288])).unwrap();
    assert!(backend.write_chunk(&spec, 0, &mut Cursor::new(vec![72; 524_288])).is_err());
    backend.write_chunk(&spec, 524_288, &mut Cursor::new(&bytes[524_288..])).unwrap();
    let data = files.join(format!("{}.data", backend.storage_key(&spec)));
    let part = files.join(format!("{}.part", backend.storage_key(&spec)));
    // Same-length corruption survives file-size checks but must lose its bitmap.
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = fs::OpenOptions::new().write(true).open(&part).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&[99]).unwrap();
        f.sync_all().unwrap();
    }
    drop(backend);
    drop(db);
    let db = Arc::new(redb::Database::open(&path).unwrap());
    let backend = LocalAttachmentBackend::open(Arc::clone(&db), [3; 32], &files).unwrap();
    backend.reconcile(&spec).unwrap();
    assert_eq!(checkpoint(&db)["bits"], 2);
    assert!(backend.commit(&spec).is_err());
    backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..524_288])).unwrap();
    let prepared = backend.prepare(&spec).unwrap();
    assert!(matches!(backend.reconcile(&spec), Err(BackendError::Busy)));
    fs::create_dir(&data).unwrap();
    assert!(backend.publish(prepared).is_err());
    assert!(!checkpoint(&db)["committed"].as_bool().unwrap());
    fs::remove_dir(&data).unwrap();
    fs::rename(&part, &data).unwrap();
    fs::File::open(&files).unwrap().sync_all().unwrap();
    assert!(
        backend
            .reconcile_with(&spec, || Err(BackendError::Remote("unconfirmed recovery")))
            .is_err()
    );
    assert!(!checkpoint(&db)["committed"].as_bool().unwrap());
    backend.reconcile(&spec).unwrap();
    assert!(checkpoint(&db)["committed"].as_bool().unwrap());
    backend.commit(&spec).unwrap();
    assert_eq!(fs::read(&data).unwrap(), bytes);
    assert!(!part.exists());
    assert!(checkpoint(&db)["committed"].as_bool().unwrap());
    drop(backend);
    drop(db);
    let db = Arc::new(redb::Database::open(&path).unwrap());
    let backend = LocalAttachmentBackend::open(Arc::clone(&db), [3; 32], &files).unwrap();
    let mut out = Vec::new();
    backend.read_range(&spec, 524_280, 25, &mut out).unwrap();
    assert_eq!(out, &bytes[524_280..]);
    assert!(backend.read_range(&spec, 0, 524_289, &mut Vec::new()).is_err());
    backend.commit(&spec).unwrap();
    let entries = backend.enumerate(None, 1).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].committed);
    assert!(backend.enumerate(Some(&backend.cursor(&spec)), 1).unwrap().is_empty());
    backend.delete(&spec).unwrap();
    assert!(!data.exists());
    assert!(backend.enumerate(None, 128).unwrap().is_empty());
    backend.delete(&spec).unwrap();
    assert!(matches!(
        backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes[..524_288])),
        Err(BackendError::Retired)
    ));
    assert!(backend.commit(&spec).is_err());
    drop(backend);
    drop(db);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn shared_backend_contract_local() {
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "rf-contract-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
    fs::create_dir_all(&root).unwrap();
    let db = Arc::new(redb::Database::create(root.join("db")).unwrap());
    let tx = db.begin_write().unwrap();
    install(&tx).unwrap();
    tx.commit().unwrap();
    contract::contract_suite(|spec, second| {
        let local =
            LocalAttachmentBackend::open(Arc::clone(&db), [4; 32], &root.join("files")).unwrap();
        let cursors = [local.cursor(spec), local.cursor(second)];
        (local, cursors)
    });
    drop(db);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_readers_and_segment_writers_do_not_starve_delete() {
    use std::{
        io::{Read, Write},
        sync::mpsc,
        time::Duration,
    };
    struct Gate {
        bytes: Cursor<Vec<u8>>,
        ready: Option<mpsc::Sender<()>>,
        release: mpsc::Receiver<()>,
    }
    impl Gate {
        fn wait(&mut self) {
            if let Some(tx) = self.ready.take() {
                tx.send(()).unwrap();
                self.release.recv().unwrap();
            }
        }
    }
    impl Read for Gate {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.wait();
            self.bytes.read(out)
        }
    }
    impl Write for Gate {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.wait();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "rf-parallel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
    fs::create_dir_all(&root).unwrap();
    let db = Arc::new(redb::Database::create(root.join("db")).unwrap());
    let tx = db.begin_write().unwrap();
    install(&tx).unwrap();
    tx.commit().unwrap();
    let backend =
        LocalAttachmentBackend::open(Arc::clone(&db), [5; 32], &root.join("files")).unwrap();
    let first = spec(&[71; 16]);
    let mut second = first.clone();
    second.index = 1;
    let timeout = Duration::from_secs(2);
    let mut writers = Vec::new();
    let mut releases = Vec::new();
    for spec in [&first, &second] {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let local = backend.clone();
        let spec = spec.clone();
        writers.push(std::thread::spawn(move || {
            local.write_chunk(
                &spec,
                0,
                &mut Gate {
                    bytes: Cursor::new(vec![71; 16]),
                    ready: Some(ready_tx),
                    release: release_rx,
                },
            )
        }));
        releases.push(release_tx);
        ready_rx.recv_timeout(timeout).unwrap();
    }
    for tx in releases {
        tx.send(()).unwrap();
    }
    for writer in writers {
        writer.join().unwrap().unwrap();
    }
    backend.commit(&first).unwrap();
    backend.commit(&second).unwrap();
    let mut readers = Vec::new();
    let mut releases = Vec::new();
    for _ in 0..2 {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let local = backend.clone();
        let spec = first.clone();
        readers.push(std::thread::spawn(move || {
            local.read_range(
                &spec,
                0,
                16,
                &mut Gate {
                    bytes: Cursor::new(Vec::new()),
                    ready: Some(ready_tx),
                    release: release_rx,
                },
            )
        }));
        releases.push(release_tx);
        ready_rx.recv_timeout(timeout).unwrap();
    }
    assert!(matches!(backend.delete(&first), Err(BackendError::Busy)));
    // Once deletion is requested, fresh readers are fenced while old readers drain.
    assert!(matches!(
        backend.read_range(&first, 0, 16, &mut Vec::new()),
        Err(BackendError::Retired)
    ));
    for tx in releases {
        tx.send(()).unwrap();
    }
    for reader in readers {
        reader.join().unwrap().unwrap();
    }
    backend.delete(&first).unwrap();
    backend.delete(&second).unwrap();
    assert!(backend.enumerate(None, 128).unwrap().is_empty());
    let locks = fs::read_dir(root.join("files"))
        .unwrap()
        .filter(|p| p.as_ref().unwrap().path().extension().is_some_and(|x| x == "lock"))
        .count();
    assert!(locks <= 4);
    drop(backend);
    drop(db);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn stripe_collision_drain_busy_is_observable_and_retryable() {
    // Generate one bounded collision fixture; backend operations run only once per case.
    let slot = |object: &[u8; 32]| {
        let mut key = [9_u8; 32].to_vec();
        key.extend(object);
        key.extend([2_u8; 32]);
        let hash = blake3::hash(&key);
        u16::from_be_bytes([hash.as_bytes()[0], hash.as_bytes()[1]]) % 4096
    };
    let first = spec(&[71; 16]);
    let second = (0_u32..65_536)
        .find_map(|nonce| {
            let mut candidate = first.clone();
            candidate.object[..4].copy_from_slice(&nonce.to_be_bytes());
            (candidate.object != first.object && slot(&candidate.object) == slot(&first.object))
                .then_some(candidate)
        })
        .unwrap();
    let root = ramflux_test_support::TestPath::new()
        .expect("test: allocate fixture directory")
        .child(format!(
            "rf-drain-metric-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
    fs::create_dir_all(&root).unwrap();
    let db = Arc::new(redb::Database::create(root.join("db")).unwrap());
    let tx = db.begin_write().unwrap();
    install(&tx).unwrap();
    tx.commit().unwrap();
    let backend =
        LocalAttachmentBackend::open(Arc::clone(&db), [9; 32], &root.join("files")).unwrap();
    for spec in [&first, &second] {
        backend.write_chunk(spec, 0, &mut Cursor::new([71; 16])).unwrap();
        backend.commit(spec).unwrap();
    }
    let clone = backend.clone();
    let held = backend.prepare(&first).unwrap();
    assert!(matches!(clone.reconcile(&second), Err(BackendError::Busy)));
    assert!(matches!(clone.delete(&second), Err(BackendError::Busy)));
    assert_eq!(backend.drain_busy_count(), 2);
    assert_eq!(clone.drain_busy_count(), 2);
    drop(held);
    clone.delete(&second).unwrap();
    backend.reconcile(&first).unwrap();
    assert_eq!(backend.drain_busy_count(), 2);
    backend.delete(&first).unwrap();
    drop(clone);
    drop(backend);
    drop(db);
    fs::remove_dir_all(root).unwrap();
}

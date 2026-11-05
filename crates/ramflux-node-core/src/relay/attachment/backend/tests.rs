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
    let root = std::env::temp_dir().join(format!(
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
    assert!(matches!(backend.delete(&spec), Err(BackendError::Busy)));
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
    assert!(!checkpoint(&db)["committed"].as_bool().unwrap());
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

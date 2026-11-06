// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
use ramflux_node_core::{
    AttachmentLedgerError, AttachmentOwner, AttachmentPolicy, AttachmentReservationRequest,
};
use redb::{ReadableDatabase, ReadableTable};
use std::{
    collections::BTreeMap,
    fs,
    io::Cursor,
    path::Path,
    sync::{Arc, Mutex},
};
#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // Independent transport failure injection points.
struct State {
    objects: BTreeMap<String, (S3Object, Vec<u8>)>,
    parts: BTreeMap<String, (String, S3Object, Vec<u8>)>,
    next: u64,
    upload_fail: bool,
    complete_fail: bool,
    abort_fail: bool,
    delete_fail: bool,
    race: bool,
    short: bool,
    probe: Option<(LocalAttachmentBackend, BackendSegment)>,
}
#[derive(Clone, Default)]
struct Fake(Arc<Mutex<State>>);
impl AuthenticatedS3Client for Fake {
    fn head(&self, key: &str) -> Result<Option<S3Object>, S3ClientError> {
        Ok(self.0.lock().unwrap().objects.get(key).map(|(m, _)| m.clone()))
    }
    fn begin_multipart(&self, key: &str, object: &S3Object) -> Result<String, S3ClientError> {
        let mut s = self.0.lock().unwrap();
        s.next += 1;
        let id = s.next.to_string();
        s.parts.insert(id.clone(), (key.into(), object.clone(), Vec::new()));
        Ok(id)
    }
    fn upload_final_part(
        &self,
        _key: &str,
        id: &str,
        length: u64,
        body: &mut dyn Read,
    ) -> Result<String, S3ClientError> {
        let mut s = self.0.lock().unwrap();
        if s.upload_fail {
            return Err(S3ClientError::Transport);
        }
        let mut bytes = Vec::new();
        let mut buf = [0; 1024];
        loop {
            let n = body.read(&mut buf)?;
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..n]);
        }
        assert_eq!(bytes.len() as u64, length);
        s.parts.get_mut(id).unwrap().2 = bytes;
        Ok("part-etag".into())
    }
    fn complete_if_absent(&self, key: &str, id: &str, _etag: &str) -> Result<(), S3ClientError> {
        let mut s = self.0.lock().unwrap();
        if s.complete_fail {
            return Err(S3ClientError::Completion);
        }
        if s.objects.contains_key(key) {
            return Err(S3ClientError::Conflict);
        }
        let (_, m, b) = s.parts.get(id).unwrap().clone();
        s.objects.insert(key.into(), (m, b));
        if s.race {
            return Err(S3ClientError::Conflict);
        }
        s.parts.remove(id);
        Ok(())
    }
    fn abort_multipart(&self, _key: &str, id: &str) -> Result<(), S3ClientError> {
        let mut s = self.0.lock().unwrap();
        if s.abort_fail {
            return Err(S3ClientError::Abort);
        }
        s.parts.remove(id);
        Ok(())
    }
    fn read_range(
        &self,
        key: &str,
        offset: u64,
        length: u64,
        out: &mut dyn Write,
    ) -> Result<(), S3ClientError> {
        let s = self.0.lock().unwrap();
        if let Some((local, spec)) = &s.probe {
            assert!(matches!(local.reconcile(spec), Err(BackendError::Busy)));
        }
        let bytes = &s.objects.get(key).ok_or(S3ClientError::Integrity)?.1;
        let length = if s.short { length - 1 } else { length };
        out.write_all(
            &bytes[usize::try_from(offset).unwrap()..usize::try_from(offset + length).unwrap()],
        )?;
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<(), S3ClientError> {
        let mut s = self.0.lock().unwrap();
        if s.delete_fail {
            return Err(S3ClientError::Delete);
        }
        s.objects.remove(key);
        Ok(())
    }
    fn list_multipart(
        &self,
        prefix: &str,
        _after: Option<&str>,
        limit: usize,
    ) -> Result<MultipartPage, S3ClientError> {
        let s = self.0.lock().unwrap();
        let uploads = s
            .parts
            .iter()
            .filter(|(_, (key, _, _))| key.starts_with(prefix))
            .take(limit)
            .map(|(id, (key, _, _))| MultipartUpload { key: key.clone(), upload_id: id.clone() })
            .collect();
        Ok(MultipartPage { uploads, next: None })
    }
}
fn fixture()
-> (BackendSegment, Vec<u8>, ramflux_protocol::large_attachment::VerifiedContentManifest) {
    let j: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../crates/ramflux-protocol/tests/fixtures/large_attachment_v1.json"
    ))
    .unwrap();
    let c = &j["cases"][0];
    let hex = |v: &str| {
        v.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    let mc = hex(c["content_manifest_unsigned_hex"].as_str().unwrap());
    let mut signed = u32::try_from(mc.len()).unwrap().to_be_bytes().to_vec();
    signed.extend(mc);
    signed.extend(64_u32.to_be_bytes());
    signed.extend(hex(c["content_signature_hex"].as_str().unwrap()));
    let verified =
        ramflux_protocol::large_attachment::ContentManifest::decode_signed(&signed).unwrap();
    (
        BackendSegment::from_manifest(&verified, 1, 0).unwrap(),
        hex(c["segments"][0]["ciphertext_hex"].as_str().unwrap()),
        verified,
    )
}
fn raw_committed(path: &Path) -> bool {
    let db = redb::Database::open(path).unwrap();
    let tx = db.begin_read().unwrap();
    let table: redb::TableDefinition<&[u8], &[u8]> =
        redb::TableDefinition::new("native_attachment_backend_segments_v1");
    let table = tx.open_table(table).unwrap();
    let Some(row) = table.iter().unwrap().next() else {
        return false;
    };
    let (_, v) = row.unwrap();
    let json: serde_json::Value = serde_json::from_slice(v.value()).unwrap();
    json["committed"].as_bool().unwrap()
}
#[test]
fn large_s3_backend_matches_local_commit_and_cleanup_contract() {
    let root = std::env::temp_dir().join(format!(
        "rf-s3-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("db");
    let files = root.join("files");
    let (spec, bytes, native) = fixture();
    let owner =
        AttachmentOwner::from_authenticated_session(&native.manifest().owner.account_anchor)
            .unwrap();
    let upload = [41; 32];
    let fake = Fake::default();
    let store = ramflux_node_core::RelayRedbStore::open(&path).unwrap();
    {
        let ledger = store.attachment_ledger(AttachmentPolicy::default()).unwrap();
        ledger
            .reserve(
                &owner,
                AttachmentReservationRequest {
                    upload_id: upload,
                    object_id: native.manifest().object_id,
                    layout: native.manifest().layout,
                },
                100,
            )
            .unwrap();
        ledger.bind(&owner, &upload, &native, 100).unwrap();
    }
    let local = store.local_attachment_backend([7; 32], &files).unwrap();
    let key = local.storage_key(&spec);
    let backend = S3AttachmentBackend::new(local, fake.clone());
    backend.write_chunk(&spec, 0, &mut Cursor::new(&bytes)).unwrap();
    fake.0.lock().unwrap().upload_fail = true;
    assert!(backend.commit(&spec).is_err());
    assert_eq!(
        store
            .attachment_ledger(AttachmentPolicy::default())
            .unwrap()
            .usage(&owner)
            .unwrap()
            .reserved,
        16
    );
    assert!(fake.0.lock().unwrap().parts.is_empty());
    assert!(backend.read_range(&spec, 0, 16, &mut Vec::new()).is_err());
    fake.0
        .lock()
        .unwrap()
        .objects
        .insert(key.clone(), (S3Object { length: 16, digest: [9; 32] }, bytes.clone()));
    assert!(matches!(backend.commit(&spec), Err(BackendError::Conflict)));
    fake.0.lock().unwrap().objects.remove(&key);
    drop(backend);
    drop(store);
    assert!(!raw_committed(&path));
    let store = ramflux_node_core::RelayRedbStore::open(&path).unwrap();
    let local = store.local_attachment_backend([7; 32], &files).unwrap();
    let backend = S3AttachmentBackend::new(local, fake.clone());
    {
        let mut s = fake.0.lock().unwrap();
        s.upload_fail = false;
        s.complete_fail = true;
        s.abort_fail = true;
    }
    assert!(backend.commit(&spec).is_err());
    assert_eq!(fake.0.lock().unwrap().parts.len(), 1);
    drop(backend);
    drop(store);
    assert!(!raw_committed(&path));
    let store = ramflux_node_core::RelayRedbStore::open(&path).unwrap();
    let local = store.local_attachment_backend([7; 32], &files).unwrap();
    let backend = S3AttachmentBackend::new(local.clone(), fake.clone());
    {
        let mut s = fake.0.lock().unwrap();
        s.abort_fail = false;
        s.complete_fail = false;
        s.race = true;
    }
    backend.reconcile_multipart_page(None, 64).unwrap();
    assert!(fake.0.lock().unwrap().parts.is_empty());
    backend.commit(&spec).unwrap();
    assert!(fake.0.lock().unwrap().parts.is_empty());
    assert_eq!(fake.0.lock().unwrap().objects[&key].1, bytes);
    fake.0.lock().unwrap().probe = Some((local.clone(), spec.clone()));
    backend.commit(&spec).unwrap();
    let mut out = Vec::new();
    backend.read_range(&spec, 3, 7, &mut out).unwrap();
    assert_eq!(out, bytes[3..10]);
    fake.0.lock().unwrap().probe = None;
    assert!(backend.drain_busy_count() > 0);
    fake.0.lock().unwrap().short = true;
    assert!(backend.read_range(&spec, 0, 16, &mut Vec::new()).is_err());
    fake.0.lock().unwrap().short = false;
    backend.reconcile(&spec).unwrap();
    assert_eq!(backend.enumerate(None, 1).unwrap().len(), 1);
    let ledger = store.attachment_ledger(AttachmentPolicy::default()).unwrap();
    ledger.commit(&owner, &upload, spec.generation(), 200).unwrap();
    assert_eq!(ledger.usage(&owner).unwrap().used, 16);
    ledger.gc_due(200 + 7 * 86_400, 64).unwrap();
    // An upload created before its local journal commit is discovered by remote listing.
    fake.begin_multipart(&key, &S3Object { length: 16, digest: spec.digest() }).unwrap();
    fake.0.lock().unwrap().delete_fail = true;
    assert!(
        ledger
            .reclaim(&owner, &upload, |_| backend
                .delete(&spec)
                .map_err(|e| AttachmentLedgerError::Store(e.to_string())))
            .is_err()
    );
    assert_eq!(ledger.usage(&owner).unwrap().used, 16);
    assert!(fake.0.lock().unwrap().parts.is_empty());
    assert!(backend.read_range(&spec, 0, 16, &mut Vec::new()).is_err());
    assert!(backend.commit(&spec).is_err());
    assert!(fake.0.lock().unwrap().objects.contains_key(&key));
    fake.0.lock().unwrap().delete_fail = false;
    ledger
        .reclaim(&owner, &upload, |_| {
            backend.delete(&spec).map_err(|e| AttachmentLedgerError::Store(e.to_string()))
        })
        .unwrap();
    assert_eq!(ledger.usage(&owner).unwrap().used, 0);
    drop(ledger);
    backend.delete(&spec).unwrap();
    assert!(fake.0.lock().unwrap().objects.is_empty());
    assert!(
        fs::read_dir(&files).unwrap().all(|p| !p
            .unwrap()
            .path()
            .extension()
            .is_some_and(|e| e == "data" || e == "part"))
    );
    drop(backend);
    drop(local);
    drop(store);
    assert!(!raw_committed(&path));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn shared_backend_contract_s3() {
    let root = std::env::temp_dir().join(format!(
        "rf-s3-contract-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let store = ramflux_node_core::RelayRedbStore::open(root.join("db")).unwrap();
    ramflux_node_core::attachment::backend::contract::contract_suite(|spec, second| {
        let local = store.local_attachment_backend([8; 32], root.join("files")).unwrap();
        let cursors = [local.cursor(spec), local.cursor(second)];
        (S3AttachmentBackend::new(local, Fake::default()), cursors)
    });
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn client_errors_discard_transport_text_and_sources() {
    let client = S3ClientError::from(std::io::Error::other("credential-bearing transport details"));
    assert_eq!(client.to_string(), "s3_transport");
    assert!(std::error::Error::source(&client).is_none());
    let backend = BackendError::from(client);
    assert!(matches!(backend, BackendError::Remote("s3_transport")));
    assert!(!backend.to_string().contains("credential"));
}

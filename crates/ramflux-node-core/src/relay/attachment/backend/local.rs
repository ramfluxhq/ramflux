// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::{
    AttachmentBackend, BackendCommit, BackendEntry, BackendError, BackendSegment, OBJECTS, Object,
    ReadableDatabase, ReadableTable, Record, SEGMENTS, chunk_length, decode, encode, hex, range,
    segment_hasher, store,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
#[derive(Clone)]
pub struct LocalAttachmentBackend {
    db: Arc<redb::Database>,
    namespace: [u8; 32],
    root: PathBuf,
}
struct Lease {
    _files: Vec<File>,
}
/// Immutable verified staged bytes. Its object lease survives through remote I/O
/// and final publication. It cannot be constructed or cloned by callers.
pub struct PreparedSegment {
    db: Arc<redb::Database>,
    file: File,
    _lease: Lease,
    spec: BackendSegment,
    root: PathBuf,
    namespace: [u8; 32],
    position: u64,
}
impl PreparedSegment {
    #[must_use]
    pub fn length(&self) -> u64 {
        self.spec.length
    }
    #[must_use]
    pub fn consumed(&self) -> u64 {
        self.position
    }
}
impl Read for PreparedSegment {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = out
            .len()
            .min(16 * 1024)
            .min(usize::try_from(self.spec.length - self.position).unwrap_or(0));
        let n = self.file.read(&mut out[..n])?;
        self.position += n as u64;
        Ok(n)
    }
}
impl LocalAttachmentBackend {
    pub(crate) fn open(
        db: Arc<redb::Database>,
        namespace: [u8; 32],
        root: &Path,
    ) -> Result<Self, BackendError> {
        fs::create_dir_all(root)?;
        if !fs::symlink_metadata(root)?.file_type().is_dir() {
            return Err(BackendError::Integrity);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { db, namespace, root: fs::canonicalize(root)? })
    }
    #[must_use]
    pub fn namespace_prefix(&self) -> String {
        hex(&self.namespace)
    }
    #[must_use]
    pub fn storage_key(&self, spec: &BackendSegment) -> String {
        hex(&self.key(spec))
    }
    fn object_key(&self, spec: &BackendSegment) -> Vec<u8> {
        let mut key = self.namespace.to_vec();
        key.extend_from_slice(&spec.object);
        key.extend_from_slice(&spec.manifest);
        key
    }
    #[must_use]
    pub fn cursor(&self, spec: &BackendSegment) -> Vec<u8> {
        self.key(spec)
    }
    fn key(&self, spec: &BackendSegment) -> Vec<u8> {
        let mut key = self.object_key(spec);
        key.extend_from_slice(&spec.generation.to_be_bytes());
        key.extend_from_slice(&spec.index.to_be_bytes());
        key
    }
    fn path(&self, spec: &BackendSegment, suffix: &str) -> PathBuf {
        self.root.join(format!("{}.{}", self.storage_key(spec), suffix))
    }
    // Fixed stripes keep filesystem lock resources bounded, including orphan sweeps.
    fn stripe(&self, key: &[u8], segment: bool, shared: bool) -> Result<File, BackendError> {
        let hash = blake3::hash(key);
        let slot = u16::from_be_bytes([hash.as_bytes()[0], hash.as_bytes()[1]]) % 4096;
        let kind = if segment { "segment" } else { "object" };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join(format!("{kind}-{slot:04x}.lock")))?;
        let result = if shared { file.try_lock_shared() } else { file.try_lock() };
        result.map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => BackendError::Busy,
            std::fs::TryLockError::Error(e) => BackendError::Io(e),
        })?;
        Ok(file)
    }
    fn unfenced(&self, spec: &BackendSegment) -> Result<(), BackendError> {
        let tx = self.db.begin_read().map_err(store)?;
        let table = tx.open_table(OBJECTS).map_err(store)?;
        if let Some(value) = table.get(self.object_key(spec).as_slice()).map_err(store)? {
            let object: Object = decode(value.value())?;
            if object.retired {
                return Err(BackendError::Retired);
            }
            if object.generation != spec.generation {
                return Err(BackendError::Conflict);
            }
        }
        Ok(())
    }
    fn lock(&self, spec: &BackendSegment, read: bool) -> Result<Lease, BackendError> {
        spec.validate()?;
        self.unfenced(spec)?;
        let object = self.stripe(&self.object_key(spec), false, true)?;
        let segment = self.stripe(&self.key(spec), true, read)?;
        self.unfenced(spec)?;
        Ok(Lease { _files: vec![object, segment] })
    }
    fn whole_object(&self, spec: &BackendSegment) -> Result<Lease, BackendError> {
        spec.validate()?;
        Ok(Lease { _files: vec![self.stripe(&self.object_key(spec), false, false)?] })
    }
    fn active(&self, spec: &BackendSegment) -> Result<(), BackendError> {
        let tx = self.db.begin_read().map_err(store)?;
        let objects = tx.open_table(OBJECTS).map_err(store)?;
        let found = objects
            .get(self.object_key(spec).as_slice())
            .map_err(store)?
            .ok_or(BackendError::Integrity)?;
        let object: Object = decode(found.value())?;
        if object.retired {
            return Err(BackendError::Retired);
        }
        if object.generation != spec.generation {
            return Err(BackendError::Conflict);
        }
        Ok(())
    }
    fn load(&self, spec: &BackendSegment) -> Result<Record, BackendError> {
        let tx = self.db.begin_read().map_err(store)?;
        let rows = tx.open_table(SEGMENTS).map_err(store)?;
        let found =
            rows.get(self.key(spec).as_slice()).map_err(store)?.ok_or(BackendError::Integrity)?;
        if found.value().len() > 8192 {
            return Err(BackendError::Integrity);
        }
        let record: Record = decode(found.value())?;
        if record.spec != *spec || record.hashes.len() != 8 {
            return Err(BackendError::Conflict);
        }
        record.spec.validate()?;
        Ok(record)
    }
    fn save(&self, record: &Record) -> Result<(), BackendError> {
        let tx = self.db.begin_write().map_err(store)?;
        {
            tx.open_table(SEGMENTS)
                .map_err(store)?
                .insert(self.key(&record.spec).as_slice(), encode(record)?.as_slice())
                .map_err(store)?;
        }
        tx.commit().map_err(store)
    }
    fn admit(&self, spec: &BackendSegment) -> Result<Record, BackendError> {
        let tx = self.db.begin_write().map_err(store)?;
        let mut objects = tx.open_table(OBJECTS).map_err(store)?;
        let old = objects
            .get(self.object_key(spec).as_slice())
            .map_err(store)?
            .map(|v| decode::<Object>(v.value()))
            .transpose()?;
        if let Some(old) = old {
            if old.retired {
                return Err(BackendError::Retired);
            }
            if old.generation != spec.generation {
                return Err(BackendError::Conflict);
            }
        } else {
            objects
                .insert(
                    self.object_key(spec).as_slice(),
                    encode(&Object { generation: spec.generation, retired: false })?.as_slice(),
                )
                .map_err(store)?;
        }
        let mut rows = tx.open_table(SEGMENTS).map_err(store)?;
        let old = rows
            .get(self.key(spec).as_slice())
            .map_err(store)?
            .map(|v| decode::<Record>(v.value()))
            .transpose()?;
        let record = old.unwrap_or_else(|| Record {
            spec: spec.clone(),
            bits: 0,
            hashes: vec![[0; 32]; 8],
            committed: false,
            upload: None,
        });
        if record.spec != *spec {
            return Err(BackendError::Conflict);
        }
        rows.insert(self.key(spec).as_slice(), encode(&record)?.as_slice()).map_err(store)?;
        drop(rows);
        drop(objects);
        tx.commit().map_err(store)?;
        Ok(record)
    }
    /// Verifies the whole staged segment once before committing either backend.
    /// # Errors
    /// Refuses missing chunks, corrupt bytes, retired identities and concurrent work.
    pub fn prepare(&self, spec: &BackendSegment) -> Result<PreparedSegment, BackendError> {
        let lease = self.lock(spec, false)?;
        self.active(spec)?;
        let record = self.load(spec)?;
        let count = spec.length.div_ceil(u64::from(spec.chunk));
        if record.bits.count_ones() != u32::try_from(count).map_err(|_| BackendError::Bounds)? {
            return Err(BackendError::Integrity);
        }
        let final_path = self.path(spec, "data");
        let path = if final_path.exists() { final_path } else { self.path(spec, "part") };
        regular(&path)?;
        let mut file = File::open(path)?;
        if file.metadata()?.len() != spec.length {
            return Err(BackendError::Integrity);
        }
        let mut hash = segment_hasher(spec.length);
        let mut buffer = [0; 16 * 1024];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        if hash.finalize().as_bytes() != &spec.digest {
            return Err(BackendError::Integrity);
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(PreparedSegment {
            db: Arc::clone(&self.db),
            file,
            _lease: lease,
            spec: spec.clone(),
            root: self.root.clone(),
            namespace: self.namespace,
            position: 0,
        })
    }
    /// Publishes only after data/name durability; failed metadata remains recoverable.
    /// # Errors
    /// Refuses a foreign proof or failed filesystem/metadata persistence.
    pub fn publish(&self, prepared: PreparedSegment) -> Result<BackendCommit, BackendError> {
        if prepared.root != self.root
            || prepared.namespace != self.namespace
            || !Arc::ptr_eq(&prepared.db, &self.db)
        {
            return Err(BackendError::Conflict);
        }
        let spec = &prepared.spec;
        self.active(spec)?;
        prepared.file.sync_all()?;
        let part = self.path(spec, "part");
        if part.exists() {
            fs::rename(part, self.path(spec, "data"))?;
        }
        sync_dir(&self.root)?;
        let mut record = self.load(spec)?;
        record.committed = true;
        record.upload = None;
        self.save(&record)?;
        let receipt = BackendCommit { spec: spec.clone() };
        drop(prepared);
        Ok(receipt)
    }
    /// Journals a remote upload before sending parts; only the prepared proof owner
    /// may call this while it holds the lease.
    /// # Errors
    /// Refuses mismatched proof, oversized upload IDs and storage failures.
    pub fn journal_upload(
        &self,
        prepared: &PreparedSegment,
        upload: Option<&str>,
    ) -> Result<(), BackendError> {
        if prepared.root != self.root
            || prepared.namespace != self.namespace
            || !Arc::ptr_eq(&prepared.db, &self.db)
            || upload.is_some_and(|s| s.is_empty() || s.len() > 1024)
        {
            return Err(BackendError::Bounds);
        }
        let mut record = self.load(&prepared.spec)?;
        record.upload = upload.map(str::to_owned);
        self.save(&record)
    }
    /// Returns physical checkpoint metadata, never serving authority.
    /// # Errors
    /// Refuses unknown identities or corrupt metadata.
    pub fn status(&self, spec: &BackendSegment) -> Result<BackendEntry, BackendError> {
        let r = self.load(spec)?;
        Ok(BackendEntry {
            spec: r.spec,
            received: r.bits,
            committed: r.committed,
            upload: r.upload,
        })
    }
    /// Aborts one abandoned remote upload under the object's exclusive lease.
    /// Unknown uploads can exist after a crash between remote creation and journal commit.
    /// # Errors
    /// Refuses foreign keys/active writers, failed aborts or journal persistence.
    pub fn abort_multipart(
        &self,
        key: &str,
        id: &str,
        abort: impl FnOnce() -> Result<(), BackendError>,
    ) -> Result<(), BackendError> {
        if key.len() != 216 || !key.starts_with(&self.namespace_prefix()) {
            return Err(BackendError::Bounds);
        }
        let mut raw = Vec::new();
        for pair in key.as_bytes().as_chunks::<2>().0 {
            let hex = std::str::from_utf8(pair).map_err(|_| BackendError::Bounds)?;
            let byte = u8::from_str_radix(hex, 16).map_err(|_| BackendError::Bounds)?;
            raw.push(byte);
        }
        if hex(&raw) != key {
            return Err(BackendError::Bounds);
        }
        let _lease = self.stripe(&raw[..96], false, false)?;
        abort()?;
        let tx = self.db.begin_write().map_err(store)?;
        {
            let mut rows = tx.open_table(SEGMENTS).map_err(store)?;
            let record = rows
                .get(raw.as_slice())
                .map_err(store)?
                .map(|v| decode::<Record>(v.value()))
                .transpose()?;
            if let Some(mut record) = record
                && record.upload.as_deref() == Some(id)
            {
                record.upload = None;
                rows.insert(raw.as_slice(), encode(&record)?.as_slice()).map_err(store)?;
            }
        }
        tx.commit().map_err(store)
    }
    /// Operator recovery page, never an unauthenticated object-list endpoint.
    /// # Errors
    /// Refuses foreign/oversized cursors, invalid limits and corrupt metadata.
    pub fn enumerate(
        &self,
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<BackendEntry>, BackendError> {
        if limit == 0
            || limit > 128
            || after.is_some_and(|key| key.len() != 108 || !key.starts_with(&self.namespace))
        {
            return Err(BackendError::Bounds);
        }
        let start = after.map_or_else(|| self.namespace.to_vec(), <[u8]>::to_vec);
        let tx = self.db.begin_read().map_err(store)?;
        let rows = tx.open_table(SEGMENTS).map_err(store)?;
        let mut out = Vec::new();
        for item in rows.range(start.as_slice()..).map_err(store)?.take(limit + 1) {
            let (key, v) = item.map_err(store)?;
            if !key.value().starts_with(&self.namespace) {
                break;
            }
            if after.is_some_and(|after| key.value() <= after) {
                continue;
            }
            if v.value().len() > 8192 {
                return Err(BackendError::Integrity);
            }
            let r: Record = decode(v.value())?;
            r.spec.validate()?;
            out.push(BackendEntry {
                spec: r.spec,
                received: r.bits,
                committed: r.committed,
                upload: r.upload,
            });
            if out.len() == limit {
                break;
            }
        }
        Ok(out)
    }
    /// # Errors
    /// Fails closed while the current writer owns bytes; otherwise verifies/clears
    /// checkpoint bits without trusting a pre-crash bitmap.
    pub fn reconcile(&self, spec: &BackendSegment) -> Result<(), BackendError> {
        self.reconcile_with(spec, || Ok(()))
    }
    /// Verifies a recovered final file and its remote durability under one lease.
    /// # Errors
    /// Does not publish recovered metadata on failed remote confirmation.
    pub fn reconcile_with(
        &self,
        spec: &BackendSegment,
        confirm: impl FnOnce() -> Result<(), BackendError>,
    ) -> Result<(), BackendError> {
        let _lease = self.whole_object(spec)?;
        self.active(spec)?;
        let mut record = self.load(spec)?;
        let data = self.path(spec, "data");
        let part = self.path(spec, "part");
        let path = if data.exists() { &data } else { &part };
        let mut bits = 0;
        let mut committed = false;
        if path.exists() {
            regular(path)?;
            let mut file = File::open(path)?;
            for index in 0..spec.length.div_ceil(u64::from(spec.chunk)) {
                let offset = index * u64::from(spec.chunk);
                let len = chunk_length(spec, offset)?;
                if record.bits & (1 << index) != 0 && file.metadata()?.len() >= offset + len {
                    let hash = hash_range(&mut file, offset, len)?;
                    if record.hashes.get(usize::try_from(index).map_err(|_| BackendError::Bounds)?)
                        == Some(&hash)
                    {
                        bits |= 1 << index;
                    }
                }
            }
            if data.exists() && file.metadata()?.len() == spec.length {
                file.seek(SeekFrom::Start(0))?;
                let mut hash = segment_hasher(spec.length);
                let mut buffer = [0; 16384];
                loop {
                    let n = file.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hash.update(&buffer[..n]);
                }
                committed = hash.finalize().as_bytes() == &spec.digest;
            }
        }
        if !committed && data.exists() {
            fs::remove_file(data)?;
            sync_dir(&self.root)?;
            bits = 0;
        }
        if committed {
            confirm()?;
        }
        record.bits = bits;
        record.committed = committed;
        self.save(&record)
    }
    /// Holds the object lease through the entire published range operation.
    /// # Errors
    /// Refuses unpublished/retired identities, invalid ranges and callback failure.
    pub fn with_committed_range<T>(
        &self,
        spec: &BackendSegment,
        offset: u64,
        length: u64,
        read: impl FnOnce() -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        let _lease = self.lock(spec, true)?;
        range(spec, offset, length)?;
        self.active(spec)?;
        if !self.load(spec)?.committed {
            return Err(BackendError::Integrity);
        }
        read()
    }
    /// Fences before remote and local cleanup, holding the lease until durability.
    /// # Errors
    /// Retains metadata/cleanup debt on any callback or filesystem failure.
    pub fn delete_with(
        &self,
        spec: &BackendSegment,
        remote: impl FnOnce(Option<&str>) -> Result<(), BackendError>,
    ) -> Result<(), BackendError> {
        spec.validate()?;
        let tx = self.db.begin_write().map_err(store)?;
        {
            let mut objects = tx.open_table(OBJECTS).map_err(store)?;
            let old = objects
                .get(self.object_key(spec).as_slice())
                .map_err(store)?
                .map(|v| decode::<Object>(v.value()))
                .transpose()?;
            if old.is_some_and(|old| old.generation != spec.generation) {
                return Err(BackendError::Conflict);
            }
            objects
                .insert(
                    self.object_key(spec).as_slice(),
                    encode(&Object { generation: spec.generation, retired: true })?.as_slice(),
                )
                .map_err(store)?;
        }
        tx.commit().map_err(store)?;
        // Persist the fence first: fresh readers cannot starve cleanup retries.
        let _lease = self.whole_object(spec)?;
        let record = {
            let tx = self.db.begin_read().map_err(store)?;
            let rows = tx.open_table(SEGMENTS).map_err(store)?;
            let value = rows.get(self.key(spec).as_slice()).map_err(store)?;
            value.map(|v| decode::<Record>(v.value())).transpose()?
        };
        if record.as_ref().is_some_and(|r| r.spec != *spec) {
            return Err(BackendError::Conflict);
        }
        remote(record.as_ref().and_then(|r| r.upload.as_deref()))?;
        for suffix in ["part", "data"] {
            let path = self.path(spec, suffix);
            if path.exists() {
                regular(&path)?;
                fs::remove_file(path)?;
            }
        }
        sync_dir(&self.root)?;
        let tx = self.db.begin_write().map_err(store)?;
        {
            tx.open_table(SEGMENTS)
                .map_err(store)?
                .remove(self.key(spec).as_slice())
                .map_err(store)?;
        }
        tx.commit().map_err(store)?;
        // Only the object generation/retired tombstone remains; segment rows are gone.

        Ok(())
    }
}
impl AttachmentBackend for LocalAttachmentBackend {
    fn write_chunk(
        &self,
        spec: &BackendSegment,
        offset: u64,
        input: &mut dyn Read,
    ) -> Result<(), BackendError> {
        let _lease = self.lock(spec, false)?;
        let len = chunk_length(spec, offset)?;
        let mut record = self.admit(spec)?;
        let index =
            usize::try_from(offset / u64::from(spec.chunk)).map_err(|_| BackendError::Bounds)?;
        let data = self.path(spec, "data");
        let path = if data.exists() { data } else { self.path(spec, "part") };
        if record.bits & (1 << index) != 0 {
            regular(&path)?;
            let mut file = File::open(path)?;
            let expected = hash_range(&mut file, offset, len)?;
            let actual = hash_reader(input, len, None)?;
            if expected != actual || record.hashes[index] != actual {
                return Err(BackendError::Conflict);
            }
            return Ok(());
        }
        let mut file = match OpenOptions::new().read(true).write(true).create_new(true).open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                regular(&path)?;
                OpenOptions::new().read(true).write(true).open(&path)?
            }
            Err(e) => return Err(e.into()),
        };
        file.seek(SeekFrom::Start(offset))?;
        let hash = hash_reader(input, len, Some(&mut file))?;
        file.sync_all()?;
        sync_dir(&self.root)?;
        record.hashes[index] = hash;
        record.bits |= 1 << index;
        self.save(&record)
    }
    fn commit(&self, spec: &BackendSegment) -> Result<BackendCommit, BackendError> {
        self.publish(self.prepare(spec)?)
    }
    fn read_range(
        &self,
        spec: &BackendSegment,
        offset: u64,
        length: u64,
        output: &mut dyn Write,
    ) -> Result<(), BackendError> {
        let _lease = self.lock(spec, true)?;
        range(spec, offset, length)?;
        self.active(spec)?;
        if !self.load(spec)?.committed {
            return Err(BackendError::Integrity);
        }
        let path = self.path(spec, "data");
        regular(&path)?;
        let mut file = File::open(path)?;
        if file.metadata()?.len() != spec.length {
            return Err(BackendError::Integrity);
        }
        file.seek(SeekFrom::Start(offset))?;
        copy_exact(&mut file, output, length)
    }
    fn enumerate(
        &self,
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<BackendEntry>, BackendError> {
        LocalAttachmentBackend::enumerate(self, after, limit)
    }
    fn reconcile(&self, spec: &BackendSegment) -> Result<(), BackendError> {
        LocalAttachmentBackend::reconcile(self, spec)
    }
    fn delete(&self, spec: &BackendSegment) -> Result<(), BackendError> {
        self.delete_with(spec, |upload| {
            if upload.is_some() {
                Err(BackendError::Remote("multipart cleanup required"))
            } else {
                Ok(())
            }
        })
    }
}
fn regular(path: &Path) -> Result<(), BackendError> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(BackendError::Integrity);
    }
    Ok(())
}
fn sync_dir(path: &Path) -> Result<(), BackendError> {
    File::open(path)?.sync_all()?;
    Ok(())
}
fn hash_range(file: &mut File, offset: u64, length: u64) -> Result<[u8; 32], BackendError> {
    file.seek(SeekFrom::Start(offset))?;
    let mut take = file.take(length);
    let mut hash = blake3::Hasher::new();
    let mut buffer = [0; 16384];
    let mut seen = 0;
    loop {
        let n = take.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        seen += n as u64;
    }
    if seen != length {
        return Err(BackendError::Integrity);
    }
    Ok(*hash.finalize().as_bytes())
}
fn hash_reader(
    input: &mut dyn Read,
    length: u64,
    mut output: Option<&mut File>,
) -> Result<[u8; 32], BackendError> {
    let mut hash = blake3::Hasher::new();
    let mut remaining = length;
    let mut buffer = [0; 16384];
    while remaining > 0 {
        let n = input.read(
            &mut buffer
                [..usize::try_from(remaining.min(16384)).map_err(|_| BackendError::Bounds)?],
        )?;
        if n == 0 {
            return Err(BackendError::Integrity);
        }
        if let Some(file) = output.as_mut() {
            file.write_all(&buffer[..n])?;
        }
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    if input.read(&mut buffer[..1])? != 0 {
        return Err(BackendError::Bounds);
    }
    Ok(*hash.finalize().as_bytes())
}
fn copy_exact(
    input: &mut dyn Read,
    output: &mut dyn Write,
    mut length: u64,
) -> Result<(), BackendError> {
    let mut buffer = [0; 16384];
    while length > 0 {
        let n = input.read(
            &mut buffer[..usize::try_from(length.min(16384)).map_err(|_| BackendError::Bounds)?],
        )?;
        if n == 0 {
            return Err(BackendError::Integrity);
        }
        output.write_all(&buffer[..n])?;
        length -= n as u64;
    }
    Ok(())
}

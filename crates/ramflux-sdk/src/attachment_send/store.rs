// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable prepare directory. One row per prepare, fsynced before the caller continues.

use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use super::budget::{self, staging_bytes};
use super::chunks::{self, accept};
use super::codes::{
    CODE_CANCELLED, CODE_DIGEST_MISMATCH, CODE_DISABLED, CODE_DUPLICATE, CODE_EXPIRED,
    CODE_FILE_TOO_LARGE, CODE_LAYOUT_INVALID, CODE_NOT_OWNER, CODE_SEAL_FAILED,
    CODE_STALE_GENERATION, CODE_STREAM_OFFSET, Refusal,
};
use super::meta::{CHUNK, IndexEntry, Intent, MAX_PLAINTEXT, Phase, Recipient, Row};
use super::path_admit::open_anchored;
use super::seal::{self, seal_key};

pub(crate) struct Store {
    root: PathBuf,
    account: String,
    account_secret: [u8; 32],
}

impl Store {
    /// # Errors
    /// Returns `seal_failed` when the account directory cannot be created.
    pub(crate) fn open(
        root: &Path,
        account: &str,
        account_secret: [u8; 32],
    ) -> Result<Self, Refusal> {
        let root = root.join("attachment-prepares");
        fs::create_dir_all(&root).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        Ok(Self { root, account: account.to_owned(), account_secret })
    }

    /// # Errors
    /// Returns a stable code when the intent, flag, path, or budget is refused.
    pub(crate) fn begin(
        &self,
        intent: Intent<'_>,
        enabled: bool,
        now: u64,
        path: Option<&Path>,
    ) -> Result<Row, Refusal> {
        if !enabled {
            return Err(Refusal::new(CODE_DISABLED));
        }
        check_intent(&intent)?;
        if let Some(existing) = self.find(&intent)? {
            return self.load(&existing.prepare_id);
        }
        let prepare_id = fresh_id()?;
        let mut row = Row::fresh(intent, prepare_id, now);
        let dir = self.dir(&row.prepare_id);
        fs::create_dir_all(&dir).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        if let Some(relative) = path {
            self.copy_path(&mut row, relative)?;
        }
        self.save(&row)?;
        self.remember(&row)?;
        Ok(row)
    }

    /// # Errors
    /// Returns `stream_offset`, `stale_generation`, `disk_full`, or `file_too_large`.
    pub(crate) fn chunk(
        &self,
        prepare_id: &str,
        generation: u64,
        offset: u64,
        bytes: &[u8],
        now: u64,
    ) -> Result<Row, Refusal> {
        let mut row = self.owned(prepare_id, generation, now)?;
        let len = u64::try_from(bytes.len()).map_err(|_| Refusal::new(CODE_STREAM_OFFSET))?;
        if len > CHUNK {
            return Err(Refusal::new(CODE_STREAM_OFFSET));
        }
        let end = offset.saturating_add(len);
        let extra = if offset == row.accepted_through {
            budget::growth(row.accepted_through, end)?
        } else {
            0
        };
        if extra > 0 {
            budget::charge(extra)?;
            row.charged = row.charged.saturating_add(extra);
        }
        if let Err(error) = accept(&self.dir(prepare_id), &mut row, offset, bytes) {
            if extra > 0 {
                budget::release(extra);
                row.charged = row.charged.saturating_sub(extra);
            }
            self.save(&row)?;
            return Err(error);
        }
        self.save(&row)?;
        Ok(row)
    }

    /// # Errors
    /// Returns `digest_mismatch` and fences the generation when the log does not match.
    pub(crate) fn finish(
        &self,
        prepare_id: &str,
        generation: u64,
        length: u64,
        digest: [u8; 32],
        now: u64,
    ) -> Result<Row, Refusal> {
        let mut row = self.owned(prepare_id, generation, now)?;
        if length > MAX_PLAINTEXT {
            return Err(Refusal::new(CODE_FILE_TOO_LARGE));
        }
        if row.phase == Phase::Accepted
            && row.plaintext_length == Some(length)
            && row.plaintext_digest == Some(digest)
        {
            return Ok(row);
        }
        if row.accepted_through != length {
            self.fence(&mut row)?;
            return Err(Refusal::new(CODE_DIGEST_MISMATCH));
        }
        let got = if length == 0 {
            *blake3::hash(b"").as_bytes()
        } else {
            chunks::digest(&self.dir(prepare_id).join("plain.bin"), length)?
        };
        if got != digest {
            self.fence(&mut row)?;
            return Err(Refusal::new(CODE_DIGEST_MISMATCH));
        }
        row.plaintext_length = Some(length);
        row.plaintext_digest = Some(digest);
        row.phase = Phase::Accepted;
        self.save(&row)?;
        self.remember(&row)?;
        Ok(row)
    }

    pub(crate) fn status(&self, prepare_id: &str) -> Result<Row, Refusal> {
        self.load(prepare_id)
    }

    /// # Errors
    /// Returns `not_owner` for another account.
    pub(crate) fn cancel(&self, prepare_id: &str, generation: u64) -> Result<Row, Refusal> {
        let mut row = self.load(prepare_id)?;
        if row.account != self.account {
            return Err(Refusal::new(CODE_NOT_OWNER));
        }
        if row.generation != generation {
            return Err(Refusal::new(CODE_STALE_GENERATION));
        }
        row.phase = if matches!(row.phase, Phase::Committed | Phase::Granted | Phase::Admitted) {
            Phase::Cleaning
        } else {
            Phase::Fenced
        };
        Self::release_charge(&mut row);
        self.save(&row)?;
        Ok(row)
    }

    /// # Errors
    /// Returns `expired`, `cancelled`, or `stale_generation`.
    pub(crate) fn renew(
        &self,
        prepare_id: &str,
        generation: u64,
        now: u64,
    ) -> Result<Row, Refusal> {
        let mut row = self.load(prepare_id)?;
        if row.account != self.account {
            return Err(Refusal::new(CODE_NOT_OWNER));
        }
        if row.generation != generation || matches!(row.phase, Phase::Fenced) {
            return Err(Refusal::new(CODE_STALE_GENERATION));
        }
        if matches!(row.phase, Phase::Cleaning) {
            return Err(Refusal::new(CODE_CANCELLED));
        }
        if now >= row.expires_at || row.expires_at >= row.hard_deadline || now >= row.hard_deadline
        {
            return Err(Refusal::new(CODE_EXPIRED));
        }
        row.expires_at = row.expires_at.saturating_add(super::meta::LEASE).min(row.hard_deadline);
        self.save(&row)?;
        Ok(row)
    }

    /// Restart. A `Sealing` row is fenced even when no segment file exists.
    /// # Errors
    /// Returns `seal_failed` when the row cannot be rewritten.
    pub(crate) fn resume(&self, prepare_id: &str, now: u64) -> Result<Row, Refusal> {
        let mut row = self.load(prepare_id)?;
        let plain = self.dir(prepare_id).join("plain.bin");
        if plain.exists() {
            let len = fs::metadata(&plain).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?.len();
            if len > row.accepted_through {
                chunks::truncate(&plain, row.accepted_through)?;
            }
        }
        if row.phase == Phase::Sealing {
            self.remove_segments(prepare_id)?;
            self.destroy_secret(&row)?;
            if let Some(upload) = row.upload_id {
                row.abandoned.push(upload);
            }
            row.upload_id = None;
            row.object_id = None;
            row.segment_digests.clear();
            row.generation = row.generation.saturating_add(1);
            row.phase = if now < row.hard_deadline && row.plaintext_digest.is_some() {
                Phase::Accepted
            } else {
                Phase::Fenced
            };
        }
        self.save(&row)?;
        Ok(row)
    }

    /// Draw a key and object id and store them before Reserve. Only from `Accepted` or a retry of `Reserved`.
    /// # Errors
    /// Returns `seal_failed` or `expired`.
    pub(crate) fn draw(&self, prepare_id: &str, now: u64) -> Result<Row, Refusal> {
        let mut row = self.load(prepare_id)?;
        if now >= row.hard_deadline {
            row.phase = Phase::Fenced;
            self.save(&row)?;
            return Err(Refusal::new(CODE_EXPIRED));
        }
        if row.phase == Phase::Reserved && row.object_id.is_some() && row.upload_id.is_some() {
            return Ok(row);
        }
        if row.phase != Phase::Accepted {
            return Err(Refusal::new(CODE_SEAL_FAILED));
        }
        let mut file_key = [0_u8; 32];
        let mut object_id = [0_u8; 32];
        let mut upload_id = [0_u8; 32];
        getrandom::fill(&mut file_key).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        getrandom::fill(&mut object_id).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        getrandom::fill(&mut upload_id).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let sealed = seal::seal(&self.wrap_key(&row.prepare_id), &file_key, &object_id)?;
        file_key.fill(0);
        write_atomic(&self.dir(&row.prepare_id).join("secret.bin"), &sealed)?;
        row.upload_id = Some(upload_id);
        row.object_id = Some(object_id);
        row.phase = Phase::Reserved;
        self.save(&row)?;
        Ok(row)
    }

    /// # Errors
    /// Returns `seal_failed` when the sealed key is missing or will not open.
    pub(crate) fn open_secret(
        &self,
        row: &Row,
    ) -> Result<(zeroize::Zeroizing<[u8; 32]>, [u8; 32]), Refusal> {
        let bytes = fs::read(self.dir(&row.prepare_id).join("secret.bin"))
            .map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let (key, object) = seal::open(&self.wrap_key(&row.prepare_id), &bytes)?;
        if Some(object) != row.object_id {
            return Err(Refusal::new(CODE_SEAL_FAILED));
        }
        Ok((key, object))
    }

    /// Marks granted prepares admitted after the one message is submitted.
    /// # Errors
    /// Returns `seal_failed` when a row cannot be rewritten.
    pub(crate) fn admit_granted(&self, ids: &[String]) -> Result<(), Refusal> {
        for id in ids {
            let row = self.load(id)?;
            if row.phase == Phase::Granted {
                self.mark(row, Phase::Admitted)?;
            }
        }
        Ok(())
    }

    pub(crate) fn mark(&self, mut row: Row, phase: Phase) -> Result<Row, Refusal> {
        row.phase = phase;
        self.save(&row)?;
        Ok(row)
    }

    pub(crate) fn load(&self, prepare_id: &str) -> Result<Row, Refusal> {
        let bytes = fs::read(self.dir(prepare_id).join("meta.json"))
            .map_err(|_| Refusal::new(CODE_NOT_OWNER))?;
        serde_json::from_slice(&bytes).map_err(|_| Refusal::new(CODE_SEAL_FAILED))
    }

    fn owned(&self, prepare_id: &str, generation: u64, now: u64) -> Result<Row, Refusal> {
        let row = self.load(prepare_id)?;
        if row.account != self.account {
            return Err(Refusal::new(CODE_NOT_OWNER));
        }
        if row.generation != generation {
            return Err(Refusal::new(CODE_STALE_GENERATION));
        }
        if matches!(row.phase, Phase::Fenced | Phase::Cleaning) {
            return Err(Refusal::new(CODE_CANCELLED));
        }
        if now >= row.expires_at || now >= row.hard_deadline {
            return Err(Refusal::new(CODE_EXPIRED));
        }
        Ok(row)
    }

    fn copy_path(&self, row: &mut Row, relative: &Path) -> Result<(), Refusal> {
        let mut file = open_anchored(self.root.parent().unwrap_or(&self.root), relative)?;
        let len = file.metadata().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?.len();
        if len > MAX_PLAINTEXT {
            return Err(Refusal::new(CODE_FILE_TOO_LARGE));
        }
        let need = staging_bytes(len)?;
        budget::charge(need)?;
        row.charged = need;
        if let Err(error) = self.copy_body(row, &mut file) {
            Self::release_charge(row);
            let _ = fs::remove_dir_all(self.dir(&row.prepare_id));
            return Err(error);
        }
        Ok(())
    }

    fn copy_body(&self, row: &mut Row, file: &mut File) -> Result<(), Refusal> {
        let mut offset = 0_u64;
        let cap = usize::try_from(CHUNK).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        let mut buf = vec![0_u8; cap];
        loop {
            let n = file.read(&mut buf).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
            if n == 0 {
                return Ok(());
            }
            accept(&self.dir(&row.prepare_id), row, offset, &buf[..n])?;
            offset += u64::try_from(n).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        }
    }

    /// # Errors
    /// Returns `seal_failed` when the row cannot be rewritten.
    pub(crate) fn save_row(&self, row: &Row) -> Result<(), Refusal> {
        self.save(row)
    }

    /// # Errors
    /// Returns `path_refused` for a name that is not a single path segment.
    pub(crate) fn write_named(
        &self,
        prepare_id: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), Refusal> {
        if !name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-') {
            return Err(Refusal::new(super::codes::CODE_PATH_REFUSED));
        }
        write_atomic(&self.dir(prepare_id).join(name), bytes)
    }

    /// # Errors
    /// Returns `seal_failed` when the named file is absent.
    pub(crate) fn read_named(&self, prepare_id: &str, name: &str) -> Result<Vec<u8>, Refusal> {
        fs::read(self.dir(prepare_id).join(name)).map_err(|_| Refusal::new(CODE_SEAL_FAILED))
    }

    #[must_use]
    pub(crate) fn plain_path(&self, prepare_id: &str) -> PathBuf {
        self.dir(prepare_id).join("plain.bin")
    }

    /// Destroys the sealed key and fences the generation. The predecessor debt stays charged.
    /// # Errors
    /// Returns `seal_failed` when the row cannot be rewritten.
    pub(crate) fn fence_secret(&self, mut row: Row) -> Result<Row, Refusal> {
        self.destroy_secret(&row)?;
        if let Some(upload) = row.upload_id {
            row.abandoned.push(upload);
        }
        row.upload_id = None;
        row.object_id = None;
        row.phase = Phase::Fenced;
        Self::release_charge(&mut row);
        self.save(&row)?;
        Ok(row)
    }

    fn remove_segments(&self, prepare_id: &str) -> Result<(), Refusal> {
        let dir = self.dir(prepare_id);
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Refusal::new(CODE_SEAL_FAILED)),
        };
        for entry in entries {
            let entry = entry.map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
            let path = entry.path();
            let segment = path
                .file_name()
                .and_then(|item| item.to_str())
                .is_some_and(|item| item.starts_with("segment-"))
                && path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("bin"));
            if segment {
                fs::remove_file(path).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
            }
        }
        Ok(())
    }

    fn fence(&self, row: &mut Row) -> Result<(), Refusal> {
        chunks::remove_plain(&self.dir(&row.prepare_id));
        row.phase = Phase::Fenced;
        self.save(row)
    }

    fn destroy_secret(&self, row: &Row) -> Result<(), Refusal> {
        let path = self.dir(&row.prepare_id).join("secret.bin");
        if path.exists() {
            fs::remove_file(&path).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        }
        Ok(())
    }

    fn release_charge(row: &mut Row) {
        budget::release(row.charged);
        row.charged = 0;
    }

    fn wrap_key(&self, prepare_id: &str) -> [u8; 32] {
        seal_key(&self.account_secret, prepare_id)
    }

    fn dir(&self, prepare_id: &str) -> PathBuf {
        self.root.join(prepare_id)
    }

    fn save(&self, row: &Row) -> Result<(), Refusal> {
        let bytes = serde_json::to_vec(row).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        write_atomic(&self.dir(&row.prepare_id).join("meta.json"), &bytes)
    }

    fn remember(&self, row: &Row) -> Result<(), Refusal> {
        let mut index = self.index()?;
        index.retain(|entry| entry.operation_id != row.operation_id);
        index.push(IndexEntry {
            prepare_id: row.prepare_id.clone(),
            account: row.account.clone(),
            operation_id: row.operation_id.clone(),
            recipient: row.recipient.clone(),
            file_name: row.file_name.clone(),
            mime: row.mime.clone(),
            digest: row.plaintext_digest,
        });
        let bytes = serde_json::to_vec(&index).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        write_atomic(&self.root.join("index.json"), &bytes)
    }

    fn find(&self, intent: &Intent<'_>) -> Result<Option<IndexEntry>, Refusal> {
        for entry in self.index()? {
            if entry.operation_id != intent.operation_id {
                continue;
            }
            let same = entry.account == intent.account
                && entry.recipient == intent.recipient
                && entry.file_name == intent.file_name
                && entry.mime == intent.mime;
            if !same {
                return Err(Refusal::new(CODE_DUPLICATE));
            }
            return Ok(Some(entry));
        }
        Ok(None)
    }

    fn index(&self) -> Result<Vec<IndexEntry>, Refusal> {
        let path = self.root.join("index.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(path).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        serde_json::from_slice(&bytes).map_err(|_| Refusal::new(CODE_SEAL_FAILED))
    }
}

fn check_intent(intent: &Intent<'_>) -> Result<(), Refusal> {
    if intent.operation_id.is_empty() || intent.operation_id.len() > 256 {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    if intent.file_name.is_empty()
        || intent.file_name.len() > 256
        || intent.mime.is_empty()
        || intent.mime.len() > 256
        || intent.file_name.chars().any(char::is_control)
    {
        return Err(Refusal::new(CODE_LAYOUT_INVALID));
    }
    match &intent.recipient {
        Recipient::Dm { peer } if peer.is_empty() => Err(Refusal::new(CODE_LAYOUT_INVALID)),
        Recipient::Group { group_id } if group_id.is_empty() => {
            Err(Refusal::new(CODE_LAYOUT_INVALID))
        }
        _ => Ok(()),
    }
}

fn fresh_id() -> Result<String, Refusal> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Refusal> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        file.write_all(bytes).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
        file.sync_all().map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    }
    fs::rename(&tmp, path).map_err(|_| Refusal::new(CODE_SEAL_FAILED))?;
    Ok(())
}

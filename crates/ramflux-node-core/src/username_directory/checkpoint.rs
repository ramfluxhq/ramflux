// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Single-owner witness: durable CAS/redo/image and ephemeral lease/publication fences.
use super::{
    CheckpointClock, CheckpointError, CheckpointHead, CheckpointTime, IMAGE, ImagePage, META, REDO,
    ReadableTable, Result, TX_IDS, apply, canonical, fixed, nonce, page, put_head, read_head,
    require, reserve_file, storage,
};
use ramflux_protocol::username_directory as wire;
use redb::{ReadableDatabase, ReadableTableMetadata};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

/// An incarnation is never restored from disk. Every operation rechecks its expiry and boot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriterLease {
    pub generation: u64,
    pub witness_boot: String,
    pub incarnation: String,
}
#[derive(Clone, Debug)]
pub struct MutationAdmission {
    pub root: String,
    pub home: String,
    pub control: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextKind {
    Resolve { name: String, nonce: String },
    Receipt { operation_id: String },
    Status { operation_id: String },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextRequest {
    pub call_id: String,
    pub session: String,
    pub caller_root: String,
    pub root: String,
    pub home: String,
    pub kind: ContextKind,
}
struct Context {
    request: ContextRequest,
    deadline: u64,
    candidate: Option<wire::ServeCandidate>,
    bytes: Vec<u8>,
    offset: usize,
}
struct Admission {
    scope: MutationAdmission,
    deadline: u64,
}
/// Witness-chosen time supplied to the typed intent builder before opening a DB write.
#[derive(Clone, Copy, Debug)]
pub struct CommitStamp {
    pub wall: u64,
}
/// Observation hooks allow faults at the actual transaction boundary, without bypassing sync.
pub trait CheckpointObserver: Send + Sync {
    /// # Errors
    /// Returns a storage fault at the named physical transaction boundary.
    fn boundary(&self, name: &'static str) -> Result<()>;
}
struct NoObserver;
impl CheckpointObserver for NoObserver {
    fn boundary(&self, _: &'static str) -> Result<()> {
        Ok(())
    }
}
/// Durable authority image. No networking, signing secret or automatic bootstrap/recovery path.
pub struct CheckpointWitness {
    pub(crate) db: redb::Database,
    head: CheckpointHead,
    clock: Arc<dyn CheckpointClock>,
    observer: Arc<dyn CheckpointObserver>,
    center_key: Option<ed25519_dalek::VerifyingKey>,
    boot: String,
    lease: Option<(WriterLease, u64)>,
    applied: Option<CheckpointHead>,
    last_monotonic: u64,
    admissions: BTreeMap<String, Admission>,
    contexts: BTreeMap<String, Context>,
}
impl CheckpointWitness {
    /// Privileged initialization only. Service adapters must authenticate controller authority.
    /// # Errors
    /// Refuses existing initialization, malformed schema/clock or unavailable storage.
    pub fn initialize(
        path: &Path,
        center: &str,
        generation: u64,
        clock: Arc<dyn CheckpointClock>,
    ) -> Result<Self> {
        require(!path.exists(), "already_initialized")?;
        let head = CheckpointHead::genesis(center, generation, clock.now().wall)?;
        reserve_file(path)?;
        let db = redb::Database::create(path).map_err(storage)?;
        let mut tx = db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        tx.open_table(META).map_err(storage)?;
        tx.open_table(IMAGE).map_err(storage)?;
        tx.open_table(REDO).map_err(storage)?;
        tx.open_table(TX_IDS).map_err(storage)?;
        tx.open_table(META)
            .map_err(storage)?
            .insert("initialized", b"1".as_slice())
            .map_err(storage)?;
        put_head(&tx, &head)?;
        tx.commit().map_err(storage)?;
        Self::from_db(db, head, clock)
    }
    /// Open existing protected state; missing anchors are never recreated.
    /// # Errors
    /// Refuses absent/corrupt/foreign/unsupported anchors and a concurrent witness instance.
    pub fn open(
        path: &Path,
        center: &str,
        generation: u64,
        clock: Arc<dyn CheckpointClock>,
    ) -> Result<Self> {
        require(path.is_file(), "missing_witness")?;
        let db = redb::Database::open(path).map_err(storage)?;
        let head = read_head(&db)?;
        require(head.center_id == center && head.generation == generation, "identity")?;
        {
            let tx = db.begin_read().map_err(storage)?;
            let table = tx.open_table(META).map_err(storage)?;
            require(
                table.get("initialized").map_err(storage)?.is_some_and(|v| v.value() == b"1"),
                "uninitialized",
            )?;
        }
        Self::from_db(db, head, clock)
    }
    fn from_db(
        db: redb::Database,
        head: CheckpointHead,
        clock: Arc<dyn CheckpointClock>,
    ) -> Result<Self> {
        let time = clock.now();
        require(
            time.wall >= head.clock_floor && time.wall <= ramflux_protocol::MAX_SAFE_JSON_INTEGER,
            "clock",
        )?;
        Ok(Self {
            db,
            head,
            clock,
            observer: Arc::new(NoObserver),
            center_key: None,
            boot: nonce()?,
            lease: None,
            applied: None,
            last_monotonic: time.monotonic,
            admissions: BTreeMap::new(),
            contexts: BTreeMap::new(),
        })
    }
    /// Configure the existing independently pinned center public key before acquiring a lease.
    /// # Errors
    /// Refuses weak keys or changing the configured identity during an active lease.
    pub fn configure_center_key(&mut self, key: ed25519_dalek::VerifyingKey) -> Result<()> {
        require(self.lease.is_none(), "center_key_busy")?;
        require(!key.is_weak(), "center_key")?;
        self.center_key = Some(key);
        Ok(())
    }
    /// Install a physical-boundary observer; it cannot approve or bypass a transaction.
    pub fn set_observer(&mut self, observer: Arc<dyn CheckpointObserver>) {
        self.observer = observer;
    }
    #[must_use]
    pub fn head(&self) -> CheckpointHead {
        self.head.clone()
    }
    #[must_use]
    pub fn witness_boot(&self) -> &str {
        &self.boot
    }
    fn time(&mut self) -> Result<CheckpointTime> {
        let time = self.clock.now();
        if time.monotonic < self.last_monotonic
            || time.wall < self.head.clock_floor
            || time.wall > ramflux_protocol::MAX_SAFE_JSON_INTEGER
        {
            self.fence();
            return Err(CheckpointError::Refused("clock"));
        }
        self.last_monotonic = time.monotonic;
        Ok(time)
    }
    fn fence(&mut self) {
        self.lease = None;
        self.applied = None;
        self.admissions.clear();
        self.contexts.clear();
    }
    fn live(&mut self, token: &WriterLease) -> Result<CheckpointTime> {
        let time = self.time()?;
        let live = self
            .lease
            .as_ref()
            .is_some_and(|(current, until)| current == token && time.monotonic < *until);
        if !live {
            if self.lease.as_ref().is_some_and(|(_, until)| time.monotonic >= *until) {
                self.fence();
            }
            return Err(CheckpointError::Refused("lease"));
        }
        Ok(time)
    }
    /// Acquire a fresh lease only after the prior lease ends. Acquisition never implies READY.
    /// # Errors
    /// Refuses an occupied lease, invalid incarnation, clock rollback or arithmetic exhaustion.
    pub fn acquire(&mut self, incarnation: &str) -> Result<WriterLease> {
        fixed(incarnation)?;
        let time = self.time()?;
        require(
            self.lease.as_ref().is_none_or(|(_, until)| time.monotonic >= *until),
            "lease_busy",
        )?;
        self.fence();
        let token = WriterLease {
            generation: self.head.generation,
            witness_boot: self.boot.clone(),
            incarnation: incarnation.into(),
        };
        let until = time.monotonic.checked_add(10_000).ok_or(CheckpointError::Refused("clock"))?;
        self.lease = Some((token.clone(), until));
        Ok(token)
    }
    /// # Errors
    /// Refuses expired/foreign lease tokens; renewal does not establish primary equality.
    pub fn renew(&mut self, token: &WriterLease) -> Result<()> {
        let time = self.live(token)?;
        let until = time.monotonic.checked_add(10_000).ok_or(CheckpointError::Refused("clock"))?;
        self.lease = Some((token.clone(), until));
        Ok(())
    }
    /// # Errors
    /// Refuses an unrelated token; release invalidates all callbacks and candidates.
    pub fn release(&mut self, token: &WriterLease) -> Result<()> {
        self.live(token)?;
        self.fence();
        Ok(())
    }
    /// Notify only after the caller's exact private primary transaction has physically synced.
    /// # Errors
    /// Refuses stale boot/incarnation, foreign/missing/ahead/conflicting heads or expired leases.
    pub fn primary_applied(&mut self, token: &WriterLease, head: &CheckpointHead) -> Result<()> {
        self.live(token)?;
        require(*head == self.head, "primary_head")?;
        self.applied = Some(head.clone());
        Ok(())
    }
    /// # Errors
    /// Refuses any unreconciled or fenced writer, even at a previously equal saved head.
    pub fn ready(&mut self, token: &WriterLease) -> Result<()> {
        self.live(token)?;
        require(self.applied.as_ref() == Some(&self.head), "primary_applied")
    }
    /// Bound queued mutations before allocation; control traffic retains sixteen global slots.
    /// # Errors
    /// Refuses duplicate root, exhausted home/global budgets, stale lease or malformed IDs.
    pub fn admit_mutation(
        &mut self,
        token: &WriterLease,
        scope: MutationAdmission,
    ) -> Result<String> {
        self.ready(token)?;
        fixed(&scope.root)?;
        CheckpointHead::genesis(&scope.home, 1, self.head.clock_floor)?;
        let now = self.time()?.monotonic;
        self.admissions.retain(|_, v| now < v.deadline);
        let cap = if scope.control { 64 } else { 48 };
        require(self.admissions.len() < cap, "queue_global")?;
        require(
            self.admissions.values().filter(|v| v.scope.home == scope.home).count() < 4,
            "queue_home",
        )?;
        require(!self.admissions.values().any(|v| v.scope.root == scope.root), "queue_root")?;
        let id = nonce()?;
        let deadline = now.checked_add(5_000).ok_or(CheckpointError::Refused("clock"))?;
        self.admissions.insert(id.clone(), Admission { scope, deadline });
        Ok(id)
    }
    /// Assign the new checkpoint head/time, validate CAS, and sync image+redo+head atomically.
    /// The builder constructs a NEW unsigned typed intent from the witness time; signed operations
    /// are never normalized. Center action/quota admission is additionally owned by the center store.
    /// # Errors
    /// Refuses stale admission/head, malformed intents, invalid images, redo saturation or I/O.
    pub fn append<F>(
        &mut self,
        token: &WriterLease,
        admission: &str,
        expected: &CheckpointHead,
        build: F,
    ) -> Result<wire::Checkpoint>
    where
        F: FnOnce(CommitStamp) -> Result<wire::CheckpointDelta>,
    {
        self.ready(token)?;
        let time = self.time()?;
        let job = self.admissions.remove(admission).ok_or(CheckpointError::Refused("admission"))?;
        require(time.monotonic < job.deadline, "deadline")?;
        require(*expected == self.head, "head_cas")?;
        let delta = build(CommitStamp { wall: time.wall })?;
        require(delta.writer_incarnation == token.incarnation, "writer_incarnation")?;
        require(delta.clock_floor == time.wall, "commit_clock")?;
        require(self.live(token)?.monotonic < job.deadline, "deadline")?;
        require(self.clock.now().wall == time.wall, "commit_clock")?;
        wire::encode(&delta)?;
        validate_transitions(&delta, &job.scope.root, time.wall)?;
        let lsn = self
            .head
            .lsn
            .checked_add(1)
            .filter(|v| *v <= ramflux_protocol::MAX_SAFE_JSON_INTEGER)
            .ok_or(CheckpointError::Refused("lsn_exhausted"))?;
        let checkpoint = wire::Checkpoint {
            center_id: self.head.center_id.clone(),
            generation: self.head.generation,
            lsn,
            previous_digest: self.head.digest.clone(),
            delta,
        };
        let frame = wire::encode(&checkpoint)?;
        let digest = ramflux_crypto::username_directory::checkpoint_hash(&checkpoint)?;
        let next = CheckpointHead { lsn, digest, clock_floor: time.wall, ..self.head.clone() };
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        let redo = tx.open_table(REDO).map_err(storage)?;
        require(
            redo.len().map_err(storage)? < if job.scope.control { 16384 } else { 16368 },
            "redo_global",
        )?;
        drop(redo);
        {
            let ids = tx.open_table(TX_IDS).map_err(storage)?;
            require(ids.get(checkpoint.delta.tx_id.as_str()).map_err(storage)?.is_none(), "tx_id")?;
        }
        // Physical redo is bounded independently per root, with no scan over unrelated roots.
        {
            let mut table = tx.open_table(META).map_err(storage)?;
            let index = format!("redo_root:{}", job.scope.root);
            let count = table
                .get(index.as_str())
                .map_err(storage)?
                .map(|v| v.value().to_vec())
                .map(|v| serde_json::from_slice::<u64>(&v))
                .transpose()?
                .unwrap_or(0);
            require(count < 64, "redo_root")?;
            table.insert(index.as_str(), canonical(&(count + 1))?.as_slice()).map_err(storage)?;
            table
                .insert(
                    format!("redo_owner:{lsn}").as_str(),
                    canonical(&job.scope.root)?.as_slice(),
                )
                .map_err(storage)?;
        }
        self.observer.boundary("before_image")?;
        apply(&tx, &checkpoint.delta)?;
        self.observer.boundary("after_image")?;
        tx.open_table(REDO).map_err(storage)?.insert(lsn, frame.as_slice()).map_err(storage)?;
        tx.open_table(TX_IDS)
            .map_err(storage)?
            .insert(checkpoint.delta.tx_id.as_str(), lsn)
            .map_err(storage)?;
        put_head(&tx, &next)?;
        self.observer.boundary("before_witness_fsync")?;
        tx.commit().map_err(storage)?;
        self.head = next;
        self.applied = None;
        self.contexts.clear();
        self.observer.boundary("after_witness_fsync")?;
        self.live(token)?;
        Ok(checkpoint)
    }
    /// Resolve a lost reply by its exact transaction ID; never append a replacement blindly.
    /// # Errors
    /// Refuses invalid IDs or corrupt storage. Compacted historical IDs may be absent.
    pub fn transaction(&self, id: &str) -> Result<Option<wire::Checkpoint>> {
        fixed(id)?;
        let tx = self.db.begin_read().map_err(storage)?;
        let ids = tx.open_table(TX_IDS).map_err(storage)?;
        let Some(lsn) = ids.get(id).map_err(storage)?.map(|v| v.value()) else { return Ok(None) };
        let redo = tx.open_table(REDO).map_err(storage)?;
        let frame =
            redo.get(lsn).map_err(storage)?.ok_or(CheckpointError::Refused("redo_missing"))?;
        Ok(Some(wire::decode(frame.value())?))
    }
    /// # Errors
    /// Refuses oversized pages or unavailable/corrupt image storage.
    pub fn image_page(&self, after: Option<&[u8]>, limit: usize) -> Result<ImagePage> {
        page(&self.db, after, limit)
    }
    /// Compact at most128 already-applied redo records; the authoritative image/head stays intact.
    /// # Errors
    /// Refuses live primary inequality, invalid bounds or storage failure.
    pub fn compact(&mut self, token: &WriterLease, through: u64) -> Result<usize> {
        self.ready(token)?;
        require(through <= self.head.lsn, "compact_head")?;
        let mut tx = self.db.begin_write().map_err(storage)?;
        tx.set_durability(redb::Durability::Immediate).map_err(storage)?;
        let mut redo = tx.open_table(REDO).map_err(storage)?;
        let mut entries = Vec::new();
        for row in redo.range(..=through).map_err(storage)?.take(128) {
            let (lsn, frame) = row.map_err(storage)?;
            let checkpoint: wire::Checkpoint = wire::decode(frame.value())?;
            entries.push((lsn.value(), checkpoint.delta.tx_id));
        }
        let mut ids = tx.open_table(TX_IDS).map_err(storage)?;
        for (lsn, id) in &entries {
            let mut meta = tx.open_table(META).map_err(storage)?;
            let owner_key = format!("redo_owner:{lsn}");
            let owner: String = serde_json::from_slice(
                meta.get(owner_key.as_str())
                    .map_err(storage)?
                    .ok_or(CheckpointError::Refused("redo_owner"))?
                    .value(),
            )?;
            let count_key = format!("redo_root:{owner}");
            let count: u64 = serde_json::from_slice(
                meta.get(count_key.as_str())
                    .map_err(storage)?
                    .ok_or(CheckpointError::Refused("redo_root"))?
                    .value(),
            )?;
            require(count > 0, "redo_root")?;
            if count == 1 {
                meta.remove(count_key.as_str()).map_err(storage)?;
            } else {
                meta.insert(count_key.as_str(), canonical(&(count - 1))?.as_slice())
                    .map_err(storage)?;
            }
            meta.remove(owner_key.as_str()).map_err(storage)?;
            redo.remove(*lsn).map_err(storage)?;
            ids.remove(id.as_str()).map_err(storage)?;
        }
        drop(ids);
        drop(redo);
        tx.commit().map_err(storage)?;
        Ok(entries.len())
    }
    fn root(&self, id: &str) -> Result<Option<wire::RootRow>> {
        let key = [b"root\0".as_slice(), canonical(&id)?.as_slice()].concat();
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(IMAGE).map_err(storage)?;
        let Some(row) = table.get(key.as_slice()).map_err(storage)? else { return Ok(None) };
        match wire::decode(row.value())? {
            wire::Replacement::Root { new, .. } => Ok(new),
            _ => Err(CheckpointError::Refused("root_image")),
        }
    }
    /// Admit authenticated request correlation. Service adapters own authentication/peer UID checks.
    /// # Errors
    /// Refuses malformed/reused contexts, wrong home, deadlines or bounded handler ceilings.
    pub fn admit_context(&mut self, token: &WriterLease, request: ContextRequest) -> Result<()> {
        self.ready(token)?;
        for id in [&request.call_id, &request.session, &request.caller_root, &request.root] {
            fixed(id)?;
        }
        CheckpointHead::genesis(&request.home, 1, self.head.clock_floor)?;
        match &request.kind {
            ContextKind::Resolve { name, nonce } => {
                wire::validate_username(name)?;
                fixed(nonce)?;
            }
            ContextKind::Receipt { operation_id } | ContextKind::Status { operation_id } => {
                fixed(operation_id)?;
            }
        }
        let time = self.time()?;
        self.contexts.retain(|_, v| time.monotonic < v.deadline);
        require(!self.contexts.contains_key(&request.call_id), "call_id")?;
        require(self.contexts.len() < 64, "context_global")?;
        require(
            self.contexts.values().filter(|v| v.request.caller_root == request.caller_root).count()
                < 4,
            "context_root",
        )?;
        require(
            self.contexts.values().filter(|v| v.request.home == request.home).count() < 16,
            "context_home",
        )?;
        let root = self.root(&request.root)?.ok_or(CheckpointError::Refused("root_missing"))?;
        if !matches!(request.kind, ContextKind::Resolve { .. }) {
            require(request.caller_root == request.root && root.node == request.home, "home")?;
        }
        let deadline =
            time.monotonic.checked_add(10_000).ok_or(CheckpointError::Refused("clock"))?;
        self.contexts.insert(
            request.call_id.clone(),
            Context { request, deadline, candidate: None, bytes: Vec::new(), offset: 0 },
        );
        Ok(())
    }
    /// Store one bounded response candidate, never a reusable publication permit.
    /// # Errors
    /// Refuses tuple/head/request/root mismatch or duplicate candidates.
    pub fn enqueue_candidate(
        &mut self,
        token: &WriterLease,
        candidate: wire::ServeCandidate,
    ) -> Result<()> {
        self.ready(token)?;
        wire::encode(&candidate)?;
        let (generation, boot, writer, lsn, digest, id) = candidate_metadata(&candidate);
        require(generation == self.head.generation, "candidate_generation")?;
        require(boot == self.boot, "candidate_boot")?;
        require(writer == token.incarnation, "candidate_writer")?;
        require(lsn == self.head.lsn && digest == self.head.digest, "candidate_head")?;
        let context = self.contexts.get(id).ok_or(CheckpointError::Refused("context"))?;
        require(context.candidate.is_none(), "candidate_duplicate")?;
        let root =
            self.root(&context.request.root)?.ok_or(CheckpointError::Refused("root_missing"))?;
        validate_response(&candidate, &context.request, &root, &self.head, self.clock.now().wall)?;
        let key = self.center_key.as_ref().ok_or(CheckpointError::Refused("center_key"))?;
        match &candidate {
            wire::ServeCandidate::Resolve { response, .. } => {
                ramflux_crypto::username_directory::verify_resolve(
                    key,
                    &self.head.center_id,
                    response,
                )?;
            }
            wire::ServeCandidate::Receipt { response, .. }
            | wire::ServeCandidate::Status { response, .. } => {
                ramflux_crypto::username_directory::verify_receipt(
                    key,
                    &self.head.center_id,
                    response,
                )?;
            }
            wire::ServeCandidate::Refusal { .. } => {}
        }
        let bytes = response_bytes(&candidate)?;
        let context = self.contexts.get_mut(id).ok_or(CheckpointError::Refused("context"))?;
        context.bytes = bytes;
        context.candidate = Some(candidate);
        Ok(())
    }
    /// Revalidate immediately before a bounded synchronous try-write. No await or DB lock spans it.
    /// An error after a partial response requires the adapter to close/reset its stream.
    /// # Errors
    /// Refuses stale lease/head/root, expired contexts, oversized writes or writer I/O failure.
    pub fn publish_step<F>(&mut self, token: &WriterLease, call_id: &str, write: F) -> Result<bool>
    where
        F: FnOnce(&[u8]) -> std::io::Result<usize>,
    {
        self.ready(token)?;
        let now = self.time()?;
        let context = self.contexts.get(call_id).ok_or(CheckpointError::Refused("context"))?;
        if now.monotonic >= context.deadline {
            self.contexts.remove(call_id);
            return Err(CheckpointError::Refused("context_deadline"));
        }
        let root =
            self.root(&context.request.root)?.ok_or(CheckpointError::Refused("root_missing"))?;
        let candidate =
            context.candidate.as_ref().ok_or(CheckpointError::Refused("candidate_missing"))?;
        validate_response(candidate, &context.request, &root, &self.head, now.wall)?;
        self.live(token)?;
        let context = self.contexts.get_mut(call_id).ok_or(CheckpointError::Refused("context"))?;
        let remaining = &context.bytes[context.offset..];
        let count = match write(remaining) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => {
                self.contexts.remove(call_id);
                return Err(e.into());
            }
        };
        require(count <= remaining.len(), "write_count")?;
        context.offset += count;
        let complete = context.offset == context.bytes.len();
        if complete {
            self.contexts.remove(call_id);
        }
        Ok(complete)
    }
    pub fn close_context(&mut self, call_id: &str) {
        self.contexts.remove(call_id);
    }
}
fn candidate_metadata(candidate: &wire::ServeCandidate) -> (u64, &str, &str, u64, &str, &str) {
    match candidate {
        wire::ServeCandidate::Receipt {
            generation,
            witness_boot,
            writer_incarnation,
            primary_lsn,
            primary_digest,
            call_id,
            ..
        }
        | wire::ServeCandidate::Status {
            generation,
            witness_boot,
            writer_incarnation,
            primary_lsn,
            primary_digest,
            call_id,
            ..
        }
        | wire::ServeCandidate::Resolve {
            generation,
            witness_boot,
            writer_incarnation,
            primary_lsn,
            primary_digest,
            call_id,
            ..
        }
        | wire::ServeCandidate::Refusal {
            generation,
            witness_boot,
            writer_incarnation,
            primary_lsn,
            primary_digest,
            call_id,
            ..
        } => (*generation, witness_boot, writer_incarnation, *primary_lsn, primary_digest, call_id),
    }
}
fn response_bytes(candidate: &wire::ServeCandidate) -> Result<Vec<u8>> {
    match candidate {
        wire::ServeCandidate::Receipt { response, .. }
        | wire::ServeCandidate::Status { response, .. } => Ok(wire::encode(response)?),
        wire::ServeCandidate::Resolve { response, .. } => Ok(wire::encode(response)?),
        wire::ServeCandidate::Refusal { response, .. } => Ok(wire::encode(response)?),
    }
}
fn validate_response(
    candidate: &wire::ServeCandidate,
    request: &ContextRequest,
    root: &wire::RootRow,
    head: &CheckpointHead,
    now: u64,
) -> Result<()> {
    let (_, _, _, lsn, digest, _) = candidate_metadata(candidate);
    require(lsn == head.lsn && digest == head.digest, "candidate_head")?;
    if !matches!(request.kind, ContextKind::Resolve { .. }) {
        require(request.caller_root == request.root && root.node == request.home, "home")?;
    }
    match (candidate, &request.kind) {
        (wire::ServeCandidate::Resolve { response, .. }, ContextKind::Resolve { name, nonce }) => {
            let b = &response.body;
            require(
                !root.deleted && root.discoverable && root.pending_operation_id.is_none(),
                "lookup_allowed",
            )?;
            require(
                root.name.as_ref() == Some(name) && b.name == *name && b.request_nonce == *nonce,
                "request_correlation",
            )?;
            require(
                b.center_id == head.center_id
                    && b.principal_commitment == request.root
                    && b.node == root.node,
                "response_owner",
            )?;
            require(
                b.epoch == root.epoch
                    && b.profile == root.profile
                    && root.binding_hash.as_ref() == Some(&b.binding_hash),
                "response_tuple",
            )?;
            require(b.issued_at <= now && now < b.expires_at, "response_time")?;
        }
        (wire::ServeCandidate::Receipt { response, .. }, ContextKind::Receipt { operation_id })
        | (wire::ServeCandidate::Status { response, .. }, ContextKind::Status { operation_id }) => {
            let b = &response.body;
            require(
                b.center_id == head.center_id
                    && b.principal_commitment == request.root
                    && b.operation_id == *operation_id,
                "response_owner",
            )?;
            // Current committed status remains available after detail GC; historical status needs
            // the center store's retained operation lookup and cannot impersonate current state.
            require(
                b.state == wire::ReceiptState::Committed
                    && root.last_operation_id.as_ref() == Some(operation_id),
                "current_receipt",
            )?;
            require(
                root.last_operation_hash.as_ref() == Some(&b.operation_hash)
                    && b.epoch == root.epoch
                    && b.profile == root.profile
                    && b.binding_hash == root.binding_hash
                    && b.discoverable == root.discoverable,
                "response_tuple",
            )?;
            require(
                root.receipt_decision.as_ref().is_some_and(|v| v.committed_at == b.committed_at),
                "receipt_decision",
            )?;
            require(now < b.expires_at && b.expires_at <= now.saturating_add(60), "response_time")?;
        }
        (wire::ServeCandidate::Refusal { response, .. }, _) => {
            require(response.code == wire::DirectoryCode::DirectoryUnavailable, "refusal_scope")?;
        }
        _ => return Err(CheckpointError::Refused("response_kind")),
    }
    Ok(())
}
fn validate_transitions(delta: &wire::CheckpointDelta, root_id: &str, now: u64) -> Result<()> {
    if let Some(operation) = &delta.operation {
        require(
            now.saturating_add(60) >= operation.body.issued_at && now < operation.body.expires_at,
            "operation_expired",
        )?;
    }
    for row in &delta.rows {
        match row {
            wire::Replacement::Root { key, old, new } => {
                validate_root_transition(key, old.as_ref(), new.as_ref(), delta, root_id, now)?;
            }
            wire::Replacement::Operation { key, old, new } => {
                validate_operation_transition(
                    key,
                    old.as_ref(),
                    new.as_ref(),
                    delta,
                    root_id,
                    now,
                )?;
            }
            wire::Replacement::Hold { old, new, .. } => {
                if let Some(next) = new {
                    require(
                        old.is_none()
                            && delta.kind == wire::DeltaKind::Commit
                            && next.release_at == now,
                        "hold_time",
                    )?;
                } else {
                    require(
                        delta.kind == wire::DeltaKind::Gc
                            && old.as_ref().is_some_and(|v| now >= v.hold_until),
                        "hold_gc",
                    )?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_root_transition(
    key: &str,
    old: Option<&wire::RootRow>,
    new: Option<&wire::RootRow>,
    delta: &wire::CheckpointDelta,
    root_id: &str,
    now: u64,
) -> Result<()> {
    require(key == root_id, "admission_root")?;
    let next = new.ok_or(CheckpointError::Refused("root_delete"))?;
    if let Some(previous) = old {
        require(
            next.profile.epoch >= previous.profile.epoch
                && next.profile.version >= previous.profile.version,
            "profile_floor",
        )?;
        if next.profile.epoch == previous.profile.epoch {
            require(next.profile == previous.profile, "profile_equivocation")?;
        }
        if delta.kind != wire::DeltaKind::Commit {
            require(
                next.epoch == previous.epoch
                    && next.name == previous.name
                    && next.node == previous.node
                    && next.discoverable == previous.discoverable
                    && next.deleted == previous.deleted
                    && next.profile == previous.profile
                    && next.binding_hash == previous.binding_hash
                    && next.current_binding == previous.current_binding
                    && next.receipt_decision == previous.receipt_decision
                    && next.last_operation_id == previous.last_operation_id
                    && next.last_operation_hash == previous.last_operation_hash,
                "uncommitted_authority",
            )?;
        }
    }
    if let Some(decision) = &next.receipt_decision {
        require(decision.committed_at <= now, "decision_time")?;
    }
    if delta.kind == wire::DeltaKind::Commit {
        require(
            next.receipt_decision.as_ref().is_some_and(|v| v.committed_at == now),
            "decision_time",
        )?;
        let op = delta.operation.as_ref().ok_or(CheckpointError::Refused("operation"))?;
        require(
            op.body.principal_commitment == *key
                && next.epoch == op.body.next_epoch
                && next.profile == op.body.profile
                && next.current_binding == op.body.binding
                && next.last_operation_id.as_ref() == Some(&op.body.operation_id)
                && next.last_operation_hash.as_ref()
                    == Some(&ramflux_crypto::username_directory::operation_hash(op)?),
            "commit_tuple",
        )?;
    }
    if let Some(binding) = &next.current_binding {
        require(
            next.binding_hash.as_ref()
                == Some(&ramflux_crypto::username_directory::binding_hash(binding)?),
            "binding_hash",
        )?;
    }

    Ok(())
}

fn validate_operation_transition(
    key: &wire::OperationKey,
    old: Option<&wire::OperationRow>,
    new: Option<&wire::OperationRow>,
    delta: &wire::CheckpointDelta,
    root_id: &str,
    now: u64,
) -> Result<()> {
    require(key.root == root_id, "admission_root")?;
    if let Some(next) = new {
        require(
            next.operation_hash
                == ramflux_crypto::username_directory::operation_hash(&next.operation)?,
            "operation_hash",
        )?;
        if let Some(previous) = old {
            require(
                next.operation == previous.operation
                    && next.operation_hash == previous.operation_hash
                    && next.reserved_at == previous.reserved_at
                    && next.reservation_expires_at == previous.reservation_expires_at,
                "operation_immutable",
            )?;
            require(
                previous.state == wire::ReceiptState::Reserved
                    && next.state != wire::ReceiptState::Reserved,
                "operation_state",
            )?;
        }
        if next.state == wire::ReceiptState::Reserved {
            require(next.reserved_at == now, "reservation_time")?;
        } else {
            require(next.finished_at == Some(now), "finished_at")?;
        }
        if next.state == wire::ReceiptState::Committed {
            require(
                now < next.reservation_expires_at && now < next.operation.body.expires_at,
                "operation_expired",
            )?;
        }
    } else {
        require(
            delta.kind == wire::DeltaKind::Gc
                && old.is_some_and(|v| {
                    v.state != wire::ReceiptState::Reserved
                        && v.retain_until.is_some_and(|until| now >= until)
                }),
            "detail_gc",
        )?;
    }

    Ok(())
}

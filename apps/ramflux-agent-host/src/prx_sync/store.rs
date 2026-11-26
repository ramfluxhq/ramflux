// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owner-only mirror of one PRX journal. The host checkpoint stays separate.

use ramflux_prx_client::{ApprovalCopy, JournalEvent, SnapshotPage, format_cursor, parse_cursor};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub(super) const MAX_SESSIONS: usize = 2048;
pub(super) const MAX_AGENTS: usize = 512;
pub(super) const MAX_TURNS: usize = 8192;
pub(super) const MAX_RUNS: usize = 1024;
pub(super) const MAX_ERASES: usize = 4096;
pub(super) const MAX_APPROVALS: usize = 256;
const MAX_SEEN: usize = 2048;
const MIRROR_MAX: usize = 16 * 1024 * 1024;
pub(super) const TURN_TEXT_CAP: usize = 256 * 1024;

#[derive(Debug)]
pub(super) enum StoreError {
    Io,
    Full,
    Cut,
    Reset,
}

#[derive(Clone)]
pub(super) struct FailureNote {
    pub reason: String,
    pub retryable: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionRow {
    pub agent: String,
    pub incarnation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub child: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_version: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentRow {
    pub incarnation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    pub enabled: bool,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum RunStatus {
    Started,
    Failed,
    Cancelled,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RunRow {
    pub session: String,
    pub agent: String,
    pub status: RunStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TurnRow {
    pub session: String,
    pub agent: String,
    pub incarnation: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<ramflux_prx_client::TurnOrigin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub final_reply: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub content_omitted: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub oversized: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Mirror {
    v: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epoch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cursor_seq: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    page_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot_id: Option<String>,
    #[serde(default)]
    ready: bool,
    #[serde(default)]
    pub(super) sessions: BTreeMap<String, SessionRow>,
    #[serde(default)]
    pub(super) agents: BTreeMap<String, AgentRow>,
    #[serde(default)]
    pub(super) turns: BTreeMap<String, TurnRow>,
    #[serde(default)]
    pub(super) runs: BTreeMap<String, RunRow>,
    #[serde(default)]
    pub(super) run_order: Vec<String>,
    #[serde(default)]
    pub(super) erases: Vec<String>,
    /// Run approvals, keyed by approval id. At most [`MAX_APPROVALS`].
    #[serde(default)]
    pub(super) approvals: BTreeMap<String, ApprovalRow>,
    #[serde(default)]
    seen: VecDeque<String>,
}

/// One stored approval. The map key is the approval id.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovalRow {
    pub session: String,
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub tool: String,
    pub preview: String,
    pub expires_at: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

pub(super) struct Counts {
    pub sessions: usize,
    pub agents: usize,
    pub turns: usize,
}

pub(super) struct MirrorStore {
    path: PathBuf,
    _lock: File,
}

impl Mirror {
    pub(super) const fn fresh() -> Self {
        Self {
            v: 1,
            epoch: None,
            cursor: None,
            cursor_seq: None,
            page_token: None,
            snapshot_id: None,
            ready: false,
            sessions: BTreeMap::new(),
            agents: BTreeMap::new(),
            turns: BTreeMap::new(),
            runs: BTreeMap::new(),
            run_order: Vec::new(),
            erases: Vec::new(),
            approvals: BTreeMap::new(),
            seen: VecDeque::new(),
        }
    }

    pub(super) const fn ready(&self) -> bool {
        self.ready
    }

    pub(super) fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    pub(super) const fn cursor_seq(&self) -> Option<i64> {
        self.cursor_seq
    }

    pub(super) fn epoch(&self) -> Option<&str> {
        self.epoch.as_deref()
    }

    pub(super) fn page_token(&self) -> Option<&str> {
        self.page_token.as_deref()
    }

    pub(super) fn counts(&self) -> Counts {
        Counts { sessions: self.sessions.len(), agents: self.agents.len(), turns: self.turns.len() }
    }

    pub(super) fn apply_page(
        &mut self,
        store: &MirrorStore,
        page: &SnapshotPage,
    ) -> Result<(), StoreError> {
        if self.page_token.is_some() {
            let same_id = self.snapshot_id.as_deref() == Some(page.snapshot_id.as_str());
            let same_epoch = self.epoch.as_deref() == Some(page.epoch.as_str());
            if !same_id || !same_epoch {
                return Err(StoreError::Cut);
            }
        }
        let mut next = self.clone();
        for row in &page.rows {
            next.apply_op(&row.op)?;
        }
        next.epoch = Some(page.epoch.clone());
        next.snapshot_id = Some(page.snapshot_id.clone());
        next.cursor_seq = Some(page.cursor.seq);
        next.cursor =
            Some(format_cursor(&page.epoch, page.cursor.seq).map_err(|_| StoreError::Io)?);
        next.page_token.clone_from(&page.next);
        next.ready = page.next.is_none();
        self.commit(store, next)
    }

    pub(super) fn apply_event(
        &mut self,
        store: &MirrorStore,
        event: &JournalEvent,
    ) -> Result<Option<FailureNote>, StoreError> {
        if self.cursor_seq.is_some_and(|cursor| event.seq <= cursor) {
            return Ok(None);
        }
        let mut next = self.clone();
        let failed = if next.saw(&event.event_id) {
            None
        } else {
            let failed = next.apply_op(&event.op)?;
            next.remember(&event.event_id);
            failed
        };
        let epoch = next.epoch.clone().ok_or(StoreError::Io)?;
        next.cursor_seq = Some(event.seq);
        next.cursor = Some(format_cursor(&epoch, event.seq).map_err(|_| StoreError::Io)?);
        self.commit(store, next)?;
        Ok(failed)
    }

    pub(super) fn clear_cut(&mut self, store: &MirrorStore) -> Result<(), StoreError> {
        let mut next = self.clone();
        next.page_token = None;
        next.snapshot_id = None;
        next.ready = false;
        self.commit(store, next)
    }

    pub(super) fn begin_resync(&mut self, store: &MirrorStore) -> Result<(), StoreError> {
        let mut next = self.clone();
        next.page_token = None;
        next.snapshot_id = None;
        next.ready = false;
        next.cursor = None;
        next.cursor_seq = None;
        next.epoch = None;
        self.commit(store, next)
    }

    fn saw(&self, event_id: &str) -> bool {
        self.seen.iter().any(|id| id == event_id)
    }

    /// Keeps a decided row over a later pending one. A decided frame that omits the preview
    /// keeps the preview, tool, and expiry already stored. Drops one pending key, else the smallest.
    pub(super) fn remember_approval(&mut self, copy: &ApprovalCopy) {
        if let Some(existing) = self.approvals.get(&copy.approval_id) {
            if existing.status == "decided" && copy.status == "pending" {
                return;
            }
            let row = merged_approval(existing, copy);
            self.approvals.insert(copy.approval_id.clone(), row);
            return;
        }
        let row = fresh_approval(copy);
        while self.approvals.len() >= MAX_APPROVALS {
            let pending = self
                .approvals
                .iter()
                .find(|(_, stored)| stored.status == "pending")
                .map(|(id, _)| id.clone());
            let Some(victim) = pending.or_else(|| self.approvals.keys().next().cloned()) else {
                break;
            };
            self.approvals.remove(&victim);
        }
        self.approvals.insert(copy.approval_id.clone(), row);
    }

    fn remember(&mut self, event_id: &str) {
        if self.saw(event_id) {
            return;
        }
        while self.seen.len() >= MAX_SEEN {
            self.seen.pop_front();
        }
        self.seen.push_back(event_id.to_owned());
    }

    fn commit(&mut self, store: &MirrorStore, mut next: Mirror) -> Result<(), StoreError> {
        fit(&mut next)?;
        store.write(&next)?;
        *self = next;
        Ok(())
    }
}

fn fresh_approval(copy: &ApprovalCopy) -> ApprovalRow {
    let mut cause = copy.cause.clone();
    if copy.decision.as_deref() == Some("expired") && cause.is_none() {
        cause = Some("expired".to_owned());
    }
    ApprovalRow {
        session: copy.session.clone(),
        agent: copy.agent.clone(),
        run_id: copy.run_id.clone(),
        tool: copy.tool.clone(),
        preview: copy.preview.clone(),
        expires_at: copy.expires_at.clone(),
        status: copy.status.clone(),
        decision: copy.decision.clone(),
        cause,
    }
}

/// A later frame keeps the earlier preview when its own copy of that field is empty.
fn merged_approval(existing: &ApprovalRow, copy: &ApprovalCopy) -> ApprovalRow {
    let mut row = fresh_approval(copy);
    if row.session.is_empty() {
        row.session.clone_from(&existing.session);
    }
    if row.agent.is_empty() {
        row.agent.clone_from(&existing.agent);
    }
    if row.tool.is_empty() {
        row.tool.clone_from(&existing.tool);
    }
    if row.preview.is_empty() {
        row.preview.clone_from(&existing.preview);
    }
    if row.expires_at.is_empty() {
        row.expires_at.clone_from(&existing.expires_at);
    }
    if row.run_id.is_none() {
        row.run_id.clone_from(&existing.run_id);
    }
    if row.decision.is_none() {
        row.decision.clone_from(&existing.decision);
    }
    if row.cause.is_none() {
        row.cause.clone_from(&existing.cause);
    }
    row
}

impl MirrorStore {
    /// Opens the mirror next to the host state file and takes the exclusive lock.
    ///
    /// # Errors
    /// Returns [`StoreError::Io`] when the parent is not private or the lock is busy.
    pub(super) fn open(state_file: &Path) -> Result<Self, StoreError> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let path = sibling(state_file, ".prx-mirror");
        let parent =
            path.parent().filter(|dir| !dir.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let mode = std::fs::metadata(parent).map_err(|_| StoreError::Io)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(StoreError::Io);
        }
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(sibling(&path, ".lock"))
            .map_err(|_| StoreError::Io)?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| StoreError::Io)?;
        let temp = sibling(&path, ".next");
        match std::fs::remove_file(&temp) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Io),
        }
        Ok(Self { path, _lock: lock })
    }

    pub(super) fn load(&self) -> Result<Mirror, StoreError> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Mirror::fresh());
            }
            Err(_) => return Err(StoreError::Io),
        };
        let mut bytes = Vec::new();
        let cap = u64::try_from(MIRROR_MAX).map_err(|_| StoreError::Io)?.saturating_add(1);
        file.take(cap).read_to_end(&mut bytes).map_err(|_| StoreError::Io)?;
        if bytes.len() > MIRROR_MAX {
            return Err(StoreError::Reset);
        }
        let mirror: Mirror = serde_json::from_slice(&bytes).map_err(|_| StoreError::Reset)?;
        validate(mirror)
    }

    pub(super) fn write(&self, mirror: &Mirror) -> Result<(), StoreError> {
        use std::os::unix::fs::OpenOptionsExt;
        let bytes = serde_json::to_vec(mirror).map_err(|_| StoreError::Io)?;
        if bytes.len() > MIRROR_MAX {
            return Err(StoreError::Full);
        }
        let parent =
            self.path.parent().filter(|dir| !dir.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let temp = sibling(&self.path, ".next");
        let result = (|| -> std::io::Result<()> {
            let mut file =
                std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temp, &self.path)?;
            File::open(parent)?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temp);
            return Err(StoreError::Io);
        }
        Ok(())
    }
}

pub(super) fn mirror_path(state_file: &Path) -> PathBuf {
    sibling(state_file, ".prx-mirror")
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn validate(mut mirror: Mirror) -> Result<Mirror, StoreError> {
    while mirror.approvals.len() > MAX_APPROVALS {
        let Some(victim) = mirror.approvals.keys().next().cloned() else { break };
        mirror.approvals.remove(&victim);
    }
    if mirror.v != 1
        || mirror.sessions.len() > MAX_SESSIONS
        || mirror.agents.len() > MAX_AGENTS
        || mirror.turns.len() > MAX_TURNS
        || mirror.runs.len() > MAX_RUNS
        || mirror.erases.len() > MAX_ERASES
        || mirror.run_order.len() > MAX_RUNS
    {
        return Err(StoreError::Reset);
    }
    if mirror.ready && (mirror.cursor.is_none() || mirror.page_token.is_some()) {
        return Err(StoreError::Reset);
    }
    match (mirror.cursor.as_deref(), mirror.cursor_seq, mirror.epoch.as_deref()) {
        (None, None, _) => {}
        (Some(cursor), Some(seq), Some(epoch)) => {
            let parsed = parse_cursor(cursor).map_err(|_| StoreError::Reset)?;
            if parsed.seq != seq || parsed.epoch != epoch {
                return Err(StoreError::Reset);
            }
        }
        _ => return Err(StoreError::Reset),
    }
    while mirror.seen.len() > MAX_SEEN {
        mirror.seen.pop_front();
    }
    Ok(mirror)
}

fn fit(mirror: &mut Mirror) -> Result<(), StoreError> {
    if within(mirror)? {
        return Ok(());
    }
    for _ in 0..4 {
        if !omit_longest(mirror) {
            return Err(StoreError::Full);
        }
        if within(mirror)? {
            return Ok(());
        }
    }
    omit_all(mirror);
    if within(mirror)? { Ok(()) } else { Err(StoreError::Full) }
}

fn within(mirror: &Mirror) -> Result<bool, StoreError> {
    let bytes = serde_json::to_vec(mirror).map_err(|_| StoreError::Io)?;
    Ok(bytes.len() <= MIRROR_MAX)
}

fn omit_longest(mirror: &mut Mirror) -> bool {
    let mut best: Option<(String, usize)> = None;
    for (id, row) in &mirror.turns {
        let Some(len) = row.content.as_ref().map(String::len) else { continue };
        if len == 0 {
            continue;
        }
        let replace = best.as_ref().is_none_or(|(_, best_len)| len > *best_len);
        if replace {
            best = Some((id.clone(), len));
        }
    }
    let Some((id, _)) = best else { return false };
    let Some(row) = mirror.turns.get_mut(&id) else { return false };
    let Some(text) = row.content.take() else { return false };
    row.bytes = u64::try_from(text.len()).ok();
    row.content_omitted = true;
    true
}

fn omit_all(mirror: &mut Mirror) {
    for row in mirror.turns.values_mut() {
        if let Some(text) = row.content.take() {
            row.bytes = u64::try_from(text.len()).ok();
            row.content_omitted = true;
        }
    }
}

// serde's `skip_serializing_if` passes `&bool`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

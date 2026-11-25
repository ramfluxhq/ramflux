// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node side of the central node directory (K4), frozen in
//! `NN-CENTRAL-OVERNIGHT-PLAN-2026-11-26.md` section 3 and amended by section 3a.
//!
//! Session `rfc-dir-1` is the only source (own session with the centre, never peers). A snapshot
//! is verified, fenced by `seq`, and then learned into sticky sanction state: the latest sanction per
//! `node_key` and per `domain`, kept durably. Expiry only stops learning; it never erases what was
//! learned, `revoked` is permanent, and a domain with a live entry binds it to that node key.
//! Off unless `[node_directory]` and `[node_report]` are both configured.

pub(crate) mod sanction;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ramflux_node_core::{NodeDirectoryConfig, NodeDirectorySanctionMode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// ALPN of the directory session (`rfc-dir-1`).
pub(crate) const ALPN: &[u8] = b"rfc-dir-1";
/// Reply limit of the directory session: `1 <= R <= 5_608_192` (5,600,000-byte document plus 8 KiB).
pub(crate) const REPLY_LIMIT: usize = 5_608_192;
const REQUEST_DOMAIN: &[u8] = b"rfc-dir-request";
const SNAPSHOT_DOMAIN: &[u8] = b"rfc-directory-snapshot";
const DSV: u64 = 1;
const DV: u64 = 1;
const MAX_ENTRIES: usize = 10_000;
const MAX_BODY_LEN: usize = 4_194_304;
/// Serialised document bound (section 3.2).
const MAX_DOC_LEN: usize = 5_600_000;
const SNAPSHOT_LIFETIME_MS: u64 = 86_400_000;
/// Section 3a point 2: `issued_at` and `seq` may not run more than 300 s ahead.
const FUTURE_SKEW_MS: u64 = 300_000;
const MIN_RETRY_MS: u64 = 1_000;
const POLL_MIN_S: u64 = 60;
const POLL_MAX_S: u64 = 3600;
const MAX_JSON_INT: u64 = (1 << 53) - 1;
/// Frame payload bound `L <= 4096`; the payload is `fv || alg || n || body || sig`.
const REQUEST_PAYLOAD_LIMIT: usize = 4096;
const REQUEST_OVERHEAD: usize = 4 + 2 + 64;
const FILE_NAME: &str = "directory.v1.json";
const LOG_TARGET: &str = "ramflux_federation_directory";

/// Entry state: `active`, `suspended` (includes an enrolment past expiry) or `revoked` (tombstone).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum State {
    Active,
    Suspended,
    Revoked,
}

impl State {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }

    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }

    pub(crate) fn sanctioned(self) -> bool {
        matches!(self, Self::Suspended | Self::Revoked)
    }
}

/// One snapshot entry. `domain` is lowercase ASCII.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Enrolled node key, canonical base64url of the 32 key bytes.
    pub(crate) key: String,
    pub(crate) domain: String,
    pub(crate) state: State,
}

/// One verified snapshot document with its signed body.
#[derive(Debug)]
pub(crate) struct Snapshot {
    pub(crate) seq: u64,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    body: Vec<u8>,
    entries: Vec<Entry>,
}

/// The snapshot document `{key_id, body, sig}` (closed members).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Doc {
    pub(crate) key_id: String,
    pub(crate) body: String,
    pub(crate) sig: String,
}

/// Latest sanction learned for one node key. `revoked` is never cleared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct KeySanction {
    pub(crate) state: State,
    pub(crate) domain: String,
}

/// Binding learned for one domain: the key of its live entry, or `None` when only revoked
/// entries were learned for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DomainBinding {
    pub(crate) live_key: Option<String>,
}

/// Sticky state, persisted with the held document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Sticky {
    /// The highest snapshot seq learned from. Learning requires a higher seq.
    pub(crate) learned_seq: u64,
    pub(crate) keys: BTreeMap<String, KeySanction>,
    pub(crate) domains: BTreeMap<String, DomainBinding>,
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    /// Fingerprint of the verify keys the held document was checked against.
    verify: String,
    doc: Option<Doc>,
    sticky: Sticky,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Applied {
    /// The held snapshot already has this seq and these bytes.
    Unchanged,
    /// A higher seq replaced the held snapshot.
    Updated { seq: u64 },
}

/// A parsed `rfc-dir-1` reply.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    Ok { poll_s: u64, applied: Applied },
    Unavailable { retry_after_ms: u64 },
    Throttled { retry_after_ms: u64 },
    Rejected { reason: String },
}

struct Runtime {
    verify: Vec<(String, String)>,
    fingerprint: String,
    sanction: NodeDirectorySanctionMode,
    centre_id: String,
    path: PathBuf,
    held: Option<(Snapshot, Doc)>,
    sticky: Sticky,
}

static RUNTIME: OnceLock<RwLock<Runtime>> = OnceLock::new();

/// The node identity used in directory requests (the report identity).
#[derive(Clone)]
pub(crate) struct DirIdentity {
    pub(crate) seed: [u8; 32],
    pub(crate) centre_id: String,
    pub(crate) node_key: String,
    pub(crate) key_gen: u64,
}

impl DirIdentity {
    /// `L:u32be || fv || alg || n:u16be || body || sig`, signed over
    /// `"rfc-dir-request" || 0x00 || fv || alg || len(centre_id) || centre_id || n || body`.
    pub(crate) fn request_frame(&self) -> Result<Vec<u8>, String> {
        self.request_frame_at(now_ms(), held_seq())
    }

    /// The frame for edge time `ts_ms` and the held sequence `have_seq` (pure; `request_frame`
    /// supplies the system clock and the held sequence).
    pub(crate) fn request_frame_at(&self, ts_ms: u64, have_seq: u64) -> Result<Vec<u8>, String> {
        // Member order is the frozen wire order (the signature covers these exact bytes).
        let body = format!(
            "{{\"dv\":{DV},\"node_key\":{},\"key_gen\":{},\"ts\":{ts_ms},\"have_seq\":{have_seq}}}",
            serde_json::to_string(&self.node_key).map_err(|e| e.to_string())?,
            self.key_gen,
        )
        .into_bytes();
        if body.len() + REQUEST_OVERHEAD > REQUEST_PAYLOAD_LIMIT {
            return Err("request body too large".to_owned());
        }
        let centre_len = u16::try_from(self.centre_id.len()).map_err(|_| "centre_id")?;
        let body_len = u16::try_from(body.len()).map_err(|_| "request body")?;
        let mut message = Vec::with_capacity(
            REQUEST_DOMAIN.len() + 1 + 4 + 2 + self.centre_id.len() + body.len(),
        );
        message.extend_from_slice(REQUEST_DOMAIN);
        message.push(0);
        message.extend_from_slice(&[1, 1]);
        message.extend_from_slice(&centre_len.to_be_bytes());
        message.extend_from_slice(self.centre_id.as_bytes());
        message.extend_from_slice(&body_len.to_be_bytes());
        message.extend_from_slice(&body);
        let sig = ramflux_crypto::sign_canonical_bytes_with_seed(&message, self.seed);
        let sig = ramflux_protocol::decode_base64url(&sig).map_err(|e| e.to_string())?;
        if sig.len() != 64 {
            return Err("signature length".to_owned());
        }
        let payload_len = 2 + 2 + body.len() + 64;
        let mut frame = Vec::with_capacity(4 + payload_len);
        frame.extend_from_slice(&u32::try_from(payload_len).map_err(|_| "frame")?.to_be_bytes());
        frame.extend_from_slice(&[1, 1]);
        frame.extend_from_slice(&body_len.to_be_bytes());
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&sig);
        Ok(frame)
    }
}

/// Activates the directory from `[node_directory]`. The persisted state is loaded and checked:
/// a bad state file stops start-up (sanctions must not be silently lost). A held document whose
/// verify keys differ from the configured ones is dropped (fence reset); sticky state is kept.
pub(crate) fn start(
    config: &NodeDirectoryConfig,
    centre_id: &str,
    redb_path: &Path,
) -> Result<(), String> {
    let path = redb_path.parent().unwrap_or(Path::new(".")).join(FILE_NAME);
    let verify: Vec<(String, String)> =
        config.verify.iter().map(|k| (k.key_id.clone(), k.public_key.clone())).collect();
    let fingerprint = fingerprint(&verify);
    let now = now_ms();
    let mut held = None;
    let mut sticky = Sticky::default();
    match std::fs::read(&path) {
        Ok(bytes) => {
            let persisted: Persisted = serde_json::from_slice(&bytes)
                .map_err(|error| format!("directory state unreadable: {error}"))?;
            sticky = persisted.sticky;
            if persisted.verify == fingerprint {
                if let Some(doc) = persisted.doc {
                    match verify_doc(&verify, centre_id, &doc, now, None, false) {
                        Ok(snapshot) => held = Some((snapshot, doc)),
                        Err(error) => {
                            tracing::warn!(target: LOG_TARGET, %error, "persisted directory snapshot ignored");
                        }
                    }
                }
            } else {
                // Sanctions stay (section 3a point 4); only the sequence fence restarts.
                sticky.learned_seq = 0;
                tracing::info!(target: LOG_TARGET, "directory verify keys changed; fence reset");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("read directory state: {error}")),
    }
    let runtime = Runtime {
        verify,
        fingerprint,
        sanction: config.sanction,
        centre_id: centre_id.to_owned(),
        path,
        held,
        sticky,
    };
    persist(
        &runtime.path,
        &runtime.fingerprint,
        runtime.held.as_ref().map(|(_, d)| d),
        &runtime.sticky,
    )?;
    let seq = runtime.held.as_ref().map_or(0, |(snapshot, _)| snapshot.seq);
    RUNTIME.set(RwLock::new(runtime)).map_err(|_| "node directory already started".to_owned())?;
    tracing::info!(target: LOG_TARGET, held_seq = seq, "node directory enabled");
    Ok(())
}

/// Whether the directory is configured.
pub(crate) fn enabled() -> bool {
    RUNTIME.get().is_some()
}

/// Sequence of the held snapshot (`have_seq`); 0 when none.
pub(crate) fn held_seq() -> u64 {
    RUNTIME
        .get()
        .and_then(|lock| lock.read().ok())
        .and_then(|runtime| runtime.held.as_ref().map(|(snapshot, _)| snapshot.seq))
        .unwrap_or(0)
}

/// Refuses any member outside `allowed` (section 3.2: parsers are strict).
fn closed_members(value: &Value, allowed: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("malformed: object expected")?;
    if object.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err("malformed: unknown member".to_owned())
    }
}

/// Parses a `rfc-dir-1` reply: `R:u32be || JSON`, `1 <= R <= REPLY_LIMIT`. The fence uses only
/// the signed body's `seq`.
pub(crate) fn accept_reply(bytes: &[u8]) -> Result<Reply, String> {
    match parse_reply(bytes)? {
        Parsed::Ok { poll_s, reply_seq, doc } => {
            let applied = match doc {
                None => {
                    tracing::debug!(reply_seq, "node directory: no snapshot (seq hint only)");
                    Applied::Unchanged
                }
                Some(doc) => install(doc, reply_seq)?,
            };
            Ok(Reply::Ok { poll_s, applied })
        }
        Parsed::Unavailable { retry_after_ms } => Ok(Reply::Unavailable { retry_after_ms }),
        Parsed::Throttled { retry_after_ms } => Ok(Reply::Throttled { retry_after_ms }),
        Parsed::Rejected { reason } => Ok(Reply::Rejected { reason }),
    }
}

/// A reply after framing and strict parsing, before any state change (pure).
#[derive(Debug)]
pub(crate) enum Parsed {
    Ok { poll_s: u64, reply_seq: u64, doc: Option<Doc> },
    Unavailable { retry_after_ms: u64 },
    Throttled { retry_after_ms: u64 },
    Rejected { reason: String },
}

/// Framing and strict parsing of `R:u32be || JSON`; no state is read or written.
pub(crate) fn parse_reply(bytes: &[u8]) -> Result<Parsed, String> {
    let Some((len_bytes, json_bytes)) = bytes.split_first_chunk::<4>() else {
        return Err("malformed: reply framing".to_owned());
    };
    if u32::from_be_bytes(*len_bytes) as usize != json_bytes.len()
        || !(1..=REPLY_LIMIT).contains(&json_bytes.len())
    {
        return Err("malformed: reply length".to_owned());
    }
    let value: Value = ramflux_protocol::parse_i_json(json_bytes).map_err(|e| e.to_string())?;
    closed_members(&value, &["status", "seq", "poll_s", "snapshot", "retry_after_ms", "reason"])?;
    let uint = |key: &str| value.get(key).and_then(Value::as_u64);
    // A retry hint below one second would make the poll loop spin (no hot loop).
    let retry = |default: u64| -> Result<u64, String> {
        let retry = uint("retry_after_ms").unwrap_or(default);
        if retry < MIN_RETRY_MS {
            return Err("malformed: retry_after_ms below 1000".to_owned());
        }
        Ok(retry)
    };
    match value.get("status").and_then(Value::as_str) {
        Some("ok") => {
            let poll_s = uint("poll_s")
                .filter(|poll| (POLL_MIN_S..=POLL_MAX_S).contains(poll))
                .ok_or("malformed: poll_s outside 60..=3600")?;
            let reply_seq = uint("seq").ok_or("malformed: reply seq")?;
            let doc = match value.get("snapshot") {
                None => None,
                Some(doc) => {
                    Some(serde_json::from_value::<Doc>(doc.clone()).map_err(|e| e.to_string())?)
                }
            };
            Ok(Parsed::Ok { poll_s, reply_seq, doc })
        }
        Some("unavailable") => Ok(Parsed::Unavailable { retry_after_ms: retry(2000)? }),
        Some("throttled") => Ok(Parsed::Throttled { retry_after_ms: retry(5000)? }),
        Some("rejected") => Ok(Parsed::Rejected {
            reason: value.get("reason").and_then(Value::as_str).unwrap_or("").to_owned(),
        }),
        other => Err(format!("malformed: status {}", other.unwrap_or("missing"))),
    }
}

/// Verifies a snapshot, checks the reply seq against the signed seq, applies the fence, learns
/// the sticky state and persists it. Nothing changes unless every step passes.
fn install(doc: Doc, reply_seq: u64) -> Result<Applied, String> {
    let now = now_ms();
    let lock = RUNTIME.get().ok_or_else(|| "node directory not configured".to_owned())?;
    let mut runtime = lock.write().map_err(|_| "directory lock poisoned".to_owned())?;
    let snapshot = verify_doc(
        &runtime.verify,
        &runtime.centre_id,
        &doc,
        now,
        runtime.held.as_ref().map(|(s, _)| s),
        true,
    )?;
    if snapshot.seq != reply_seq {
        return Err("malformed: reply seq differs from signed body seq".to_owned());
    }
    if runtime.held.as_ref().is_some_and(|(held, _)| held.seq == snapshot.seq) {
        return Ok(Applied::Unchanged);
    }
    let mut sticky = runtime.sticky.clone();
    if snapshot.seq > sticky.learned_seq {
        learn(&mut sticky, &snapshot);
        sticky.learned_seq = snapshot.seq;
    }
    persist(&runtime.path, &runtime.fingerprint, Some(&doc), &sticky)?;
    let seq = snapshot.seq;
    runtime.held = Some((snapshot, doc));
    runtime.sticky = sticky;
    tracing::info!(target: LOG_TARGET, seq, "node directory snapshot adopted");
    Ok(Applied::Updated { seq })
}

/// Folds a valid snapshot into the sticky state (section 3a points 1, 4 and 5).
fn learn(sticky: &mut Sticky, snapshot: &Snapshot) {
    for entry in &snapshot.entries {
        let revoked_already =
            sticky.keys.get(&entry.key).is_some_and(|known| known.state == State::Revoked);
        if !revoked_already {
            sticky.keys.insert(
                entry.key.clone(),
                KeySanction { state: entry.state, domain: entry.domain.clone() },
            );
        }
    }
    let mut domains: BTreeMap<&str, Option<&str>> = BTreeMap::new();
    for entry in &snapshot.entries {
        let live = domains.entry(entry.domain.as_str()).or_insert(None);
        if entry.state != State::Revoked {
            *live = Some(entry.key.as_str());
        }
    }
    for (domain, live) in domains {
        sticky
            .domains
            .insert(domain.to_owned(), DomainBinding { live_key: live.map(str::to_owned) });
    }
}

/// Signed message: `"rfc-directory-snapshot" || 0x00 || u16be len(centre_id) || centre_id || u32be len(body) || body`.
fn snapshot_message(centre_id: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let centre_len = u16::try_from(centre_id.len()).map_err(|_| "centre_id too long".to_owned())?;
    let body_len = u32::try_from(body.len()).map_err(|_| "body too long".to_owned())?;
    let mut message =
        Vec::with_capacity(SNAPSHOT_DOMAIN.len() + 1 + 2 + centre_id.len() + 4 + body.len());
    message.extend_from_slice(SNAPSHOT_DOMAIN);
    message.push(0);
    message.extend_from_slice(&centre_len.to_be_bytes());
    message.extend_from_slice(centre_id.as_bytes());
    message.extend_from_slice(&body_len.to_be_bytes());
    message.extend_from_slice(body);
    Ok(message)
}

/// Doc members, key id, signature, body rules, freshness (`future`), expiry (when `check_expiry`)
/// and the fence against the held snapshot.
fn verify_doc(
    verify: &[(String, String)],
    centre_id: &str,
    doc: &Doc,
    now: u64,
    held: Option<&Snapshot>,
    check_expiry: bool,
) -> Result<Snapshot, String> {
    let doc_bytes = serde_json::to_vec(doc).map_err(|e| e.to_string())?;
    if doc_bytes.len() > MAX_DOC_LEN {
        return Err("directory document too large".to_owned());
    }
    let key_id_ok = !doc.key_id.is_empty()
        && doc.key_id.len() <= 32
        && doc.key_id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !key_id_ok {
        return Err("directory key id grammar".to_owned());
    }
    let Some((_, public_key)) = verify.iter().find(|(id, _)| *id == doc.key_id) else {
        return Err("directory key id is not pinned".to_owned());
    };
    let body = ramflux_protocol::decode_base64url(&doc.body).map_err(|e| e.to_string())?;
    if !(2..=MAX_BODY_LEN).contains(&body.len()) {
        return Err("directory body length".to_owned());
    }
    let message = snapshot_message(centre_id, &body)?;
    ramflux_crypto::verify_canonical_signature(&message, &doc.sig, public_key)
        .map_err(|_| "directory signature rejected".to_owned())?;
    let snapshot = parse_body(&body, centre_id)?;
    if snapshot.issued_at > now.saturating_add(FUTURE_SKEW_MS) {
        return Err("future: issued_at ahead of edge clock".to_owned());
    }
    if snapshot.seq > snapshot.issued_at.saturating_add(FUTURE_SKEW_MS) {
        return Err("future: seq ahead of issued_at".to_owned());
    }
    if check_expiry && snapshot.expires_at <= now {
        return Err("directory snapshot expired".to_owned());
    }
    match held {
        Some(held) if snapshot.seq < held.seq => Err("rollback: seq below held".to_owned()),
        Some(held) if snapshot.seq == held.seq && held.body != snapshot.body => {
            Err("conflict: seq repeated with other bytes".to_owned())
        }
        _ => Ok(snapshot),
    }
}

fn parse_body(body: &[u8], centre_id: &str) -> Result<Snapshot, String> {
    let value: Value = ramflux_protocol::parse_i_json(body).map_err(|e| e.to_string())?;
    closed_members(&value, &["dsv", "centre_id", "seq", "issued_at", "expires_at", "entries"])?;
    let uint = |key: &str| value.get(key).and_then(Value::as_u64);
    if uint("dsv") != Some(DSV) {
        return Err("unsupported directory snapshot version".to_owned());
    }
    if value.get("centre_id").and_then(Value::as_str) != Some(centre_id) {
        return Err("directory centre_id does not match".to_owned());
    }
    let seq = uint("seq").filter(|s| (1..=MAX_JSON_INT).contains(s)).ok_or("directory seq")?;
    let issued_at = uint("issued_at").ok_or("directory issued_at")?;
    let expires_at = uint("expires_at").ok_or("directory expires_at")?;
    if issued_at.checked_add(SNAPSHOT_LIFETIME_MS) != Some(expires_at) {
        return Err("directory expires_at is not issued_at + 24 h".to_owned());
    }
    let nodes = value.get("entries").and_then(Value::as_array).ok_or("directory entries")?;
    if nodes.len() > MAX_ENTRIES {
        return Err("directory snapshot has too many entries".to_owned());
    }
    let mut entries: Vec<Entry> = Vec::with_capacity(nodes.len());
    let mut previous: Option<Vec<u8>> = None;
    for node in nodes {
        let entry = parse_entry(node)?;
        let raw = ramflux_protocol::decode_base64url(&entry.key).map_err(|e| e.to_string())?;
        if previous.as_ref().is_some_and(|prev| prev >= &raw) {
            return Err("directory entries must be strictly sorted by node_key".to_owned());
        }
        previous = Some(raw);
        entries.push(entry);
    }
    // Section 3a point 1: a domain is unique among active and suspended entries only.
    let mut live_domains = std::collections::BTreeSet::new();
    for entry in entries.iter().filter(|e| e.state != State::Revoked) {
        if !live_domains.insert(entry.domain.as_str()) {
            return Err("directory domain repeated among live entries".to_owned());
        }
    }
    Ok(Snapshot { seq, issued_at, expires_at, body: body.to_vec(), entries })
}

fn parse_entry(node: &Value) -> Result<Entry, String> {
    closed_members(node, &["node_key", "key_gen", "domain", "state", "trust", "changed_at"])?;
    let text = |key: &str| node.get(key).and_then(Value::as_str).ok_or("directory entry field");
    let raw = ramflux_protocol::decode_base64url(text("node_key")?).map_err(|e| e.to_string())?;
    if raw.len() != 32 {
        return Err("directory node_key must be 32 bytes".to_owned());
    }
    let key = ramflux_protocol::encode_base64url(&raw);
    if text("node_key")? != key {
        return Err("directory node_key is not canonical".to_owned());
    }
    let domain = text("domain")?;
    if domain.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err("directory domain must be lowercase".to_owned());
    }
    let domain = domain.to_owned();
    if !crate::peer_pin::node_id_ok(&domain) {
        return Err("directory domain rejected".to_owned());
    }
    let state = State::parse(text("state")?).ok_or("directory state")?;
    if !matches!(text("trust")?, "limited" | "standard" | "publisher") {
        return Err("directory trust".to_owned());
    }
    let key_gen_ok = node
        .get("key_gen")
        .and_then(Value::as_u64)
        .is_some_and(|generation| (1..=MAX_JSON_INT).contains(&generation));
    let changed_ok = node.get("changed_at").and_then(Value::as_u64).is_some();
    if !key_gen_ok || !changed_ok {
        return Err("directory entry key_gen or changed_at".to_owned());
    }
    Ok(Entry { key, domain, state })
}

/// The sanction decision for a peer with `domain` and (when known) `node_key`. It reads sticky
/// state only, so an expired snapshot still applies what it taught. Returns the refusal reason.
pub(crate) fn decide(domain: &str, key: Option<&str>) -> Result<(), &'static str> {
    let Some(lock) = RUNTIME.get() else { return Ok(()) };
    let Ok(runtime) = lock.read() else { return Err("unavailable") };
    let domain = domain.to_ascii_lowercase();
    let presented = match key {
        Some(key) => Some(
            ramflux_protocol::decode_base64url(key)
                .map(|bytes| ramflux_protocol::encode_base64url(&bytes))
                .map_err(|_| "malformed")?,
        ),
        None => None,
    };
    if let Some(key) = presented.as_deref()
        && runtime.sticky.keys.get(key).is_some_and(|known| known.state.sanctioned())
    {
        return Err("sanctioned");
    }
    match runtime.sticky.domains.get(&domain) {
        Some(DomainBinding { live_key: None }) => Err("domain_revoked"),
        Some(DomainBinding { live_key: Some(bound) }) => match presented.as_deref() {
            Some(key) if key != bound => Err("domain_binding"),
            _ => Ok(()),
        },
        None => Ok(()),
    }
}

/// The configured sanction mode, when the directory is configured.
pub(crate) fn sanction_mode() -> Option<NodeDirectorySanctionMode> {
    RUNTIME.get().and_then(|lock| lock.read().ok()).map(|runtime| runtime.sanction)
}

/// Read-only admin view (`POST /admin/federation/directory`).
pub(crate) fn admin_view() -> Value {
    let Some(lock) = RUNTIME.get() else { return json!({ "enabled": false }) };
    let Ok(runtime) = lock.read() else {
        return json!({ "enabled": true, "error": "unavailable" });
    };
    let mode = match runtime.sanction {
        NodeDirectorySanctionMode::Refuse => "refuse",
        NodeDirectorySanctionMode::Observe => "observe",
    };
    let sanctioned: Vec<Value> = runtime
        .sticky
        .keys
        .iter()
        .filter(|(_, known)| known.state.sanctioned())
        .map(|(key, known)| json!({ "k": key, "d": known.domain, "s": known.state.code() }))
        .collect();
    let (seq, expires_at, usable) = match runtime.held.as_ref() {
        Some((snapshot, _)) => {
            (snapshot.seq, Some(snapshot.expires_at), snapshot.expires_at > now_ms())
        }
        None => (0, None, false),
    };
    json!({
        "enabled": true,
        "sanction": mode,
        "seq": seq,
        "expires_at": expires_at,
        "usable": usable,
        "learned_seq": runtime.sticky.learned_seq,
        "sticky_keys": runtime.sticky.keys.len(),
        "sanctioned": sanctioned,
    })
}

/// Writes the persisted state atomically (temporary file, then rename).
fn persist(
    path: &Path,
    fingerprint: &str,
    doc: Option<&Doc>,
    sticky: &Sticky,
) -> Result<(), String> {
    let persisted =
        Persisted { verify: fingerprint.to_owned(), doc: doc.cloned(), sticky: sticky.clone() };
    let bytes = serde_json::to_vec(&persisted).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&tmp)
            .map_err(|error| format!("write directory state: {error}"))?;
        file.write_all(&bytes).map_err(|error| format!("write directory state: {error}"))?;
        file.sync_all().map_err(|error| format!("sync directory state: {error}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|error| format!("store directory state: {error}"))?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| format!("sync directory state dir: {error}"))
}

fn fingerprint(verify: &[(String, String)]) -> String {
    let mut parts: Vec<String> = verify.iter().map(|(id, key)| format!("{id}:{key}")).collect();
    parts.sort();
    parts.join("\n")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

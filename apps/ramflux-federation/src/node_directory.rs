// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Node side of the central node directory (K4, CENTRAL-BATCH-PLAN-02 section 4).
//!
//! PENDING CENTRE CONFIRMATION: no centre document defines this wire yet. The framing and fields
//! below are the plan's assumption (section 4.1) and must be confirmed or replaced by the centre.
//!
//! Off unless `[node_directory]` and `[node_report]` are both configured. A snapshot is complete,
//! signed by the directory key and re-verified when loaded from disk. It can cross-check a pin
//! (refuse a key mismatch at installation) and apply sanctions. It never removes an existing pin.

pub(crate) mod sanction;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

use ramflux_node_core::{NodeCoreError, NodeDirectoryConfig, NodeDirectorySanctionMode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Domain string of the directory snapshot signature (the plan's assumption, section 4.1).
const SNAPSHOT_DOMAIN: &[u8] = b"rfc-directory-snapshot";
const SNAPSHOT_VERSION: u64 = 1;
const MAX_ENTRIES: usize = 10_000;
const MAX_CLOCK_SKEW_S: u64 = 60;
const MAX_JSON_INT: u64 = (1 << 53) - 1;
const FILE_NAME: &str = "directory.v1.json";
const LOG_TARGET: &str = "ramflux_federation_directory";

/// Entry state from the centre: `a` active, `l` limited, `s` suspended, `r` revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Active,
    Limited,
    Suspended,
    Revoked,
}

impl State {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "a" => Some(Self::Active),
            "l" => Some(Self::Limited),
            "s" => Some(Self::Suspended),
            "r" => Some(Self::Revoked),
            _ => None,
        }
    }

    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Active => "a",
            Self::Limited => "l",
            Self::Suspended => "s",
            Self::Revoked => "r",
        }
    }

    pub(crate) fn sanctioned(self) -> bool {
        matches!(self, Self::Suspended | Self::Revoked)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Node key, canonical base64url of the 32 key bytes.
    pub(crate) key: String,
    pub(crate) domain: String,
    pub(crate) state: State,
}

/// One verified complete snapshot.
#[derive(Debug)]
pub(crate) struct Snapshot {
    pub(crate) seq: u64,
    pub(crate) issued_at: u64,
    body: Vec<u8>,
    entries: BTreeMap<String, Entry>,
    domains: BTreeMap<String, String>,
}

/// The wire envelope of a snapshot: `{key_id, body, sig}`, all base64url except `key_id`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Envelope {
    pub(crate) key_id: String,
    pub(crate) body: String,
    pub(crate) sig: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Applied {
    /// The centre had nothing new (`directory: null`, or the same snapshot again).
    Unchanged,
    /// A newer snapshot replaced the held one.
    Updated { seq: u64 },
}

struct Runtime {
    config: NodeDirectoryConfig,
    centre_id: String,
    path: PathBuf,
    held: Option<(Snapshot, Envelope)>,
}

static RUNTIME: OnceLock<RwLock<Runtime>> = OnceLock::new();

/// Activates the directory. Called once at start-up when `[node_directory]` and `[node_report]`
/// are configured. A persisted snapshot is re-verified; one that fails is ignored with a warning.
pub(crate) fn start(
    config: NodeDirectoryConfig,
    centre_id: &str,
    redb_path: &std::path::Path,
) -> Result<(), String> {
    let path = redb_path.parent().unwrap_or(std::path::Path::new(".")).join(FILE_NAME);
    let now = crate::now_unix_seconds().map_err(|error| error.to_string())?;
    let held = match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<Envelope>(&bytes)
            .map_err(|error| error.to_string())
            .and_then(|envelope| {
                verify(&config, centre_id, &envelope, now, None)
                    .map(|snapshot| (snapshot, envelope))
            }) {
            Ok(pair) => Some(pair),
            Err(error) => {
                tracing::warn!(target: LOG_TARGET, %error, "persisted directory snapshot ignored");
                None
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("read directory snapshot: {error}")),
    };
    let runtime = Runtime { config, centre_id: centre_id.to_owned(), path, held };
    let seq = runtime.held.as_ref().map_or(0, |(snapshot, _)| snapshot.seq);
    RUNTIME.set(RwLock::new(runtime)).map_err(|_| "node directory already started".to_owned())?;
    tracing::info!(target: LOG_TARGET, held_seq = seq, "node directory enabled");
    Ok(())
}

/// Sequence of the held snapshot (`have` in the next request); 0 when none is held.
pub(crate) fn held_seq() -> u64 {
    RUNTIME
        .get()
        .and_then(|lock| lock.read().ok())
        .and_then(|runtime| runtime.held.as_ref().map(|(snapshot, _)| snapshot.seq))
        .unwrap_or(0)
}

/// Whether the directory is configured (requests may then be sent).
pub(crate) fn enabled() -> bool {
    RUNTIME.get().is_some()
}

/// Parses and applies the reply to a directory request: `u32be || JSON`,
/// `{"status":"accepted","directory":null | {key_id,body,sig}}`.
pub(crate) fn accept_reply(bytes: &[u8]) -> Result<Applied, String> {
    let Some((len_bytes, json_bytes)) = bytes.split_first_chunk::<4>() else {
        return Err("reply framing".to_owned());
    };
    if u32::from_be_bytes(*len_bytes) as usize != json_bytes.len() {
        return Err("reply length mismatch".to_owned());
    }
    let value: Value = ramflux_protocol::parse_i_json(json_bytes).map_err(|e| e.to_string())?;
    match value.get("status").and_then(Value::as_str) {
        Some("accepted") => {}
        other => return Err(format!("status {}", other.unwrap_or("missing"))),
    }
    let envelope = match value.get("directory") {
        None | Some(Value::Null) => return Ok(Applied::Unchanged),
        Some(directory) => {
            serde_json::from_value::<Envelope>(directory.clone()).map_err(|e| e.to_string())?
        }
    };
    install(envelope)
}

fn install(envelope: Envelope) -> Result<Applied, String> {
    let now = crate::now_unix_seconds().map_err(|error| error.to_string())?;
    let lock = RUNTIME.get().ok_or_else(|| "node directory not configured".to_owned())?;
    let mut runtime = lock.write().map_err(|_| "directory lock poisoned".to_owned())?;
    let snapshot = verify(
        &runtime.config,
        &runtime.centre_id,
        &envelope,
        now,
        runtime.held.as_ref().map(|(snapshot, _)| snapshot),
    )?;
    if runtime.held.as_ref().is_some_and(|(held, _)| held.seq == snapshot.seq) {
        return Ok(Applied::Unchanged);
    }
    let bytes = serde_json::to_vec(&envelope).map_err(|e| e.to_string())?;
    let tmp = runtime.path.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes).map_err(|error| format!("write directory snapshot: {error}"))?;
    std::fs::rename(&tmp, &runtime.path)
        .map_err(|error| format!("store directory snapshot: {error}"))?;
    let seq = snapshot.seq;
    runtime.held = Some((snapshot, envelope));
    tracing::info!(target: LOG_TARGET, seq, "node directory snapshot accepted");
    Ok(Applied::Updated { seq })
}

/// Signed message of a snapshot: `domain || 0x00 || u16be len(centre_id) || centre_id || u32be len(body) || body`.
fn signed_message(centre_id: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let centre_len = u16::try_from(centre_id.len()).map_err(|_| "centre_id too long".to_owned())?;
    let body_len = u32::try_from(body.len()).map_err(|_| "body too long".to_owned())?;
    let mut message =
        Vec::with_capacity(SNAPSHOT_DOMAIN.len() + 1 + 6 + centre_id.len() + body.len());
    message.extend_from_slice(SNAPSHOT_DOMAIN);
    message.push(0);
    message.extend_from_slice(&centre_len.to_be_bytes());
    message.extend_from_slice(centre_id.as_bytes());
    message.extend_from_slice(&body_len.to_be_bytes());
    message.extend_from_slice(body);
    Ok(message)
}

/// Verifies a complete snapshot against the configured key, the centre and the held sequence.
fn verify(
    config: &NodeDirectoryConfig,
    centre_id: &str,
    envelope: &Envelope,
    now: u64,
    held: Option<&Snapshot>,
) -> Result<Snapshot, String> {
    if envelope.key_id != config.key_id {
        return Err("directory key id does not match configuration".to_owned());
    }
    let body = ramflux_protocol::decode_base64url(&envelope.body).map_err(|e| e.to_string())?;
    let message = signed_message(centre_id, &body)?;
    ramflux_crypto::verify_canonical_signature(&message, &envelope.sig, &config.public_key)
        .map_err(|_| "directory signature rejected".to_owned())?;
    let snapshot = parse_body(&body, centre_id, now)?;
    match held {
        Some(held) if snapshot.seq < held.seq => {
            Err("directory snapshot is older than held".to_owned())
        }
        Some(held) if snapshot.seq == held.seq && held.body != snapshot.body => {
            Err("directory snapshot repeats a sequence with different bytes".to_owned())
        }
        _ => Ok(snapshot),
    }
}

fn parse_body(body: &[u8], centre_id: &str, now: u64) -> Result<Snapshot, String> {
    let value: Value = ramflux_protocol::parse_i_json(body).map_err(|e| e.to_string())?;
    let uint = |key: &str| value.get(key).and_then(Value::as_u64);
    if uint("sv") != Some(SNAPSHOT_VERSION) {
        return Err("unsupported directory snapshot version".to_owned());
    }
    if value.get("centre_id").and_then(Value::as_str) != Some(centre_id) {
        return Err("directory centre_id does not match".to_owned());
    }
    let seq = uint("seq").filter(|seq| (1..=MAX_JSON_INT).contains(seq)).ok_or("directory seq")?;
    let issued_at = uint("issued_at").ok_or("directory issued_at")?;
    if issued_at > now.saturating_add(MAX_CLOCK_SKEW_S) {
        return Err("directory snapshot issued in the future".to_owned());
    }
    let nodes = value.get("nodes").and_then(Value::as_array).ok_or("directory nodes")?;
    if nodes.len() > MAX_ENTRIES {
        return Err("directory snapshot has too many entries".to_owned());
    }
    let mut entries = BTreeMap::new();
    let mut domains = BTreeMap::new();
    let mut previous: Option<String> = None;
    for node in nodes {
        let entry = parse_entry(node)?;
        if previous.as_ref().is_some_and(|prev| prev >= &entry.key) {
            return Err("directory entries must be strictly sorted by key".to_owned());
        }
        if domains.insert(entry.domain.clone(), entry.key.clone()).is_some() {
            return Err("directory domain repeated".to_owned());
        }
        previous = Some(entry.key.clone());
        entries.insert(entry.key.clone(), entry);
    }
    Ok(Snapshot { seq, issued_at, body: body.to_vec(), entries, domains })
}

fn parse_entry(node: &Value) -> Result<Entry, String> {
    let text = |key: &str| node.get(key).and_then(Value::as_str).ok_or("directory entry field");
    let key_bytes = ramflux_protocol::decode_base64url(text("k")?).map_err(|e| e.to_string())?;
    if key_bytes.len() != 32 {
        return Err("directory node key must be 32 bytes".to_owned());
    }
    let key = ramflux_protocol::encode_base64url(&key_bytes);
    if text("k")? != key {
        return Err("directory node key is not canonical".to_owned());
    }
    let domain = text("d")?;
    if !crate::peer_pin::node_id_ok(domain) {
        return Err("directory domain rejected".to_owned());
    }
    let state = State::parse(text("s")?).ok_or("directory state")?;
    // Trust level and key generation are validated but not used by the node yet.
    if !matches!(text("tl")?, "limited" | "standard" | "publisher") {
        return Err("directory trust level".to_owned());
    }
    let key_gen_ok = node
        .get("g")
        .and_then(Value::as_u64)
        .is_some_and(|generation| (1..=MAX_JSON_INT).contains(&generation));
    if !key_gen_ok {
        return Err("directory key generation".to_owned());
    }
    Ok(Entry { key, domain: domain.to_owned(), state })
}

/// Pin cross-check at installation: a directory entry for `domain` must carry the same node key.
/// No entry means no cross-check (the directory is optional).
pub(crate) fn check_pin(domain: &str, node_public_key: &str) -> Result<(), NodeCoreError> {
    let Some(lock) = RUNTIME.get() else { return Ok(()) };
    let runtime = lock.read().map_err(|_| directory_unavailable())?;
    let Some((snapshot, _)) = runtime.held.as_ref() else { return Ok(()) };
    let Some(key) = snapshot.domains.get(domain) else { return Ok(()) };
    let presented = ramflux_protocol::decode_base64url(node_public_key)
        .map(|bytes| ramflux_protocol::encode_base64url(&bytes))
        .unwrap_or_default();
    if &presented == key {
        Ok(())
    } else {
        tracing::warn!(target: LOG_TARGET, %domain, "directory key mismatch; pin refused");
        Err(NodeCoreError::ItestHttp("directory_key_mismatch".to_owned()))
    }
}

pub(crate) fn directory_unavailable() -> NodeCoreError {
    NodeCoreError::ItestHttp("node directory unavailable".to_owned())
}

/// Read-only admin view (`GET /admin/federation/directory`).
pub(crate) fn admin_view() -> Value {
    let Some(lock) = RUNTIME.get() else { return json!({ "enabled": false }) };
    let Ok(runtime) = lock.read() else {
        return json!({ "enabled": true, "error": "unavailable" });
    };
    let mode = match runtime.config.sanction {
        NodeDirectorySanctionMode::Refuse => "refuse",
        NodeDirectorySanctionMode::Observe => "observe",
    };
    let Some((snapshot, _)) = runtime.held.as_ref() else {
        return json!({ "enabled": true, "sanction": mode, "seq": 0, "issued_at": null,
            "entries": 0, "sanctioned": [] });
    };
    let sanctioned: Vec<Value> = snapshot
        .entries
        .values()
        .filter(|entry| entry.state.sanctioned())
        .map(|entry| json!({ "k": entry.key, "d": entry.domain, "s": entry.state.code() }))
        .collect();
    json!({
        "enabled": true,
        "sanction": mode,
        "seq": snapshot.seq,
        "issued_at": snapshot.issued_at,
        "entries": snapshot.entries.len(),
        "sanctioned": sanctioned,
    })
}

/// The mode the operator configured; `refuse` is the default.
pub(crate) fn sanction_mode() -> Option<NodeDirectorySanctionMode> {
    RUNTIME.get().and_then(|lock| lock.read().ok()).map(|runtime| runtime.config.sanction)
}

/// Looks up the sanction state of `domain` in the held snapshot.
pub(crate) fn sanction_of(domain: &str) -> Result<Option<State>, NodeCoreError> {
    let Some(lock) = RUNTIME.get() else { return Ok(None) };
    let runtime = lock.read().map_err(|_| directory_unavailable())?;
    let Some((snapshot, _)) = runtime.held.as_ref() else { return Ok(None) };
    Ok(snapshot
        .domains
        .get(domain)
        .and_then(|key| snapshot.entries.get(key))
        .map(|entry| entry.state))
}

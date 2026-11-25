// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Notify-to-federation handoff contract for central push, plus the push state file.
//! Frames on the Unix socket and in the state file are `u32be length || JSON`.
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::NodeCoreError;

pub const HANDOFF_VERSION: u8 = 1;
/// Largest JSON body of one handoff frame (length prefix excluded).
pub const MAX_HANDOFF_FRAME: usize = 40 * 1024;
pub const MAX_WAKES: usize = 32;
/// Total time bound of one blocking handoff exchange.
const HANDOFF_TOTAL: Duration = Duration::from_secs(12);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CentralClass {
    M,
    Call,
    X,
    T,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffWake {
    pub w: String,
    pub c: CentralClass,
    pub ttl: u64,
    pub rt: String,
    pub st: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffRequest {
    pub v: u8,
    pub wakes: Vec<HandoffWake>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffStatus {
    Ok,
    Unavailable,
    Throttled,
    Rejected,
    Stopped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandoffReply {
    pub v: u8,
    pub status: HandoffStatus,
    pub retry_after_ms: Option<u64>,
    pub why: Option<String>,
    /// Same length as the request's `wakes` iff `status` is `Ok`.
    pub results: Vec<HandoffResult>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeOutcome {
    Accepted,
    Duplicate,
    InvalidRoute,
    Reseal,
    Unserved,
    Refused,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandoffResult {
    pub r: WakeOutcome,
    pub why: Option<String>,
    pub at: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PushCentralState {
    pub ks: Option<KeysetDoc>,
    pub ks_seq: u64,
    pub served: Served,
    pub classes: Vec<CentralClass>,
    pub ttl_max_s: TtlMax,
    /// `dir.policy` (A7.1); defaults until the first `ok` reply carries one.
    #[serde(default)]
    pub policy: PushPolicy,
    /// `dir.quota` (A7.4), display only; absent until the first `ok` reply carries one.
    #[serde(default)]
    pub quota: Option<PushQuota>,
    pub updated_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PushPolicy {
    pub version: u64,
    pub n_s: u64,
    pub t_s: u64,
}

impl Default for PushPolicy {
    fn default() -> Self {
        Self { version: 0, n_s: 120, t_s: 10 }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum QuotaState {
    Normal,
    Warning,
    Grace,
    Coalescing,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PushQuota {
    pub state: QuotaState,
    pub enforced: bool,
    pub used: u64,
    /// `None` means unmetered.
    pub allowance: Option<u64>,
    pub period_end: u64,
    pub grace_end: Option<u64>,
    pub coalesce_s: u64,
}

/// Key set document as the centre sent it. Strings are base64url and opaque to the node.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeysetDoc {
    pub key_id: String,
    pub body: String,
    pub sig: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Served {
    pub apns: bool,
    pub apns_voip: bool,
    pub fcm: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TtlMax {
    pub m: u64,
    pub call: u64,
    pub x: u64,
    pub t: u64,
}

impl Default for TtlMax {
    fn default() -> Self {
        Self { m: 3600, call: 30, x: 3600, t: 300 }
    }
}

/// Reads the state file. An absent file is `None` (no session has reported yet).
/// # Errors
/// Returns a configuration error for unreadable or malformed files.
pub fn read_push_central_state(path: &Path) -> Result<Option<PushCentralState>, NodeCoreError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(invalid(format!("read push state: {error}"))),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| invalid(format!("parse push state: {error}")))
}

/// Writes the state file atomically: temporary file (mode 0600), fsync, rename.
/// # Errors
/// Returns a configuration error when the file cannot be written.
pub fn write_push_central_state(
    path: &Path,
    state: &PushCentralState,
) -> Result<(), NodeCoreError> {
    let bytes = serde_json::to_vec(state)
        .map_err(|error| invalid(format!("encode push state: {error}")))?;
    let tmp = path.with_extension("tmp");
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    result.map_err(|error| {
        let _ = std::fs::remove_file(&tmp);
        invalid(format!("write push state: {error}"))
    })
}

/// Blocking client used by notify: connect, one request, one reply, 12 s total bound.
/// # Errors
/// Returns an error when the request is oversized, the socket is unreachable, the exchange
/// times out, or the reply is not a valid frame.
pub fn exchange_handoff(
    socket: &Path,
    request: &HandoffRequest,
) -> Result<HandoffReply, NodeCoreError> {
    if request.wakes.len() > MAX_WAKES {
        return Err(invalid("handoff batch exceeds 32 wakes".into()));
    }
    let body =
        serde_json::to_vec(request).map_err(|error| invalid(format!("encode handoff: {error}")))?;
    if body.len() > MAX_HANDOFF_FRAME {
        return Err(invalid("handoff frame exceeds 40 KiB".into()));
    }
    let deadline = Instant::now() + HANDOFF_TOTAL;
    let mut stream = UnixStream::connect(socket)
        .map_err(|error| invalid(format!("connect handoff socket: {error}")))?;
    stream
        .set_write_timeout(Some(HANDOFF_TOTAL))
        .map_err(|error| invalid(format!("handoff timeout: {error}")))?;
    write_frame(&mut stream, &body)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| invalid("handoff exchange timed out".into()))?;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|error| invalid(format!("handoff timeout: {error}")))?;
    let reply_bytes = read_frame(&mut stream)?;
    serde_json::from_slice(&reply_bytes)
        .map_err(|error| invalid(format!("parse handoff reply: {error}")))
}

fn write_frame(stream: &mut UnixStream, body: &[u8]) -> Result<(), NodeCoreError> {
    let len = u32::try_from(body.len()).map_err(|_| invalid("handoff frame too long".into()))?;
    stream
        .write_all(&len.to_be_bytes())
        .and_then(|()| stream.write_all(body))
        .map_err(|error| invalid(format!("write handoff: {error}")))
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, NodeCoreError> {
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|error| invalid(format!("read handoff header: {error}")))?;
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_HANDOFF_FRAME {
        return Err(invalid("handoff reply exceeds 40 KiB".into()));
    }
    let mut body = vec![0_u8; len];
    stream.read_exact(&mut body).map_err(|error| invalid(format!("read handoff body: {error}")))?;
    Ok(body)
}

fn invalid(message: String) -> NodeCoreError {
    NodeCoreError::InvalidConfiguration(message)
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed diagnostic events (DIAGNOSTIC-LOGGING-01 section 4.4, phases 0 and 1).
//! Every writer goes through `emit`, which keeps only registered fields. Identifiers
//! are hashed here, never by the caller, and no free text is accepted.
use super::logging::{self, fields};
use crate::SdkError;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const MAX_ERROR_KEYS: usize = 200;

/// Fresh correlation id: 12 Crockford characters from 60 random bits (4.3).
pub(crate) fn new_cid() -> String {
    let mut bytes = [0_u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        bytes = logging::now_ms().to_be_bytes();
    }
    let bits = u64::from_be_bytes(bytes) >> 4;
    (0..12_u32)
        .rev()
        .map(|index| {
            let digit = usize::try_from((bits >> (index * 5)) & 31).unwrap_or(0);
            char::from(CROCKFORD.get(digit).copied().unwrap_or(b'0'))
        })
        .collect()
}

/// A caller trace id: 1 to 128 bytes of `[A-Za-z0-9_-]` (C-8).
pub(crate) fn valid_trace_id(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// A correlation id is exactly 12 Crockford characters, as `new_cid` makes them.
#[cfg(feature = "c-abi")]
pub(crate) fn valid_cid(text: &str) -> bool {
    text.len() == 12 && text.bytes().all(|byte| CROCKFORD.contains(&byte))
}

/// Milliseconds since `start`, saturating.
#[cfg(feature = "c-abi")]
pub(crate) fn elapsed_ms(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// `account.open.end`, `account.suspend`, `account.resume` (info, no identifiers).
#[cfg(feature = "c-abi")]
pub(crate) fn account_event(event: &str, fields: Value) {
    emit("I", "sdk.account", event, None, fields, None);
}

/// `abi.event.drop` (stale generation) or `abi.event.resync` (credit exhausted).
#[cfg(feature = "c-abi")]
pub(crate) fn abi_event(event: &str, generation: u64, reason: &str) {
    emit("W", "abi.event", event, None, json!({"generation": generation, "reason": reason}), None);
}

/// `recv.item` (W) for a page outcome that did not apply: held, deferred or needs a point.
pub(crate) fn recv_item(outcome: &str, inbox_seq: u64) {
    emit(
        "W",
        "sdk.recv",
        "recv.item",
        None,
        json!({"outcome": outcome, "inbox_seq": inbox_seq}),
        None,
    );
}

/// Consecutive passes that ended without cursor progress; the last cursor and count.
static STALL: LazyLock<Mutex<(u64, u32)>> = LazyLock::new(|| Mutex::new((0, 0)));
const STALL_PASSES: u32 = 3;

/// `recv.cursor.stall` (E) after three passes with no cursor progress while the node head is higher.
pub(crate) fn recv_progress(before: u64, after: u64, head: u64) {
    let Ok(mut state) = STALL.lock() else { return };
    if after > before || head <= after {
        *state = (after, 0);
        return;
    }
    if state.0 != after {
        *state = (after, 0);
    }
    state.1 = state.1.saturating_add(1);
    if state.1 == STALL_PASSES {
        emit(
            "E",
            "sdk.recv",
            "recv.cursor.stall",
            None,
            json!({"cursor": after, "head": head, "passes": STALL_PASSES}),
            None,
        );
    }
}

/// `backup.job` per state change: kind, state, and the failing check when the job failed.
pub(crate) fn backup_job(
    row: &crate::backup::BackupJob,
    check: Option<crate::backup::BackupFailureCode>,
) {
    let token = |value: serde_json::Result<Value>| {
        value
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned())
    };
    let kind = token(serde_json::to_value(row.kind));
    let state = token(serde_json::to_value(row.state));
    match check {
        None => {
            emit("I", "sdk.backup", "backup.job", None, json!({"kind": kind, "state": state}), None)
        }
        Some(code) => {
            let check = token(serde_json::to_value(code));
            emit(
                "W",
                "sdk.backup",
                "backup.job",
                None,
                json!({"kind": kind, "state": state, "check": check}),
                Some(
                    json!({"name": "BackupFailed", "reason": check, "variant": "BackupFailed", "effect": "none"}),
                ),
            );
        }
    }
}

/// Writes one typed record through the process sink. Unregistered fields are dropped.
pub(crate) fn emit(
    level: &str,
    component: &str,
    event: &str,
    cid: Option<&str>,
    fields: Value,
    error: Option<Value>,
) {
    if let Some(session) = logging::active() {
        session.write("sdk", level, component, event, cid, fields::sanitize(fields), error);
    }
}

/// The Rust variant name of an error: the identifier before its payload, never the payload.
pub(crate) fn variant_of(error: &impl std::fmt::Debug) -> String {
    let name: String = format!("{error:?}")
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(48)
        .collect();
    if name.is_empty() { "unknown".to_owned() } else { name }
}

#[derive(Clone)]
struct Tally {
    count: u64,
    first_ms: u64,
    last_ms: u64,
    last_cid: Option<String>,
}

/// Bounded in-memory table of failures for the bundle (C-10 `errors`).
type Errors = BTreeMap<(String, i64, String, String), Tally>;
static ERRORS: LazyLock<Mutex<Errors>> = LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn note_error(method: &str, code: i64, name: &str, reason: &str, cid: Option<&str>) {
    let Ok(mut table) = ERRORS.lock() else { return };
    let key = (method.to_owned(), code, name.to_owned(), reason.to_owned());
    if !table.contains_key(&key) && table.len() >= MAX_ERROR_KEYS {
        return;
    }
    let now = logging::now_ms();
    let entry =
        table.entry(key).or_insert(Tally { count: 0, first_ms: now, last_ms: now, last_cid: None });
    entry.count = entry.count.saturating_add(1);
    entry.last_ms = now;
    entry.last_cid = cid.map(str::to_owned);
}

/// The failure table: `{method, code, name, reason, count, first_ms, last_ms, last_cid}`.
pub(crate) fn error_table(since_ms: Option<u64>) -> Vec<Value> {
    let Ok(table) = ERRORS.lock() else { return Vec::new() };
    table
        .iter()
        .filter(|(_, tally)| since_ms.is_none_or(|since| tally.last_ms >= since))
        .map(|((method, code, name, reason), tally)| {
            json!({
                "method": method,
                "code": code,
                "name": name,
                "reason": reason,
                "count": tally.count,
                "first_ms": tally.first_ms,
                "last_ms": tally.last_ms,
                "last_cid": tally.last_cid,
            })
        })
        .collect()
}

/// A local bus error reply (`abi.failed`, C-5): name, reason and the Rust variant, no message.
pub(crate) fn bus_failure(method: &str, cid: Option<&str>, error: &SdkError) {
    let name = crate::bus::io::local_bus_error_code(error);
    let variant = variant_of(error);
    note_error(method, 0, name, name, cid);
    emit(
        "W",
        "abi.call",
        "abi.failed",
        cid,
        json!({"method": method, "name": name, "reason": name, "variant": variant}),
        Some(json!({"name": name, "reason": name, "variant": variant, "effect": "unknown"})),
    );
}

/// An SDK panic caught at the C ABI boundary (`abi.panic`): thread name only, never the payload.
#[cfg(feature = "c-abi")]
pub(crate) fn panic_caught() {
    let thread = std::thread::current().name().unwrap_or("unnamed").to_owned();
    let thread = if fields::token(&thread) { thread } else { "other".to_owned() };
    emit(
        "E",
        "abi.call",
        "abi.panic",
        None,
        json!({"thread": thread}),
        Some(
            json!({"name": "PanicAborted", "reason": "panic_caught", "variant": "Panic", "effect": "unknown"}),
        ),
    );
}

/// `send.stage` at the start of a send (`submit`).
pub(crate) fn send_submit(cid: &str) {
    emit("I", "sdk.send", "send.stage", Some(cid), json!({"stage": "submit"}), None);
}

/// `send.stage` at its end: `accepted`, or `failed` with the variant of the error.
pub(crate) fn send_finish(cid: &str, method: &str, error: Option<&SdkError>) {
    match error {
        None => emit("I", "sdk.send", "send.stage", Some(cid), json!({"stage": "accepted"}), None),
        Some(error) => {
            let name = crate::bus::io::local_bus_error_code(error);
            let variant = variant_of(error);
            note_error(method, 0, name, name, Some(cid));
            emit(
                "W",
                "sdk.send",
                "send.stage",
                Some(cid),
                json!({"stage": "failed", "name": name, "variant": variant}),
                Some(
                    json!({"name": name, "reason": name, "variant": variant, "effect": "unknown"}),
                ),
            );
        }
    }
}

/// `recv.pass.end` for one ledger catch-up pass. The caller supplies the pass fields.
pub(crate) fn recv_pass_end(cid: &str, fields: Value) {
    emit("I", "sdk.recv", "recv.pass.end", Some(cid), fields, None);
}

/// `conn.connect` when a session goes Live.
pub(crate) fn conn_connect(resumed: bool, generation: u64) {
    emit(
        "I",
        "sdk.conn",
        "conn.connect",
        None,
        json!({"resumed": resumed, "generation": generation}),
        None,
    );
}

/// `conn.disconnect`; the reason is the stable variant name, lower-cased.
pub(crate) fn conn_disconnect(reason: &str, generation: u64) {
    emit(
        "I",
        "sdk.conn",
        "conn.disconnect",
        None,
        json!({"reason": reason.to_ascii_lowercase(), "generation": generation}),
        None,
    );
}

/// `conn.backoff` with the delay and the variant of the failing attempt.
pub(crate) fn conn_backoff(error: &SdkError, delay_ms: u64) {
    emit(
        "I",
        "sdk.conn",
        "conn.backoff",
        None,
        json!({"delay_ms": delay_ms, "reason": variant_of(error).to_ascii_lowercase()}),
        None,
    );
}

/// Flushes the sink; bounded by the sink's own five-second wait.
pub(crate) fn flush() {
    if let Some(session) = logging::active() {
        session.flush();
    }
}

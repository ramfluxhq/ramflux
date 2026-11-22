// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Local ingress limits and permanent forward-refusal classification.
//! Counters live on this process. They are not shared with other nodes.
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// One foreign node cannot fill one recipient. A person sends less than once a minute.
const DEFAULT_PEER_RECIPIENT_PER_HOUR: u64 = 60;
// Envelope JSON, not attachment bytes. One mebibyte an hour is many text messages.
const DEFAULT_PEER_RECIPIENT_BYTES_PER_HOUR: u64 = 1024 * 1024;
// Several honest peers can still reach one person. Same order as the plan's unread cap,
// counted as admissions because unread depth lives in the router store.
const DEFAULT_RECIPIENT_PER_HOUR: u64 = 500;
// Stops many peers combining into a disk flood of one inbox.
const DEFAULT_RECIPIENT_BYTES_PER_HOUR: u64 = 8 * 1024 * 1024;
// One node minting many accounts cannot flood every local recipient.
const DEFAULT_PEER_PER_MINUTE: u64 = 600;
// Bounds one node's total ciphertext for the hour.
const DEFAULT_PEER_BYTES_PER_HOUR: u64 = 64 * 1024 * 1024;
const HOUR: u64 = 3600;
const MINUTE: u64 = 60;
const MAX_ID_LEN: usize = 256;
const MAX_KEYS: usize = 8192;

struct Config {
    peer_recipient_per_hour: u64,
    peer_recipient_bytes_per_hour: u64,
    recipient_per_hour: u64,
    recipient_bytes_per_hour: u64,
    peer_per_minute: u64,
    peer_bytes_per_hour: u64,
}

#[derive(Default)]
struct Window {
    start: u64,
    count: u64,
    bytes: u64,
}

#[derive(Default)]
struct Tables {
    peer_recipient: HashMap<(String, String), Window>,
    recipient: HashMap<String, Window>,
    peer_minute: HashMap<String, Window>,
    peer_hour: HashMap<String, Window>,
}

pub(crate) fn is_permanent_outcome(outcome: &str) -> bool {
    matches!(
        outcome,
        "rejected_authority" | "rejected_limit" | "rejected_blocked" | "rejected_malformed"
    )
}

/// Classify a destination failure the sender must not spool or retry.
#[must_use]
pub(crate) fn permanent_outcome(error: &ramflux_node_core::NodeCoreError) -> Option<&'static str> {
    match error {
        ramflux_node_core::NodeCoreError::SourceAuthorityRefused { .. }
        | ramflux_node_core::NodeCoreError::CustodyConflict { .. } => {
            return Some("rejected_authority");
        }
        ramflux_node_core::NodeCoreError::Unauthorized(message)
            if message.contains("foreign custody")
                || message.contains("native forwarded")
                || message.contains("stale native")
                || message.contains("floor") =>
        {
            return Some("rejected_authority");
        }
        _ => {}
    }
    let text = error.to_string();
    if text.contains("rejected_blocked") {
        return Some("rejected_blocked");
    }
    if text.contains("rejected_limit") {
        return Some("rejected_limit");
    }
    if text.contains("rejected_malformed")
        || text.contains("HTTP 400:")
        || text.contains("signing key id mismatch")
        || text.contains("missing federation forward signature")
        || text.contains("must be opaque_event")
    {
        return Some("rejected_malformed");
    }
    if text.contains("envelope root authority mismatch")
        || text.contains("source authority refused")
        || text.contains("rejected_authority")
        || text.contains("sender_authority_refused")
        || text.contains("custody authority conflict")
        || text.contains("missing federation pin")
        || text.contains("missing federation capability")
        || text.contains("missing negotiated capabilities")
        || text.contains("HTTP 401:")
        || text.contains("HTTP 403:")
        || text.contains("HTTP 409:")
        || text.contains("HTTP 422:")
    {
        Some("rejected_authority")
    } else {
        None
    }
}

/// Count one verified forward. Over the cap the envelope is refused and not counted past it.
/// # Errors
/// Returns `rejected_malformed` for an oversized id and `rejected_limit` over a cap.
pub(crate) fn admit(peer: &str, recipient: &str, bytes: u64, now: u64) -> Result<(), &'static str> {
    if peer.is_empty()
        || recipient.is_empty()
        || peer.len() > MAX_ID_LEN
        || recipient.len() > MAX_ID_LEN
    {
        return Err("rejected_malformed");
    }
    let mut tables = tables().lock().map_err(|_| "rejected_limit")?;
    if key_count(&tables) >= MAX_KEYS {
        sweep(&mut tables, now);
    }
    let peer_recipient_key = (peer.to_owned(), recipient.to_owned());
    if key_count(&tables) >= MAX_KEYS && !tables.peer_recipient.contains_key(&peer_recipient_key) {
        return Err("rejected_limit");
    }
    if exceeds(&tables, peer, recipient, now, bytes) {
        return Err("rejected_limit");
    }
    add_pair(tables.peer_recipient.entry(peer_recipient_key), now / HOUR, bytes);
    add_one(tables.recipient.entry(recipient.to_owned()), now / HOUR, bytes);
    add_one(tables.peer_minute.entry(peer.to_owned()), now / MINUTE, bytes);
    add_one(tables.peer_hour.entry(peer.to_owned()), now / HOUR, bytes);
    Ok(())
}

fn key_count(tables: &Tables) -> usize {
    tables.peer_recipient.len()
        + tables.recipient.len()
        + tables.peer_minute.len()
        + tables.peer_hour.len()
}

fn exceeds(tables: &Tables, peer: &str, recipient: &str, now: u64, bytes: u64) -> bool {
    let config = config();
    let pair = (peer.to_owned(), recipient.to_owned());
    over(
        tables.peer_recipient.get(&pair),
        now / HOUR,
        config.peer_recipient_per_hour,
        config.peer_recipient_bytes_per_hour,
        bytes,
    ) || over(
        tables.recipient.get(recipient),
        now / HOUR,
        config.recipient_per_hour,
        config.recipient_bytes_per_hour,
        bytes,
    ) || over(tables.peer_minute.get(peer), now / MINUTE, config.peer_per_minute, u64::MAX, bytes)
        || over(tables.peer_hour.get(peer), now / HOUR, u64::MAX, config.peer_bytes_per_hour, bytes)
}

fn over(window: Option<&Window>, start: u64, max_count: u64, max_bytes: u64, bytes: u64) -> bool {
    let (count, used) = match window {
        Some(window) if window.start == start => (window.count, window.bytes),
        _ => (0, 0),
    };
    count >= max_count || used.saturating_add(bytes) > max_bytes
}

fn add_pair(
    entry: std::collections::hash_map::Entry<'_, (String, String), Window>,
    start: u64,
    bytes: u64,
) {
    match entry {
        std::collections::hash_map::Entry::Occupied(mut slot) => bump(slot.get_mut(), start, bytes),
        std::collections::hash_map::Entry::Vacant(slot) => {
            slot.insert(Window { start, count: 1, bytes });
        }
    }
}

fn add_one(entry: std::collections::hash_map::Entry<'_, String, Window>, start: u64, bytes: u64) {
    match entry {
        std::collections::hash_map::Entry::Occupied(mut slot) => bump(slot.get_mut(), start, bytes),
        std::collections::hash_map::Entry::Vacant(slot) => {
            slot.insert(Window { start, count: 1, bytes });
        }
    }
}

fn bump(window: &mut Window, start: u64, bytes: u64) {
    if window.start == start {
        window.count = window.count.saturating_add(1);
        window.bytes = window.bytes.saturating_add(bytes);
    } else {
        *window = Window { start, count: 1, bytes };
    }
}

fn sweep(tables: &mut Tables, now: u64) {
    let hour = now / HOUR;
    let minute = now / MINUTE;
    tables.peer_recipient.retain(|_, window| window.start == hour);
    tables.recipient.retain(|_, window| window.start == hour);
    tables.peer_hour.retain(|_, window| window.start == hour);
    tables.peer_minute.retain(|_, window| window.start == minute);
}

fn tables() -> &'static Mutex<Tables> {
    static TABLES: OnceLock<Mutex<Tables>> = OnceLock::new();
    TABLES.get_or_init(|| Mutex::new(Tables::default()))
}

fn config() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(|| Config {
        peer_recipient_per_hour: env_u64(
            "RAMFLUX_FEDERATION_LIMIT_PEER_RECIPIENT_PER_HOUR",
            DEFAULT_PEER_RECIPIENT_PER_HOUR,
        ),
        peer_recipient_bytes_per_hour: env_u64(
            "RAMFLUX_FEDERATION_LIMIT_PEER_RECIPIENT_BYTES_PER_HOUR",
            DEFAULT_PEER_RECIPIENT_BYTES_PER_HOUR,
        ),
        recipient_per_hour: env_u64(
            "RAMFLUX_FEDERATION_LIMIT_RECIPIENT_PER_HOUR",
            DEFAULT_RECIPIENT_PER_HOUR,
        ),
        recipient_bytes_per_hour: env_u64(
            "RAMFLUX_FEDERATION_LIMIT_RECIPIENT_BYTES_PER_HOUR",
            DEFAULT_RECIPIENT_BYTES_PER_HOUR,
        ),
        peer_per_minute: env_u64(
            "RAMFLUX_FEDERATION_LIMIT_PEER_PER_MINUTE",
            DEFAULT_PEER_PER_MINUTE,
        ),
        peer_bytes_per_hour: env_u64(
            "RAMFLUX_FEDERATION_LIMIT_PEER_BYTES_PER_HOUR",
            DEFAULT_PEER_BYTES_PER_HOUR,
        ),
    })
}

fn env_u64(name: &str, default_value: u64) -> u64 {
    ramflux_node_core::environment::parsed::<u64>(name).unwrap_or(default_value)
}

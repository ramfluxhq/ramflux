// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Centre-provisioned list of home nodes the witness accepts reports from (K7B-WITNESS-01).
//! The producer writes the file with tmp + rename; the witness polls it and keeps the last good
//! list when an update is invalid. An expired list refuses every node until a fresh one arrives.
use super::{Result, error, refuse};
use std::{
    collections::HashMap,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const SUPPORTED_VERSION: u64 = 1;
const MAX_BYTES: u64 = 1_048_576;
const MAX_ENTRIES: usize = 10_000;
const LIFETIME_SECONDS: u64 = 86_400;
const FUTURE_SKEW_SECONDS: u64 = 300;
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const KEY_BYTES: usize = 32;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    v: u64,
    generated_at: u64,
    nodes: Vec<Entry>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    node_key: String,
    state: State,
}

#[derive(serde::Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum State {
    Active,
    Suspended,
}

/// Change detector: modification time, size and inode.
#[derive(PartialEq, Eq, Clone, Copy)]
struct Fingerprint {
    mtime: (i64, i64),
    size: u64,
    inode: u64,
}

struct Snapshot {
    generated_at: u64,
    nodes: HashMap<String, State>,
}

pub(super) struct RegisteredNodes {
    path: PathBuf,
    current: Snapshot,
    seen: Option<Fingerprint>,
    expired: bool,
    last_poll: Instant,
}

fn fingerprint(path: &Path) -> std::io::Result<Fingerprint> {
    let meta = std::fs::metadata(path)?;
    Ok(Fingerprint {
        mtime: (meta.mtime(), meta.mtime_nsec()),
        size: meta.size(),
        inode: meta.ino(),
    })
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > MAX_BYTES) {
        return refuse("registered nodes file too large");
    }
    Ok(bytes)
}

fn parse(bytes: &[u8], now: u64) -> Result<Snapshot> {
    let document: Document = ramflux_protocol::parse_i_json(bytes)?;
    if document.v != SUPPORTED_VERSION {
        return refuse("registered nodes version unsupported");
    }
    if document.generated_at > ramflux_protocol::MAX_SAFE_JSON_INTEGER {
        return refuse("registered nodes generated_at out of range");
    }
    if document.generated_at > now.saturating_add(FUTURE_SKEW_SECONDS) {
        return refuse("registered nodes generated_at in the future");
    }
    if document.nodes.len() > MAX_ENTRIES {
        return refuse("registered nodes has too many entries");
    }
    let mut nodes = HashMap::with_capacity(document.nodes.len());
    for entry in document.nodes {
        let raw = ramflux_protocol::decode_base64url(&entry.node_key)
            .map_err(|_| error("registered nodes key encoding"))?;
        if raw.len() != KEY_BYTES || ramflux_protocol::encode_base64url(&raw) != entry.node_key {
            return refuse("registered nodes key not canonical");
        }
        if nodes.insert(entry.node_key, entry.state).is_some() {
            return refuse("registered nodes duplicate key");
        }
    }
    Ok(Snapshot { generated_at: document.generated_at, nodes })
}

impl RegisteredNodes {
    /// Startup load: a missing, unreadable or invalid file refuses to start the witness.
    pub(super) fn load(path: &Path) -> Result<Self> {
        let seen = fingerprint(path)?;
        let current = parse(&read_bounded(path)?, crate::now_unix_seconds()?).map_err(|reason| {
            tracing::error!(path = %path.display(), %reason, "registered_nodes invalid at start");
            reason
        })?;
        let mut loaded = Self {
            path: path.to_owned(),
            current,
            seen: Some(seen),
            expired: false,
            last_poll: Instant::now(),
        };
        loaded.announce_loaded();
        loaded.check_expiry(crate::now_unix_seconds()?);
        Ok(loaded)
    }

    fn announce_loaded(&self) {
        tracing::info!(
            count = self.current.nodes.len(),
            generated_at = self.current.generated_at,
            "registered_nodes loaded"
        );
    }

    /// Re-read the file when its mtime, size or inode changed. Any failure keeps the last list.
    pub(super) fn poll(&mut self) {
        if self.last_poll.elapsed() < POLL_INTERVAL {
            return;
        }
        self.last_poll = Instant::now();
        let now = match crate::now_unix_seconds() {
            Ok(now) => now,
            Err(reason) => {
                tracing::warn!(%reason, "registered_nodes clock unavailable");
                return;
            }
        };
        let observed = fingerprint(&self.path).ok();
        if observed != self.seen {
            self.seen = observed;
            let outcome = match observed {
                Some(_) => read_bounded(&self.path).and_then(|bytes| parse(&bytes, now)),
                None => refuse("registered nodes file missing"),
            };
            match outcome {
                Ok(snapshot) => {
                    self.current = snapshot;
                    self.announce_loaded();
                }
                Err(reason) => tracing::warn!(
                    path = %self.path.display(),
                    %reason,
                    "registered_nodes update rejected, keeping last good list"
                ),
            }
        }
        self.check_expiry(now);
    }

    fn check_expiry(&mut self, now: u64) {
        let expired = now >= self.current.generated_at.saturating_add(LIFETIME_SECONDS);
        if expired && !self.expired {
            tracing::error!(
                generated_at = self.current.generated_at,
                "registered_nodes expired"
            );
        } else if !expired && self.expired {
            tracing::info!("registered_nodes valid");
        }
        self.expired = expired;
    }

    /// True only for an `active` node on a list that has not expired.
    pub(super) fn authorize(&mut self, node_key: &str, now: u64) -> bool {
        self.check_expiry(now);
        !self.expired && self.current.nodes.get(node_key) == Some(&State::Active)
    }
}

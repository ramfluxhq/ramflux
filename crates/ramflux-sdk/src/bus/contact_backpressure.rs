// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded per-root redrive of unacknowledged contact admissions, independent of the live inbox cursor.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
const KEY: &str = "contact-admission/backpressure";
#[derive(Default, Deserialize, Serialize)]
pub(super) struct Backpressure {
    floor: Option<u64>,
    next_at: i64,
    expires_at: i64,
    scan: Option<Scan>,
    #[serde(default)]
    roots: BTreeMap<String, Deferred>,
}
#[derive(Deserialize, Serialize)]
struct Deferred {
    sequence: u64,
    expires_at: i64,
}
#[derive(Deserialize, Serialize)]
struct Scan {
    cursor: u64,
    until: u64,
    pending: Option<u64>,
    future: Option<u64>,
}
fn earliest(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    a.into_iter().chain(b).min()
}
pub(super) fn deferred(entry: &GatewayInboxEntry, error: &SdkError) -> bool {
    matches!(error, SdkError::ContactRequestCapacity(_))
        && crate::client::routed::decode(&entry.envelope)
            .is_ok_and(|packet| packet.schema == crate::client::contact_requests::ENVELOPE_SCHEMA)
}
impl Backpressure {
    pub fn load(client: &RamfluxClient, now: i64) -> Result<Self, SdkError> {
        let mut state = client.account_db()?.load_actor_state::<Self>(KEY)?.unwrap_or_default();
        state.roots.retain(|_, entry| entry.expires_at > now);
        Ok(if state.expires_at <= now { Self::default() } else { state })
    }
    fn save(&self, client: &RamfluxClient) -> Result<(), SdkError> {
        if self.floor.is_some() || self.scan.is_some() {
            client.account_db()?.persist_actor_state(KEY, self)?;
        } else {
            client.account_db()?.remove_actor_state(KEY)?;
        }
        Ok(())
    }
    pub fn record(
        &mut self,
        client: &RamfluxClient,
        entry: &GatewayInboxEntry,
        now: i64,
    ) -> Result<bool, SdkError> {
        let Some(root) = requester(entry) else {
            return Ok(false);
        };
        if self.duplicate(entry) || (!self.roots.contains_key(&root) && self.roots.len() >= 1024) {
            return Ok(false);
        }
        self.roots.insert(
            root,
            Deferred {
                sequence: entry.inbox_seq,
                expires_at: entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl)),
            },
        );
        if self.floor.is_none() {
            self.next_at = now.saturating_add(60);
        }
        self.floor = earliest(self.floor, Some(entry.inbox_seq));
        let expires = entry.envelope.created_at.saturating_add(i64::from(entry.envelope.ttl));
        self.expires_at = self.expires_at.max(expires.min(now.saturating_add(604_860)));
        if let Some(scan) = &mut self.scan {
            if entry.inbox_seq <= scan.until {
                scan.pending = earliest(scan.pending, Some(entry.inbox_seq));
            } else {
                scan.future = earliest(scan.future, Some(entry.inbox_seq));
            }
        }
        // Persist before the normal cursor advances. The gateway retains the original ciphertext.
        self.save(client)?;
        // Existing generic retry rows must not stay due every tick. The durable floor owns redrive.
        client.account_db()?.remove_inbox_retry(&client.inbox_admission_key(entry)?)?;
        Ok(true)
    }
    pub fn duplicate(&self, entry: &GatewayInboxEntry) -> bool {
        requester(entry)
            .and_then(|root| self.roots.get(&root))
            .is_some_and(|held| held.sequence != entry.inbox_seq)
    }
    pub fn completed(
        &mut self,
        client: &RamfluxClient,
        entry: &GatewayInboxEntry,
    ) -> Result<(), SdkError> {
        if let Some(root) = requester(entry)
            && self.roots.get(&root).is_some_and(|held| held.sequence == entry.inbox_seq)
        {
            self.roots.remove(&root);
            self.save(client)?;
        }
        Ok(())
    }
    pub fn scan_cursor(
        &mut self,
        client: &RamfluxClient,
        walk: u64,
        now: i64,
    ) -> Result<Option<(u64, u64)>, SdkError> {
        if self.scan.is_none()
            && now >= self.next_at
            && let Some(floor) = self.floor
        {
            self.scan = Some(Scan {
                cursor: floor.saturating_sub(1),
                until: walk,
                pending: None,
                future: None,
            });
            self.save(client)?;
        }
        Ok(self.scan.as_ref().map(|scan| (scan.cursor, scan.until)))
    }
    pub fn scanned(
        &mut self,
        client: &RamfluxClient,
        last: Option<u64>,
        count: usize,
        now: i64,
    ) -> Result<(), SdkError> {
        if let Some(scan) = &mut self.scan {
            if let Some(last) = last {
                scan.cursor = scan.cursor.max(last);
            }
            if last.is_none() || count < 64 || scan.cursor >= scan.until {
                self.floor = earliest(scan.pending, scan.future);
                self.scan = None;
                self.next_at = now.saturating_add(60);
            }
        }
        self.save(client)
    }
}

fn requester(entry: &GatewayInboxEntry) -> Option<String> {
    let packet = crate::client::routed::decode(&entry.envelope).ok()?;
    (packet.schema == crate::client::contact_requests::ENVELOPE_SCHEMA)
        .then_some(packet.source_principal_commitment)
        .flatten()
}

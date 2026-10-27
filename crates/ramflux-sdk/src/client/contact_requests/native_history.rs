// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Evictable public evidence cache; eviction never removes durable account mode/head pins.
use super::invalid;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::custody::{Publication, object_hash};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "contact-request/native-history/";
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_ROWS: usize = 256;
#[derive(Deserialize, Serialize)]
struct Cached {
    publication: Publication,
    expires_at: u64,
    accessed_at: u64,
}
fn key(root: &str, hash: &str) -> String {
    format!("{PREFIX}{root}/{hash}")
}

impl RamfluxClient {
    pub(super) fn cached_contact_consent_authority(
        &self,
        root: &str,
        hash: &str,
        now: u64,
    ) -> Result<Option<Publication>, SdkError> {
        let Some(cached) = self.account_db()?.load_actor_state::<Cached>(&key(root, hash))? else {
            return Ok(None);
        };
        if cached.expires_at <= now {
            return Ok(None);
        }
        if cached.publication.record.body.account_anchor != root
            || object_hash(&cached.publication.record)? != hash
        {
            return Err(invalid("cached consent history namespace mismatch"));
        }
        Ok(Some(cached.publication))
    }

    pub(super) fn cache_contact_consent_authority(
        &self,
        publication: &Publication,
        expires_at: u64,
        now: u64,
    ) -> Result<(), SdkError> {
        let root = &publication.record.body.account_anchor;
        let hash = object_hash(&publication.record)?;
        let id = key(root, &hash);
        let db = self.account_db()?;
        db.write_transaction(|| -> Result<(), SdkError> {
            let mut retained = Vec::new();
            for entry in db.list_actor_states::<Cached>(PREFIX)? {
                let key = key(
                    &entry.publication.record.body.account_anchor,
                    &object_hash(&entry.publication.record)?,
                );
                if entry.expires_at <= now || key == id {
                    db.remove_actor_state(&key)?;
                } else {
                    let size = ramflux_protocol::canonical_json_bytes(&entry)?.len();
                    retained.push((key, entry, size));
                }
            }
            retained.sort_by_key(|(_, entry, _)| entry.accessed_at);
            let entry = Cached {
                publication: publication.clone(),
                expires_at: expires_at
                    .saturating_add(ramflux_protocol::custody::CLOCK_SKEW_SECONDS),
                accessed_at: now,
            };
            let added = ramflux_protocol::canonical_json_bytes(&entry)?.len();
            if added > MAX_BYTES {
                return Err(invalid("consent history cache entry exceeds byte budget"));
            }
            let mut total = retained.iter().map(|(_, _, size)| size).sum::<usize>();
            let mut per_root = retained
                .iter()
                .filter(|(_, entry, _)| entry.publication.record.body.account_anchor == *root)
                .count();
            while retained.len() >= MAX_ROWS
                || total.saturating_add(added) > MAX_BYTES
                || per_root >= 8
            {
                let index = if per_root >= 8 {
                    retained
                        .iter()
                        .position(|(_, entry, _)| {
                            entry.publication.record.body.account_anchor == *root
                        })
                        .ok_or_else(|| invalid("consent history cache accounting mismatch"))?
                } else {
                    0
                };
                let (key, old, size) = retained.remove(index);
                db.remove_actor_state(&key)?;
                total -= size;
                if old.publication.record.body.account_anchor == *root {
                    per_root -= 1;
                }
            }
            db.persist_actor_state(&id, &entry)?;
            Ok(())
        })
    }
}

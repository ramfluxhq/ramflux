// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Retire terminal wakes and provider diagnostics while preserving undelivered live work.
use super::{
    NOTIFY_PROVIDER_ATTEMPT_TABLE, NOTIFY_QUEUE_ENTRY_TABLE, NOTIFY_QUEUE_KEY, NOTIFY_QUEUE_TABLE,
    NOTIFY_ROUTE_TABLE, NodeCoreError, NotifyQueueState, NotifyQueueStatus, NotifyRedbStore,
    ProviderPushAttempt, deserialize_notify_provider_attempt, deserialize_notify_queue_entry,
    routes, serialize_notify_value,
};
use redb::ReadableTable;
use std::collections::BTreeMap;
pub(crate) fn prune_attempts(attempts: &mut BTreeMap<String, Vec<ProviderPushAttempt>>, now: u64) {
    attempts.retain(|_, values| {
        values.retain(|attempt| attempt.sent_at >= now.saturating_sub(3600));
        if values.len() > 16 {
            values.drain(..values.len() - 16);
        }
        !values.is_empty()
    });
    while attempts.len() > 1024 {
        let oldest = attempts
            .iter()
            .min_by_key(|(_, values)| values.last().map_or(0, |attempt| attempt.sent_at))
            .map(|(id, _)| id.clone());
        if let Some(id) = oldest {
            attempts.remove(&id);
        } else {
            break;
        }
    }
}
impl NotifyQueueState {
    pub(crate) fn prune_retention(&mut self, now: u64) -> usize {
        let before = self.entries_by_id.len();
        self.entries_by_id.retain(|_, entry| {
            entry.status == NotifyQueueStatus::Pending && entry.expires_at > now
        });
        prune_attempts(&mut self.provider_attempts_by_queue, now);
        self.routes_by_device.retain(|_, routes| {
            routes.retain(|route| route.expires_at > now);
            !routes.is_empty()
        });
        self.deferred_by_device.retain(|_, ids| {
            ids.retain(|id| self.entries_by_id.contains_key(id));
            !ids.is_empty()
        });
        before - self.entries_by_id.len()
    }
}
impl NotifyRedbStore {
    /// # Errors
    /// Returns transactional storage or WAL compaction errors; sweeps never replace live queue rows.
    pub fn sweep_retention(&self, now: u64) -> Result<usize, NodeCoreError> {
        let txn = self.db.begin_write().map_err(error)?;
        let mut removed = 0;
        {
            let mut table = txn.open_table(NOTIFY_QUEUE_ENTRY_TABLE).map_err(error)?;
            let mut keys = Vec::new();
            for row in table.iter().map_err(error)? {
                let (key, value) = row.map_err(error)?;
                let entry = deserialize_notify_queue_entry(value.value())?;
                if entry.status != NotifyQueueStatus::Pending || entry.expires_at <= now {
                    keys.push(key.value().to_owned());
                }
            }
            removed += keys.len();
            for key in keys {
                table.remove(key.as_str()).map_err(error)?;
            }
        }
        {
            let mut table = txn.open_table(NOTIFY_PROVIDER_ATTEMPT_TABLE).map_err(error)?;
            let mut grouped: BTreeMap<String, Vec<(String, ProviderPushAttempt)>> = BTreeMap::new();
            for row in table.iter().map_err(error)? {
                let (key, value) = row.map_err(error)?;
                let attempt = deserialize_notify_provider_attempt(value.value())?;
                grouped
                    .entry(attempt.queue_id.clone())
                    .or_default()
                    .push((key.value().to_owned(), attempt));
            }
            let mut retained: BTreeMap<String, Vec<ProviderPushAttempt>> = grouped
                .iter()
                .map(|(id, values)| {
                    (id.clone(), values.iter().map(|(_, attempt)| attempt.clone()).collect())
                })
                .collect();
            prune_attempts(&mut retained, now);
            for (id, values) in grouped {
                for (key, attempt) in values {
                    if !retained.get(&id).is_some_and(|values| values.contains(&attempt)) {
                        table.remove(key.as_str()).map_err(error)?;
                        removed += 1;
                    }
                }
            }
        }
        {
            let mut table = txn.open_table(NOTIFY_ROUTE_TABLE).map_err(error)?;
            let mut updates = Vec::new();
            for row in table.iter().map_err(error)? {
                let (key, value) = row.map_err(error)?;
                let mut values = routes::open(&self.route_key, key.value(), value.value())?;
                let before = values.len();
                values.retain(|route| route.expires_at > now);
                if values.len() != before {
                    removed += before - values.len();
                    updates.push((key.value().to_owned(), values));
                }
            }
            for (key, values) in updates {
                if values.is_empty() {
                    table.remove(key.as_str()).map_err(error)?;
                } else {
                    table
                        .insert(
                            key.as_str(),
                            routes::seal(&self.route_key, &key, &values)?.as_slice(),
                        )
                        .map_err(error)?;
                }
            }
        }
        {
            let mut table = txn.open_table(NOTIFY_QUEUE_TABLE).map_err(error)?;
            let bytes =
                table.get(NOTIFY_QUEUE_KEY).map_err(error)?.map(|value| value.value().to_vec());
            if let Some(bytes) = bytes {
                let mut state: NotifyQueueState = serde_json::from_slice(&bytes).map_err(error)?;
                removed += state.prune_retention(now);
                table
                    .insert(NOTIFY_QUEUE_KEY, serialize_notify_value(&state)?.as_slice())
                    .map_err(error)?;
            }
        }
        txn.commit().map_err(error)?;
        self.prune_route_owners()?;
        if let Some(shards) = &self.wal_shards {
            for shard in shards {
                shard.store.prune_expired(now)?;
            }
        }
        Ok(removed)
    }
}
fn error(value: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(value.to_string())
}

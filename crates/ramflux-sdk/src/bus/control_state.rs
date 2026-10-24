// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded control-state views with encrypted per-record backing and commit-first updates.

use crate::prelude::*;

const CONTROL_CACHE_CAPACITY: usize = 256;
pub(super) enum Snapshot {
    Call { id: String, before: Vec<u8> },
    A2i,
}

pub(super) fn snapshot(
    account: &mut LocalBusAccountState,
    request: &LocalBusFrame,
) -> Result<Option<Snapshot>, SdkError> {
    let method = request.method.as_str();
    if method.starts_with("call.") {
        let Some(id) = request.body.get("call_id").and_then(serde_json::Value::as_str) else {
            return Ok(None);
        };
        if !account.calls.contains_key(id)
            && let Some(record) =
                account.client.account_db()?.load_actor_state(&format!("call/{id}"))?
        {
            account.calls.insert(id.to_owned(), record);
        }
        touch(&mut account.call_lru, id);
        prune(&mut account.calls, &mut account.call_lru);
        Ok(Some(Snapshot::Call {
            id: id.to_owned(),
            before: serde_json::to_vec(&account.calls.get(id))?,
        }))
    } else if matches!(method, "a2i.list" | "a2i.list_pending" | "a2i.acknowledge") {
        // The A2I dispatcher persists each root-scoped record before changing its cache.
        // This wrapper only bounds the transient view; it must not write a second event-id index.
        Ok(Some(Snapshot::A2i))
    } else {
        Ok(None)
    }
}

pub(super) fn commit(account: &mut LocalBusAccountState, before: Snapshot) -> Result<(), SdkError> {
    match before {
        Snapshot::Call { id, before } => {
            let current = account.calls.get(&id);
            if before != serde_json::to_vec(&current)?
                && let Some(current) = current
                && let Err(error) =
                    account.client.account_db()?.persist_actor_state(&format!("call/{id}"), current)
            {
                if let Some(record) = serde_json::from_slice::<Option<LocalCallRecord>>(&before)? {
                    account.calls.insert(id, record);
                } else {
                    account.calls.remove(&id);
                }
                return Err(error.into());
            }
            touch(&mut account.call_lru, &id);
            prune(&mut account.calls, &mut account.call_lru);
        }
        Snapshot::A2i => {
            prune(&mut account.pending_a2i, &mut account.a2i_lru);
        }
    }
    Ok(())
}

pub(super) fn trim(account: &mut LocalBusAccountState) {
    prune(&mut account.calls, &mut account.call_lru);
    prune(&mut account.pending_a2i, &mut account.a2i_lru);
}
fn touch(order: &mut VecDeque<String>, id: &str) {
    order.retain(|entry| entry != id);
    order.push_back(id.to_owned());
}
fn prune<T>(entries: &mut BTreeMap<String, T>, order: &mut VecDeque<String>) {
    order.retain(|id| entries.contains_key(id));
    for id in entries.keys() {
        if !order.contains(id) {
            order.push_back(id.clone());
        }
    }
    while entries.len() > CONTROL_CACHE_CAPACITY {
        let Some(id) = order.pop_front() else {
            break;
        };
        entries.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_control_views_have_a_fixed_lru_bound() {
        let mut entries = BTreeMap::new();
        let mut recent = VecDeque::new();
        for index in 0..256 {
            let id = index.to_string();
            entries.insert(id.clone(), index);
            touch(&mut recent, &id);
        }
        touch(&mut recent, "0");
        entries.insert("new".to_owned(), 256);
        prune(&mut entries, &mut recent);
        assert!(entries.contains_key("0"));
        assert!(!entries.contains_key("1"));
        assert_eq!(entries.len(), 256);
        assert_eq!(recent.len(), 256);
    }
}

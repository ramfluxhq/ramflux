// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Volatile authenticated receiver budgets, charged before pair decryption.
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

struct Bucket {
    tokens: u8,
    refill: Instant,
    last: Instant,
}
#[derive(Default)]
pub(super) struct ReceiverRates {
    conversations: BTreeMap<(String, String), Bucket>,
    roots: BTreeMap<String, VecDeque<Instant>>,
}
impl ReceiverRates {
    pub(super) fn admit(&mut self, root: &str, conversation: &str, now: Instant) -> bool {
        self.roots.retain(|_, events| {
            events.retain(|event| now.saturating_duration_since(*event) < Duration::from_secs(60));
            !events.is_empty()
        });
        self.conversations.retain(|_, bucket| {
            now.saturating_duration_since(bucket.last) < Duration::from_secs(60)
        });
        let key = (root.to_owned(), conversation.to_owned());
        if self.roots.get(root).is_some_and(|events| events.len() >= 30)
            || (!self.conversations.contains_key(&key)
                && self.conversations.len() >= super::MAX_DEDUP)
        {
            return false;
        }
        let bucket =
            self.conversations.entry(key).or_insert(Bucket { tokens: 6, refill: now, last: now });
        let added = now.saturating_duration_since(bucket.refill).as_secs() / 2;
        if added != 0 {
            bucket.tokens =
                bucket.tokens.saturating_add(u8::try_from(added.min(6)).unwrap_or(6)).min(6);
            let Some(refill) = bucket.refill.checked_add(Duration::from_secs(added * 2)) else {
                return false;
            };
            bucket.refill = refill;
        }
        if bucket.tokens == 0 {
            return false;
        }
        bucket.tokens -= 1;
        bucket.last = now;
        self.roots.entry(root.to_owned()).or_default().push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typing_rate_limits_are_per_peer_and_conversation() {
        let now = Instant::now();
        let mut rates = ReceiverRates::default();
        for _ in 0..6 {
            assert!(rates.admit("a", "one", now));
        }
        assert!(!rates.admit("a", "one", now));
        assert!(rates.admit("a", "two", now));
        assert!(rates.admit("b", "one", now));
        assert!(rates.admit("a", "one", now + Duration::from_secs(2)));
        assert!(!rates.admit("a", "one", now + Duration::from_secs(2)));
        let mut rates = ReceiverRates::default();
        for scope in 0..5 {
            for _ in 0..6 {
                assert!(rates.admit("a", &scope.to_string(), now));
            }
        }
        assert!(!rates.admit("a", "six", now));
        assert!(rates.admit("b", "six", now));
        assert!(rates.admit("a", "six", now + Duration::from_secs(60)));
    }
}

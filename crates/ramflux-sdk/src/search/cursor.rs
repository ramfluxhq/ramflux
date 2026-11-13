// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Volatile unpredictable cursors contain only keysets and scope fingerprints.
use ramflux_storage::local_search::{
    MAX_CURSORS, SearchError, SearchKind, SearchResult, SearchText, SearchViewEpoch,
};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub(super) struct Cursor {
    client: u64,
    account: String,
    query: [u8; 32],
    epoch: SearchViewEpoch,
    expires: Instant,
    pub kind: SearchKind,
    pub before: i64,
}
#[derive(Default)]
pub(super) struct Cursors(BTreeMap<SearchText, Cursor>);
impl Cursors {
    pub fn disconnect(&mut self, client: u64) {
        self.0.retain(|_, cursor| cursor.client != client);
    }
    pub fn clear(&mut self) {
        self.0.clear();
    }
    pub fn close(&mut self, client: u64, token: &str) {
        if self.0.get(token).is_some_and(|cursor| cursor.client == client) {
            self.0.remove(token);
        }
    }
    pub fn take(
        &mut self,
        client: u64,
        account: &str,
        query: [u8; 32],
        epoch: SearchViewEpoch,
        token: &str,
    ) -> SearchResult<(SearchKind, i64)> {
        let Some(cursor) = self.0.get(token) else { return Err(SearchError::CursorStale) };
        if cursor.client != client
            || cursor.account != account
            || cursor.query != query
            || cursor.epoch != epoch
            || Instant::now() >= cursor.expires
        {
            return Err(SearchError::CursorStale);
        }
        let position = (cursor.kind, cursor.before);
        self.0.remove(token);
        Ok(position)
    }
    pub fn insert(
        &mut self,
        client: u64,
        account: &str,
        query: [u8; 32],
        epoch: SearchViewEpoch,
        (kind, before): (SearchKind, i64),
    ) -> SearchResult<SearchText> {
        let now = Instant::now();
        self.0.retain(|_, cursor| cursor.expires > now);
        if self.0.values().filter(|cursor| cursor.client == client).count() >= MAX_CURSORS {
            return Err(SearchError::Capacity);
        }
        // IDs are bounded to 256 bytes; the eight entries are below the 32 KiB/client ceiling.
        if account.len() > 256 || self.0.len() >= 256 {
            return Err(SearchError::Capacity);
        }
        let token = SearchText::from(ramflux_protocol::encode_base64url(
            ramflux_crypto::random_32().map_err(ramflux_storage::StorageError::from)?,
        ));
        let expires =
            now.checked_add(Duration::from_secs(60)).ok_or(SearchError::IndexUnavailable)?;
        self.0.insert(
            token.clone(),
            Cursor { client, account: account.to_owned(), query, epoch, expires, kind, before },
        );
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_search_cursor_scope_capacity_and_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let mut cursors = Cursors::default();
        let epoch = SearchViewEpoch { unlock: 7, publication: 8, erasure: 9, index: 10 };
        let token = cursors.insert(1, "account", [4; 32], epoch, (SearchKind::Message, 42))?;
        assert_eq!(token.expose().len(), 43, "cursor must carry 256 unpredictable bits");
        assert!(
            matches!(
                cursors.take(2, "account", [4; 32], epoch, token.expose()),
                Err(SearchError::CursorStale)
            ),
            "cross-client cursor must be refused without consuming its owner's token"
        );
        let changed = SearchViewEpoch { index: 11, ..epoch };
        assert!(
            matches!(
                cursors.take(1, "account", [4; 32], changed, token.expose()),
                Err(SearchError::CursorStale)
            ),
            "changed source epoch must refuse cursor continuation"
        );
        assert_eq!(
            cursors.take(1, "account", [4; 32], epoch, token.expose())?,
            (SearchKind::Message, 42),
            "owner may resume only the exact query and epoch"
        );
        assert!(
            matches!(
                cursors.take(1, "account", [4; 32], epoch, token.expose()),
                Err(SearchError::CursorStale)
            ),
            "consumed cursors cannot be replayed"
        );
        for _ in 0..MAX_CURSORS {
            cursors.insert(1, "account", [4; 32], epoch, (SearchKind::Message, 42))?;
        }
        assert!(
            matches!(
                cursors.insert(1, "account", [4; 32], epoch, (SearchKind::Message, 42)),
                Err(SearchError::Capacity)
            ),
            "cursor capacity must be per client"
        );
        cursors.disconnect(1);
        let token = cursors.insert(1, "account", [4; 32], epoch, (SearchKind::Message, 42))?;
        cursors.0.get_mut(token.expose()).ok_or("cursor")?.expires = Instant::now();
        assert!(
            matches!(
                cursors.take(1, "account", [4; 32], epoch, token.expose()),
                Err(SearchError::CursorStale)
            ),
            "expired cursor must not retain a usable keyset"
        );
        Ok(())
    }
}

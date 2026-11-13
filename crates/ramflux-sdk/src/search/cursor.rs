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

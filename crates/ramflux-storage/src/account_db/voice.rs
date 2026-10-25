// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded public voice-call queries; media keys and credentials are never stored here.
use super::*;
impl AccountDb {
    /// Returns live calls or the most recent public call records, bounded before decoding.
    /// # Errors
    /// Returns SQL or public-row decoding errors.
    pub fn voice_call_rows(
        &self,
        live_only: bool,
    ) -> Result<Vec<ramflux_protocol::CallRow>, StorageError> {
        let mut query=self.connection.prepare("SELECT state_json FROM runtime_actor_state WHERE substr(state_kind,1,13)='voice/public/' AND (?1=0 OR json_extract(CAST(state_json AS TEXT),'$.state')!='ended') ORDER BY (json_extract(CAST(state_json AS TEXT),'$.state')='ended'),json_extract(CAST(state_json AS TEXT),'$.created_at') DESC,state_kind LIMIT 128")?;
        let rows = query.query_map(params![live_only], |r| r.get::<_, Vec<u8>>(0))?;
        rows.map(|bytes| Ok(serde_json::from_slice(&bytes?)?)).collect()
    }
}

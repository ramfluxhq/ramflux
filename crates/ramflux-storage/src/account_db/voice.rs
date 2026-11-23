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

    /// Replace one call-summary body without opening a second transaction.
    /// # Errors
    /// Refuses a missing or deleted projection, or a conversation mismatch.
    pub fn replace_call_summary_body(
        &self,
        conversation: &str,
        message: &str,
        body: &[u8],
    ) -> Result<(), StorageError> {
        let changed = self.connection.execute(
            "UPDATE direct_message_projection SET encrypted_body=?3 WHERE conversation_id=?1 AND message_id=?2 AND deleted=0",
            params![conversation, message, body],
        )?;
        if changed != 1 {
            return Err(StorageError::AuthorizationRejected);
        }
        self.replace_surface_message_content(conversation, message, body)
    }
}

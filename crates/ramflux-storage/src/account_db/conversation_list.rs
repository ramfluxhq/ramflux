#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use rusqlite::OptionalExtension;

impl AccountDb {
    pub fn set_conversation_archived(
        &self,
        conversation_id: &str,
        archived: bool,
    ) -> Result<(), StorageError> {
        self.ensure_conversation_list_state(conversation_id)?;
        self.connection.execute(
            "UPDATE conversation_list_state
                SET archived = ?2, updated_at = ?3
              WHERE conversation_id = ?1",
            params![conversation_id, i64::from(archived), self.now_unix()],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn pin_conversation(
        &self,
        conversation_id: &str,
        pin_order: i64,
    ) -> Result<(), StorageError> {
        self.ensure_conversation_list_state(conversation_id)?;
        self.connection.execute(
            "UPDATE conversation_list_state
                SET pin_order = ?2, updated_at = ?3
              WHERE conversation_id = ?1",
            params![conversation_id, pin_order, self.now_unix()],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn unpin_conversation(&self, conversation_id: &str) -> Result<(), StorageError> {
        self.ensure_conversation_list_state(conversation_id)?;
        self.connection.execute(
            "UPDATE conversation_list_state
                SET pin_order = NULL, updated_at = ?2
              WHERE conversation_id = ?1",
            params![conversation_id, self.now_unix()],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn mute_conversation(
        &self,
        conversation_id: &str,
        mute_until: i64,
    ) -> Result<(), StorageError> {
        self.ensure_conversation_list_state(conversation_id)?;
        self.connection.execute(
            "UPDATE conversation_list_state
                SET mute_until = ?2, updated_at = ?3
              WHERE conversation_id = ?1",
            params![conversation_id, mute_until, self.now_unix()],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn unmute_conversation(&self, conversation_id: &str) -> Result<(), StorageError> {
        self.ensure_conversation_list_state(conversation_id)?;
        self.connection.execute(
            "UPDATE conversation_list_state
                SET mute_until = NULL, updated_at = ?2
              WHERE conversation_id = ?1",
            params![conversation_id, self.now_unix()],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn hide_conversation_at(
        &self,
        conversation_id: &str,
        hidden_at: i64,
    ) -> Result<(), StorageError> {
        self.ensure_conversation_list_state(conversation_id)?;
        self.connection.execute(
            "UPDATE conversation_list_state
                SET hidden_at = ?2, updated_at = ?2
              WHERE conversation_id = ?1",
            params![conversation_id, hidden_at],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn clear_conversation_at(
        &self,
        conversation_id: &str,
        cleared_at: i64,
        _scope: &str,
    ) -> Result<(), StorageError> {
        self.ensure_conversation_list_state(conversation_id)?;
        self.connection.execute(
            "UPDATE conversation_list_state
                SET cleared_at = ?2, hidden_at = NULL, updated_at = ?2
              WHERE conversation_id = ?1",
            params![conversation_id, cleared_at],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn conversation_list_state(
        &self,
        conversation_id: &str,
    ) -> Result<ConversationListState, StorageError> {
        self.ensure_conversation_list_state(conversation_id)?;
        self.read_conversation_list_state(conversation_id)
    }

    pub(crate) fn ensure_conversation_list_state(
        &self,
        conversation_id: &str,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "INSERT OR IGNORE INTO conversation_list_state
                (conversation_id, archived, pin_order, mute_until, hidden_at, cleared_at, updated_at)
             VALUES (?1, 0, NULL, NULL, NULL, NULL, ?2)",
            params![conversation_id, self.now_unix()],
        )?;
        Ok(())
    }

    pub(crate) fn read_conversation_list_state(
        &self,
        conversation_id: &str,
    ) -> Result<ConversationListState, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT conversation_id, archived, pin_order, mute_until, hidden_at, cleared_at
                   FROM conversation_list_state
                  WHERE conversation_id = ?1",
                params![conversation_id],
                |row| {
                    Ok(ConversationListState {
                        conversation_id: row.get(0)?,
                        archived: row.get::<_, i64>(1)? != 0,
                        pin_order: row.get(2)?,
                        mute_until: row.get(3)?,
                        hidden_at: row.get(4)?,
                        cleared_at: row.get(5)?,
                    })
                },
            )
            .optional()?
            .unwrap_or_else(|| ConversationListState {
                conversation_id: conversation_id.to_owned(),
                ..ConversationListState::default()
            }))
    }
}

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::conversation_helpers::has_unread_after_read;
use rusqlite::OptionalExtension;

impl AccountDb {
    pub fn mark_read(
        &self,
        conversation_id: &str,
        reader_id: &str,
        message_id: &str,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "INSERT INTO conversation_read_state
                (conversation_id, reader_id, read_through_message_id, read_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(conversation_id, reader_id)
             DO UPDATE SET read_through_message_id = excluded.read_through_message_id,
                           read_at = excluded.read_at",
            params![conversation_id, reader_id, message_id, self.now_unix()],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn mark_delivered(
        &self,
        conversation_id: &str,
        receiver_device_id: &str,
        message_id: &str,
        delivered_at: i64,
        ttl_seconds: i64,
    ) -> Result<DeliveryReceiptRecord, StorageError> {
        let ttl_seconds = bounded_ttl_seconds(
            ttl_seconds,
            DEFAULT_DELIVERY_RECEIPT_TTL_SECONDS,
            MAX_DELIVERY_RECEIPT_TTL_SECONDS,
        );
        self.connection.execute(
            "INSERT INTO conversation_delivery_state
                (conversation_id, receiver_device_id, delivered_through_message_id, delivered_at, ttl_seconds)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(conversation_id, receiver_device_id)
             DO UPDATE SET delivered_through_message_id = excluded.delivered_through_message_id,
                           delivered_at = excluded.delivered_at,
                           ttl_seconds = excluded.ttl_seconds",
            params![conversation_id, receiver_device_id, message_id, delivered_at, ttl_seconds],
        )?;
        Ok(DeliveryReceiptRecord {
            conversation_id: conversation_id.to_owned(),
            receiver_device_id: receiver_device_id.to_owned(),
            delivered_through_message_id: message_id.to_owned(),
            delivered_at,
            ttl_seconds,
        })
    }

    /// # Errors
    /// Returns an error when expired receipt cleanup fails.
    pub fn expire_delivery_receipts(&self, now: i64) -> Result<usize, StorageError> {
        Ok(self.connection.execute(
            "DELETE FROM conversation_delivery_state
              WHERE delivered_at + ttl_seconds <= ?1",
            params![now],
        )?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn delivery_receipt(
        &self,
        conversation_id: &str,
        receiver_device_id: &str,
    ) -> Result<Option<DeliveryReceiptRecord>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT conversation_id, receiver_device_id, delivered_through_message_id,
                        delivered_at, ttl_seconds
                   FROM conversation_delivery_state
                  WHERE conversation_id = ?1 AND receiver_device_id = ?2",
                params![conversation_id, receiver_device_id],
                |row| {
                    Ok(DeliveryReceiptRecord {
                        conversation_id: row.get(0)?,
                        receiver_device_id: row.get(1)?,
                        delivered_through_message_id: row.get(2)?,
                        delivered_at: row.get(3)?,
                        ttl_seconds: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn set_unread_marker(
        &self,
        conversation_id: &str,
        marker_owner: &str,
        message_id: &str,
        marker_epoch: u64,
    ) -> Result<(), StorageError> {
        let marker_epoch =
            i64::try_from(marker_epoch).map_err(|_err| StorageError::AuthorizationRejected)?;
        self.connection.execute(
            "INSERT INTO conversation_unread_marker
                (conversation_id, marker_owner, message_id, marker_epoch, active, updated_at)
             VALUES (?1, ?2, ?3, ?4, 1, ?5)
             ON CONFLICT(conversation_id, marker_owner)
             DO UPDATE SET message_id = excluded.message_id,
                           marker_epoch = excluded.marker_epoch,
                           active = 1,
                           updated_at = excluded.updated_at",
            params![conversation_id, marker_owner, message_id, marker_epoch, self.now_unix()],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn clear_unread_marker(
        &self,
        conversation_id: &str,
        marker_owner: &str,
        marker_epoch: u64,
    ) -> Result<(), StorageError> {
        let marker_epoch =
            i64::try_from(marker_epoch).map_err(|_err| StorageError::AuthorizationRejected)?;
        self.connection.execute(
            "INSERT INTO conversation_unread_marker
                (conversation_id, marker_owner, message_id, marker_epoch, active, updated_at)
             VALUES (?1, ?2, '', ?3, 0, ?4)
             ON CONFLICT(conversation_id, marker_owner)
             DO UPDATE SET marker_epoch = excluded.marker_epoch,
                           active = 0,
                           updated_at = excluded.updated_at",
            params![conversation_id, marker_owner, marker_epoch, self.now_unix()],
        )?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn conversation_projection(
        &self,
        conversation_id: &str,
        reader_id: &str,
    ) -> Result<ConversationProjection, StorageError> {
        let list_state = self.read_conversation_list_state(conversation_id)?;
        let cleared_at = list_state.cleared_at.unwrap_or(i64::MIN);
        let message_count = self.connection.query_row(
            "SELECT COUNT(*)
               FROM direct_message_projection
              WHERE conversation_id = ?1 AND deleted = 0 AND created_at > ?2",
            params![conversation_id, cleared_at],
            |row| row.get::<_, u64>(0),
        )?;
        let last_message_id = self
            .connection
            .query_row(
                "SELECT message_id
                   FROM direct_message_projection
                  WHERE conversation_id = ?1 AND deleted = 0 AND created_at > ?2
                  ORDER BY created_at DESC, message_id DESC
                  LIMIT 1",
                params![conversation_id, cleared_at],
                |row| row.get(0),
            )
            .optional()?;
        let last_message_created_at = self
            .connection
            .query_row(
                "SELECT created_at
                   FROM direct_message_projection
                  WHERE conversation_id = ?1 AND deleted = 0
                  ORDER BY created_at DESC, message_id DESC
                  LIMIT 1",
                params![conversation_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let read_through_message_id = self
            .connection
            .query_row(
                "SELECT read_through_message_id
                   FROM conversation_read_state
                  WHERE conversation_id = ?1 AND reader_id = ?2",
                params![conversation_id, reader_id],
                |row| row.get(0),
            )
            .optional()?;
        let delivered_through_message_id = self
            .connection
            .query_row(
                "SELECT delivered_through_message_id
                   FROM conversation_delivery_state
                  WHERE conversation_id = ?1 AND receiver_device_id = ?2",
                params![conversation_id, reader_id],
                |row| row.get(0),
            )
            .optional()?;
        let manual_unread_message_id = self
            .connection
            .query_row(
                "SELECT message_id
                   FROM conversation_unread_marker
                  WHERE conversation_id = ?1 AND marker_owner = ?2 AND active = 1",
                params![conversation_id, reader_id],
                |row| row.get(0),
            )
            .optional()?;
        let is_unread = manual_unread_message_id.is_some()
            || has_unread_after_read(
                &self.connection,
                conversation_id,
                read_through_message_id.as_deref(),
            )?;
        Ok(ConversationProjection {
            conversation_id: conversation_id.to_owned(),
            message_count,
            last_message_id,
            read_through_message_id,
            delivered_through_message_id,
            manual_unread_message_id,
            is_unread,
            is_archived: list_state.archived,
            pin_order: list_state.pin_order,
            mute_until: list_state.mute_until,
            is_hidden: list_state.hidden_at.is_some_and(|hidden_at| {
                last_message_created_at.is_none_or(|created_at| created_at <= hidden_at)
            }),
            cleared_at: list_state.cleared_at,
        })
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use rusqlite::OptionalExtension;

impl AccountDb {
    pub fn upsert_device_directory_entry(
        &self,
        device_id: &str,
        principal_commitment: &str,
        source: &str,
        verified_at: i64,
    ) -> Result<DeviceDirectoryRecord, StorageError> {
        self.connection.execute(
            "INSERT INTO device_directory
                (device_id, principal_commitment, source, verified_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(device_id) DO UPDATE SET
                principal_commitment = excluded.principal_commitment,
                source = excluded.source,
                verified_at = excluded.verified_at",
            params![device_id, principal_commitment, source, verified_at],
        )?;
        self.device_directory_entry(device_id)?
            .ok_or_else(|| StorageError::Sqlite(rusqlite::Error::QueryReturnedNoRows))
    }

    pub fn device_directory_entry(
        &self,
        device_id: &str,
    ) -> Result<Option<DeviceDirectoryRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT device_id, principal_commitment, source, verified_at
                   FROM device_directory
                  WHERE device_id = ?1",
                params![device_id],
                |row| {
                    Ok(DeviceDirectoryRecord {
                        device_id: row.get(0)?,
                        principal_commitment: row.get(1)?,
                        source: row.get(2)?,
                        verified_at: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }
}

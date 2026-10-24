// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified directory entries retain independent addresses for equal names under different roots.
use super::*;
impl AccountDb {
    pub fn upsert_device_directory_entry(
        &self,
        device_id: &str,
        principal_commitment: &str,
        source: &str,
        verified_at: i64,
    ) -> Result<DeviceDirectoryRecord, StorageError> {
        let address = ramflux_protocol::qualified_device_id(principal_commitment, device_id)?;
        self.connection.execute("INSERT INTO device_directory(device_id,principal_commitment,source,verified_at,raw_device_id) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(device_id) DO UPDATE SET source=excluded.source,verified_at=excluded.verified_at,raw_device_id=excluded.raw_device_id",params![address,principal_commitment,source,verified_at,device_id])?;
        self.connection.execute("DELETE FROM device_directory WHERE device_id=?1 AND principal_commitment=?2 AND device_id<>?3 AND COALESCE(raw_device_id,device_id)=?1",params![device_id,principal_commitment,address])?;
        self.device_directory_entry(&address)?.ok_or(StorageError::AuthorizationRejected)
    }
    pub fn device_directory_entry(
        &self,
        device_id: &str,
    ) -> Result<Option<DeviceDirectoryRecord>, StorageError> {
        let qualified = ramflux_protocol::parse_qualified_device_id(device_id)?;
        let (root, raw) = qualified
            .as_ref()
            .map_or((None, device_id), |(root, raw)| (Some(root.as_str()), raw.as_str()));
        let mut statement=self.connection.prepare("SELECT device_id,principal_commitment,source,verified_at,raw_device_id FROM device_directory WHERE COALESCE(raw_device_id,device_id)=?2 AND (?3 IS NULL OR principal_commitment=?3) AND (?1 IS NOT NULL) ORDER BY device_id DESC LIMIT 3")?;
        let rows = statement
            .query_map(params![device_id, raw, root], |row| {
                Ok(DeviceDirectoryRecord {
                    device_id: row.get::<_, Option<String>>(4)?.unwrap_or(row.get(0)?),
                    principal_commitment: row.get(1)?,
                    source: row.get(2)?,
                    verified_at: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows
            .iter()
            .map(|row| &row.principal_commitment)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            > 1
        {
            return Err(StorageError::AmbiguousDeviceId(device_id.into()));
        }
        Ok(rows.into_iter().next())
    }
}

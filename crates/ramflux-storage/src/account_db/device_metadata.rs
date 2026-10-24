// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device metadata is keyed by root and literal device name; bare reads must be unambiguous.
use super::AccountDb;
use crate::StorageError;
use rusqlite::params;
use serde_json::{Value, json};
impl AccountDb {
    pub(super) fn device_record(&self, address: &str) -> Result<Option<Value>, StorageError> {
        if let Some((root, device)) = ramflux_protocol::parse_qualified_device_id(address)? {
            if let Some(row) = self.load_actor_state(&format!("directory/device/{address}"))? {
                return Ok(Some(row).filter(|row: &Value| {
                    row["principal_commitment"] == root && row["device_id"] == device
                }));
            }
            // Historical rows are metadata only. Never assign a row to a different root.
            return Ok(self
                .load_actor_state::<Value>(&format!("directory/device/{device}"))?
                .filter(|row| row["principal_commitment"] == root));
        }
        if address.starts_with("legacy~") {
            let row = self.load_actor_state::<Value>(&format!("directory/device/{address}"))?;
            if row
                .as_ref()
                .is_some_and(|row| row["principal_commitment"].as_str().is_none_or(str::is_empty))
            {
                return Ok(row);
            }
        }
        self.client_device_record_by_name(address)
    }
    /// Read a literal raw name; multiple roots return an explicit ambiguity error.
    /// # Errors
    /// Returns ambiguity, SQL or decoding errors.
    pub fn client_device_record_by_name(
        &self,
        address: &str,
    ) -> Result<Option<Value>, StorageError> {
        let exact = format!("directory/device/{address}");
        let mut statement=self.connection.prepare("SELECT state_json FROM runtime_actor_state WHERE state_kind GLOB 'directory/device/*' AND (json_extract(CAST(state_json AS TEXT),'$.device_id')=?2 OR (state_kind=?1 AND json_extract(CAST(state_json AS TEXT),'$.device_id') IS NULL)) ORDER BY state_kind DESC LIMIT 3")?;
        let rows = statement
            .query_map(params![exact, address], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut rows = rows
            .iter()
            .map(|bytes| serde_json::from_slice::<Value>(bytes))
            .collect::<Result<Vec<_>, _>>()?;
        if rows
            .iter()
            .any(|row| row["principal_commitment"].as_str().is_some_and(|root| !root.is_empty()))
        {
            rows.retain(|row| {
                row["principal_commitment"].as_str().is_some_and(|root| !root.is_empty())
            });
        }
        if rows
            .iter()
            .map(|row| row["principal_commitment"].as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            > 1
        {
            return Err(StorageError::AmbiguousDeviceId(address.into()));
        }
        Ok(rows.into_iter().next())
    }
    pub(super) fn persist_device_metadata(
        &self,
        id: &str,
        value: &Value,
    ) -> Result<(), StorageError> {
        if !value.is_object() {
            return Err(StorageError::AuthorizationRejected);
        }
        let Some(root) = value["principal_commitment"].as_str().filter(|root| !root.is_empty())
        else {
            // Retain legacy read-model rows; authority code never trusts them without a signed set.
            let raw = value["device_id"].as_str().unwrap_or(id);
            let mut row = value.clone();
            row["device_id"] = json!(raw);
            return self.persist_actor_state(
                &format!(
                    "directory/device/{}",
                    crate::schema_device_namespace::legacy_address(raw)
                ),
                &row,
            );
        };
        let device = value["device_id"].as_str().unwrap_or(id).to_owned();
        let address = ramflux_protocol::qualified_device_id(root, &device)?;
        let mut row = value.clone();
        row["device_id"] = json!(device);
        row["qualified_device_id"] = json!(address);
        self.write_transaction(|| {
            self.persist_actor_state(&format!("directory/device/{address}"), &row)?;
            let legacy = format!("directory/device/{device}");
            if legacy != format!("directory/device/{address}")
                && self.load_actor_state::<Value>(&legacy)?.is_some_and(|row| {
                    row["principal_commitment"] == root
                        && row["device_id"].as_str().is_none_or(|raw| raw == device)
                })
            {
                self.remove_actor_state(&legacy)?;
            }
            Ok::<_, StorageError>(())
        })
    }
}

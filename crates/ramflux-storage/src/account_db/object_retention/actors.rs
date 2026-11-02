// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Register object-bearing actor and retry copies before they become visible.
use super::*;

impl AccountDb {
    pub(crate) fn guard_object_actor(&self, key: &str, value: &Value) -> Result<(), StorageError> {
        if !(key.starts_with("attachment/")
            || key.starts_with("directory/object/")
            || key.starts_with("sync/attachment/"))
        {
            return Ok(());
        }
        if let Some(reference) = value.get("reference") {
            if let (Some(wire), Some(manifest)) = (
                reference.get("object_id").and_then(Value::as_str),
                reference.get("manifest_hash").and_then(Value::as_str),
            ) {
                self.check_object_identity(wire, manifest)?;
                let hash = ramflux_crypto::blake3_256_base64url(
                    "ramflux.attachment.reference.v1",
                    &ramflux_protocol::canonical_json_bytes(reference)?,
                );
                self.connection.execute("UPDATE object_retention_reference SET reference_json=?2 WHERE reference_hash=?1", params![hash,serde_json::to_vec(value)?])?;
            }
        }
        let selector = value
            .get("object_id")
            .and_then(Value::as_str)
            .or_else(|| {
                if key.starts_with("attachment/reference-by-") { value.as_str() } else { None }
            })
            .or_else(|| key.strip_prefix("directory/object/"));
        if let Some(selector) = selector {
            self.check_object_access(selector)?;
            self.connection.execute("INSERT INTO object_payload_actor SELECT p.commitment,?2 FROM object_retention_payload p WHERE p.wire_id=?1 UNION SELECT r.commitment,?2 FROM object_retention_reference r WHERE r.selector=?1 ON CONFLICT DO NOTHING", params![selector,key])?;
        }
        if let Some(chunk) = key.strip_prefix("attachment/chunk/") {
            if let Some((wire_manifest, _)) = chunk.rsplit_once('/')
                && let Some((wire, _)) = wire_manifest.rsplit_once('/')
            {
                self.check_object_access(wire)?;
                self.connection.execute("INSERT INTO object_payload_actor SELECT commitment,?2 FROM object_retention_payload WHERE wire_id=?1 ON CONFLICT DO NOTHING",params![wire,key])?;
            }
        }
        Ok(())
    }

    /// # Errors
    /// Registers a private alias against its exact authenticated reference.
    pub fn register_object_reference_actor(
        &self,
        reference_hash: &str,
        key: &str,
    ) -> Result<(), StorageError> {
        self.connection.execute("INSERT INTO object_reference_actor SELECT reference_hash,?2 FROM object_retention_reference WHERE reference_hash=?1 ON CONFLICT DO NOTHING", params![reference_hash,key])?;
        Ok(())
    }

    pub(crate) fn register_object_response(
        &self,
        operation: &str,
        response: &Value,
    ) -> Result<(), StorageError> {
        let encoded = serde_json::to_string(response)?;
        let mut q = self.connection.prepare(
            "SELECT DISTINCT value FROM json_tree(?1) WHERE key='object_id' AND type='text'",
        )?;
        let ids = q
            .query_map(params![encoded], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for id in ids {
            self.check_object_access(&id)?;
            self.connection.execute("INSERT INTO object_runtime_response SELECT commitment,?2 FROM object_retention_payload WHERE wire_id=?1 UNION SELECT commitment,?2 FROM object_retention_reference WHERE selector=?1 ON CONFLICT DO NOTHING", params![id,operation])?;
        }
        Ok(())
    }
}

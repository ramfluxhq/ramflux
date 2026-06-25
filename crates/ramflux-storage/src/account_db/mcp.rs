#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use rusqlite::OptionalExtension;
use serde::Serialize;
use serde::de::DeserializeOwned;

impl AccountDb {
    pub fn upsert_mcp_grant<T>(&self, write: &McpGrantWrite<'_, T>) -> Result<(), StorageError>
    where
        T: Serialize,
    {
        self.connection.execute(
            "INSERT OR REPLACE INTO mcp_grant (
                grant_id, target_ai_device_id, source_app_device_id, capability, risk_level,
                mcp_registry_hash, tool_manifest_set_hash, expires_at, signature, created_at,
                grant_body, revoked
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                write.grant_id,
                write.target_ai_device_id,
                write.source_app_device_id,
                write.capability,
                write.risk_level,
                write.registry_hash.as_bytes(),
                write.tool_manifest_set_hash.as_bytes(),
                write.expires_at,
                write.signature.as_bytes(),
                write.created_at,
                serde_json::to_vec(write.grant)?,
                i64::from(write.revoked)
            ],
        )?;
        Ok(())
    }

    pub fn set_mcp_grant_revoked(&self, grant_id: &str) -> Result<(), StorageError> {
        let grant_body = self
            .connection
            .query_row(
                "SELECT grant_body FROM mcp_grant WHERE grant_id = ?1",
                params![grant_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let Some(grant_body) = grant_body else {
            return Ok(());
        };
        let mut body: serde_json::Value = serde_json::from_slice(&grant_body)?;
        if let Some(state) = body.get_mut("state").and_then(serde_json::Value::as_object_mut) {
            state.insert("revoked".to_owned(), serde_json::Value::Bool(true));
        }
        if let Some(object) = body.as_object_mut() {
            object.insert("revoked".to_owned(), serde_json::Value::Bool(true));
        }
        self.connection.execute(
            "UPDATE mcp_grant SET revoked = 1, grant_body = ?2 WHERE grant_id = ?1",
            params![grant_id, serde_json::to_vec(&body)?],
        )?;
        Ok(())
    }

    pub fn load_mcp_grants<T>(&self) -> Result<BTreeMap<String, T>, StorageError>
    where
        T: DeserializeOwned,
    {
        let mut statement = self.connection.prepare(
            "SELECT grant_id, grant_body
               FROM mcp_grant
              WHERE grant_body IS NOT NULL
              ORDER BY grant_id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            let grant_id: String = row.get(0)?;
            let body: Vec<u8> = row.get(1)?;
            Ok((grant_id, body))
        })?;
        let mut grants = BTreeMap::new();
        for row in rows {
            let (grant_id, body) = row?;
            grants.insert(grant_id, serde_json::from_slice(&body)?);
        }
        Ok(grants)
    }

    pub fn append_mcp_audit<T>(&self, write: &McpAuditWrite<'_, T>) -> Result<(), StorageError>
    where
        T: Serialize,
    {
        let next_id: i64 = self.connection.query_row(
            "SELECT COUNT(*) + 1 FROM audit_log WHERE audit_type LIKE 'mcp.%'",
            [],
            |row| row.get(0),
        )?;
        let audit_id = format!("mcp_audit_{}_{}", write.created_at, next_id);
        self.connection.execute(
            "INSERT INTO audit_log (
                audit_id, audit_type, actor_device_id, subject_hash, redacted_summary, created_at,
                audit_body
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                audit_id,
                write.audit_type,
                write.actor_device_id,
                write.subject_hash,
                write.redacted_summary,
                write.created_at,
                serde_json::to_vec(write.audit)?
            ],
        )?;
        Ok(())
    }

    pub fn load_mcp_audit<T>(&self) -> Result<Vec<T>, StorageError>
    where
        T: DeserializeOwned,
    {
        let mut statement = self.connection.prepare(
            "SELECT audit_body
               FROM audit_log
              WHERE audit_type LIKE 'mcp.%' AND audit_body IS NOT NULL
              ORDER BY created_at ASC, audit_id ASC",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut audit = Vec::new();
        for row in rows {
            audit.push(serde_json::from_slice(&row?)?);
        }
        Ok(audit)
    }

    pub fn upsert_mcp_tool<T>(&self, write: &McpToolWrite<'_, T>) -> Result<(), StorageError>
    where
        T: Serialize,
    {
        self.connection.execute(
            "INSERT OR REPLACE INTO mcp_server_registry (
                server_id, registry_hash, tool_manifest_set_hash, server_label, transport,
                endpoint_or_command_hash, server_public_key, trust_state, server_state,
                revocation_cursor, updated_at
             ) VALUES (?1, '', '', NULL, 'local_bus', '', NULL, 'trusted', 'active', NULL, ?2)",
            params![write.server_id, write.updated_at],
        )?;
        self.connection.execute(
            "INSERT OR REPLACE INTO mcp_tool_manifest (
                tool_manifest_hash, server_id, tool_name, manifest_body, required_capability,
                risk_level, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                write.tool_manifest_hash.as_bytes(),
                write.server_id,
                write.tool_name,
                serde_json::to_vec(write.manifest)?,
                write.required_capability,
                write.risk_level,
                write.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn remove_mcp_tool(&self, server_id: &str, tool_name: &str) -> Result<(), StorageError> {
        self.connection.execute(
            "DELETE FROM mcp_tool_manifest WHERE server_id = ?1 AND tool_name = ?2",
            params![server_id, tool_name],
        )?;
        Ok(())
    }

    pub fn load_mcp_tools<T>(&self) -> Result<Vec<T>, StorageError>
    where
        T: DeserializeOwned,
    {
        let mut statement = self.connection.prepare(
            "SELECT manifest_body
               FROM mcp_tool_manifest
              ORDER BY server_id ASC, tool_name ASC",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut tools = Vec::new();
        for row in rows {
            tools.push(serde_json::from_slice(&row?)?);
        }
        Ok(tools)
    }

    pub fn upsert_mcp_standing_approval<T>(
        &self,
        write: &McpStandingApprovalWrite<'_, T>,
    ) -> Result<(), StorageError>
    where
        T: Serialize,
    {
        self.connection.execute(
            "INSERT OR REPLACE INTO mcp_standing_approval (
                standing_approval_id, server_id, tool_name, capability, risk_level,
                mcp_registry_hash, tool_manifest_set_hash, expires_at, created_at,
                created_by_device_id, approval_body, revoked
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                write.standing_approval_id,
                write.server_id,
                write.tool_name,
                write.capability,
                write.risk_level,
                write.registry_hash.as_bytes(),
                write.tool_manifest_set_hash.as_bytes(),
                write.expires_at,
                write.created_at,
                write.created_by_device_id,
                serde_json::to_vec(write.approval)?,
                i64::from(write.revoked)
            ],
        )?;
        Ok(())
    }

    pub fn set_mcp_standing_approval_revoked(
        &self,
        standing_approval_id: &str,
    ) -> Result<(), StorageError> {
        let approval_body = self
            .connection
            .query_row(
                "SELECT approval_body FROM mcp_standing_approval WHERE standing_approval_id = ?1",
                params![standing_approval_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let Some(approval_body) = approval_body else {
            return Ok(());
        };
        let mut body: serde_json::Value = serde_json::from_slice(&approval_body)?;
        if let Some(object) = body.as_object_mut() {
            object.insert("revoked".to_owned(), serde_json::Value::Bool(true));
        }
        self.connection.execute(
            "UPDATE mcp_standing_approval
                SET revoked = 1, approval_body = ?2
              WHERE standing_approval_id = ?1",
            params![standing_approval_id, serde_json::to_vec(&body)?],
        )?;
        Ok(())
    }

    pub fn load_mcp_standing_approvals<T>(&self) -> Result<BTreeMap<String, T>, StorageError>
    where
        T: DeserializeOwned,
    {
        let mut statement = self.connection.prepare(
            "SELECT standing_approval_id, approval_body
               FROM mcp_standing_approval
              WHERE approval_body IS NOT NULL
              ORDER BY standing_approval_id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            let approval_id: String = row.get(0)?;
            let body: Vec<u8> = row.get(1)?;
            Ok((approval_id, body))
        })?;
        let mut approvals = BTreeMap::new();
        for row in rows {
            let (approval_id, body) = row?;
            approvals.insert(approval_id, serde_json::from_slice(&body)?);
        }
        Ok(approvals)
    }
}

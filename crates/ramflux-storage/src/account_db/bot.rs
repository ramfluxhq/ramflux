#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use super::*;
use rusqlite::OptionalExtension;

impl AccountDb {
    pub fn upsert_bot_trust_pin(&self, pin: &BotTrustPinRecord) -> Result<(), StorageError> {
        self.connection.execute(
            "INSERT OR REPLACE INTO bot_trust_pin (
                bot_identity_commitment, bot_public_key, signing_key_id, trust_source, pinned_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                pin.bot_identity_commitment,
                pin.bot_public_key,
                pin.signing_key_id,
                pin.trust_source,
                pin.pinned_at
            ],
        )?;
        Ok(())
    }

    pub fn bot_trust_pin(
        &self,
        bot_identity_commitment: &str,
    ) -> Result<Option<BotTrustPinRecord>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT bot_identity_commitment, bot_public_key, signing_key_id, trust_source, pinned_at
                   FROM bot_trust_pin
                  WHERE bot_identity_commitment = ?1",
                params![bot_identity_commitment],
                |row| {
                    Ok(BotTrustPinRecord {
                        bot_identity_commitment: row.get(0)?,
                        bot_public_key: row.get(1)?,
                        signing_key_id: row.get(2)?,
                        trust_source: row.get(3)?,
                        pinned_at: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn upsert_bot_manifest_cache(
        &self,
        manifest_hash: &str,
        manifest: &ramflux_protocol::BotManifest,
        manifest_body: &[u8],
        cached_at: i64,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "INSERT OR REPLACE INTO bot_manifest_cache (
                bot_identity_commitment, bot_manifest_hash, actor_type, display_name, home_node,
                owner_identity_commitment, hosting_model, capabilities_json, permissions_json,
                safety_disclosure_json, manifest_body, signature_by_bot_identity, expires_at, cached_at
             ) VALUES (?1, ?2, 'bot', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                manifest.bot_identity_commitment,
                manifest_hash.as_bytes(),
                manifest.display_name,
                manifest.home_node,
                manifest.owner_identity_commitment,
                serde_json::to_string(&manifest.hosting_model)?,
                serde_json::to_vec(&manifest.capabilities)?,
                serde_json::to_vec(&manifest.permissions)?,
                serde_json::to_vec(&manifest.safety_disclosure)?,
                manifest_body,
                manifest.signature_by_bot_identity.as_bytes(),
                manifest.expires_at,
                cached_at
            ],
        )?;
        Ok(())
    }

    pub fn upsert_bot_install_grant(
        &self,
        grant: &ramflux_protocol::BotInstallGrant,
        grant_hash: &str,
        grant_body: &[u8],
        consent_member_ids: &[String],
        created_at: i64,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "INSERT OR REPLACE INTO bot_install_grant (
                grant_id, bot_identity_commitment, bot_manifest_hash, installer_identity,
                installer_device_id, scope_json, conversation_id, group_id, expires_at,
                signature, revoked_at, revocation_event_id, created_at, grant_hash, grant_body,
                consent_member_ids_json, state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                       NULL, NULL, ?11, ?12, ?13, ?14, 'installed')",
            params![
                grant.grant_id,
                grant.bot_identity_commitment,
                grant.bot_manifest_hash.as_bytes(),
                grant.installer_identity,
                grant.installer_device_id,
                serde_json::to_vec(&grant.scope)?,
                grant.conversation_id,
                grant.group_id,
                grant.expires_at,
                grant.signature_by_installer_device.as_bytes(),
                created_at,
                grant_hash,
                grant_body,
                serde_json::to_vec(consent_member_ids)?
            ],
        )?;
        Ok(())
    }

    pub fn revoke_bot_install_grant(
        &self,
        bot_identity_commitment: &str,
        revoked_at: i64,
        revocation_event_id: &str,
    ) -> Result<(), StorageError> {
        self.connection.execute(
            "UPDATE bot_install_grant
                SET revoked_at = ?2, revocation_event_id = ?3, state = 'revoked'
              WHERE bot_identity_commitment = ?1",
            params![bot_identity_commitment, revoked_at, revocation_event_id],
        )?;
        Ok(())
    }

    pub fn bot_install_revoked(&self, bot_identity_commitment: &str) -> Result<bool, StorageError> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*)
               FROM bot_install_grant
              WHERE bot_identity_commitment = ?1 AND revoked_at IS NOT NULL",
            params![bot_identity_commitment],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn installed_bots(&self) -> Result<Vec<StoredBotInstallRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT g.bot_identity_commitment, g.bot_manifest_hash, g.grant_id, g.grant_hash,
                    'bot', p.trust_source, m.manifest_body, g.grant_body, g.scope_json,
                    g.consent_member_ids_json, g.state, g.revoked_at, g.revocation_event_id
               FROM bot_install_grant g
               JOIN bot_manifest_cache m ON m.bot_manifest_hash = g.bot_manifest_hash
               LEFT JOIN bot_trust_pin p ON p.bot_identity_commitment = g.bot_identity_commitment
              WHERE g.grant_hash IS NOT NULL
                AND g.grant_body IS NOT NULL
                AND g.consent_member_ids_json IS NOT NULL
              ORDER BY g.bot_identity_commitment ASC, g.grant_id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            let scope_json: Vec<u8> = row.get(8)?;
            let consent_json: Vec<u8> = row.get(9)?;
            Ok(StoredBotInstallRecord {
                bot_identity_commitment: row.get(0)?,
                bot_manifest_hash: blob_to_string(&row.get::<_, Vec<u8>>(1)?),
                grant_id: row.get(2)?,
                grant_hash: row.get(3)?,
                actor_type: row.get(4)?,
                trust_source: row
                    .get::<_, Option<String>>(5)?
                    .unwrap_or_else(|| "unknown".to_owned()),
                manifest_body: row.get(6)?,
                grant_body: row.get(7)?,
                scope: serde_json::from_slice(&scope_json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        8,
                        rusqlite::types::Type::Blob,
                        Box::new(error),
                    )
                })?,
                consent_member_ids: serde_json::from_slice(&consent_json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        9,
                        rusqlite::types::Type::Blob,
                        Box::new(error),
                    )
                })?,
                state: row.get(10)?,
                revoked_at: row.get(11)?,
                revocation_event_id: row.get(12)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StorageError::from)
    }
}

fn blob_to_string(value: &[u8]) -> String {
    String::from_utf8_lossy(value).into_owned()
}

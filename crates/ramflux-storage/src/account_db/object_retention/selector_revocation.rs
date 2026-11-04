// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Missing-row revocation identity resolution, independent of display metadata.
use super::*;

fn agree(
    selected: &mut Option<(String, String)>,
    candidate: (String, String),
) -> Result<(), StorageError> {
    if candidate.0.is_empty()
        || candidate.1.is_empty()
        || candidate.1.bytes().all(|byte| byte == 0)
        || selected.as_ref().is_some_and(|identity| identity != &candidate)
    {
        return Err(StorageError::AuthorizationRejected);
    }
    *selected = Some(candidate);
    Ok(())
}

impl AccountDb {
    pub(in crate::account_db) fn resolve_revocation_manifest(
        &self,
        selector: &str,
        sender: Option<&str>,
        record: Option<&Value>,
    ) -> Result<String, StorageError> {
        let actor: Option<Value> =
            self.load_actor_state(&format!("attachment/reference/{selector}"))?;
        let mut selected = None;
        if let Some(reference) = actor.as_ref().and_then(|value| value.get("reference"))
            && let (Some(wire), Some(manifest)) =
                (reference["object_id"].as_str(), reference["manifest_hash"].as_str())
        {
            agree(&mut selected, (wire.to_owned(), manifest.to_owned()))?;
        }
        let mut query = self.connection.prepare(
            "SELECT p.wire_id,p.manifest_hash,m.message_id FROM object_retention_reference r
             JOIN object_retention_payload p USING(commitment)
             JOIN object_message_reference m USING(reference_hash) WHERE r.selector=?1",
        )?;
        let rows = query
            .query_map(params![selector], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut managed = false;
        for (wire, manifest, message) in rows {
            if self.message_is_deleted(&message)? {
                continue;
            }
            agree(&mut selected, (wire, manifest))?;
            managed = true;
        }
        // Display-only records cannot authorize creation. A legacy actor still
        // requires the same owner authorization as the authenticated control.
        if !managed
            && (selected.is_none()
                || sender.is_none()
                || record.and_then(|value| value["owner"].as_str()) != sender)
        {
            return Err(StorageError::AuthorizationRejected);
        }
        let (wire, manifest) = selected.ok_or(StorageError::AuthorizationRejected)?;
        if record
            .and_then(|value| value["manifest_hash"].as_str())
            .is_some_and(|display| display != manifest)
        {
            return Err(StorageError::AuthorizationRejected);
        }
        self.check_object_identity(&wire, &manifest)?;
        if !managed {
            self.enroll_legacy_revocation(selector, sender, &wire, &manifest)?;
        }
        Ok(manifest)
    }

    // Called only inside the missing-row creation transaction, after G2 agreement.
    fn enroll_legacy_revocation(
        &self,
        selector: &str,
        sender: Option<&str>,
        wire: &str,
        manifest: &str,
    ) -> Result<(), StorageError> {
        // Re-read the authorizing record under the account writer transaction.
        let record = self.client_record("object", selector)?;
        let record = record.as_ref().ok_or(StorageError::AuthorizationRejected)?;
        if sender.is_none() || record["owner"].as_str() != sender {
            return Err(StorageError::AuthorizationRejected);
        }
        let message = record["message_id"].as_str().ok_or(StorageError::AuthorizationRejected)?;
        if self.message_is_deleted(message)? {
            return Err(StorageError::AuthorizationRejected);
        }
        self.check_object_identity(wire, manifest)?;
        let locator = serde_json::json!({
            "selector": selector,
            "wire": wire,
            "manifest": manifest,
            "commitment": object_erasure_commitment(self.object_erasure_root(), wire, manifest),
            "selector_lookup": object_erasure_lookup(self.object_erasure_root(), selector),
        });
        self.connection.execute(
            "INSERT INTO message_copy_binding(copy_id,message_id) VALUES(?1,?2) ON CONFLICT DO NOTHING",
            params![format!("object:{selector}"), message],
        )?;
        self.connection.execute(
            "INSERT INTO message_footprint(message_id,kind,locator) VALUES(?1,'revocation_selector',?2) ON CONFLICT DO NOTHING",
            params![message, locator.to_string()],
        )?;
        for key in [
            format!("attachment/reference/{selector}"),
            format!("directory/object/{selector}"),
            format!("attachment/reference-by-slot/{selector}"),
        ] {
            self.connection.execute(
                "INSERT INTO message_footprint(message_id,kind,locator) VALUES(?1,'actor',?2) ON CONFLICT DO NOTHING",
                params![message, key],
            )?;
        }
        Ok(())
    }
}

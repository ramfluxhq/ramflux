// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Surface membership follows verified account roots across their authorized terminal devices.
use super::invalid;
use crate::{RamfluxClient, SdkError};
use serde_json::json;
impl RamfluxClient {
    pub(crate) fn surface_group_device_allowed(
        &self,
        group: &str,
        device: &str,
    ) -> Result<bool, SdkError> {
        let state = self.group_state(group)?;
        let db = self.account_db()?;
        let source = if let Some(source) = db.client_record("device", device)? {
            source
        } else {
            let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
            if device != local.device_id {
                return Ok(false);
            }
            json!({"principal_id":local.principal_id,"principal_commitment":self.surface_local_root_commitment()?,"signing_public_key":ramflux_protocol::encode_base64url(local.signing_key.verifying_key().to_bytes())})
        };
        if state.members.contains(device) {
            let key = db.group_member_device_key(group, device)?;
            return Ok(key.is_none_or(|key| source["signing_public_key"] == key));
        }
        let commitment = source["principal_commitment"]
            .as_str()
            .ok_or_else(|| invalid("surface sibling device root missing"))?;
        let routes = self.group_member_routes(group)?;
        for member in &state.members {
            let known = db.client_record("device", member)?;
            let same_root = known.as_ref().and_then(|v| v["principal_commitment"].as_str())
                == Some(commitment)
                || routes.iter().any(|r| {
                    r.member_id == *member
                        && r.member_principal_commitment.as_deref() == Some(commitment)
                });
            if same_root {
                if let (Some(record), Some(key)) =
                    (known, db.group_member_device_key(group, member)?)
                    && record["signing_public_key"] != key
                {
                    continue;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
}

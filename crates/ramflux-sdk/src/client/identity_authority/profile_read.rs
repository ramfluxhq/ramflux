// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Request-scoped profile verification and warning-only public-name collision lookup.
use super::{invalid, record_key};
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{ActorType, DeviceSetStatus, PrincipalKind, SignedDeviceSetRecord};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
/// Public profile facts authenticated by account authority; this is not a signed wire record.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct VerifiedIdentityProfile {
    pub principal_id: String,
    pub principal_commitment: String,
    pub kind: PrincipalKind,
    pub display_name: String,
    pub epoch: u64,
}
#[derive(Clone)]
pub(crate) struct VerifiedProfileFacts {
    pub profile: VerifiedIdentityProfile,
    active_devices: BTreeSet<String>,
}
impl VerifiedProfileFacts {
    pub(crate) fn matches_device(&self, device: &str) -> bool {
        if device.is_empty() {
            return true;
        }
        match ramflux_protocol::parse_qualified_device_id(device) {
            Ok(Some((root, raw))) => {
                root == self.profile.principal_commitment && self.active_devices.contains(&raw)
            }
            Ok(None) => self.active_devices.contains(device),
            Err(_) => false,
        }
    }
    pub(crate) fn matches_role(&self, device: &str, role: ActorType) -> bool {
        self.matches_device(device)
            && matches!(
                (role, self.profile.kind),
                (ActorType::Human, PrincipalKind::Human)
                    | (ActorType::Bot, PrincipalKind::Bot | PrincipalKind::HeadlessAi)
            )
    }
}
#[derive(Default)]
pub(crate) struct ProfileReadCache {
    records: BTreeMap<(String, [u8; 32]), Option<Arc<VerifiedProfileFacts>>>,
    names: Option<BTreeMap<String, Vec<String>>>,
    #[cfg(test)]
    checks: usize,
}
fn native_profile_facts(
    authority: &ramflux_crypto::custody::VerifiedRecord,
    principal: &str,
    commitment: &str,
) -> Result<VerifiedProfileFacts, SdkError> {
    let body = &authority.envelope().body;
    if body.principal_id != principal {
        return Err(invalid("native profile ownership mismatch"));
    }
    let now = crate::custody::network_now()?;
    let active_devices = body
        .devices
        .iter()
        .filter(|entry| {
            authority
                .authorize(
                    &ramflux_protocol::custody::DeviceRef {
                        account_anchor: commitment.into(),
                        device_id: entry.device_id.clone(),
                        device_epoch: entry.device_epoch,
                    },
                    "message",
                    now,
                )
                .is_ok()
        })
        .map(|entry| entry.device_id.clone())
        .collect();
    Ok(VerifiedProfileFacts {
        profile: VerifiedIdentityProfile {
            principal_id: principal.into(),
            principal_commitment: commitment.into(),
            kind: body.principal_kind,
            display_name: body.profile.display_name.clone(),
            epoch: body.device_set_epoch,
        },
        active_devices,
    })
}
type Slot = RefCell<Option<Box<ProfileReadCache>>>;
struct Scope<'a> {
    slot: &'a Slot,
    owner: bool,
}
impl Drop for Scope<'_> {
    fn drop(&mut self) {
        if self.owner {
            self.slot.replace(None);
        }
    }
}
impl RamfluxClient {
    // The callback is synchronous; no cache or borrow is retained across an await or request.
    pub(crate) fn with_profile_read_scope<T>(&self, read: impl FnOnce() -> T) -> T {
        let owner = self.profile_read_cache.borrow().is_none();
        if owner {
            self.profile_read_cache.replace(Some(Box::default()));
        }
        let _scope = Scope { slot: &self.profile_read_cache, owner };
        read()
    }
    pub(crate) fn verified_profile_facts(
        &self,
        principal: &str,
    ) -> Result<Option<Arc<VerifiedProfileFacts>>, SdkError> {
        let db = self.account_db()?;
        let Some(row) = db.client_record("identity", principal)? else { return Ok(None) };
        let Some(commitment) = row["contact_identity_commitment"].as_str() else { return Ok(None) };
        if let Some(authority) =
            self.current_custody_authority(commitment, crate::custody::network_now()?)?
        {
            return Ok(Some(Arc::new(native_profile_facts(&authority, principal, commitment)?)));
        }

        let Some(record) = db.load_actor_state::<SignedDeviceSetRecord>(&record_key(commitment))?
        else {
            return Ok(None);
        };
        if record.principal_id != principal || record.principal_commitment != commitment {
            return Err(invalid("profile cache ownership mismatch"));
        }
        let Some(profile) = record.profile.as_deref() else { return Ok(None) };
        let public = if let Some(root) =
            self.identity_root.as_ref().filter(|r| r.principal_id == principal)
        {
            root.signing_key.verifying_key()
        } else {
            let encoded = if let Some(manifest) = db
                .load_actor_state::<crate::prekey::SdkDeviceManifestResponse>(&format!(
                    "identity/manifest-root/{commitment}"
                ))? {
                manifest.root_public_key
            } else if let Some(key) =
                db.load_actor_state::<String>(&format!("identity/root_public/{commitment}"))?
            {
                key
            } else {
                return Ok(None);
            };
            ramflux_crypto::verifying_key_from_base64url(&encoded)?
        };
        // Include every encoded record byte and the actual verification key, not just an epoch
        // or an untrusted cached digest. A same-epoch substitution must miss this cache.
        let hash = ramflux_protocol::hash_base64url(
            "ramflux.sdk.profile_read_record.v1",
            &serde_json::to_vec(&record)?,
        );
        let key = (hash, public.to_bytes());
        if let Some(cached) = self
            .profile_read_cache
            .borrow()
            .as_ref()
            .and_then(|cache| cache.records.get(&key))
            .cloned()
        {
            return cached.map(Some).ok_or_else(|| invalid("cached profile authentication failed"));
        }
        let result = ramflux_crypto::verify_signed_device_set(&public, &record)
            .map(|()| {
                Arc::new(VerifiedProfileFacts {
                    profile: VerifiedIdentityProfile {
                        principal_id: profile.principal_id.clone(),
                        principal_commitment: profile.principal_commitment.clone(),
                        kind: profile.kind,
                        display_name: profile.display_name.clone(),
                        epoch: profile.epoch,
                    },
                    active_devices: record
                        .devices
                        .iter()
                        .filter(|d| d.status == DeviceSetStatus::Active)
                        .map(|d| d.device_id.clone())
                        .collect(),
                })
            })
            .map_err(SdkError::from);
        if let Some(cache) = self.profile_read_cache.borrow_mut().as_mut() {
            #[cfg(test)]
            {
                cache.checks += 1;
            }
            cache.records.insert(key, result.as_ref().ok().cloned());
        }
        result.map(Some)
    }
    pub(crate) fn read_profile_facts(&self, principal: &str) -> Option<Arc<VerifiedProfileFacts>> {
        match self.verified_profile_facts(principal) {
            Ok(facts) => facts,
            Err(error) => {
                tracing::debug!(principal,%error,"cached public profile is unverified");
                None
            }
        }
    }
    pub(crate) fn identity_name_warnings(
        &self,
        principal: &str,
        name: Option<&str>,
    ) -> Result<serde_json::Value, SdkError> {
        let Some(analysis) =
            name.and_then(|n| ramflux_protocol::profile_display_name_security(n).ok())
        else {
            return Ok(
                serde_json::json!({"display_name_confusable_with":null,"mixed_script":false}),
            );
        };
        let needs_index =
            self.profile_read_cache.borrow().as_ref().is_none_or(|cache| cache.names.is_none());
        let index = if needs_index { Some(self.public_name_index()?) } else { None };
        let mut slot = self.profile_read_cache.borrow_mut();
        let names = if let Some(cache) = slot.as_mut() {
            if let Some(index) = index {
                cache.names = Some(index);
            }
            cache.names.as_ref()
        } else {
            index.as_ref()
        };
        let other = names
            .and_then(|names| names.get(&analysis.confusable_skeleton))
            .and_then(|ids| ids.iter().find(|id| id.as_str() != principal))
            .cloned();
        Ok(
            serde_json::json!({"display_name_confusable_with":other,"mixed_script":analysis.mixed_script}),
        )
    }
    fn public_name_index(&self) -> Result<BTreeMap<String, Vec<String>>, SdkError> {
        let db = self.account_db()?;
        let mut names = BTreeMap::<String, Vec<String>>::new();
        let mut after = String::new();
        loop {
            let ids = db.client_directory_ids("identity", &after, 101)?;
            let done = ids.len() < 101;
            for id in ids {
                after.clone_from(&id);
                // These cached/local labels only cause warnings; they never grant verification.
                if let Ok(Some(row)) = db.client_record("identity", &id)
                    && let Some(analysis) = row["display_name"]
                        .as_str()
                        .and_then(|n| ramflux_protocol::profile_display_name_security(n).ok())
                {
                    names.entry(analysis.confusable_skeleton).or_default().push(id);
                }
            }
            if done {
                break;
            }
        }
        Ok(names)
    }
    #[cfg(test)]
    pub(crate) fn profile_read_verifications(&self) -> usize {
        self.profile_read_cache.borrow().as_ref().map_or(0, |cache| cache.checks)
    }
}

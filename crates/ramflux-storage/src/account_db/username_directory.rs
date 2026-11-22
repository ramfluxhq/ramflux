// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-signed directory/profile observation floors, distinct from contact acceptance pins.
use super::AccountDb;
use crate::StorageError;
use ramflux_protocol::username_directory::{self as w, DirectoryCode as Code};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

pub(super) const FLOOR_PREFIX: &str = "username/floor/";
pub(super) const NAME_PREFIX: &str = "username/name-pin/";
pub(super) const INTENT_PREFIX: &str = "username/intent/";
pub(super) const MAX_ROOTS: u64 = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum UsernameStorageError {
    #[error("username directory refused: {0:?}")]
    Refused(Code),
    #[error(transparent)]
    Storage(#[from] StorageError),
}
type Result<T> = std::result::Result<T, UsernameStorageError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsernameFloor {
    pub master_public_key: String,
    pub binding: Option<w::UsernameBinding>,
    pub operation: w::UsernameOperation,
    pub profile: w::SignedIdentityProfileV2,
    pub quarantined: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsernameNamePin {
    pub master_public_key: String,
    pub binding: w::UsernameBinding,
    pub conflicted: bool,
}

fn refused(code: Code) -> UsernameStorageError {
    UsernameStorageError::Refused(code)
}

impl UsernameFloor {
    /// Offline validation establishes signed historical restrictions, never present serving authority.
    /// # Errors
    /// Refuses substituted roots, invalid signatures, oversized records and avatars.
    pub fn validate(&self) -> Result<()> {
        let key = ramflux_crypto::verifying_key_from_base64url(&self.master_public_key)
            .map_err(|_| refused(Code::SignatureInvalid))?;
        ramflux_crypto::username_directory::verify_operation(&key, &self.operation)
            .map_err(|_| refused(Code::SignatureInvalid))?;
        if let Some(binding) = &self.binding {
            ramflux_crypto::username_directory::verify_binding(&key, binding)
                .map_err(|_| refused(Code::SignatureInvalid))?;
        }
        ramflux_crypto::username_directory::verify_profile(&key, &self.profile)
            .map_err(|_| refused(Code::SignatureInvalid))?;
        if self.operation.body.principal_commitment != self.profile.body.principal_commitment
            || self.operation.body.binding != self.binding
            || ramflux_crypto::identity_root_commitment(&key)
                != self.operation.body.principal_commitment
        {
            return Err(refused(Code::OwnershipMismatch));
        }
        if self.profile.body.avatar.is_some() {
            return Err(refused(Code::InvalidAvatar));
        }
        Ok(())
    }

    #[must_use]
    pub fn root(&self) -> &str {
        &self.operation.body.principal_commitment
    }

    /// # Errors
    /// Refuses regressions and equal-epoch substitutions; quarantine cannot be cleared by a read.
    pub fn admits(&self, candidate: &Self) -> Result<()> {
        candidate.validate()?;
        if self.quarantined || candidate.quarantined {
            return Err(refused(Code::ProfileEquivocation));
        }
        if self.root() != candidate.root() || self.master_public_key != candidate.master_public_key
        {
            return Err(refused(Code::KeyChanged));
        }
        if self.operation.body.action == w::Action::Delete && candidate.operation != self.operation
        {
            return Err(refused(Code::AccountDeleted));
        }
        if candidate.operation.body.next_epoch < self.operation.body.next_epoch
            || candidate.profile.body.epoch < self.profile.body.epoch
        {
            return Err(refused(Code::ProfileRollback));
        }
        if candidate.operation.body.next_epoch == self.operation.body.next_epoch
            && candidate.operation != self.operation
            || candidate.profile.body.epoch == self.profile.body.epoch
                && candidate.profile != self.profile
        {
            return Err(refused(Code::ProfileEquivocation));
        }
        Ok(())
    }

    /// Restore unions the two independent signed floors; equal-epoch disagreement is quarantined.
    /// This never imports a live permit, staged operation, contact acceptance or currentness claim.
    /// # Errors
    /// Refuses invalid evidence or root/key substitution.
    pub fn restriction_union(&self, incoming: &Self) -> Result<Self> {
        self.validate()?;
        incoming.validate()?;
        if self.root() != incoming.root() || self.master_public_key != incoming.master_public_key {
            return Err(refused(Code::KeyChanged));
        }
        let mut merged = self.clone();
        merged.quarantined |= incoming.quarantined
            || self.operation.body.next_epoch == incoming.operation.body.next_epoch
                && self.operation != incoming.operation
            || self.profile.body.epoch == incoming.profile.body.epoch
                && self.profile != incoming.profile;
        merged.quarantined |= self.operation.body.action == w::Action::Delete
            && incoming.operation.body.next_epoch >= self.operation.body.next_epoch
            && incoming.operation != self.operation
            || incoming.operation.body.action == w::Action::Delete
                && self.operation.body.next_epoch >= incoming.operation.body.next_epoch
                && self.operation != incoming.operation;
        if incoming.operation.body.next_epoch > self.operation.body.next_epoch {
            merged.binding.clone_from(&incoming.binding);
            merged.operation = incoming.operation.clone();
        }
        if incoming.profile.body.epoch > self.profile.body.epoch {
            merged.profile = incoming.profile.clone();
        }
        Ok(merged)
    }
}

impl UsernameNamePin {
    /// # Errors
    /// Refuses invalid root-signed name evidence.
    pub fn validate(&self) -> Result<()> {
        let key = ramflux_crypto::verifying_key_from_base64url(&self.master_public_key)
            .map_err(|_| refused(Code::SignatureInvalid))?;
        ramflux_crypto::username_directory::verify_binding(&key, &self.binding)
            .map_err(|_| refused(Code::SignatureInvalid))?;
        if ramflux_crypto::identity_root_commitment(&key) != self.binding.body.principal_commitment
        {
            return Err(refused(Code::OwnershipMismatch));
        }
        Ok(())
    }
}

pub(super) fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = ramflux_protocol::canonical_json_bytes(value)
        .map_err(|e| UsernameStorageError::Storage(StorageError::Protocol(e)))?;
    if bytes.len() > 8192 {
        return Err(refused(Code::Capacity));
    }
    Ok(bytes)
}

pub(super) fn decode_floor(bytes: &[u8]) -> Result<UsernameFloor> {
    if bytes.len() > 8192 {
        return Err(refused(Code::Capacity));
    }
    let floor: UsernameFloor = serde_json::from_slice(bytes)
        .map_err(|e| UsernameStorageError::Storage(StorageError::Serde(e)))?;
    floor.validate()?;
    if encode(&floor)? != bytes {
        return Err(refused(Code::ProfileEquivocation));
    }
    Ok(floor)
}

pub(super) fn decode_name(bytes: &[u8]) -> Result<UsernameNamePin> {
    if bytes.len() > 2048 {
        return Err(refused(Code::Capacity));
    }
    let pin: UsernameNamePin = serde_json::from_slice(bytes)
        .map_err(|e| UsernameStorageError::Storage(StorageError::Serde(e)))?;
    pin.validate()?;
    if encode(&pin)? != bytes {
        return Err(refused(Code::NameChanged));
    }
    Ok(pin)
}

impl AccountDb {
    /// # Errors
    /// Refuses malformed or unsigned stored evidence and unavailable storage.
    pub fn username_floor(&self, root: &str) -> Result<Option<UsernameFloor>> {
        let key = format!("{FLOOR_PREFIX}{root}");
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::from)?;
        let floor = bytes.as_deref().map(decode_floor).transpose()?;
        if floor.as_ref().is_some_and(|floor| floor.root() != root) {
            return Err(refused(Code::OwnershipMismatch));
        }
        Ok(floor)
    }

    /// Persist before exposing any verified profile preview; no automatic eviction at capacity.
    /// Caller has already verified a fresh pinned-centre resolve and current home response.
    /// # Errors
    /// Refuses rollback/equivocation, substituted roots, capacity and storage failures.
    pub fn observe_username(&self, floor: &UsernameFloor) -> Result<()> {
        floor.validate()?;
        self.join_write(|| {
            if let Some(old) = self.username_floor(floor.root())? { old.admits(floor)?; }
            else {
                let count: u64 = self.connection.query_row("SELECT count(*) FROM runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2",
                    params![FLOOR_PREFIX, "username/floor0"], |row| row.get(0)).map_err(StorageError::from)?;
                if count >= MAX_ROOTS { return Err(refused(Code::Capacity)); }
            }
            let bytes = encode(floor)?;
            self.connection.execute("INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json",
                params![format!("{FLOOR_PREFIX}{}", floor.root()), bytes]).map_err(StorageError::from)?;
            Ok(())
        })
    }

    /// # Errors
    /// Refuses malformed pins and unavailable storage.
    pub fn username_name_pin(&self, name: &str) -> Result<Option<UsernameNamePin>> {
        w::validate_username(name).map_err(|_| refused(Code::InvalidUsername))?;
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT state_json FROM runtime_actor_state WHERE state_kind=?1",
                params![format!("{NAME_PREFIX}{name}")],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::from)?;
        let pin = bytes.as_deref().map(decode_name).transpose()?;
        if pin.as_ref().is_some_and(|pin| pin.binding.body.name != name) {
            return Err(refused(Code::NameChanged));
        }
        Ok(pin)
    }

    /// Pin only on explicit Add. Historical name reuse never silently changes a known root.
    /// # Errors
    /// Refuses changed roots/conflicted names, invalid signed evidence and capacity/storage failures.
    pub fn pin_username_name(&self, pin: &UsernameNamePin) -> Result<()> {
        pin.validate()?;
        self.join_write(|| {
            let name = &pin.binding.body.name;
            if let Some(old) = self.username_name_pin(name)? {
                if old.conflicted || pin.conflicted || old.binding.body.principal_commitment != pin.binding.body.principal_commitment {
                    return Err(refused(Code::NameChanged));
                }
            } else {
                let count: u64 = self.connection.query_row("SELECT count(*) FROM runtime_actor_state WHERE state_kind>=?1 AND state_kind<?2",
                    params![NAME_PREFIX, "username/name-pin0"], |row| row.get(0)).map_err(StorageError::from)?;
                if count >= MAX_ROOTS { return Err(refused(Code::Capacity)); }
            }
            self.connection.execute("INSERT INTO runtime_actor_state(state_kind,state_json) VALUES(?1,?2) ON CONFLICT(state_kind) DO UPDATE SET state_json=excluded.state_json",
                params![format!("{NAME_PREFIX}{name}"), encode(pin)?]).map_err(StorageError::from)?;
            Ok(())
        })
    }
}

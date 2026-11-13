// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Certified everyday-signer directory records; profiles remain home-owned documents.
use super::{COMMAND_LIFETIME, actor, digest, invalid, lifetime, node, safe, text};
use crate::{
    ProtocolError,
    custody::{DeviceRef, Envelope as Signed},
    username_directory::{AvatarRef, ProfileKind, ReceiptState},
};
use serde::{Deserialize, Serialize};

pub const BINDING_DOMAIN: &str = "ramflux.identity.username_binding.v2";
pub const OPERATION_DOMAIN: &str = "ramflux.identity.username_operation.v2";
pub const PROFILE_DOMAIN: &str = "ramflux.identity.profile_certified.v1";
pub const RECEIPT_DOMAIN: &str = "ramflux.identity.username_receipt.v2";
pub const RESOLVE_DOMAIN: &str = "ramflux.identity.username_resolve.v2";
pub const BINDING_HASH_DOMAIN: &str = "ramflux.identity.username_binding_hash.v2";
pub const OPERATION_HASH_DOMAIN: &str = "ramflux.identity.username_operation_hash.v2";
pub const PROFILE_HASH_DOMAIN: &str = "ramflux.identity.profile_certified_hash.v1";
pub const RPC_DOMAIN: &str = "ramflux.identity.directory_rpc.v1";
pub const RPC_BODY_DOMAIN: &str = "ramflux.identity.directory_rpc_body.v1";
pub const CENTRE_ROTATION_DOMAIN: &str = "ramflux.identity.centre_rotation.v1";

fn name(value: &str) -> Result<(), ProtocolError> {
    crate::username_directory::validate_username(value)
        .map_err(|_| invalid("invalid exact username"))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub version: u32,
    pub name: String,
    pub home_node: String,
    pub account_anchor: String,
    pub epoch: u64,
    pub home_head_hash: String,
    pub authority_head_hash: String,
    pub master_certificate_hash: String,
    pub issued_at: u64,
}
impl Binding {
    /// Validate the certified binding body, without trusting its name mapping.
    /// # Errors
    /// Refuses malformed names, epochs, hashes or home ids.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        name(&self.name)?;
        node(&self.home_node)?;
        for d in [
            &self.account_anchor,
            &self.home_head_hash,
            &self.authority_head_hash,
            &self.master_certificate_hash,
        ] {
            digest(d)?;
        }
        safe(self.epoch)?;
        safe(self.issued_at)?;
        if self.version != 2 || self.epoch == 0 {
            return Err(invalid("binding version or epoch"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameAction {
    Claim,
    Rename,
    Release,
    SetVisibility,
    Delete,
    MoveHome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameOperation {
    pub version: u32,
    pub operation_id: String,
    pub account_anchor: String,
    pub home_head_hash: String,
    pub authority_head_hash: String,
    pub master_certificate_hash: String,
    pub actor: DeviceRef,
    pub action: NameAction,
    pub expected_epoch: u64,
    pub next_epoch: u64,
    pub old_name: Option<String>,
    pub binding: Option<Signed<Binding>>,
    pub discoverable: bool,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl NameOperation {
    /// Validate exact action fields and nested binding correlation.
    /// # Errors
    /// Refuses malformed epochs, contradictory nulls or mismatching bindings.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        for d in [
            &self.operation_id,
            &self.account_anchor,
            &self.home_head_hash,
            &self.authority_head_hash,
            &self.master_certificate_hash,
        ] {
            digest(d)?;
        }
        actor(&self.actor)?;
        safe(self.expected_epoch)?;
        safe(self.next_epoch)?;
        lifetime(self.issued_at, self.expires_at, COMMAND_LIFETIME)?;
        if self.version != 2 || self.expected_epoch.checked_add(1) != Some(self.next_epoch) {
            return Err(invalid("name operation version or epoch"));
        }
        if let Some(old) = &self.old_name {
            name(old)?;
        }
        if let Some(binding) = &self.binding {
            let b = &binding.body;
            b.validate()?;
            if b.account_anchor != self.account_anchor
                || b.epoch != self.next_epoch
                || b.home_head_hash != self.home_head_hash
                || b.authority_head_hash != self.authority_head_hash
                || b.master_certificate_hash != self.master_certificate_hash
                || b.issued_at != self.issued_at
            {
                return Err(invalid("name operation binding mismatch"));
            }
        }
        let valid = match self.action {
            NameAction::Claim => self.old_name.is_none() && self.binding.is_some(),
            NameAction::Rename => {
                self.old_name.is_some()
                    && self
                        .binding
                        .as_ref()
                        .is_some_and(|b| Some(&b.body.name) != self.old_name.as_ref())
            }
            NameAction::Release => {
                self.old_name.is_some() && self.binding.is_none() && !self.discoverable
            }
            NameAction::Delete => self.binding.is_none() && !self.discoverable,
            NameAction::SetVisibility | NameAction::MoveHome => {
                self.old_name.is_some()
                    && self
                        .binding
                        .as_ref()
                        .is_some_and(|b| Some(&b.body.name) == self.old_name.as_ref())
            }
        };
        if !valid {
            return Err(invalid("invalid name action fields"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub version: u32,
    pub account_anchor: String,
    pub principal_id: String,
    pub kind: ProfileKind,
    pub display_name: String,
    pub bio: String,
    pub avatar: Option<AvatarRef>,
    pub epoch: u64,
    pub discoverable: bool,
    pub deleted: bool,
    pub home_head_hash: String,
    pub authority_head_hash: String,
    pub master_certificate_hash: String,
    pub issued_at: u64,
}
impl Profile {
    /// Validate independent profile epochs, safe text and terminal deletion fields.
    /// # Errors
    /// Refuses oversized avatars/text, invalid identifiers and noncanonical bios.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        for d in [
            &self.account_anchor,
            &self.home_head_hash,
            &self.authority_head_hash,
            &self.master_certificate_hash,
        ] {
            digest(d)?;
        }
        if self.principal_id.is_empty()
            || self.principal_id.len() > 256
            || !self.principal_id.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(invalid("invalid profile principal"));
        }
        text(&self.display_name)?;
        if !crate::text_safety::single_line_is_safe(&self.display_name)
            || crate::username_directory::normalize_bio(&self.bio)
                .map_err(|_| invalid("invalid bio"))?
                != self.bio
        {
            return Err(invalid("invalid profile text"));
        }
        if let Some(avatar) = &self.avatar {
            digest(&avatar.content_hash)?;
            if avatar.size == 0 || avatar.size > 512 * 1024 || avatar.relay_ref.len() > 2048 {
                return Err(invalid("invalid avatar bounds"));
            }
        }
        safe(self.epoch)?;
        safe(self.issued_at)?;
        if self.version != 1
            || self.epoch == 0
            || self.deleted && (self.discoverable || !self.bio.is_empty() || self.avatar.is_some())
        {
            return Err(invalid("profile version, epoch or deleted fields"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexReceipt {
    pub version: u32,
    pub centre_id: String,
    pub operation_id: String,
    pub operation_hash: String,
    pub account_anchor: String,
    pub epoch: u64,
    pub state: ReceiptState,
    pub binding_hash: Option<String>,
    pub discoverable: bool,
    pub committed_at: u64,
    pub expires_at: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexResolve {
    pub version: u32,
    pub centre_id: String,
    pub name: String,
    pub home_node: String,
    pub account_anchor: String,
    pub epoch: u64,
    pub binding_hash: String,
    pub request_nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryAuth {
    pub version: u32,
    pub centre_id: String,
    pub node_id: String,
    pub method: String,
    pub path: String,
    pub body_hash: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CentrePin {
    pub centre_id: String,
    pub origin: String,
    pub key: String,
    pub epoch: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CentreManifest {
    pub version: u32,
    pub centres: Vec<CentrePin>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CentreRotationBody {
    pub version: u32,
    pub centre_id: String,
    pub origin: String,
    pub old_key: String,
    pub new_key: String,
    pub expected_epoch: u64,
    pub epoch: u64,
    pub issued_at: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CentreRotation {
    pub body: CentreRotationBody,
    pub old_signature: String,
    pub new_signature: String,
}

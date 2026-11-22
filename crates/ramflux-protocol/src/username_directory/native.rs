// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed detached JSON operations on an authenticated native gateway session.
use super::{
    DirectoryFailure, DirectoryReceipt, DirectoryResolve, SignedIdentityProfileV2, UsernameBinding,
    UsernameOperation,
};
use serde::{Deserialize, Serialize};

impl super::DirectoryCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "authentication_required",
            Self::InvalidUsername => "invalid_username",
            Self::InvalidProfile => "invalid_profile",
            Self::InvalidAvatar => "invalid_avatar",
            Self::UsernameTaken => "username_taken",
            Self::UsernameHeld => "username_held",
            Self::UsernameReserved => "username_reserved",
            Self::RateLimited => "rate_limited",
            Self::Capacity => "capacity",
            Self::DirectoryUnavailable => "directory_unavailable",
            Self::UnsupportedVersion => "unsupported_version",
            Self::OperationPending => "operation_pending",
            Self::StaleEpoch => "stale_epoch",
            Self::Replay => "replay",
            Self::OwnershipMismatch => "ownership_mismatch",
            Self::SignatureInvalid => "signature_invalid",
            Self::NotFound => "not_found",
            Self::KeyChanged => "key_changed",
            Self::NameChanged => "name_changed",
            Self::StaleProfile => "stale_profile",
            Self::ProfileRollback => "profile_rollback",
            Self::ProfileEquivocation => "profile_equivocation",
            Self::ProfileDowngrade => "profile_downgrade",
            Self::ClockUnsafe => "clock_unsafe",
            Self::MigrationRequired => "migration_required",
            Self::AccountDeleted => "account_deleted",
        }
    }
}

impl super::ProfileKind {
    /// Public profile classification follows native authority; workflows use the bot category.
    #[must_use]
    pub const fn from_principal_kind(kind: crate::PrincipalKind) -> Self {
        match kind {
            crate::PrincipalKind::Human => Self::Human,
            crate::PrincipalKind::HeadlessAi => Self::HeadlessAi,
            crate::PrincipalKind::Bot | crate::PrincipalKind::Workflow => Self::Bot,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeUsernameAction {
    Mutate { operation: Box<UsernameOperation>, profile: Box<SignedIdentityProfileV2> },
    Status { operation_id: Option<String> },
    Resolve { name: String, nonce: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDirectoryPin {
    pub url: String,
    pub id: String,
    pub public_key: String,
    pub generation: u64,
}

impl NativeDirectoryPin {
    /// # Errors
    /// Refuses noncanonical origins, malformed public identities and unsafe trust generations.
    pub fn validate(&self) -> Result<(), super::CodecError> {
        parse_directory_origin(&self.url)?;
        super::codec::node(&self.id)?;
        super::codec::fixed(&self.public_key, 32, "native_center_key")?;
        super::codec::need(
            self.generation > 0 && self.generation <= crate::MAX_SAFE_JSON_INTEGER,
            "native_center_generation",
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryOrigin {
    pub host: String,
    pub port: u16,
}

/// # Errors
/// Refuses noncanonical HTTPS origins, credentials, paths, queries and ambiguous IP literals.
pub fn parse_directory_origin(value: &str) -> Result<DirectoryOrigin, super::CodecError> {
    use super::{CodecError, codec::need};
    let authority = value.strip_prefix("https://").ok_or(CodecError::Field("origin_https"))?;
    need(!authority.is_empty() && authority.len() <= 259, "origin")?;
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']').ok_or(CodecError::Field("origin_host"))?;
        let ip: std::net::Ipv6Addr = host.parse().map_err(|_| CodecError::Field("origin_host"))?;
        need(ip.to_string() == host, "origin_host")?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or(CodecError::Field("origin_port"))?)
        };
        (host, port)
    } else {
        let (host, port) =
            authority.split_once(':').map_or((authority, None), |(h, p)| (h, Some(p)));
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            need(ip.to_string() == host, "origin_host")?;
        } else {
            need(!host.bytes().all(|b| b.is_ascii_digit() || b == b'.'), "origin_host")?;
            super::codec::node(host)?;
        }
        (host, port)
    };
    let port = if let Some(value) = port {
        let port: u16 = value.parse().map_err(|_| CodecError::Field("origin_port"))?;
        need(port != 0 && port.to_string() == value, "origin_port")?;
        port
    } else {
        443
    };
    Ok(DirectoryOrigin { host: host.into(), port })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeUsernameRequest {
    pub center: NativeDirectoryPin,
    pub declaration: Option<crate::home_migration::Signed<crate::home_migration::HomeDeclarationV1>>,
    pub action: NativeUsernameAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeUsernameState {
    Empty,
    Pending,
    Committed,
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeUsernameStatus {
    pub current_operation: Option<UsernameOperation>,
    pub operation_id: Option<String>,
    pub state: NativeUsernameState,
    pub binding: Option<UsernameBinding>,
    pub profile: Option<SignedIdentityProfileV2>,
    pub receipt: Option<DirectoryReceipt>,
    pub operation_receipt: Option<DirectoryReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeUsernameReply {
    Status {
        status: Box<NativeUsernameStatus>,
    },
    Resolved {
        operation: Box<UsernameOperation>,
        resolve: Box<DirectoryResolve>,
        binding: Box<UsernameBinding>,
        profile: Box<SignedIdentityProfileV2>,
        receipt: Box<DirectoryReceipt>,
        history: Box<crate::home_migration::ResolveResult>,
        nonce: String,
    },
    Refused {
        failure: DirectoryFailure,
    },
}

impl NativeUsernameRequest {
    /// # Errors
    /// Refuses oversized/native malformed records, remote name normalization and avatar payloads.
    pub fn validate(&self) -> Result<(), super::CodecError> {
        use super::{Wire, codec::need};
        need(crate::canonical_json_bytes(self)?.len() <= 16384, "native_request_size")?;
        self.center.validate()?;
        if let Some(declaration) = &self.declaration {
        let declaration = crate::canonical_json_bytes(declaration)?;
        crate::home_migration::decode::<
            crate::home_migration::Signed<crate::home_migration::HomeDeclarationV1>,
        >(&declaration, 8192)
        .map_err(|_| super::CodecError::Field("home_declaration"))?;
        }
        match &self.action {
            NativeUsernameAction::Mutate { operation, profile } => {
                operation.validate()?;
                profile.validate()?;
                need(profile.body.avatar.is_none(), "avatar_out_of_scope")?;
                need(
                    operation.body.principal_commitment == profile.body.principal_commitment
                        && self.declaration.as_ref().is_none_or(|d| d.body.account_anchor == operation.body.principal_commitment),
                    "native_root",
                )
            }
            NativeUsernameAction::Status { operation_id } => {
                if let Some(id) = operation_id {
                    super::codec::fixed(id, 32, "operation_id")?;
                }
                Ok(())
            }
            NativeUsernameAction::Resolve { name, nonce } => {
                super::validate_username(name)?;
                super::codec::fixed(nonce, 32, "nonce")
            }
        }
    }
}

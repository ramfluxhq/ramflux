// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed detached JSON operations on an authenticated native gateway session.
use super::{
    DirectoryFailure, DirectoryReceipt, DirectoryResolve, SignedIdentityProfileV2, UsernameBinding,
    UsernameOperation,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeUsernameAction {
    Mutate { operation: Box<UsernameOperation>, profile: Box<SignedIdentityProfileV2> },
    Status { operation_id: Option<String> },
    Resolve { name: String, nonce: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeUsernameRequest {
    pub declaration: crate::home_migration::Signed<crate::home_migration::HomeDeclarationV1>,
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
    pub operation_id: Option<String>,
    pub state: NativeUsernameState,
    pub binding: Option<UsernameBinding>,
    pub profile: Option<SignedIdentityProfileV2>,
    pub receipt: Option<DirectoryReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeUsernameReply {
    Status {
        status: Box<NativeUsernameStatus>,
    },
    Resolved {
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
        let declaration = crate::canonical_json_bytes(&self.declaration)?;
        crate::home_migration::decode::<
            crate::home_migration::Signed<crate::home_migration::HomeDeclarationV1>,
        >(&declaration, 8192)
        .map_err(|_| super::CodecError::Field("home_declaration"))?;
        match &self.action {
            NativeUsernameAction::Mutate { operation, profile } => {
                operation.validate()?;
                profile.validate()?;
                need(profile.body.avatar.is_none(), "avatar_out_of_scope")?;
                need(
                    operation.body.principal_commitment == self.declaration.body.account_anchor
                        && profile.body.principal_commitment
                            == self.declaration.body.account_anchor,
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

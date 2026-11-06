// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

/// Configuration refusals contain no caller-supplied values or secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LinuxVaultConfigError {
    /// Only explicitly supported backend names are accepted.
    #[error("unsupported Linux vault mode")]
    UnsupportedMode,
    /// Unattended roles cannot receive primary authority.
    #[error("primary credential is forbidden for this role")]
    PrimaryCredentialForbidden,
    /// Each systemd role must receive its exact credential set.
    #[error("incorrect Linux vault credential set")]
    CredentialSet,
    /// Credential arguments must be absolute paths, never inline key material.
    #[error("credential path must be absolute")]
    CredentialPath,
}

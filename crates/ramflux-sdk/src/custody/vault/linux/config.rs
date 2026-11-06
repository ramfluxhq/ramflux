// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::path::{Component, PathBuf};

use super::LinuxVaultConfigError;

/// Explicit backend choice; availability never changes the selected mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxVaultMode {
    /// Host-key wrapped systemd credentials; portable default for headless setup.
    SystemdHost,
    /// Host plus TPM2 wrapping, with no host-only downgrade.
    SystemdTpm2,
    /// Attended local Secret Service collection holding realm KEKs.
    DesktopSecretService,
}

impl LinuxVaultMode {
    /// Parse the closed configuration grammar without aliases or fallback.
    /// # Errors
    /// Rejects empty, unknown, padded and legacy backend names.
    pub fn parse(mode: &str) -> Result<Self, LinuxVaultConfigError> {
        match mode {
            "systemd-host" => Ok(Self::SystemdHost),
            "systemd-tpm2" => Ok(Self::SystemdTpm2),
            "desktop-secret-service" => Ok(Self::DesktopSecretService),
            _ => Err(LinuxVaultConfigError::UnsupportedMode),
        }
    }

    /// Honest persisted strength class; no hardware-nonexportability claim.
    #[must_use]
    pub const fn strength_class(self) -> &'static str {
        match self {
            Self::SystemdHost => "software_encrypted_file_systemd_host",
            Self::SystemdTpm2 => "software_encrypted_file_systemd_tpm2",
            Self::DesktopSecretService => "software_secret_service_wrapped_file",
        }
    }
}

/// Local process role, independent of account or branch enrollment authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxVaultRole {
    /// Explicit attended primary process, never the unattended service role.
    AttendedPrimary,
    /// rfd receives device and data realms only.
    Device,
    /// Agent host receives the data realm only.
    DataOnly,
}

/// Paths only. Secret bytes, environment values and command-line KEKs are unsupported.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinuxCredentialPaths {
    /// Attended primary credential, absent from unattended services.
    pub primary: Option<PathBuf>,
    /// Device signing/agreement credential, absent from agent host.
    pub device: Option<PathBuf>,
    /// Data-unlock credential.
    pub data: Option<PathBuf>,
}

/// Validated candidate configuration; constructing it does not activate a provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxVaultConfig {
    mode: LinuxVaultMode,
    role: LinuxVaultRole,
    credentials: LinuxCredentialPaths,
}

impl LinuxVaultConfig {
    /// Bind an explicit mode to the exact role-scoped credential paths.
    /// Desktop mode obtains its scoped KEKs from Secret Service, with no file fallback.
    /// # Errors
    /// Rejects unsupported modes, primary material in a service, incorrect realm sets
    /// and relative, duplicate, traversing or overlong credential paths. Provider availability is checked by later parts.
    pub fn new(
        mode: &str,
        role: LinuxVaultRole,
        credentials: LinuxCredentialPaths,
    ) -> Result<Self, LinuxVaultConfigError> {
        let mode = LinuxVaultMode::parse(mode)?;
        if role != LinuxVaultRole::AttendedPrimary && credentials.primary.is_some() {
            return Err(LinuxVaultConfigError::PrimaryCredentialForbidden);
        }
        let present = (
            credentials.primary.is_some(),
            credentials.device.is_some(),
            credentials.data.is_some(),
        );
        let expected = if mode == LinuxVaultMode::DesktopSecretService {
            (false, false, false)
        } else {
            match role {
                LinuxVaultRole::AttendedPrimary => (true, true, true),
                LinuxVaultRole::Device => (false, true, true),
                LinuxVaultRole::DataOnly => (false, false, true),
            }
        };
        if present != expected {
            return Err(LinuxVaultConfigError::CredentialSet);
        }
        let paths: Vec<_> = [&credentials.primary, &credentials.device, &credentials.data]
            .into_iter()
            .flatten()
            .collect();
        for (index, path) in paths.iter().enumerate() {
            if !path.is_absolute() {
                return Err(LinuxVaultConfigError::CredentialPath);
            }
            if path.as_os_str().as_encoded_bytes().contains(&0) {
                return Err(LinuxVaultConfigError::CredentialPathNul);
            }
            if path.as_os_str().as_encoded_bytes().len() > 4095 {
                return Err(LinuxVaultConfigError::CredentialPathLength);
            }
            if path.components().any(|part| part == Component::ParentDir) {
                return Err(LinuxVaultConfigError::CredentialPathTraversal);
            }
            if paths[..index].contains(path) {
                return Err(LinuxVaultConfigError::CredentialPathDuplicate);
            }
        }
        Ok(Self { mode, role, credentials })
    }

    /// Selected backend, unchanged by provider availability.
    #[must_use]
    pub const fn mode(&self) -> LinuxVaultMode {
        self.mode
    }
    /// Bound role; this does not prove current account authority.
    #[must_use]
    pub const fn role(&self) -> LinuxVaultRole {
        self.role
    }
    /// Path-only inputs for the selected backend.
    #[must_use]
    pub const fn credentials(&self) -> &LinuxCredentialPaths {
        &self.credentials
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(primary: bool, device: bool, data: bool) -> LinuxCredentialPaths {
        LinuxCredentialPaths {
            primary: primary.then(|| "/credentials/rf-primary-kek".into()),
            device: device.then(|| "/credentials/rf-device-kek".into()),
            data: data.then(|| "/credentials/rf-data-kek".into()),
        }
    }

    #[test]
    fn linux_vault_credentials_reject_duplicate_paths() {
        for pair in [(0, 1), (0, 2), (1, 2)] {
            let mut values = ["/primary".to_owned(), "/device".to_owned(), "/data".to_owned()];
            values[pair.1] = values[pair.0].clone();
            let supplied = LinuxCredentialPaths {
                primary: Some(values[0].clone().into()),
                device: Some(values[1].clone().into()),
                data: Some(values[2].clone().into()),
            };
            assert_eq!(
                LinuxVaultConfig::new("systemd-host", LinuxVaultRole::AttendedPrimary, supplied),
                Err(LinuxVaultConfigError::CredentialPathDuplicate)
            );
        }
    }
    #[test]
    fn linux_vault_credentials_reject_parent_components() {
        for field in 0..3 {
            let mut supplied = paths(true, true, true);
            let slot = match field {
                0 => &mut supplied.primary,
                1 => &mut supplied.device,
                _ => &mut supplied.data,
            };
            *slot = Some("/credentials/../rf-kek".into());
            assert_eq!(
                LinuxVaultConfig::new("systemd-host", LinuxVaultRole::AttendedPrimary, supplied),
                Err(LinuxVaultConfigError::CredentialPathTraversal)
            );
        }
    }
    #[test]
    fn linux_vault_credentials_reject_overlong_paths() -> Result<(), LinuxVaultConfigError> {
        for field in 0..3 {
            for length in [4095, 4096] {
                let mut supplied = paths(true, true, true);
                let slot = match field {
                    0 => &mut supplied.primary,
                    1 => &mut supplied.device,
                    _ => &mut supplied.data,
                };
                *slot = Some(format!("/{}", "x".repeat(length - 1)).into());
                let result = LinuxVaultConfig::new(
                    "systemd-host",
                    LinuxVaultRole::AttendedPrimary,
                    supplied,
                );
                if length == 4095 {
                    result?;
                } else {
                    assert_eq!(result, Err(LinuxVaultConfigError::CredentialPathLength));
                }
            }
        }
        Ok(())
    }

    fn assert_nul_path_rejected(realm: usize) {
        let mut supplied = paths(true, true, true);
        let slot = match realm {
            0 => &mut supplied.primary,
            1 => &mut supplied.device,
            _ => &mut supplied.data,
        };
        *slot = Some("/credentials/rf\0kek".into());
        assert_eq!(
            LinuxVaultConfig::new("systemd-host", LinuxVaultRole::AttendedPrimary, supplied),
            Err(LinuxVaultConfigError::CredentialPathNul),
            "realm index {realm}"
        );
    }
    #[test]
    fn linux_vault_credentials_reject_nul_primary_path() {
        assert_nul_path_rejected(0);
    }
    #[test]
    fn linux_vault_credentials_reject_nul_device_path() {
        assert_nul_path_rejected(1);
    }
    #[test]
    fn linux_vault_credentials_reject_nul_data_path() {
        assert_nul_path_rejected(2);
    }
    #[test]
    fn linux_vault_credentials_accept_path_at_length_cap() -> Result<(), LinuxVaultConfigError> {
        for realm in 0..3 {
            let cap = format!("/{}", "x".repeat(4094));
            assert_eq!(cap.len(), 4095);
            let mut supplied = paths(true, true, true);
            let slot = match realm {
                0 => &mut supplied.primary,
                1 => &mut supplied.device,
                _ => &mut supplied.data,
            };
            *slot = Some(cap.into());
            let config = LinuxVaultConfig::new(
                "systemd-host",
                LinuxVaultRole::AttendedPrimary,
                supplied.clone(),
            )?;
            assert_eq!(config.credentials(), &supplied, "realm index {realm}");
        }
        Ok(())
    }

    #[test]
    fn linux_vault_selection_rejects_invalid_modes() -> Result<(), LinuxVaultConfigError> {
        for mode in [
            "",
            "auto",
            "host",
            "memory",
            "file",
            "SYSTEMD-HOST",
            " systemd-host",
            "systemd-host ",
            "systemd-host\0",
            "systemd-tpm",
        ] {
            assert_eq!(
                LinuxVaultMode::parse(mode),
                Err(LinuxVaultConfigError::UnsupportedMode),
                "{mode:?}"
            );
            assert_eq!(
                LinuxVaultConfig::new(mode, LinuxVaultRole::Device, paths(false, true, true)),
                Err(LinuxVaultConfigError::UnsupportedMode)
            );
        }
        let roles =
            [LinuxVaultRole::AttendedPrimary, LinuxVaultRole::Device, LinuxVaultRole::DataOnly];
        for (name, expected) in [
            ("systemd-host", LinuxVaultMode::SystemdHost),
            ("systemd-tpm2", LinuxVaultMode::SystemdTpm2),
            ("desktop-secret-service", LinuxVaultMode::DesktopSecretService),
        ] {
            assert_eq!(LinuxVaultMode::parse(name), Ok(expected));
            for role in roles {
                for bits in 0..8 {
                    let supplied = paths(bits & 4 != 0, bits & 2 != 0, bits & 1 != 0);
                    let expected_bits = if expected == LinuxVaultMode::DesktopSecretService {
                        0
                    } else {
                        match role {
                            LinuxVaultRole::AttendedPrimary => 7,
                            LinuxVaultRole::Device => 3,
                            LinuxVaultRole::DataOnly => 1,
                        }
                    };
                    let result = LinuxVaultConfig::new(name, role, supplied.clone());
                    if role != LinuxVaultRole::AttendedPrimary && bits & 4 != 0 {
                        assert_eq!(result, Err(LinuxVaultConfigError::PrimaryCredentialForbidden));
                    } else if bits != expected_bits {
                        assert_eq!(result, Err(LinuxVaultConfigError::CredentialSet));
                    } else {
                        let config = result?;
                        assert_eq!(config.mode(), expected);
                        assert_eq!(config.role(), role);
                        assert_eq!(config.credentials(), &supplied);
                    }
                }
            }
        }
        for field in 0..3 {
            let mut supplied = paths(true, true, true);
            match field {
                0 => supplied.primary = Some("relative".into()),
                1 => supplied.device = Some("relative".into()),
                _ => supplied.data = Some("relative".into()),
            }
            assert_eq!(
                LinuxVaultConfig::new("systemd-host", LinuxVaultRole::AttendedPrimary, supplied),
                Err(LinuxVaultConfigError::CredentialPath)
            );
        }
        assert_eq!(
            LinuxVaultMode::SystemdHost.strength_class(),
            "software_encrypted_file_systemd_host"
        );
        assert_eq!(
            LinuxVaultMode::SystemdTpm2.strength_class(),
            "software_encrypted_file_systemd_tpm2"
        );
        assert_eq!(
            LinuxVaultMode::DesktopSecretService.strength_class(),
            "software_secret_service_wrapped_file"
        );
        Ok(())
    }
}

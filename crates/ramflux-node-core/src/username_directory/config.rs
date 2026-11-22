// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit provisioning inputs. Configuration alone never enables directory publication.
use super::{CheckpointError, Result, fixed, require};
use ed25519_dalek::VerifyingKey;
use std::path::{Component, Path, PathBuf};

const PREFIX: &str = "RAMFLUX_USERNAME_";
const INPUTS: &[&str] = &[
    "ROLE",
    "CENTER_URL",
    "CENTER_ID",
    "CENTER_PUBLIC_KEY",
    "CENTER_TLS_SERVER_NAME",
    "CENTER_CA_FILE",
    "TRUST_GENERATION",
    "PRIMARY_DB",
    "HOME_DB",
    "HOME_URL",
    "HOME_TLS_SERVER_NAME",
    "PRIVATE_PEERS_FILE",
    "LISTEN_ADDR",
    "WITNESS_DB",
    "WITNESS_SOCKET",
    "CENTER_UID",
    "WITNESS_UID",
];

/// Independently provisioned centre identity; TLS identity and signing identity are separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CenterPin {
    pub url: String,
    pub id: String,
    pub public_key: String,
    pub tls_server_name: String,
    pub ca_file: PathBuf,
    pub generation: u64,
}

impl CenterPin {
    #[must_use]
    pub fn public_identity(&self) -> ramflux_protocol::username_directory::NativeDirectoryPin {
        ramflux_protocol::username_directory::NativeDirectoryPin {
            url: self.url.clone(),
            id: self.id.clone(),
            public_key: self.public_key.clone(),
            generation: self.generation,
        }
    }
    /// # Errors
    /// Refuses incomplete pins, malformed HTTPS origins, weak keys and invalid generations.
    pub fn validate(&self) -> Result<()> {
        validate_node(&self.id)?;
        validate_node(&self.tls_server_name)?;
        validate_origin(&self.url)?;
        fixed(&self.public_key)?;
        let bytes: [u8; 32] = ramflux_protocol::decode_base64url(&self.public_key)
            .map_err(|_| CheckpointError::Refused("center_key"))?
            .try_into()
            .map_err(|_| CheckpointError::Refused("center_key"))?;
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| CheckpointError::Refused("center_key"))?;
        require(!key.is_weak(), "center_key")?;
        require(
            self.generation > 0 && self.generation <= ramflux_protocol::MAX_SAFE_JSON_INTEGER,
            "generation",
        )?;
        validate_path(&self.ca_file)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryRole {
    Home { database: PathBuf, service: HomeServiceConfig },
    Center { primary: PathBuf, witness: WitnessPeer },
    Witness { database: PathBuf, peer: WitnessPeer, listen: std::net::SocketAddr },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HomeServiceConfig {
    pub origin: String,
    pub tls_server_name: String,
    pub listen: std::net::SocketAddr,
    pub private_peers_file: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateHomePin {
    pub node: String,
    pub public_key: String,
    pub origin: String,
}

impl PrivateHomePin {
    /// # Errors
    /// Refuses malformed explicit private-network peer pins.
    pub fn validate(&self) -> Result<()> {
        validate_node(&self.node)?;
        validate_origin(&self.origin)?;
        fixed(&self.public_key)?;
        let key = ramflux_crypto::verifying_key_from_base64url(&self.public_key)
            .map_err(|_| CheckpointError::Refused("home_service_key"))?;
        require(!key.is_weak(), "home_service_key")
    }
}

/// UID pins are checked against socket peer credentials, never a request's claimed UID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessPeer {
    pub socket: PathBuf,
    pub center_uid: u32,
    pub witness_uid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryConfig {
    pub center: CenterPin,
    pub role: DirectoryRole,
}

impl DirectoryConfig {
    /// Read through the process's validated environment adapter.
    /// # Errors
    /// Refuses partial, blank, foreign-role or malformed provisioning.
    pub fn from_env() -> Result<Option<Self>> {
        let mut values = std::collections::BTreeMap::new();
        for suffix in INPUTS {
            let name = format!("{PREFIX}{suffix}");
            match crate::environment::var(&name) {
                Ok(value) => {
                    crate::environment::validate_input(&name, std::ffi::OsStr::new(&value))
                        .map_err(|_| CheckpointError::Refused("config_expression"))?;
                    values.insert(name, value);
                }
                Err(std::env::VarError::NotPresent) => {}
                Err(std::env::VarError::NotUnicode(_)) => {
                    return Err(CheckpointError::Refused("config_encoding"));
                }
            }
        }
        Self::from_values(|key| values.remove(key))
    }

    /// Pure adapter for explicit operator inputs; does not initialize storage or advertise routes.
    /// # Errors
    /// Refuses partial provisioning, cross-role fields, weak pins and unsafe path/UID shapes.
    pub fn from_values(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Option<Self>> {
        let mut values = std::collections::BTreeMap::new();
        for suffix in INPUTS {
            if let Some(value) = lookup(&format!("{PREFIX}{suffix}")) {
                require(!value.is_empty() && value.trim() == value, "config_value")?;
                values.insert(*suffix, value);
            }
        }
        if values.is_empty() {
            return Ok(None);
        }
        let private_peers_file = values.remove("PRIVATE_PEERS_FILE").map(PathBuf::from);
        if let Some(path) = &private_peers_file {
            validate_path(path)?;
        }
        let mut take =
            |key| values.remove(key).ok_or(CheckpointError::Refused("config_incomplete"));
        let role = take("ROLE")?;
        let center = CenterPin {
            url: take("CENTER_URL")?,
            id: take("CENTER_ID")?,
            public_key: take("CENTER_PUBLIC_KEY")?,
            tls_server_name: take("CENTER_TLS_SERVER_NAME")?,
            ca_file: PathBuf::from(take("CENTER_CA_FILE")?),
            generation: decimal(&take("TRUST_GENERATION")?)?,
        };
        center.validate()?;
        let role = match role.as_str() {
            "home" => {
                let origin = take("HOME_URL")?;
                let tls_server_name = take("HOME_TLS_SERVER_NAME")?;
                validate_origin(&origin)?;
                validate_node(&tls_server_name)?;
                let listen =
                    take("LISTEN_ADDR")?.parse().map_err(|_| CheckpointError::Refused("listen"))?;
                DirectoryRole::Home {
                    database: PathBuf::from(take("HOME_DB")?),
                    service: HomeServiceConfig {
                        origin,
                        tls_server_name,
                        listen,
                        private_peers_file: private_peers_file.clone(),
                    },
                }
            }
            "center" | "witness" => {
                let peer = WitnessPeer {
                    socket: PathBuf::from(take("WITNESS_SOCKET")?),
                    center_uid: u32::try_from(decimal(&take("CENTER_UID")?)?)
                        .map_err(|_| CheckpointError::Refused("uid"))?,
                    witness_uid: u32::try_from(decimal(&take("WITNESS_UID")?)?)
                        .map_err(|_| CheckpointError::Refused("uid"))?,
                };
                validate_path(&peer.socket)?;
                require(
                    peer.center_uid != 0
                        && peer.witness_uid != 0
                        && peer.center_uid != peer.witness_uid,
                    "uid_separation",
                )?;
                if role == "center" {
                    DirectoryRole::Center {
                        primary: PathBuf::from(take("PRIMARY_DB")?),
                        witness: peer,
                    }
                } else {
                    DirectoryRole::Witness {
                        database: PathBuf::from(take("WITNESS_DB")?),
                        peer,
                        listen: take("LISTEN_ADDR")?
                            .parse()
                            .map_err(|_| CheckpointError::Refused("listen"))?,
                    }
                }
            }
            _ => return Err(CheckpointError::Refused("role")),
        };
        require(values.is_empty(), "config_foreign_role")?;
        require(
            private_peers_file.is_none() || matches!(role, DirectoryRole::Home { .. }),
            "config_foreign_role",
        )?;
        let database = match &role {
            DirectoryRole::Home { database, .. } | DirectoryRole::Witness { database, .. } => {
                database
            }
            DirectoryRole::Center { primary, .. } => primary,
        };
        validate_path(database)?;
        require(database != &center.ca_file, "config_paths")?;
        if let DirectoryRole::Center { witness: peer, .. } | DirectoryRole::Witness { peer, .. } =
            &role
        {
            require(database != &peer.socket && center.ca_file != peer.socket, "config_paths")?;
        }
        Ok(Some(Self { center, role }))
    }
}

pub type HttpsOrigin = ramflux_protocol::username_directory::DirectoryOrigin;

/// # Errors
/// Refuses noncanonical or unsupported HTTPS origins.
pub fn parse_https_origin(value: &str) -> Result<HttpsOrigin> {
    Ok(ramflux_protocol::username_directory::parse_directory_origin(value)?)
}

pub(super) fn validate_origin(value: &str) -> Result<()> {
    parse_https_origin(value).map(|_| ())
}

pub(crate) fn validate_node(value: &str) -> Result<()> {
    require(
        !value.is_empty()
            && value.len() <= 253
            && value.parse::<std::net::IpAddr>().is_err()
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }),
        "node",
    )
}

fn validate_path(value: &Path) -> Result<()> {
    require(
        value.is_absolute()
            && value.as_os_str().len() <= 4096
            && value.file_name().is_some()
            && value.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "config_path",
    )
}

fn decimal(value: &str) -> Result<u64> {
    let number = value.parse::<u64>().map_err(|_| CheckpointError::Refused("config_integer"))?;
    require(number.to_string() == value, "config_integer")?;
    Ok(number)
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Mounted node secrets and context-bound encryption for server credentials.
use crate::NodeCoreError;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use std::{io::Read, path::Path, sync::OnceLock};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct NodeSecret(Zeroizing<[u8; 32]>);
impl std::fmt::Debug for NodeSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NodeSecret(<redacted>)")
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    version: u8,
    nonce: String,
    ciphertext: String,
}
fn invalid() -> NodeCoreError {
    NodeCoreError::Unauthorized("node secret or sealed credential is invalid".into())
}

impl NodeSecret {
    pub fn with_bytes<T>(&self, operation: impl FnOnce(&[u8; 32]) -> T) -> T {
        operation(&self.0)
    }

    /// Accepted modes are 0600, 0400, 0640 and 0440.
    /// # Errors
    /// Rejects non-regular files, permissive Unix modes, oversized input and invalid key encoding.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, NodeCoreError> {
        let path = path.as_ref();
        let metadata = std::fs::symlink_metadata(path).map_err(|_| invalid())?;
        if !metadata.file_type().is_file() {
            return Err(invalid());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Owner read (optionally write) plus optional group read: containers that drop
            // every capability read the secret through a supplementary group, never "other".
            if !matches!(metadata.permissions().mode() & 0o777, 0o600 | 0o400 | 0o640 | 0o440) {
                return Err(invalid());
            }
        }
        let mut bytes = Zeroizing::new(Vec::new());
        std::fs::File::open(path)
            .map_err(|_| invalid())?
            .take(129)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        if bytes.len() > 128 {
            return Err(invalid());
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?.trim();
        let decoded =
            Zeroizing::new(ramflux_protocol::decode_base64url(text).map_err(|_| invalid())?);
        Ok(Self(Zeroizing::new(decoded.as_slice().try_into().map_err(|_| invalid())?)))
    }
    /// # Errors
    /// Rejects a secret mounted inside the durable database volume.
    pub fn require_external_path(secret: &Path, database: &Path) -> Result<(), NodeCoreError> {
        let parent = secret.parent().ok_or_else(invalid)?.canonicalize().map_err(|_| invalid())?;
        let data = database.parent().ok_or_else(invalid)?.canonicalize().map_err(|_| invalid())?;
        if parent.starts_with(data) {
            return Err(invalid());
        }
        Ok(())
    }
    /// # Errors
    /// Rejects an unset or invalid mounted secret.
    pub fn required_env(name: &str) -> Result<Self, NodeCoreError> {
        Self::from_file(crate::environment::var_os(name).ok_or_else(invalid)?)
    }
    /// An in-process default is intentionally ephemeral; persistent services must mount a key.
    /// # Errors
    /// Returns operating-system entropy failures.
    pub fn ephemeral() -> Result<Self, NodeCoreError> {
        Ok(Self(Zeroizing::new(ramflux_crypto::random_32().map_err(|_| invalid())?)))
    }
    pub(crate) fn process_key() -> &'static Self {
        static KEY: OnceLock<NodeSecret> = OnceLock::new();
        KEY.get_or_init(|| Self::ephemeral().unwrap_or_else(|_| std::process::abort()))
    }
    /// # Errors
    /// Returns encryption, randomness or serialization errors; never includes credential bytes.
    pub fn seal(&self, context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NodeCoreError> {
        let random = ramflux_crypto::random_32().map_err(|_| invalid())?;
        let nonce = &random[..12];
        let ciphertext = Aes256Gcm::new_from_slice(self.0.as_ref())
            .map_err(|_| invalid())?
            .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad: context })
            .map_err(|_| invalid())?;
        serde_json::to_vec(&Sealed {
            version: 1,
            nonce: ramflux_protocol::encode_base64url(nonce),
            ciphertext: ramflux_protocol::encode_base64url(ciphertext),
        })
        .map_err(|_| invalid())
    }
    /// # Errors
    /// Rejects a different key, context, version, malformed encoding or unauthenticated ciphertext.
    pub fn open(&self, context: &[u8], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, NodeCoreError> {
        let sealed: Sealed = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        let nonce = ramflux_protocol::decode_base64url(&sealed.nonce).map_err(|_| invalid())?;
        if sealed.version != 1 || nonce.len() != 12 {
            return Err(invalid());
        }
        let ciphertext =
            ramflux_protocol::decode_base64url(&sealed.ciphertext).map_err(|_| invalid())?;
        Ok(Zeroizing::new(
            Aes256Gcm::new_from_slice(self.0.as_ref())
                .map_err(|_| invalid())?
                .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: context })
                .map_err(|_| invalid())?,
        ))
    }
    #[must_use]
    pub fn pseudonym(&self, domain: &str, value: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(self.0.as_ref())
            .unwrap_or_else(|_| std::process::abort());
        mac.update(domain.as_bytes());
        mac.update(&[0]);
        mac.update(value);
        ramflux_protocol::encode_base64url(mac.finalize().into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sealed_credentials_bind_key_context_and_integrity() -> Result<(), NodeCoreError> {
        let a = NodeSecret::ephemeral()?;
        let b = NodeSecret::ephemeral()?;
        let sealed = a.seal(b"device-a", b"private-token")?;
        assert!(!String::from_utf8_lossy(&sealed).contains("private-token"));
        assert_eq!(a.open(b"device-a", &sealed)?.as_slice(), b"private-token");
        assert!(a.open(b"device-b", &sealed).is_err());
        assert!(b.open(b"device-a", &sealed).is_err());
        assert_ne!(a.pseudonym("ip", b"192.0.2.1"), b.pseudonym("ip", b"192.0.2.1"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn mounted_secret_allows_group_read_but_never_world_access() -> Result<(), NodeCoreError> {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("rf-node-secret-mode-{}", std::process::id()));
        std::fs::write(&path, ramflux_protocol::encode_base64url([7_u8; 32]))
            .map_err(|_| invalid())?;
        for (mode, accepted) in [
            (0o600, true),
            (0o400, true),
            (0o640, true),
            (0o440, true),
            (0o644, false),
            (0o660, false),
        ] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .map_err(|_| invalid())?;
            assert_eq!(NodeSecret::from_file(&path).is_ok(), accepted, "mode {mode:o}");
        }
        std::fs::remove_file(&path).map_err(|_| invalid())?;
        Ok(())
    }
}

#![allow(clippy::wildcard_imports)]
use crate::*;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionMode {
    SqlCipher,
    InsecureTestSqlite,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountDbKey {
    bytes: [u8; 32],
}

impl AccountDbKey {
    /// # Errors
    /// Returns an error when the operating system CSPRNG cannot provide fresh key material.
    pub fn generate() -> Result<Self, StorageError> {
        Ok(Self { bytes: ramflux_crypto::random_32()? })
    }

    #[must_use]
    pub fn derive(local_account_id: &str, secret: &[u8]) -> Self {
        let mut input = Vec::new();
        input.extend_from_slice(b"ramflux.account_db_key.v1");
        input.extend_from_slice(local_account_id.as_bytes());
        input.extend_from_slice(secret);
        Self { bytes: *blake3::hash(&input).as_bytes() }
    }

    #[must_use]
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        blake3::hash(self.bytes()).to_hex().to_string()
    }

    pub(crate) fn sqlcipher_hex(&self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in self.bytes {
            hex.push(hex_char(byte >> 4));
            hex.push(hex_char(byte & 0x0f));
        }
        hex
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedAccountDbKey {
    pub key_wrapping_provider: String,
    pub key_wrapping_ref: String,
    pub nonce: [u8; 12],
    pub wrapped_key: Vec<u8>,
}

pub trait VaultSecretSource {
    /// # Errors
    /// Returns an error when the vault secret cannot be generated, read, or persisted.
    fn vault_secret(&self, local_account_id: &str) -> Result<[u8; 32], StorageError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileVaultSecretSource {
    root: PathBuf,
}

impl FileVaultSecretSource {
    #[must_use]
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self { root: root.as_ref().to_path_buf() }
    }

    #[must_use]
    pub fn vault_secret_path(&self, local_account_id: &str) -> PathBuf {
        self.root.join("vault").join(format!("{local_account_id}.key"))
    }
}

impl VaultSecretSource for FileVaultSecretSource {
    fn vault_secret(&self, local_account_id: &str) -> Result<[u8; 32], StorageError> {
        let path = self.vault_secret_path(local_account_id);
        if path.exists() {
            let mut file = fs::File::open(&path)?;
            let mut bytes = [0_u8; 32];
            file.read_exact(&mut bytes)?;
            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            return Ok(bytes);
        }

        let secret = ramflux_crypto::random_32()?;
        let parent = path.parent().ok_or_else(|| {
            StorageError::KeyWrappingFailed("invalid vault secret path".to_owned())
        })?;
        fs::create_dir_all(parent)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&path)?;
        file.write_all(&secret)?;
        file.sync_all()?;
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(secret)
    }
}

pub trait AccountKeyWrappingProvider {
    fn provider_name(&self) -> &'static str;

    /// # Errors
    /// Returns an error when the platform provider cannot wrap or persist the account DB key.
    fn wrap_account_db_key(
        &mut self,
        local_account_id: &str,
        key: &AccountDbKey,
    ) -> Result<WrappedAccountDbKey, StorageError>;

    /// # Errors
    /// Returns an error when the platform provider cannot restore the prior wrapped key.
    fn restore_wrapped_account_db_key(
        &mut self,
        local_account_id: &str,
        previous: &WrappedAccountDbKey,
    ) -> Result<(), StorageError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalVaultKeyWrappingProvider {
    vault_secret: [u8; 32],
    wrapped_keys: BTreeMap<String, WrappedAccountDbKey>,
    fail_next_wrap: bool,
}

impl LocalVaultKeyWrappingProvider {
    #[must_use]
    pub fn new(vault_secret: [u8; 32]) -> Self {
        Self { vault_secret, wrapped_keys: BTreeMap::new(), fail_next_wrap: false }
    }

    pub fn fail_next_wrap(&mut self) {
        self.fail_next_wrap = true;
    }

    #[must_use]
    pub fn wrapped_key(&self, local_account_id: &str) -> Option<&WrappedAccountDbKey> {
        self.wrapped_keys.get(local_account_id)
    }
}

impl AccountKeyWrappingProvider for LocalVaultKeyWrappingProvider {
    fn provider_name(&self) -> &'static str {
        "platform-local-vault"
    }

    fn wrap_account_db_key(
        &mut self,
        local_account_id: &str,
        key: &AccountDbKey,
    ) -> Result<WrappedAccountDbKey, StorageError> {
        if self.fail_next_wrap {
            self.fail_next_wrap = false;
            return Err(StorageError::KeyWrappingFailed("injected provider failure".to_owned()));
        }
        let (nonce, wrapped_key) = wrap_with_vault_secret(&self.vault_secret, key.bytes())?;
        let wrapped = WrappedAccountDbKey {
            key_wrapping_provider: self.provider_name().to_owned(),
            key_wrapping_ref: format!("platform-local-vault:{local_account_id}"),
            nonce,
            wrapped_key,
        };
        self.wrapped_keys.insert(local_account_id.to_owned(), wrapped.clone());
        Ok(wrapped)
    }

    fn restore_wrapped_account_db_key(
        &mut self,
        local_account_id: &str,
        previous: &WrappedAccountDbKey,
    ) -> Result<(), StorageError> {
        self.wrapped_keys.insert(local_account_id.to_owned(), previous.clone());
        Ok(())
    }
}

/// # Errors
/// Returns an error when fresh nonce generation or AEAD encryption fails.
pub fn wrap_with_vault_secret(
    vault_secret: &[u8; 32],
    key: &[u8; 32],
) -> Result<([u8; 12], Vec<u8>), StorageError> {
    let random = ramflux_crypto::random_32()?;
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&random[..12]);
    let ciphertext = ChaCha20Poly1305::new(Key::from_slice(vault_secret))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: key.as_slice(), aad: b"ramflux.account_db_key.wrap.v1" },
        )
        .map_err(|_err| {
            StorageError::KeyWrappingFailed("account DB key AEAD wrap failed".to_owned())
        })?;
    Ok((nonce, ciphertext))
}

/// # Errors
/// Returns an error when the wrapped key was tampered with or the wrong vault secret is used.
pub fn unwrap_with_vault_secret(
    vault_secret: &[u8; 32],
    wrapped: &WrappedAccountDbKey,
) -> Result<AccountDbKey, StorageError> {
    let plaintext = ChaCha20Poly1305::new(Key::from_slice(vault_secret))
        .decrypt(
            Nonce::from_slice(&wrapped.nonce),
            Payload { msg: wrapped.wrapped_key.as_slice(), aad: b"ramflux.account_db_key.wrap.v1" },
        )
        .map_err(|_err| {
            StorageError::KeyWrappingFailed("account DB key AEAD unwrap failed".to_owned())
        })?;
    let bytes: [u8; 32] = plaintext.try_into().map_err(|bytes: Vec<u8>| {
        StorageError::KeyWrappingFailed(format!("invalid unwrapped DB key length: {}", bytes.len()))
    })?;
    Ok(AccountDbKey { bytes })
}

pub(crate) fn apply_key(connection: &Connection, key: &AccountDbKey) -> Result<(), StorageError> {
    connection.execute_batch(&format!(
        "PRAGMA key = \"x'{}'\";
         PRAGMA cipher_page_size = 4096;
         PRAGMA kdf_iter = 256000;
         PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
         PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
         PRAGMA foreign_keys = ON;",
        key.sqlcipher_hex()
    ))?;
    Ok(())
}

pub(crate) fn verify_or_install_key_fingerprint(
    connection: &Connection,
    key: &AccountDbKey,
) -> Result<(), StorageError> {
    let existing: Option<String> = connection
        .query_row(
            "SELECT key_fingerprint FROM account_key_check WHERE singleton_id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match existing {
        Some(value) if value == key.fingerprint() => Ok(()),
        Some(_value) => Err(StorageError::AccountKeyMismatch),
        None => {
            connection.execute(
                "INSERT INTO account_key_check (singleton_id, key_fingerprint) VALUES (1, ?1)",
                params![key.fingerprint()],
            )?;
            Ok(())
        }
    }
}

pub(crate) fn current_encryption_mode(connection: &Connection) -> EncryptionMode {
    let cipher_version =
        connection.query_row("PRAGMA cipher_version", [], |row| row.get::<_, String>(0)).optional();
    match cipher_version {
        Ok(Some(_version)) => EncryptionMode::SqlCipher,
        Ok(None) => EncryptionMode::InsecureTestSqlite,
        Err(_err) => EncryptionMode::InsecureTestSqlite,
    }
}

fn hex_char(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        _ => char::from(b'a' + (value - 10)),
    }
}

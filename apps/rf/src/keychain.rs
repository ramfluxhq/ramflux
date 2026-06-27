// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use crate::RfError;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

pub(crate) const RAMFLUX_KEYCHAIN_SERVICE: &str = "ramflux";

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct KeychainSecret {
    pub(crate) passphrase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) device_seed_base64url: Option<String>,
}

impl KeychainSecret {
    pub(crate) fn new(passphrase: String, device_seed: Option<[u8; 32]>) -> Self {
        Self {
            passphrase,
            device_seed_base64url: device_seed.map(ramflux_protocol::encode_base64url),
        }
    }
}

impl Drop for KeychainSecret {
    fn drop(&mut self) {
        self.passphrase.zeroize();
        if let Some(device_seed) = self.device_seed_base64url.as_mut() {
            device_seed.zeroize();
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeychainStatus {
    pub(crate) available: bool,
    pub(crate) present: bool,
    pub(crate) has_device_seed: bool,
    pub(crate) error: Option<String>,
}

pub(crate) trait KeyStore {
    fn load(&self, account_id: &str) -> Result<Option<KeychainSecret>, RfError>;
    fn store(&self, account_id: &str, secret: &KeychainSecret) -> Result<(), RfError>;
    fn remove(&self, account_id: &str) -> Result<(), RfError>;

    fn status(&self, account_id: &str) -> KeychainStatus {
        match self.load(account_id) {
            Ok(Some(secret)) => KeychainStatus {
                available: true,
                present: true,
                has_device_seed: secret.device_seed_base64url.is_some(),
                error: None,
            },
            Ok(None) => KeychainStatus {
                available: true,
                present: false,
                has_device_seed: false,
                error: None,
            },
            Err(error) => KeychainStatus {
                available: false,
                present: false,
                has_device_seed: false,
                error: Some(error.to_string()),
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OsKeychain;

impl OsKeychain {
    fn entry(account_id: &str) -> Result<keyring::Entry, RfError> {
        keyring::Entry::new(RAMFLUX_KEYCHAIN_SERVICE, account_id)
            .map_err(|error| keyring_error(&error))
    }
}

impl KeyStore for OsKeychain {
    fn load(&self, account_id: &str) -> Result<Option<KeychainSecret>, RfError> {
        let entry = Self::entry(account_id)?;
        match entry.get_password() {
            Ok(raw) => Ok(Some(decode_keychain_secret(&raw))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(keyring_error(&error)),
        }
    }

    fn store(&self, account_id: &str, secret: &KeychainSecret) -> Result<(), RfError> {
        let entry = Self::entry(account_id)?;
        entry.set_password(&serde_json::to_string(secret)?).map_err(|error| keyring_error(&error))
    }

    fn remove(&self, account_id: &str) -> Result<(), RfError> {
        let entry = Self::entry(account_id)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(keyring_error(&error)),
        }
    }
}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct InMemoryKeyStore {
    values: Arc<Mutex<BTreeMap<String, String>>>,
    fail: Arc<Mutex<Option<String>>>,
}

#[cfg(test)]
impl InMemoryKeyStore {
    pub(crate) fn fail_with(&self, message: &str) -> Result<(), RfError> {
        let mut fail = self.fail.lock().map_err(|_error| {
            RfError::Message("in-memory key store fail lock poisoned".to_owned())
        })?;
        *fail = Some(message.to_owned());
        Ok(())
    }

    fn maybe_fail(&self) -> Result<(), RfError> {
        let fail = self.fail.lock().map_err(|_error| {
            RfError::Message("in-memory key store fail lock poisoned".to_owned())
        })?;
        if let Some(message) = fail.as_ref() {
            return Err(RfError::Message(message.clone()));
        }
        Ok(())
    }
}

#[cfg(test)]
impl KeyStore for InMemoryKeyStore {
    fn load(&self, account_id: &str) -> Result<Option<KeychainSecret>, RfError> {
        self.maybe_fail()?;
        let values = self.values.lock().map_err(|_error| {
            RfError::Message("in-memory key store values lock poisoned".to_owned())
        })?;
        Ok(values.get(account_id).map(|raw| decode_keychain_secret(raw)))
    }

    fn store(&self, account_id: &str, secret: &KeychainSecret) -> Result<(), RfError> {
        self.maybe_fail()?;
        let mut values = self.values.lock().map_err(|_error| {
            RfError::Message("in-memory key store values lock poisoned".to_owned())
        })?;
        values.insert(account_id.to_owned(), serde_json::to_string(secret)?);
        Ok(())
    }

    fn remove(&self, account_id: &str) -> Result<(), RfError> {
        self.maybe_fail()?;
        let mut values = self.values.lock().map_err(|_error| {
            RfError::Message("in-memory key store values lock poisoned".to_owned())
        })?;
        values.remove(account_id);
        Ok(())
    }
}

fn decode_keychain_secret(raw: &str) -> KeychainSecret {
    match serde_json::from_str::<KeychainSecret>(raw) {
        Ok(secret) => secret,
        Err(_error) => KeychainSecret { passphrase: raw.to_owned(), device_seed_base64url: None },
    }
}

fn keyring_error(error: &keyring::Error) -> RfError {
    RfError::Message(format!("OS keychain error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_key_store_round_trips_secret_bundle() -> Result<(), RfError> {
        let store = InMemoryKeyStore::default();
        let secret = KeychainSecret::new("vault-passphrase".to_owned(), Some([0x22; 32]));

        store.store("alice", &secret)?;
        let loaded =
            store.load("alice")?.ok_or_else(|| RfError::Message("secret missing".to_owned()))?;

        assert_eq!(loaded.passphrase, "vault-passphrase");
        assert!(loaded.device_seed_base64url.is_some());
        assert_eq!(
            store.status("alice"),
            KeychainStatus { available: true, present: true, has_device_seed: true, error: None }
        );
        Ok(())
    }

    #[test]
    fn in_memory_key_store_status_reports_unavailable() -> Result<(), RfError> {
        let store = InMemoryKeyStore::default();
        store.fail_with("secret service unavailable")?;

        let status = store.status("alice");

        assert!(!status.available);
        assert!(!status.present);
        assert!(status.error.is_some());
        Ok(())
    }

    #[test]
    fn keychain_secret_reader_accepts_legacy_plaintext_passphrase() {
        let secret = decode_keychain_secret("legacy-passphrase");

        assert_eq!(secret.passphrase, "legacy-passphrase");
        assert_eq!(secret.device_seed_base64url, None);
    }
}

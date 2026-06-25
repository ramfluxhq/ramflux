#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::handlers::account::rf_required_env;
use crate::keychain::{KeyStore, KeychainSecret, OsKeychain, RAMFLUX_KEYCHAIN_SERVICE};

pub(crate) fn handle_keychain(command: KeychainCommand) -> Result<(), RfError> {
    handle_keychain_with_store(command, &OsKeychain)
}

fn handle_keychain_with_store(
    command: KeychainCommand,
    store: &impl KeyStore,
) -> Result<(), RfError> {
    match command.action {
        KeychainAction::Store(store_command) => {
            let passphrase = rf_required_env(
                store_command.passphrase_env.as_deref(),
                "RAMFLUX_ACCOUNT_PASSPHRASE",
            )?;
            let device_seed =
                store_command.device_seed_byte_hex.as_deref().map(repeated_seed).transpose()?;
            let secret = KeychainSecret::new(passphrase, device_seed);
            store.store(&store_command.account, &secret)?;
            print_json(&serde_json::json!({
                "account": store_command.account,
                "service": RAMFLUX_KEYCHAIN_SERVICE,
                "stored": true,
                "has_device_seed": secret.device_seed_base64url.is_some(),
            }))
        }
        KeychainAction::Remove(selector) => {
            store.remove(&selector.account)?;
            print_json(&serde_json::json!({
                "account": selector.account,
                "service": RAMFLUX_KEYCHAIN_SERVICE,
                "removed": true,
            }))
        }
        KeychainAction::Status(selector) => {
            let status = store.status(&selector.account);
            print_json(&serde_json::json!({
                "account": selector.account,
                "service": RAMFLUX_KEYCHAIN_SERVICE,
                "available": status.available,
                "present": status.present,
                "has_device_seed": status.has_device_seed,
                "error": status.error,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::InMemoryKeyStore;

    #[test]
    fn keychain_store_status_remove_use_in_memory_store() -> Result<(), RfError> {
        let store = InMemoryKeyStore::default();
        let secret = KeychainSecret::new("secret".to_owned(), Some([0x33; 32]));

        store.store("alice", &secret)?;
        assert!(store.status("alice").present);

        store.remove("alice")?;
        assert!(!store.status("alice").present);
        Ok(())
    }
}

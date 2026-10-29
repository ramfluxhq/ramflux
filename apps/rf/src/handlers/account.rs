// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
#![allow(clippy::wildcard_imports)]
use super::*;
use crate::keychain::{KeyStore, KeychainSecret, OsKeychain, RAMFLUX_KEYCHAIN_SERVICE};
use zeroize::Zeroize;

pub(crate) async fn handle_account(
    socket: PathBuf,
    command: AccountCommand,
) -> Result<(), RfError> {
    match &command.action {
        AccountAction::Recover(selector) => {
            return super::account_ceremony::recover(&socket, &selector.account).await;
        }
        AccountAction::Create(create) => {
            return super::account_ceremony::create(&socket, &create.display_name).await;
        }
        _ => {}
    }
    let mut bus = LocalBusClient::connect(socket).await?;
    match command.action {
        AccountAction::Backup(backup) => super::account_backup::handle(&mut bus, backup).await,
        AccountAction::List => {
            print_json(&bus.request(None, "account", "account.list", serde_json::json!({})).await?)
        }
        AccountAction::Lock(lock) => {
            let account = lock.account;
            let response = bus
                .request(Some(account.clone()), "account", "account.lock", serde_json::json!({}))
                .await?;
            let response = if lock.use_keychain {
                with_keychain_status(response, &account, &OsKeychain.status(&account))
            } else {
                response
            };
            print_json(&response)
        }
        AccountAction::Passphrase(passphrase) => {
            handle_account_passphrase(&mut bus, passphrase).await
        }
        AccountAction::Switch(selector) => print_json(
            &bus.request(
                Some(selector.account),
                "account",
                "account.switch",
                serde_json::json!({}),
            )
            .await?,
        ),
        AccountAction::Status(selector) => print_json(
            &bus.request(
                Some(selector.account),
                "account",
                "account.status",
                serde_json::json!({}),
            )
            .await?,
        ),
        AccountAction::Unlock(unlock) => handle_account_unlock(&mut bus, unlock, &OsKeychain).await,
        AccountAction::Recover(_) | AccountAction::Create(_) => Err(RfError::Message(
            "Account ceremonies require the exclusive ceremony client.".into(),
        )),
    }
}

async fn handle_account_unlock(
    bus: &mut LocalBusClient,
    unlock: AccountUnlock,
    store: &impl KeyStore,
) -> Result<(), RfError> {
    let account_id = unlock.account;
    let (passphrase, source, keychain_error) = resolve_unlock_passphrase(
        store,
        &account_id,
        unlock.use_keychain,
        unlock.passphrase_env.as_deref(),
    )?;
    let mut request = LocalBusAccountUnlockRequest { passphrase };
    let fallback_secret = if unlock.use_keychain && source != "keychain" {
        Some(KeychainSecret::new(request.passphrase.clone(), None))
    } else {
        None
    };
    let response = bus
        .request(
            Some(account_id.clone()),
            "account",
            "account.unlock",
            serde_json::to_value(&request)?,
        )
        .await;
    request.passphrase.zeroize();
    let response = response?;
    let mut response = with_keychain_source(response, &source, keychain_error.as_ref());
    if let Some(secret) = fallback_secret {
        response = with_keychain_store_result(
            response,
            store_keychain_secret(store, &account_id, &secret),
        );
    }
    print_json(&response)
}

async fn handle_account_passphrase(
    bus: &mut LocalBusClient,
    passphrase: AccountPassphraseCommand,
) -> Result<(), RfError> {
    match passphrase.action {
        AccountPassphraseAction::Rotate(rotate) => {
            let old_passphrase = rf_optional_env(
                rotate.old_passphrase_env.as_deref(),
                "RAMFLUX_ACCOUNT_OLD_PASSPHRASE",
            )?;
            let new_passphrase = rf_required_env(
                rotate.new_passphrase_env.as_deref(),
                "RAMFLUX_ACCOUNT_NEW_PASSPHRASE",
            )?;
            let request = LocalBusAccountPassphraseRotateRequest { old_passphrase, new_passphrase };
            print_json(
                &bus.request(
                    Some(rotate.account),
                    "account",
                    "account.passphrase.rotate",
                    serde_json::to_value(request)?,
                )
                .await?,
            )
        }
    }
}

pub(crate) fn rf_required_env(
    explicit: Option<&str>,
    default_name: &str,
) -> Result<String, RfError> {
    let name = explicit.unwrap_or(default_name);
    std::env::var(name).map_err(|_error| {
        RfError::Message(format!("required passphrase environment variable {name} is not set"))
    })
}

pub(crate) fn rf_optional_env(
    explicit: Option<&str>,
    default_name: &str,
) -> Result<Option<String>, RfError> {
    match explicit {
        Some(name) => Ok(Some(std::env::var(name).map_err(|_error| {
            RfError::Message(format!("required passphrase environment variable {name} is not set"))
        })?)),
        None => match std::env::var(default_name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(error) => Err(RfError::Message(format!(
                "failed to read passphrase environment variable {default_name}: {error}"
            ))),
        },
    }
}

fn resolve_unlock_passphrase(
    store: &impl KeyStore,
    account_id: &str,
    use_keychain: bool,
    passphrase_env: Option<&str>,
) -> Result<(String, String, Option<String>), RfError> {
    resolve_unlock_passphrase_with_env_reader(
        store,
        account_id,
        use_keychain,
        passphrase_env,
        |name| {
            std::env::var(name).map_err(|_error| {
                RfError::Message(format!(
                    "required passphrase environment variable {name} is not set"
                ))
            })
        },
    )
}

fn resolve_unlock_passphrase_with_env_reader(
    store: &impl KeyStore,
    account_id: &str,
    use_keychain: bool,
    passphrase_env: Option<&str>,
    read_env: impl Fn(&str) -> Result<String, RfError>,
) -> Result<(String, String, Option<String>), RfError> {
    let env_name = passphrase_env.unwrap_or("RAMFLUX_ACCOUNT_PASSPHRASE");
    if use_keychain {
        match store.load(account_id) {
            Ok(Some(secret)) => {
                return Ok((secret.passphrase.clone(), "keychain".to_owned(), None));
            }
            Ok(None) => {
                let passphrase = read_env(env_name)?;
                return Ok((
                    passphrase,
                    "env".to_owned(),
                    Some("keychain entry not found".to_owned()),
                ));
            }
            Err(error) => {
                let message = error.to_string();
                let passphrase = read_env(env_name)?;
                return Ok((passphrase, "env".to_owned(), Some(message)));
            }
        }
    }
    let passphrase = read_env(env_name)?;
    Ok((passphrase, "env".to_owned(), None))
}

fn store_keychain_secret(
    store: &impl KeyStore,
    account_id: &str,
    secret: &KeychainSecret,
) -> Result<(), String> {
    store.store(account_id, secret).map_err(|error| error.to_string())
}

fn with_keychain_store_result(
    response: serde_json::Value,
    result: Result<(), String>,
) -> serde_json::Value {
    let (stored, error) = match result {
        Ok(()) => (true, None),
        Err(error) => (false, Some(error)),
    };
    merge_response(
        response,
        serde_json::json!({
            "keychain": {
                "service": RAMFLUX_KEYCHAIN_SERVICE,
                "stored": stored,
                "error": error,
            }
        }),
    )
}

fn with_keychain_status(
    response: serde_json::Value,
    account_id: &str,
    status: &crate::keychain::KeychainStatus,
) -> serde_json::Value {
    merge_response(
        response,
        serde_json::json!({
            "keychain": {
                "account": account_id,
                "service": RAMFLUX_KEYCHAIN_SERVICE,
                "available": status.available,
                "present": status.present,
                "has_device_seed": status.has_device_seed,
                "error": status.error,
            }
        }),
    )
}

fn with_keychain_source(
    response: serde_json::Value,
    source: &str,
    keychain_error: Option<&String>,
) -> serde_json::Value {
    merge_response(
        response,
        serde_json::json!({
            "keychain": {
                "service": RAMFLUX_KEYCHAIN_SERVICE,
                "passphrase_source": source,
                "fallback_reason": keychain_error,
            }
        }),
    )
}

fn merge_response(
    mut response: serde_json::Value,
    extension: serde_json::Value,
) -> serde_json::Value {
    let Some(response_object) = response.as_object_mut() else {
        return extension;
    };
    if let Some(extension_object) = extension.as_object() {
        for (key, value) in extension_object {
            response_object.insert(key.clone(), value.clone());
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::InMemoryKeyStore;

    #[test]
    fn unlock_passphrase_uses_keychain_when_present() -> Result<(), RfError> {
        let store = InMemoryKeyStore::default();
        store.store("alice", &KeychainSecret::new("from-keychain".to_owned(), None))?;

        let (passphrase, source, error) = resolve_unlock_passphrase(&store, "alice", true, None)?;

        assert_eq!(passphrase, "from-keychain");
        assert_eq!(source, "keychain");
        assert_eq!(error, None);
        Ok(())
    }

    #[test]
    fn unlock_passphrase_falls_back_to_env_when_keychain_unavailable() -> Result<(), RfError> {
        let store = InMemoryKeyStore::default();
        store.fail_with("secret service unavailable")?;

        let (passphrase, source, error) = resolve_unlock_passphrase_with_env_reader(
            &store,
            "alice",
            true,
            Some("TEST_PASSPHRASE"),
            |name| {
                if name == "TEST_PASSPHRASE" {
                    Ok("from-env".to_owned())
                } else {
                    Err(RfError::Message(format!("unexpected env name {name}")))
                }
            },
        )?;

        assert_eq!(passphrase, "from-env");
        assert_eq!(source, "env");
        assert!(error.is_some());
        Ok(())
    }
}

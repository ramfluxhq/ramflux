// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    pub fn open_account_index(&mut self, root: impl AsRef<Path>) -> Result<(), SdkError> {
        let index = AccountIndex::open(root)?;
        if !self.vault_secret_source_is_custom {
            self.vault_secret_source = Some(Box::new(FileVaultSecretSource::new(index.root())));
        }
        self.account_index = Some(index);
        Ok(())
    }

    pub fn set_vault_secret_source(&mut self, source: Box<dyn VaultSecretSource>) {
        self.vault_secret_source = Some(source);
        self.vault_secret_source_is_custom = true;
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn create_account(
        &self,
        local_account_id: &str,
        principal_commitment: &str,
    ) -> Result<ramflux_storage::LocalAccountRecord, SdkError> {
        Ok(self.account_index()?.create_account(local_account_id, principal_commitment)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn set_active_account(&self, local_account_id: &str) -> Result<(), SdkError> {
        Ok(self.account_index()?.set_active_account(local_account_id)?)
    }

    /// # Errors
    /// Returns an error when the account index is not open or cannot be queried.
    pub fn active_account(&self) -> Result<Option<String>, SdkError> {
        Ok(self.account_index()?.active_account()?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn unlock_account(
        &mut self,
        local_account_id: &str,
        secret: &[u8],
    ) -> Result<(), SdkError> {
        let vault_secret = self.vault_secret_source()?.vault_secret(local_account_id)?;
        let key_encryption_key = account_db_key_encryption_key(&vault_secret, secret);
        let account_index = self.account_index()?;
        let key = if let Some(wrapped) = account_index.load_wrapped_db_key(local_account_id)? {
            unwrap_with_vault_secret(&key_encryption_key, &wrapped)?
        } else {
            let generated = AccountDbKey::generate()?;
            let (nonce, wrapped_key) =
                wrap_with_vault_secret(&key_encryption_key, generated.bytes())?;
            account_index.store_wrapped_db_key(
                local_account_id,
                &WrappedAccountDbKey {
                    key_wrapping_provider: "platform-local-vault".to_owned(),
                    key_wrapping_ref: format!("platform-local-vault:{local_account_id}"),
                    nonce,
                    wrapped_key,
                },
            )?;
            generated
        };
        let mut db = AccountDb::open(account_index, local_account_id, &key)?;
        if let Some(device_branch) = self.device_branch.clone() {
            db.set_device_signer(device_branch);
        }
        self.active_account_db = Some(db);
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn rekey_active_account(
        &mut self,
        local_account_id: &str,
        new_secret: &[u8],
    ) -> Result<(), SdkError> {
        let vault_secret = self.vault_secret_source()?.vault_secret(local_account_id)?;
        let key_encryption_key = account_db_key_encryption_key(&vault_secret, new_secret);
        let wrapped = self.account_db()?.wrap_current_db_key(&key_encryption_key)?;
        self.account_index()?.store_wrapped_db_key(local_account_id, &wrapped)?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn append_event(
        &self,
        event_id: &str,
        event_type: &str,
        body: &[u8],
    ) -> Result<(), SdkError> {
        Ok(self.account_db()?.append_event(event_id, event_type, body)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn event_body(&self, event_id: &str) -> Result<Option<Vec<u8>>, SdkError> {
        Ok(self.account_db()?.event_body(event_id)?)
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or the checkpoint cannot be stored.
    pub fn set_projection_checkpoint(
        &self,
        projection_name: &str,
        last_event_id: &str,
    ) -> Result<(), SdkError> {
        Ok(self.account_db()?.set_projection_checkpoint(projection_name, last_event_id)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn projection_checkpoint(&self, projection_name: &str) -> Result<Option<String>, SdkError> {
        Ok(self.account_db()?.projection_checkpoint(projection_name)?)
    }

    /// # Errors
    /// Returns an error when the account DB is locked or the stored cursor is malformed.
    pub fn gateway_cursor(&self, target_delivery_id: &str) -> Result<u64, SdkError> {
        let checkpoint = self
            .projection_checkpoint(&gateway_cursor_checkpoint_name(target_delivery_id))?
            .unwrap_or_else(|| "0".to_owned());
        checkpoint.parse::<u64>().map_err(|_error| SdkError::InvalidGatewayCursor(checkpoint))
    }

    /// # Errors
    /// Returns an error when the account DB is locked or the stored receive cursor is malformed.
    pub fn gateway_receive_cursor(&self, target_delivery_id: &str) -> Result<u64, SdkError> {
        let checkpoint = self
            .projection_checkpoint(&gateway_receive_cursor_checkpoint_name(target_delivery_id))?
            .unwrap_or_else(|| "0".to_owned());
        checkpoint.parse::<u64>().map_err(|_error| SdkError::InvalidGatewayCursor(checkpoint))
    }

    /// # Errors
    /// Returns an error when the account DB is locked or the cursor cannot be stored.
    pub fn persist_gateway_cursor(
        &self,
        target_delivery_id: &str,
        inbox_seq: u64,
    ) -> Result<(), SdkError> {
        self.set_projection_checkpoint(
            &gateway_cursor_checkpoint_name(target_delivery_id),
            &inbox_seq.to_string(),
        )
    }

    /// # Errors
    /// Returns an error when the account DB is locked or the receive cursor cannot be stored.
    pub fn persist_gateway_receive_cursor(
        &self,
        target_delivery_id: &str,
        inbox_seq: u64,
    ) -> Result<(), SdkError> {
        self.set_projection_checkpoint(
            &gateway_receive_cursor_checkpoint_name(target_delivery_id),
            &inbox_seq.to_string(),
        )
    }

    /// # Errors
    /// Returns an error when the gateway cannot be reached, authenticated, or resumed.
    pub async fn connect_gateway_session(
        &self,
        mut config: GatewaySessionConfig,
    ) -> Result<GatewaySessionEngine, SdkError> {
        config.last_seen_inbox_seq = self.gateway_cursor(&config.target_delivery_id)?;
        if config.device_branch.is_none()
            && let Some(branch) = self.device_branch.as_ref()
            && branch.principal_id == config.principal_id
            && branch.device_id == config.device_id
            && branch.device_epoch == config.device_epoch
        {
            config.device_branch = Some(std::sync::Arc::new(branch.clone()));
        }
        GatewaySessionEngine::connect(config).await
    }

    /// # Errors
    /// Returns an error when no account DB is unlocked or bundle export fails.
    pub fn export_history_bundle(
        &self,
        source_device_id: &str,
        target_device_id: &str,
    ) -> Result<HistoryBundle, SdkError> {
        Ok(self.account_db()?.export_history_bundle(source_device_id, target_device_id)?)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn import_history_bundle(&self, bundle: &HistoryBundle) -> Result<(), SdkError> {
        Ok(self.account_db()?.import_history_bundle(bundle)?)
    }
}

fn account_db_key_encryption_key(vault_secret: &[u8; 32], secret: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ramflux.account_db_kek.v2");
    hasher.update(vault_secret);
    hasher.update(secret);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos =
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir()
            .join(format!("ramflux-sdk-account-{test_name}-{}-{nanos}", std::process::id()))
    }

    fn wrapped_db_key(
        root: &Path,
        local_account_id: &str,
        secret: &[u8],
    ) -> Result<AccountDbKey, SdkError> {
        let index = AccountIndex::open(root)?;
        let vault_secret =
            FileVaultSecretSource::new(index.root()).vault_secret(local_account_id)?;
        let wrapped = index.load_wrapped_db_key(local_account_id)?.ok_or_else(|| {
            SdkError::LocalBus(format!("missing wrapped key for {local_account_id}"))
        })?;
        Ok(unwrap_with_vault_secret(
            &account_db_key_encryption_key(&vault_secret, secret),
            &wrapped,
        )?)
    }

    #[test]
    fn account_unlock_uses_random_wrapped_key_and_rewraps_on_secret_change() -> Result<(), SdkError>
    {
        let root = temp_root("wrapped-key-default");
        let mut client = RamfluxClient::new();
        client.open_account_index(&root)?;
        client.create_account("acct_a", "principal_a")?;
        client.create_account("acct_b", "principal_b")?;
        client.unlock_account("acct_a", b"shared-secret")?;
        client.append_event("evt_a_1", "test.event", b"persisted")?;
        client.unlock_account("acct_b", b"shared-secret")?;

        let key_a = wrapped_db_key(&root, "acct_a", b"shared-secret")?;
        let key_b = wrapped_db_key(&root, "acct_b", b"shared-secret")?;
        assert_ne!(key_a, key_b);

        let mut restored = RamfluxClient::new();
        restored.open_account_index(&root)?;
        restored.unlock_account("acct_a", b"shared-secret")?;
        assert_eq!(restored.event_body("evt_a_1")?, Some(b"persisted".to_vec()));

        let mut wrong_secret = RamfluxClient::new();
        wrong_secret.open_account_index(&root)?;
        assert!(matches!(
            wrong_secret.unlock_account("acct_a", b"wrong-secret"),
            Err(SdkError::Storage(StorageError::KeyWrappingFailed(_)))
        ));

        restored.rekey_active_account("acct_a", b"new-secret")?;
        let rewrapped_key_a = wrapped_db_key(&root, "acct_a", b"new-secret")?;
        assert_eq!(rewrapped_key_a, key_a);
        let mut old_secret_after_rekey = RamfluxClient::new();
        old_secret_after_rekey.open_account_index(&root)?;
        assert!(matches!(
            old_secret_after_rekey.unlock_account("acct_a", b"shared-secret"),
            Err(SdkError::Storage(StorageError::KeyWrappingFailed(_)))
        ));
        let mut new_secret_after_rekey = RamfluxClient::new();
        new_secret_after_rekey.open_account_index(&root)?;
        new_secret_after_rekey.unlock_account("acct_a", b"new-secret")?;
        assert_eq!(new_secret_after_rekey.event_body("evt_a_1")?, Some(b"persisted".to_vec()));

        std::fs::remove_file(FileVaultSecretSource::new(&root).vault_secret_path("acct_a"))?;
        let mut missing_vault_secret = RamfluxClient::new();
        missing_vault_secret.open_account_index(&root)?;
        assert!(matches!(
            missing_vault_secret.unlock_account("acct_a", b"new-secret"),
            Err(SdkError::Storage(StorageError::KeyWrappingFailed(_)))
        ));

        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}

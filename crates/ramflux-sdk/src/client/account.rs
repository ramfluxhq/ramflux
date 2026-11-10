// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) fn verify_stored_data_secret(
    root: &Path,
    id: &str,
    secret: &[u8],
) -> Result<(), SdkError> {
    let index = AccountIndex::open(root)?;
    let _writer = index.acquire_account_writer(id)?;
    let vault = FileVaultSecretSource::new(root);
    let vault_secret = zeroize::Zeroizing::new(vault.vault_secret(id)?);
    let wrapping = zeroize::Zeroizing::new(account_db_key_encryption_key(&vault_secret, secret));
    let wrapped = index.load_wrapped_db_key(id)?.ok_or(SdkError::AccountDbNotUnlocked)?;
    let _key = unwrap_with_vault_secret(&wrapping, &wrapped)?;
    Ok(())
}

impl RamfluxClient {
    pub fn open_account_index(&mut self, root: impl AsRef<Path>) -> Result<(), SdkError> {
        let index = match self.account_index.take() {
            Some(index) if index.root() == root.as_ref() => index,
            _ => AccountIndex::open(root)?,
        };
        if !self.vault_secret_source_is_custom {
            self.vault_secret_source = Some(Box::new(FileVaultSecretSource::new(index.root())));
        }
        self.account_index = Some(index);
        Ok(())
    }

    /// Verifies a passphrase using the supervisor index and already-open account key.
    ///
    /// # Errors
    /// Returns an error for a wrong secret, missing key wrapping, or a locked account.
    pub fn verify_active_account_secret(
        &self,
        account_id: &str,
        secret: &[u8],
    ) -> Result<(), SdkError> {
        let account_index = self.account_index()?;
        let _writer = account_index.acquire_account_writer(account_id)?;
        let vault_secret = self.vault_secret_source()?.vault_secret(account_id)?;
        let wrapping_key = account_db_key_encryption_key(&vault_secret, secret);
        let wrapped =
            account_index.load_wrapped_db_key(account_id)?.ok_or(SdkError::AccountDbNotUnlocked)?;
        let key = unwrap_with_vault_secret(&wrapping_key, &wrapped)?;
        self.account_db()?.verify_key(&key)?;
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

    pub(crate) fn seal_new_account_data(
        &self,
        local_account_id: &str,
        expected_anchor: &str,
        secret: &[u8],
    ) -> Result<(), SdkError> {
        let index = self.account_index()?;
        let _writer = index.acquire_account_writer(local_account_id)?;
        if index.account(local_account_id)?.principal_commitment != expected_anchor
            || index.load_wrapped_db_key(local_account_id)?.is_some()
        {
            return Err(SdkError::CustodySetupInvalid);
        }
        let local_secret =
            zeroize::Zeroizing::new(self.vault_secret_source()?.vault_secret(local_account_id)?);
        let wrapping =
            zeroize::Zeroizing::new(account_db_key_encryption_key(&local_secret, secret));
        let key = AccountDbKey::generate()?;
        let db = AccountDb::open(index, local_account_id, &key)?;
        let wrapped = db.wrap_current_db_key(&wrapping)?;
        index.store_wrapped_db_key(local_account_id, &wrapped)?;
        drop(db);
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn unlock_account(
        &mut self,
        local_account_id: &str,
        secret: &[u8],
    ) -> Result<(), SdkError> {
        let root = self.account_index()?.root().to_path_buf();
        let born = if crate::custody::account_exists(&root, local_account_id)? {
            match crate::custody::load_data_account(
                &root,
                local_account_id,
                crate::custody::network_now()?,
            ) {
                Ok(account) => {
                    if self.account_index()?.account(local_account_id)?.principal_commitment
                        != account.record().body.account_anchor
                    {
                        return Err(SdkError::CustodySetupInvalid);
                    }
                    Some(Box::new(account))
                }
                Err(SdkError::Io(ref cause)) if cause.kind() == std::io::ErrorKind::NotFound => {
                    if crate::custody::pairing::recipient::unadmitted_data_unlock(
                        &root,
                        local_account_id,
                    )? {
                        None
                    } else {
                        return Err(SdkError::NetworkingPending);
                    }
                }
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        // Custody validation comes first; key wrapping and vault access share writer ownership.
        let _writer = self.account_index()?.acquire_account_writer(local_account_id)?;
        let wrapped = self.account_index()?.load_wrapped_db_key(local_account_id)?;
        if born.is_some() && wrapped.is_none() {
            return Err(SdkError::CustodySetupInvalid);
        }
        let account_index = self.account_index()?;
        let vault_secret = self.vault_secret_source()?.vault_secret(local_account_id)?;
        let key_encryption_key = account_db_key_encryption_key(&vault_secret, secret);
        let key = if let Some(wrapped) = wrapped {
            unwrap_with_vault_secret(&key_encryption_key, &wrapped)?
        } else {
            let generated = AccountDbKey::generate()?;
            let (nonce, wrapped_key) =
                wrap_with_vault_secret(&key_encryption_key, generated.bytes())?;
            account_index.store_wrapped_db_key(
                local_account_id,
                &WrappedAccountDbKey {
                    key_wrapping_provider: "platform-local-vault".to_owned(),
                    key_wrapping_ref: FileVaultSecretSource::owner_ref(local_account_id),
                    nonce,
                    wrapped_key,
                },
            )?;
            generated
        };
        let mut db = AccountDb::open(account_index, local_account_id, &key)?;
        if born.is_some() {
            crate::bus::group_conversation::repair_on_open(&db)?;
            self.identity_root = None;
            self.device_branch = None;
            self.reader_device_identity = None;
            self.reader_account_root = None;
        }
        if let Some(device_branch) = self.device_branch.clone() {
            db.set_device_signer(device_branch);
        }
        super::contact_verification::migrate_legacy_contact_verifications(&db)?;
        self.born_v3_account = born;
        self.object_store.replace_persisted(Vec::new(), BTreeMap::new());
        self.active_account_db = Some(db);
        self.bind_object_retirement()?;
        Ok(())
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn rekey_active_account(
        &mut self,
        local_account_id: &str,
        new_secret: &[u8],
    ) -> Result<(), SdkError> {
        let _writer = self.account_index()?.acquire_account_writer(local_account_id)?;
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
        let db = self.account_db()?;
        match db.event_body(event_id)? {
            Some(body) => Ok(Some(body)),
            None => Ok(db.archived_backup_event_body(event_id)?),
        }
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
        Ok(self.account_db()?.persist_legacy_checkpoint_if_inactive(
            &gateway_cursor_checkpoint_name(target_delivery_id),
            &inbox_seq.to_string(),
        )?)
    }

    /// # Errors
    /// Returns an error when the account DB is locked or the receive cursor cannot be stored.
    pub fn persist_gateway_receive_cursor(
        &self,
        target_delivery_id: &str,
        inbox_seq: u64,
    ) -> Result<(), SdkError> {
        Ok(self.account_db()?.persist_receive_cursor_if_inactive(target_delivery_id, inbox_seq)?)
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
        crate::gateway::apply_session_push_advertise(
            &mut config,
            self.account_db()?.receive_activation()?,
        );
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

pub(crate) fn account_db_key_encryption_key(vault_secret: &[u8; 32], secret: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ramflux.account_db_kek.v2");
    hasher.update(vault_secret);
    hasher.update(secret);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
#[path = "account_tests.rs"]
mod tests;

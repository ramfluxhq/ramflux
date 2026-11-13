// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Pairing handback drains old readers and session work before the new generation starts.
use super::AccountRuntime;
use crate::prelude::{SdkError, local_bus_error_code};

impl AccountRuntime {
    pub(super) async fn service_pairing_data(&mut self) {
        let prior = self.pairing_database_path();
        match super::super::pairing::adopt_installed(&mut self.state, &self.id) {
            Ok(_) => {}
            Err(error) => tracing::warn!(
                error_code = local_bus_error_code(&error),
                "pairing frontend handback deferred"
            ),
        }
        let result = self.state.accounts.get_mut(&self.id).map_or(Ok(false), |account| {
            crate::custody::pairing::service_frontend(
                &self.state.config.data_root,
                &self.id,
                &mut account.client,
            )
        });
        if (self.pairing_database_path() != prior || self.pairing_readers_stale())
            && let Err(error) = Box::pin(self.restart_pairing_generation()).await
        {
            tracing::warn!(
                error_code = local_bus_error_code(&error),
                "pairing selected generation startup deferred"
            );
        }
        match result {
            Ok(true) => {
                if let Some(account) = self.state.accounts.get_mut(&self.id)
                    && let Err(error) = super::super::pairing::refresh_source_role(account)
                {
                    tracing::debug!(
                        error_code = local_bus_error_code(&error),
                        "pairing public role refresh deferred"
                    );
                }
            }
            Ok(false) => {}
            Err(error) => tracing::warn!(
                error_code = local_bus_error_code(&error),
                "pairing local data step deferred; account remains open"
            ),
        }
    }
    fn pairing_readers_stale(&self) -> bool {
        let selected = self.pairing_database_path();
        self.readers.lock().ok().is_some_and(|slot| {
            slot.as_ref().is_some_and(|pool| {
                selected.as_deref().is_some_and(|path| path != pool.generation_path())
            })
        })
    }
    pub(super) async fn refresh_pairing_reader_generation(&mut self) -> Result<(), SdkError> {
        if self.pairing_readers_stale() {
            Box::pin(self.restart_pairing_generation()).await?;
        }
        Ok(())
    }
    fn pairing_database_path(&self) -> Option<std::path::PathBuf> {
        self.state
            .accounts
            .get(&self.id)
            .and_then(|account| account.client.account_db().ok())
            .map(|db| db.path.clone())
    }
    async fn restart_pairing_generation(&mut self) -> Result<(), SdkError> {
        self.ledger = None;
        self.stop_courier().await;
        self.stop_connection().await;
        self.close_readers().await;
        self.transfers.stop().await;
        self.transfers = super::uploads::Transfers::start();
        if let Some(account) = self.state.accounts.get_mut(&self.id) {
            let native =
                account.client.born_v3_account.as_ref().ok_or(SdkError::CustodySetupInvalid)?;
            account.gateway_config = account.gateway_config.clone().with_born_v3_account(native);
            account.activation_pending = true;
        }
        self.initialize_readers()?;
        self.start_connection()?;
        self.start_courier();
        Ok(())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Reader-pool installation, snapshot publication and teardown.

use super::{AccountRuntime, stopped};
use crate::bus::readers::AccountReaders;
use crate::prelude::{
    LocalBusFrame, SdkError, local_bus_account_manifest_path, now_unix_timestamp,
};

impl AccountRuntime {
    pub(super) fn initialize_readers(&mut self) -> Result<(), SdkError> {
        let missing = self.readers.lock().map_err(|_| stopped())?.is_none();
        if missing && let Some(account) = self.state.accounts.get_mut(&self.id) {
            account.client.object_store.set_cache_capacity(8);
            super::super::control_state::trim(account);
            super::super::read_model::initialize(account)?;
            let db = account.client.account_db()?;
            let path = local_bus_account_manifest_path(&self.state.config.data_root, &self.id);
            let node_id = if account.client.born_v3_account.is_some() {
                db.load_actor_state::<String>("account/node-id")?
            } else {
                super::super::sync_status::optional_manifest(&path)
                    .and_then(|manifest| manifest.node_id)
            };
            db.persist_actor_state("sync/node-id", &node_id)?;
            let tick = db.journal_bounds()?.head_seq;
            db.append_journal(
                &format!("account:unlocked:{tick}"),
                "account.state",
                &serde_json::json!({"local_account_id":self.id,"state":"unlocked"}),
                now_unix_timestamp(),
                None,
            )?;
            let pool = AccountReaders::start(db, account.client.owned_device_identity().ok())?;
            pool.set_account_view(&self.state, &self.id)?;
            *self.readers.lock().map_err(|_| stopped())? = Some(pool);
        }
        Ok(())
    }

    pub(super) async fn close_readers(&self) {
        let pool = self.readers.lock().ok().and_then(|mut readers| readers.take());
        if let Some(pool) = pool {
            pool.stop().await;
        }
    }

    pub(super) async fn publish(&self, request: &LocalBusFrame) -> Result<(), SdkError> {
        if let Some(account) = self.state.accounts.get(&self.id) {
            if let Some(pool) = self.readers.lock().map_err(|_| stopped())?.as_ref() {
                pool.set_identity(account.client.owned_device_identity().ok())?;
                pool.set_account_view(&self.state, &self.id)?;
            }
            let expiry = self.networking_expiry_pending.then(|| self.networking_expiry_request());
            super::super::events::publish(
                &account.client,
                &self.id,
                request,
                expiry.as_ref(),
                &self.events,
            )
            .await?;
        }
        Ok(())
    }
}

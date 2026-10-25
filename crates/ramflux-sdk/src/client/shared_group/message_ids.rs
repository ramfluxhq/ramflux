// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Caller ids are aliases owned by this authenticated sender, never global claims.
use crate::prelude::*;
use serde::{Deserialize, Serialize};
#[derive(Deserialize, Serialize)]
struct Alias {
    group: String,
    root: String,
    device: String,
    logical: String,
}
impl RamfluxClient {
    pub(crate) fn qualify_outgoing_group_message(
        &self,
        group: &str,
        supplied: &str,
    ) -> Result<(String, String), SdkError> {
        let own = self.owned_device_identity()?;
        let logical = if let Some(alias) = self
            .account_db()?
            .load_actor_state::<Alias>(&format!("group-message/alias/{supplied}"))?
        {
            if alias.group != group
                || alias.root != own.root_commitment()
                || alias.device != own.device_id()
            {
                return Err(StorageError::GroupPermissionDenied.into());
            }
            alias.logical
        } else {
            supplied.into()
        };
        if logical.is_empty() || logical.len() > 256 {
            return Err(SdkError::LocalBus("group logical message id budget exceeded".into()));
        }
        let canonical = ramflux_protocol::group_message_id(
            group,
            own.root_commitment(),
            own.device_id(),
            &logical,
        )?;
        self.account_db()?.persist_actor_state(
            &format!("group-message/alias/{canonical}"),
            &Alias {
                group: group.into(),
                root: own.root_commitment().into(),
                device: own.device_id().into(),
                logical: logical.clone(),
            },
        )?;
        Ok((canonical, logical))
    }
    pub(crate) fn outgoing_group_logical_id(
        &self,
        canonical: &str,
    ) -> Result<Option<String>, SdkError> {
        let Some(alias) = self
            .account_db()?
            .load_actor_state::<Alias>(&format!("group-message/alias/{canonical}"))?
        else {
            return Ok(None);
        };
        let own = self.owned_device_identity()?;
        if alias.root != own.root_commitment() || alias.device != own.device_id() {
            return Err(StorageError::GroupPermissionDenied.into());
        }
        Ok(Some(alias.logical))
    }
}

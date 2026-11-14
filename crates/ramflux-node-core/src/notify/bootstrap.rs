// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Restore and fund preexisting local rows before the service accepts notification work.

use super::{NOTIFY_CREDENTIAL_TABLE, NOTIFY_ROUTE_TABLE, NodeCoreError, NotifyRedbStore};
use crate::send_authority::{AuthorityScope, SendAuthorityError};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::Redb(error.to_string())
}

fn page(
    db: &redb::Database,
    definition: TableDefinition<&str, &[u8]>,
    after: Option<&str>,
) -> Result<Vec<String>, NodeCoreError> {
    let tx = db.begin_read().map_err(error)?;
    let table = tx.open_table(definition).map_err(error)?;
    let range = match after {
        Some(after) => {
            table.range::<&str>((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
        }
        None => table.range::<&str>(..),
    }
    .map_err(error)?;
    range
        .take(128)
        .map(|entry| {
            let (key, _) = entry.map_err(error)?;
            if key.value().len() > 512 {
                return Err(SendAuthorityError::Invalid.into());
            }
            Ok(key.value().to_owned())
        })
        .collect()
}

impl NotifyRedbStore {
    /// Fund existing route/credential rows and reconcile local fences before serving traffic.
    /// Call after configuring the coordinator's identities and root budget.
    /// # Errors
    /// Corrupt, uncertain or over-capacity startup data remains closed and refuses startup.
    pub fn restore_notification_authority(&self) -> Result<(), NodeCoreError> {
        let _writer = self.local_writer.try_lock().map_err(|_| SendAuthorityError::Busy)?;
        for routes in [true, false] {
            let mut cursor = None;
            loop {
                let keys = page(
                    &self.db,
                    if routes { NOTIFY_ROUTE_TABLE } else { NOTIFY_CREDENTIAL_TABLE },
                    cursor.as_deref(),
                )?;
                for key in &keys {
                    let scope = if routes {
                        AuthorityScope::TargetRoutes { target_delivery_id: key.clone() }
                    } else {
                        AuthorityScope::Credential { credential_id: key.clone() }
                    };
                    self.resume_local_mutation(&scope)?;
                    if self.send_authority.pin(&scope).is_err() {
                        let tx = self.db.begin_write().map_err(error)?;
                        if routes {
                            self.commit_route_transaction(tx, key)?;
                        } else {
                            self.commit_credential_transaction(tx, key)?;
                        }
                    }
                }
                if keys.len() < 128 {
                    break;
                }
                cursor = keys.last().cloned();
            }
        }
        Ok(())
    }
}

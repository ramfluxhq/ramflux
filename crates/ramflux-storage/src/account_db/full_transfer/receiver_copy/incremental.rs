// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The fourth attempt refreshes a retained union from local B row differences only.
use super::{FullReceiverBaseCopy, FullTransferStage, seal, sql_delta, wrong};
use crate::{BackupDatabase, StorageError};
use ramflux_protocol::custody::pairing::full_transfer::Disposition;
use std::collections::BTreeSet;

impl FullReceiverBaseCopy {
    pub(super) fn rebase_current_target(
        &mut self,
        stage: &FullTransferStage<'_>,
    ) -> Result<(), StorageError> {
        stage.require_io()?;
        super::rebase::require_before_selection(stage)?;
        self.attested
            .lock()
            .map_err(|_| wrong())?
            .as_ref()
            .ok_or_else(wrong)?
            .require(&self.scratch.path)?;
        if self.stage_digest != stage.resume_record()?.stage_digest()? || self.union.is_none() {
            return Err(wrong());
        }
        let observation = self.observation.refresh_current(stage.db)?;
        let schema = stage.db.inspect_full_transfer_schema(super::super::full_transfer_catalog())?;
        schema.require_typed_owners(super::super::full_transfer_catalog())?;
        let current =
            BackupDatabase::open_full_selected_read(&stage.db.path, &stage.db.current_key)?;
        observation.require_current(stage.db)?;
        let mut private = BackupDatabase::open_full_receiver_copy(
            &self.scratch.path.join("private.db"),
            &self.key,
        )?;
        sql_delta::attach(&mut private.db, &stage.db.path, &stage.db.current_key)?;
        self.union = None;
        self.attested.lock().map_err(|_| wrong())?.take();
        private.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let tables: BTreeSet<_> = super::super::full_transfer_catalog()
                .iter()
                .filter_map(|rule| match rule.selector {
                    super::super::FamilySelector::Table(table)
                        if rule.disposition != Disposition::Transfer
                            && table != "account_key_check" =>
                    {
                        Some(table)
                    }
                    _ => None,
                })
                .collect();
            for table in tables {
                stage.require_io()?;
                sql_delta::table(&private.db, table)?;
            }
            sql_delta::sequences(&private.db)?;
            let encoding = self.contributions.rebase_target(
                &self.scratch.path.join("contributions.db"),
                &self.key,
                &mut private,
                stage,
                super::super::receiver_contributions::TargetRows {
                    current: &current,
                    schema: &schema,
                },
            )?;
            observation.require_current(stage.db)?;
            stage.require_io()?;
            private.db.execute_batch("COMMIT")?;
            Ok::<_, StorageError>(encoding)
        })();
        let encoding = match result {
            Ok(encoding) => encoding,
            Err(error) => {
                let _ = private.db.execute_batch("ROLLBACK");
                return Err(error);
            }
        };
        drop(private);
        drop(current);
        let sealed = seal::CopySeal::capture(&self.scratch.path)?;
        self.observation = observation;
        self.union = Some(encoding);
        *self.attested.lock().map_err(|_| wrong())? = Some(sealed);
        self.verify_input(stage)
    }
}

#[cfg(test)]
mod tests;

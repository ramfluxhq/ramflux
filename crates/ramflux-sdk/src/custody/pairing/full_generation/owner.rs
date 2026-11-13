// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Owned G1/G2/G3 sequence. Native queries finish before borrowing the actual B writer.
use super::{FullGenerationManifest, pending, require_selected_full_generation};
use crate::custody::pairing::{
    Installation,
    install_store::{self, FullInstall, Install, PriorGeneration},
};
use crate::{SdkError, bus::backup_jobs::full_generation::FullGenerationDirectory, custody};
use ramflux_protocol::custody::{CustodyAuthority, object_hash};
use ramflux_storage::{
    FullPreparedReceiverDatabase, FullReceiverBaseCopy, FullReceiverDatabaseWork,
    FullSelectedReceiverGeneration, FullTransferStage,
};

mod stage;
use stage::InstallStage;

/// Root-drained local G1 work. No original writer or network/signing capability.
pub struct FullGenerationPreparation {
    database: FullReceiverDatabaseWork,
    directory: FullGenerationDirectory,
    install: Install,
}
/// Durable G1 retained by the common backup/pairing generation owner.
pub struct FullGenerationPrepared {
    database: FullPreparedReceiverDatabase,
    directory: FullGenerationDirectory,
    install: Install,
}
/// Exact selected data generation, still fenced until native files and G3 agree.
pub struct FullGenerationCommitted {
    data: FullSelectedReceiverGeneration,
    directory: FullGenerationDirectory,
    install: Install,
}
pub(crate) struct FullGenerationRecoveryPreparation {
    data: ramflux_storage::FullGenerationRecoveryWork,
    directory: FullGenerationDirectory,
    install: Install,
}
pub(crate) struct FullGenerationRecoveryPrepared {
    data: ramflux_storage::FullGenerationRecoveryDraft,
    directory: FullGenerationDirectory,
    install: Install,
}
fn acknowledged(
    local: &Installation<'_>,
    install: &Install,
    authority: &CustodyAuthority,
) -> Result<(), SdkError> {
    let head = local.db.pairing_head()?.ok_or_else(pending)?;
    let hash = object_hash(&authority.publication.record)?;
    let actual = ramflux_storage::AccountIndex::open(local.db.account_index_root())?
        .account(&local.db.local_account_id)?;
    if local.db.local_account_id != install.account_id
        || actual.principal_commitment != install.account_anchor
        || head.operation_id != install.operation_id
        || head.state != "acknowledged"
        || head.candidate_hash != hash
        || install.record_hash.as_deref() != Some(hash.as_str())
    {
        return Err(pending());
    }
    custody::verify_generation_keys(install, authority, local.vault, local.now)
}
impl FullGenerationPreparation {
    /// Freeze locally generated paths and current B operands only after this node's J6.
    /// The caller independently fetches/validates `authority` before this short local loan;
    /// a relay ACK or peer-provided publication never satisfies that requirement.
    /// # Errors
    /// Refuses missing J6, wrong original B/keys/refs, changed input or a busy generation owner.
    pub fn pin(
        local: &Installation<'_>,
        stage: &FullTransferStage<'_>,
        copy: FullReceiverBaseCopy,
        install: Install,
        authority: &CustodyAuthority,
    ) -> Result<Self, SdkError> {
        Self::pin_stage(local, stage, copy, install, authority)
    }
    /// Finish an already-published candidate after data cancellation/expiry without restoring an epoch.
    /// # Errors
    /// Refuses wrong own native candidate/keys, missing retained data or changed current B.
    pub fn pin_reconciliation(
        local: &Installation<'_>,
        stage: &ramflux_storage::FullRecipientInstallStage<'_>,
        copy: FullReceiverBaseCopy,
        install: Install,
        authority: &CustodyAuthority,
    ) -> Result<Self, SdkError> {
        Self::pin_stage(local, stage, copy, install, authority)
    }
    fn pin_stage(
        local: &Installation<'_>,
        stage: &impl InstallStage,
        copy: FullReceiverBaseCopy,
        mut install: Install,
        authority: &CustodyAuthority,
    ) -> Result<Self, SdkError> {
        let destination = stage.destination()?;
        if install.install_purpose != "transfer_destination"
            || install.account_id != local.db.local_account_id
            || install.account_anchor != destination.account_anchor
            || install.recipient_ref != destination
            || std::fs::canonicalize(local.root)? != local.db.account_index_root()
        {
            return Err(pending());
        }
        copy.target_observation().require_current(local.db)?;
        let directory = FullGenerationDirectory::begin(local.root, &install.account_id)?;
        let prior =
            ramflux_storage::AccountIndex::open(local.root)?.account(&install.account_id)?;
        let union = copy.union_encoding().ok_or_else(pending)?;
        install.schema = "ramflux.pairing.Install.v3".into();
        install.version = 3;
        install.full_transfer = Some(FullInstall {
            chain_hash: stage.duplex(local.now)?.manifest_chain_hash().into(),
            db_relative_path: directory.relative(&directory.path().join("account.db"))?,
            object_relative_path: directory.relative(&directory.path().join("objects"))?,
            stage_id: stage.reference().stage_id.clone(),
            generation_nonce: ramflux_protocol::encode_base64url(union.generation_nonce),
            expected_prior_generation: PriorGeneration {
                db_relative_path: copy.target_observation().prior_db_relative_path().into(),
                object_relative_path: copy.target_observation().prior_object_relative_path().into(),
            },
            expected_prior_privacy_epoch: ramflux_protocol::custody::pairing::full_transfer::U64(
                copy.target_observation().privacy_epoch(),
            ),
            initial_union_root: ramflux_protocol::encode_base64url(union.chunks_root),
        });
        install.validate()?;
        acknowledged(local, &install, authority)?;
        stage.preservation(&authority.publication.record, local.now)?;
        let database = stage.prepare(
            copy,
            directory.path().join("account.db"),
            super::super::activate::adoption(&install)?,
            local.now,
        )?;
        directory.remember_prior(&prior)?;
        install.state = "adopt_prepared".into();
        install_store::write_pending(local.root, &install)?;
        Ok(Self { database, directory, install })
    }
    /// Perform bounded encrypted G1 I/O after releasing the ordinary writer loan.
    /// # Errors
    /// Refuses lock/cancel, unsupported payload owners, low space or durability errors.
    pub fn prepare(self) -> Result<FullGenerationPrepared, SdkError> {
        let Self { database, directory, install } = self;
        match database.prepare() {
            Ok(database) => Ok(FullGenerationPrepared { database, directory, install }),
            Err(error) => {
                if error.is_writer_busy() {
                    directory.discard_unselected(&install)?;
                }
                Err(error.into())
            }
        }
    }
}
impl FullGenerationPrepared {
    #[must_use]
    pub const fn install(&self) -> &Install {
        &self.install
    }
    /// Commit G2 under the actual B all-writer fence. No native query runs in this call.
    /// # Errors
    /// Refuses changed B/keys/J6/pending record, wrong G1 bytes or an uncertain G2 outcome.
    pub fn select(
        self,
        local: &Installation<'_>,
        stage: &FullTransferStage<'_>,
        authority: &CustodyAuthority,
    ) -> Result<FullGenerationCommitted, SdkError> {
        self.select_stage(local, stage, authority)
    }
    /// Select the exact reconciled G1 using the same actual writer fence and own native keys.
    /// # Errors
    /// Refuses changed B, pending-install disagreement or any uncertain G2 outcome.
    pub fn select_reconciliation(
        self,
        local: &Installation<'_>,
        stage: &ramflux_storage::FullRecipientInstallStage<'_>,
        authority: &CustodyAuthority,
    ) -> Result<FullGenerationCommitted, SdkError> {
        self.select_stage(local, stage, authority)
    }
    fn select_stage(
        self,
        local: &Installation<'_>,
        stage: &impl InstallStage,
        authority: &CustodyAuthority,
    ) -> Result<FullGenerationCommitted, SdkError> {
        acknowledged(local, &self.install, authority)?;
        stage.preservation(&authority.publication.record, local.now)?;
        if install_store::read_pending(
            local.root,
            &self.install.account_id,
            &self.install.operation_id,
        )?
        .as_ref()
            != Some(&self.install)
        {
            return Err(pending());
        }
        let marker = FullGenerationManifest::for_install(&self.install)?.encode()?;
        let full = self.install.full_transfer.as_ref().ok_or_else(pending)?;
        let index = ramflux_storage::AccountIndex::open(local.root)?;
        let wrapped = index.load_wrapped_db_key(&self.install.account_id)?.ok_or_else(pending)?;
        let selected = stage.select(
            self.database,
            &ramflux_storage::BackupIndexInstall {
                account_id: &self.install.account_id,
                principal_commitment: &self.install.account_anchor,
                db_relative_path: &full.db_relative_path,
                object_relative_path: &full.object_relative_path,
                manifest_json: &marker,
                wrapped_key: &wrapped,
            },
            local.now,
        );
        let data = match selected {
            Ok(data) => data,
            Err(error) => {
                if matches!(error, SdkError::PairingCode("Busy"))
                    || matches!(&error, SdkError::Storage(error) if error.is_writer_busy())
                {
                    self.directory.discard_unselected(&self.install)?;
                }
                return Err(error);
            }
        };
        Ok(FullGenerationCommitted { data, directory: self.directory, install: self.install })
    }
}
impl FullGenerationCommitted {
    /// Reconstruct the exact already selected G2 from its encrypted application ledger.
    /// Native observation must finish before this local installation-only operation.
    /// # Errors
    /// Refuses a foreign G2/receipt/union, unavailable original local keys or wrong native head.
    pub fn recover(
        local: &Installation<'_>,
        stage: &ramflux_storage::FullRecipientInstallStage<'_>,
        install: Install,
        authority: &CustodyAuthority,
    ) -> Result<Self, SdkError> {
        Self::pin_recovery(local, stage, install, authority)?
            .verify()?
            .accept(local, stage, authority)
    }
    pub(crate) fn pin_recovery(
        local: &Installation<'_>,
        stage: &ramflux_storage::FullRecipientInstallStage<'_>,
        install: Install,
        authority: &CustodyAuthority,
    ) -> Result<FullGenerationRecoveryPreparation, SdkError> {
        acknowledged(local, &install, authority)?;
        stage.require_preservation_after_native_ack(&authority.publication.record)?;
        let adoption = super::super::activate::adoption(&install)?;
        require_selected_full_generation(local.root, &install, &adoption)?;
        if install_store::read_pending(local.root, &install.account_id, &install.operation_id)?
            .as_ref()
            != Some(&install)
        {
            return Err(pending());
        }
        let directory = FullGenerationDirectory::recover_selected(local.root, &install)?;
        let marker = FullGenerationManifest::for_install(&install)?.encode()?;
        let data = stage.pin_generation_recovery(&marker, &adoption)?;
        Ok(FullGenerationRecoveryPreparation { data, directory, install })
    }
    /// Open the exact selected generation while ordinary network admission stays closed.
    /// # Errors
    /// Refuses root lock/cancel, replaced selection, bad key/schema or adoption disagreement.
    pub fn open_selected(&self) -> Result<ramflux_storage::AccountDb, SdkError> {
        Ok(self.data.open()?)
    }
    /// Finish only the exact published local owners, then fsync G3 and release reclamation.
    /// Caller must use an independently fetched native authority for this same candidate.
    /// This supplies no new publication/SAS consent and does not start a network session.
    /// # Errors
    /// Any owner/file/index disagreement remains fenced for exact idempotent recovery.
    pub fn finish(
        mut self,
        local: &Installation<'_>,
        authority: &CustodyAuthority,
    ) -> Result<(), SdkError> {
        let _authority =
            super::super::activate::authority_lock(local.root, &self.install.account_id)?;
        acknowledged(local, &self.install, authority)?;
        self.data.require_database(local.db)?;
        let adoption = super::super::activate::adoption(&self.install)?;
        require_selected_full_generation(local.root, &self.install, &adoption)?;
        custody::write_generation_authority(local, &self.install, authority, &self.data)?;
        let account = custody::load_data_account(local.root, &self.install.account_id, local.now)?;
        if !custody::matches_generation_install(&account, &self.install)? {
            return Err(pending());
        }
        self.install.state = "authority_durable".into();
        install_store::write_pending(local.root, &self.install)?;
        local.db.commit_pairing_install(&adoption)?;
        self.data.require_database(local.db)?;
        self.install.state = "installed".into();
        install_store::write_installed(local.root, &self.install)?;
        install_store::remove_pending(
            local.root,
            &self.install.account_id,
            &self.install.operation_id,
        )?;
        require_selected_full_generation(local.root, &self.install, &adoption)?;
        self.directory.finish_g3()?;
        local.db.retire_full_recipient_install_head(&adoption)?;
        Ok(())
    }
}

impl FullGenerationRecoveryPreparation {
    pub(crate) fn verify(self) -> Result<FullGenerationRecoveryPrepared, SdkError> {
        Ok(FullGenerationRecoveryPrepared {
            data: self.data.verify()?,
            directory: self.directory,
            install: self.install,
        })
    }
}
impl FullGenerationRecoveryPrepared {
    pub(crate) fn accept(
        self,
        local: &Installation<'_>,
        stage: &ramflux_storage::FullRecipientInstallStage<'_>,
        authority: &CustodyAuthority,
    ) -> Result<FullGenerationCommitted, SdkError> {
        acknowledged(local, &self.install, authority)?;
        stage.require_preservation_after_native_ack(&authority.publication.record)?;
        let adoption = super::super::activate::adoption(&self.install)?;
        require_selected_full_generation(local.root, &self.install, &adoption)?;
        if install_store::read_pending(
            local.root,
            &self.install.account_id,
            &self.install.operation_id,
        )?
        .as_ref()
            != Some(&self.install)
        {
            return Err(pending());
        }
        let data = self.data.accept(stage)?;
        Ok(FullGenerationCommitted { data, directory: self.directory, install: self.install })
    }
}

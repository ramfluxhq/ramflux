// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native source J6/tail-cut component. Candidate transport and tail stream remain separate.
use super::{CustodyAuthority, Rig, encode_base64url};
use crate::custody::pairing::{FullSourcePublished, FullSourceRetirementOutcome, Installation};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub(super) fn acknowledge(
    rig: &mut Rig,
    published: &FullSourcePublished,
    deferred_cleanup: bool,
) -> TestResult {
    let authority: CustodyAuthority = published.authority().clone();
    let later = rig.now + 301; // Approval expired after native publication; the lease is still live.
    ramflux_crypto::custody::verify_publication(&authority, later)?;
    let candidate_hash = ramflux_protocol::custody::object_hash(&authority.publication.record)?;
    rig.participant_a.take_client(&mut rig.source.client)?;
    let (cut, operation) = {
        let slot = rig.participant_a.db.lock().map_err(|_| "source J6 owner")?;
        let db = slot.as_ref().ok_or("source J6 writer")?;
        let cut = published.acknowledge(db, later).map_err(|error| {
            format!("J6 lost the already-published candidate after approval expiry: {error}")
        })?;
        let head = db.pairing_head()?.ok_or("source J6 head")?;
        assert_eq!(head.state, "acknowledged");
        assert_eq!(head.candidate_hash, candidate_hash);
        retire_with_deferred_cleanup(rig, published, db, later)?;
        let stage = db.open_full_transfer_stage(
            &head.operation_id,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            later,
        )?;
        assert!(
            stage
                .commit_source_ack_and_pin_tail(
                    &head,
                    &encode_base64url(ramflux_crypto::random_32()?),
                    later
                )
                .is_err(),
            "J6 silently recut the existing source tail"
        );
        assert!(stage.finish_source_tail_capture().is_err(), "missing J6 snapshot silently recut");
        drop(stage);
        (cut, head.operation_id)
    };
    rig.participant_a.return_client(&mut rig.source.client)?;
    assert!(
        crate::custody::pairing::ordinary_session_admitted(
            &rig.source.client,
            &rig.participant_a.account_id
        )?,
        "cleanup_pending closed the installed secondary branch"
    );
    rig.participant_a.take_client(&mut rig.source.client)?;
    let work = {
        let slot = rig.participant_a.db.lock().map_err(|_| "source cleanup retry")?;
        let db = slot.as_ref().ok_or("source cleanup writer")?;
        if !deferred_cleanup {
            complete_and_replay_retirement(rig, published, db, later)?;
        }
        let stage = db.open_full_transfer_stage(
            &operation,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            later,
        )?;
        let owner = stage.source_primary_owner()?.ok_or("source old owner")?;
        assert_eq!(
            rig.participant_a.vault.load_primary(owner.reference()).is_ok(),
            deferred_cleanup,
            "source cleanup changed an unexpected owner"
        );
        cut.into_private_work(stage)?
    };
    rig.participant_a.return_client(&mut rig.source.client)?;
    work.copy()?; // No ordinary writer/stage loan crosses the bulk private copy.
    rig.participant_a.take_client(&mut rig.source.client)?;
    {
        let slot = rig.participant_a.db.lock().map_err(|_| "source durable tail")?;
        let db = slot.as_ref().ok_or("source durable writer")?;
        let stage = db.open_full_transfer_stage(
            &operation,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            later,
        )?;
        stage.finish_source_tail_capture()?;
        drop(stage);
        let reopened = db.open_full_transfer_stage(
            &operation,
            ramflux_crypto::custody::pairing::PairingRole::Initiator,
            later,
        )?;
        reopened.finish_source_tail_capture()?; // Reopen the keyed cut; never recapture.
    }
    rig.participant_a.return_client(&mut rig.source.client)?;
    Ok(())
}

fn complete_and_replay_retirement(
    rig: &Rig,
    published: &FullSourcePublished,
    db: &ramflux_storage::AccountDb,
    later: u64,
) -> TestResult {
    assert_eq!(
        published.retire_source(&Installation {
            root: &rig.participant_a.root,
            db,
            vault: rig.participant_a.vault.as_ref(),
            now: later,
        })?,
        FullSourceRetirementOutcome::Complete
    );
    // Completed local retirement cannot recreate a cleanup task or touch any provider item.
    let unavailable = DeleteUnavailable(rig.participant_a.vault.as_ref());
    assert_eq!(
        published.retire_source(&Installation {
            root: &rig.participant_a.root,
            db,
            vault: &unavailable,
            now: later,
        })?,
        FullSourceRetirementOutcome::Complete
    );
    Ok(())
}

fn retire_with_deferred_cleanup(
    rig: &Rig,
    published: &FullSourcePublished,
    db: &ramflux_storage::AccountDb,
    later: u64,
) -> TestResult {
    let deferred = DeleteUnavailable(rig.participant_a.vault.as_ref());
    assert_eq!(
        published.retire_source(&Installation {
            root: &rig.participant_a.root,
            db,
            vault: &deferred,
            now: later
        })?,
        FullSourceRetirementOutcome::CleanupPending
    );
    assert!(
        db.pairing_head()?.is_none(),
        "source secondary retained the primary head-writer fence"
    );
    let account = crate::custody::load_account(
        &rig.participant_a.root,
        &rig.participant_a.account_id,
        later,
    )?;
    assert_eq!(account.primary_vault_ref(), "");
    assert!(matches!(
        account.group_primary(&deferred),
        Err(crate::SdkError::PairingCode("PrimaryRequired"))
    ));
    let branch = account.credentials(&deferred, account.local_device_id()?, later)?;
    drop(branch);
    Ok(())
}

pub(super) struct DeleteUnavailable<'a>(pub(super) &'a dyn crate::custody::PrimaryVault);
impl crate::custody::PrimaryVault for DeleteUnavailable<'_> {
    fn preflight(&self) -> Result<(), crate::SdkError> {
        self.0.preflight()
    }
    fn store_new(
        &self,
        _: &str,
        _: &ramflux_crypto::custody::SelfSigningKey,
    ) -> Result<(), crate::SdkError> {
        Err(crate::SdkError::CustodyVaultUnavailable)
    }
    fn load_primary(
        &self,
        _: &str,
    ) -> Result<ramflux_crypto::custody::SelfSigningKey, crate::SdkError> {
        Err(crate::SdkError::CustodyVaultUnavailable)
    }
    fn delete(&self, _: &str) -> Result<(), crate::SdkError> {
        Err(crate::SdkError::CustodyVaultUnavailable)
    }
    fn store_branch(
        &self,
        _: &str,
        _: &zeroize::Zeroizing<[u8; 64]>,
    ) -> Result<(), crate::SdkError> {
        Err(crate::SdkError::CustodyVaultUnavailable)
    }
    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<crate::custody::BranchCredentials, crate::SdkError> {
        self.0.load_branch(reference, principal, device)
    }
}

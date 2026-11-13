// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lose the real G2 in-memory owner, reopen with B's password, reverify bytes and finish G3.
use super::*;
use crate::custody::pairing::full_generation::owner::FullGenerationCommitted;
pub(super) fn finish_after_g2_restart(
    rig: &Rig,
    committed: FullGenerationCommitted,
    install: &Install,
    authority: &CustodyAuthority,
) -> Result<ramflux_storage::AccountDb, Box<dyn std::error::Error>> {
    // The old ordinary B writer is positively retired. No key/proof from this
    // committed owner crosses into recovery; only the original private credential does.
    drop(committed);
    let mut frontend = crate::RamfluxClient::new();
    frontend.open_account_index(&rig.participant_b.root)?;
    assert!(
        frontend.unlock_account(&rig.participant_b.account_id, b"wrong-original-password").is_err(),
        "test: G2 crash recovery bypassed B's wrapping"
    );
    frontend.unlock_account(&rig.participant_b.account_id, b"component-recipient-passphrase")?;
    assert!(
        !crate::custody::pairing::ordinary_session_admitted(
            &frontend,
            &rig.participant_b.account_id
        )?,
        "test: G2-only password unlock opened ordinary admission"
    );
    let current = rig.participant_b.query.current_authority(&install.account_anchor)?;
    assert_eq!(
        current.publication.record, authority.publication.record,
        "test: recovery query returned another candidate"
    );
    let verified = ramflux_crypto::custody::verify_publication(&current, rig.now)?;
    let db = frontend.account_db()?;
    let stage = db.open_full_recipient_install_stage(&install.operation_id, &verified, rig.now)?;
    let local = Installation {
        root: &rig.participant_b.root,
        db,
        vault: rig.participant_b.vault.as_ref(),
        now: rig.now,
    };
    let mut wrong = install.clone();
    wrong.full_transfer.as_mut().ok_or("test: full install")?.generation_nonce =
        encode_base64url([99; 32]);
    assert!(
        FullGenerationCommitted::recover(&local, &stage, wrong, &current).is_err(),
        "test: recovery accepted another G1 nonce with identical paths"
    );
    let recovered = FullGenerationCommitted::recover(&local, &stage, install.clone(), &current)?;
    drop(stage);
    let selected = super::finish_installed(rig, recovered, install, &current)?;
    assert!(
        crate::custody::pairing::ordinary_session_admitted(
            &frontend,
            &rig.participant_b.account_id
        )?,
        "test: exact recovered G3 did not admit the original data owner"
    );
    Ok(selected)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn pairing_full_selected_g2_reopens_from_encrypted_union_before_g3() -> TestResult {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
        hold.finish().await?;
        result
    }
    async fn run() -> TestResult {
        let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
        rig.primary.sync_relay().await?;
        rig.participant_a.return_client(&mut rig.source.client)?;
        Box::pin(finish_owned_stream(&mut rig)).await?;
        let published = Box::pin(publication(&mut rig, &operation)).await?;
        install_generation_case(&rig, &operation, published, true)?;
        rig.primary.lock().await?;
        rig.secondary.lock().await?;
        Ok(())
    }
}

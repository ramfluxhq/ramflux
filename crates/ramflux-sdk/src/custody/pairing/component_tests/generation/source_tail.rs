// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native source J6/tail-cut component. Candidate transport and tail stream remain separate.
use super::{CustodyAuthority, Rig, encode_base64url};
use crate::custody::pairing::FullSourcePublished;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub(super) fn acknowledge(rig: &mut Rig, published: FullSourcePublished) -> TestResult {
    let authority: CustodyAuthority = published.authority().clone();
    let later = rig.now + 301; // Approval expired after native publication; the lease is still live.
    ramflux_crypto::custody::verify_publication(&authority, later)?;
    let candidate_hash = ramflux_protocol::custody::object_hash(&authority.publication.record)?;
    rig.participant_a.take_client(&mut rig.source.client)?;
    let work = {
        let slot = rig.participant_a.db.lock().map_err(|_| "source J6 owner")?;
        let db = slot.as_ref().ok_or("source J6 writer")?;
        let cut = published.acknowledge(db, later).map_err(|error| {
            format!("J6 lost the already-published candidate after approval expiry: {error}")
        })?;
        let head = db.pairing_head()?.ok_or("source J6 head")?;
        assert_eq!(head.state, "acknowledged");
        assert_eq!(head.candidate_hash, candidate_hash);
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
        cut.into_private_work(stage)?
    };
    rig.participant_a.return_client(&mut rig.source.client)?;
    work.copy()?; // No ordinary writer/stage loan crosses the bulk private copy.
    rig.participant_a.take_client(&mut rig.source.client)?;
    {
        let slot = rig.participant_a.db.lock().map_err(|_| "source durable tail")?;
        let db = slot.as_ref().ok_or("source durable writer")?;
        let operation = db.pairing_head()?.ok_or("source durable head")?.operation_id;
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

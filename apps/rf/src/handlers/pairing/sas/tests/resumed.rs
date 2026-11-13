// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The actual file comparison and attended candidate path grant different, fresh consent.
use super::*;
use ramflux_protocol::custody::pairing::local_dto::TransferAffirm;

#[tokio::test]
async fn pairing_cli_sas_and_resumed_candidate_affirmation() -> TestResult {
    super::super::super::tests::deadline(async {
        let owner = tempfile::tempdir()?;
        let operation = ramflux_protocol::encode_base64url([71; 32]);
        let socket = owner.path().join("bus.sock");
        let local = owner.path().join("local-sas");
        let peer = owner.path().join("peer-sas");
        write_sas(&socket, &local, &operation, &[0, 1, 2, 3, 4, 5, 6], "initiator")?;
        let Outcome::Update { value: original } =
            current(&operation, &[0, 1, 2, 3, 4, 5, 6]).outcome
        else {
            return Err("test: SAS view missing".into());
        };
        let old_sas = comparison::encode(&original, "responder")?;
        InvitationOutput::create(peer.clone())?.commit(&old_sas)?;
        confirm_case(&socket, &operation, &peer, true).await?;
        assert!(
            !local.exists() && !peer.exists(),
            "test: SAS approval left reusable comparison files"
        );
        assert_resumed_candidate(*original, &old_sas)?;
        Ok(())
    })
    .await
}

fn assert_resumed_candidate(mut current: Update, old_sas: &[u8]) -> TestResult {
    current.generation = 2;
    current.phase = "proposal_pending".into();
    current.emoji_indices = None;
    current.proposal_hash = Some(ramflux_protocol::encode_base64url([72; 32]));
    assert!(
        comparison::peer_matches(&current, "initiator", old_sas).is_err(),
        "test: old SAS file restored approval after data-only reconnect"
    );
    let mut request = TransferAffirm {
        schema: "ramflux.pairing.TransferAffirm.v2".into(),
        version: 2,
        operation_id: current.operation_id.clone(),
        generation: 2,
        transcript_hash: current.transcript_hash.clone().ok_or("test: transcript missing")?,
        new_record_hash: current.proposal_hash.clone().ok_or("test: candidate missing")?,
        approved: true,
    };
    let mut stale = current.clone();
    stale.generation = 1;
    let prompted = std::cell::Cell::new(false);
    let rejected = super::super::super::transfer::attended_affirm(&mut request, &stale, |_| {
        prompted.set(true);
        Ok(zeroize::Zeroizing::new("affirm".into()))
    });
    assert!(
        rejected.is_err() && !prompted.get(),
        "test: stale generation reached attended approval"
    );
    super::super::super::transfer::attended_affirm(&mut request, &current, |_| {
        Ok(zeroize::Zeroizing::new("match".into()))
    })?;
    assert!(!request.approved, "test: SAS match text approved a resumed candidate");
    let expected = request.new_record_hash.clone();
    super::super::super::transfer::attended_affirm(&mut request, &current, |prompt| {
        assert!(
            prompt.contains(&expected),
            "test: terminal did not display exact resumed candidate"
        );
        Ok(zeroize::Zeroizing::new("affirm".into()))
    })?;
    assert!(request.approved, "test: fresh attended candidate affirmation was not retained");
    current.proposal_hash = Some(ramflux_protocol::encode_base64url([73; 32]));
    assert!(
        super::super::super::transfer::attended_affirm(&mut request, &current, |_| Err(invalid()))
            .is_err(),
        "test: changed candidate reused prior affirmation"
    );
    Ok(())
}

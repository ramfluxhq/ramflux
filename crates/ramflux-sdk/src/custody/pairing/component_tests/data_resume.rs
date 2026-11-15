// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! New B reopens its actual encrypted stage through the private original credential.
#[cfg(test)]
mod tests {
    use super::super::*;
    use ramflux_crypto::custody::pairing::PairingRole;
    use ramflux_protocol::custody::pairing::{
        PairingWire, context_v3::TranscriptV3, local_dto::StatusRequest,
    };
    #[tokio::test(start_paused = true)]
    async fn pairing_full_new_recipient_cold_resume_requires_original_private_unlock() -> TestResult
    {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
        hold.finish().await?;
        result
    }
    async fn run() -> TestResult {
        let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
        let (request, record) = retained_b(&rig, &operation)?;
        let context = TranscriptV3::from_wire_bytes(&record.transcript)?;
        let original_key = context.responder.hpke_key.clone();
        let mut relay = None;
        rig.secondary.wrap_transport_for_test(|inner| {
            relay = Some(inner.clone());
            inner
        });
        rig.secondary.lock().await?;
        let wrong = crate::custody::pairing::recipient::tests::Phrase::setup(b"wrong-password");
        assert!(
            crate::bus::unlock_for_test(
                &rig.participant_b.root,
                &rig.participant_b.account_id,
                &request,
                &wrong
            )
            .is_err(),
            "test: wrong private password reopened the DATA-only stage"
        );
        let db = crate::bus::unlock_for_test(
            &rig.participant_b.root,
            &rig.participant_b.account_id,
            &request,
            rig.participant_b.provider.as_ref(),
        )?;
        assert!(db.pairing_adoption()?.is_none(), "test: private unlock fabricated G3 admission");
        *rig.participant_b.db.lock().map_err(|_| "test: new B writer")? = Some(db);
        let mut secondary = PairingActor::new(
            PairingIdentity {
                account_id: rig.participant_b.account_id.clone(),
                local_ref: record.grant.destination_ref,
                master_public_key: Some(context.initiator.common.master_public_key),
                base_record_hash: record.base_record_hash,
                base_epoch: context.initiator.common.device_set_epoch,
                is_primary: false,
            },
            None,
            relay.ok_or("test: own relay")?,
            PairingConfig { enabled: true, extra_root_ca_pem: None },
        );
        secondary.set_participant(rig.participant_b.clone());
        secondary.set_full_node(
            crate::custody::network_tests::node(
                rig.now,
                ramflux_protocol::encode_base64url([29; 32]),
            )
            .map_err(|error| error.to_string())?,
        );
        rig.secondary = secondary;
        rig.secondary.resume_full_data(&request).await?;
        rig.participant_a.return_client(&mut rig.source.client)?;
        Box::pin(finish_owned_stream(&mut rig)).await?;
        assert!(
            rig.participant_b
                .db
                .lock()
                .map_err(|_| "test: new B writer")?
                .as_ref()
                .ok_or("test: reopened B")?
                .pairing_adoption()?
                .is_none(),
            "test: resumed data duplex admitted an ordinary account"
        );
        {
            let seen = rig.full_hellos.lock().map_err(|_| "test: own proofs")?;
            assert!(
                seen.iter().any(|hello| hello.role == "responder"
                    && Some(&hello.hpke_key) != original_key.as_ref()),
                "test: new B resume reused its lost SAS HPKE key"
            );
        }
        assert!(
            rig.secondary.displayed_proposal().is_err(),
            "test: new B resume reconstructed human approval"
        );
        rig.primary.lock().await?;
        rig.secondary.lock().await?;
        Ok(())
    }
    fn retained_b(
        rig: &Rig,
        operation: &str,
    ) -> Result<
        (StatusRequest, ramflux_crypto::custody::pairing::FullResumeRecord),
        Box<dyn std::error::Error>,
    > {
        let slot = rig.participant_b.db.lock().map_err(|_| "test: original B writer")?;
        let db = slot.as_ref().ok_or("test: original B DB")?;
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or("test: B live row")?;
        let stage = db.open_full_transfer_stage(operation, PairingRole::Responder, rig.now)?;
        Ok((
            StatusRequest {
                schema: "ramflux.pairing.StatusRequest.v2".into(),
                version: 2,
                operation_id: operation.into(),
                generation: live.generation,
            },
            stage.resume_record()?,
        ))
    }
}

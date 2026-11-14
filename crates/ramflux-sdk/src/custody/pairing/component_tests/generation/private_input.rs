// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual B candidate scope gates the same-connection private phrase consumer.
#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::custody::pairing::{
        CredentialOutcome, LocalPairingParticipant, SecretUtf8,
        private_credential::{
            PrivateCredentialCallKind, bind_call, encode_reply, provider_for_account,
        },
    };
    use ramflux_protocol::custody::pairing::local_dto::Prepare;
    use std::sync::{Arc, Mutex};
    fn request(rig: &Rig, operation: &str) -> Result<Prepare, Box<dyn std::error::Error>> {
        let slot = rig.participant_b.db.lock().map_err(|_| "B original owner")?;
        let db = slot.as_ref().ok_or("B writer")?;
        let live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or("B live")?;
        let stage = db.open_full_transfer_stage(
            operation,
            ramflux_crypto::custody::pairing::PairingRole::Responder,
            rig.now,
        )?;
        Ok(Prepare {
            schema: "ramflux.pairing.Prepare.v2".into(),
            version: 2,
            operation_id: operation.into(),
            generation: live.generation,
            transcript_hash: encode_base64url(stage.resume_record()?.th),
        })
    }
    fn phase(rig: &Rig, operation: &str, value: &str) -> TestResult {
        let slot = rig.participant_b.db.lock().map_err(|_| "B original owner")?;
        let db = slot.as_ref().ok_or("B writer")?;
        let mut live = db
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or("B live")?;
        live.phase = value.into();
        live.proposal_hash =
            if value == "proposal_pending" { Some(encode_base64url([92; 32])) } else { None };
        db.put_pairing_live(&live)?;
        Ok(())
    }
    async fn attended_rig() -> Result<(Rig, String), Box<dyn std::error::Error>> {
        let (mut rig, operation, _) = Box::pin(bootstrap_full_rig()).await?;
        rig.primary.sync_relay().await?;
        rig.participant_a.return_client(&mut rig.source.client)?;
        Box::pin(finish_owned_stream(&mut rig)).await?;
        let old = &rig.participant_b;
        let owner = Arc::new(LocalPairingParticipant {
            root: old.root.clone(),
            account_id: old.account_id.clone(),
            vault: old.vault.clone(),
            provider: provider_for_account(&old.root, old.account_id.clone())?,
            db: Mutex::new(old.db.lock().map_err(|_| "B handoff")?.take()),
            persist: old.persist.clone(),
            query: old.query.clone(),
        });
        rig.secondary.set_participant(owner.clone());
        rig.participant_b = owner;
        Ok((rig, operation))
    }
    fn refuses_unattended(
        rig: &Rig,
        request: &Prepare,
        frontend_generation: u64,
        prompts: &mut tokio::sync::mpsc::Receiver<crate::LocalBusFrame>,
    ) -> TestResult {
        let owner = &rig.participant_b;
        let mut stale = request.clone();
        stale.generation += 1;
        assert!(
            owner.prepare_full_transfer_candidate(&stale, frontend_generation).is_err(),
            "test: B preparation bypassed live role, stage or callback ownership"
        );
        assert!(
            rig.participant_a
                .prepare_full_transfer_candidate(request, frontend_generation)
                .is_err(),
            "test: B preparation bypassed live role, stage or callback ownership"
        );
        phase(rig, &request.operation_id, "proposal_pending")?;
        assert!(
            owner.prepare_full_transfer_candidate(request, frontend_generation).is_err(),
            "test: B preparation bypassed live role, stage or callback ownership"
        );
        assert!(prompts.try_recv().is_err(), "wrong generation/role/stage prompted for phrase");
        phase(rig, &request.operation_id, "mutually_confirmed")?;
        Ok(())
    }
    async fn consume_phrase(
        rig: &mut Rig,
        request: &Prepare,
        frontend_generation: u64,
        prompts: &mut tokio::sync::mpsc::Receiver<crate::LocalBusFrame>,
        channel: &Arc<crate::custody::pairing::private_credential::PrivateCredentialChannel>,
    ) -> TestResult {
        let owner = rig.participant_b.clone();
        let operation = &request.operation_id;
        for changed in [true, false] {
            let _call = bind_call(
                &owner.root,
                &owner.account_id,
                format!("prepare-{changed}"),
                PrivateCredentialCallKind::Prepare { operation_id: operation.clone() },
                channel.clone(),
            )?;
            let participant = owner.clone();
            let candidate = request.clone();
            let worker = tokio::task::spawn_blocking(move || {
                participant.prepare_full_transfer_candidate(&candidate, frontend_generation)
            });
            let prompt = prompts.recv().await.ok_or("missing B phrase prompt")?;
            assert_eq!(
                prompt.body["action"], "phrase",
                "test: B preparation bypassed live role, stage or callback ownership"
            );
            assert_eq!(
                prompt.request_id,
                format!("prepare-{changed}"),
                "test: B preparation bypassed live role, stage or callback ownership"
            );
            let phrase = rig.source.phrase.as_deref().ok_or("source phrase fixture")?;
            let public = canonical_json_bytes(&prompt)?;
            assert!(
                !public.windows(phrase.len()).any(|window| window == phrase.as_bytes()),
                "phrase entered JSON prompt"
            );
            if changed {
                phase(rig, operation, "proposal_pending")?;
            }
            let generation: u64 =
                prompt.frame_id.strip_prefix("credential-").ok_or("prompt generation")?.parse()?;
            let bytes = encode_reply(
                generation,
                "phrase",
                &CredentialOutcome::Provided {
                    passphrase: SecretUtf8::from_bytes(phrase.as_bytes())?,
                    confirmation: None,
                },
            )?;
            assert!(
                crate::bus::credentials::read_frame(&mut bytes.as_slice(), channel, 71)
                    .await?
                    .is_none(),
                "test: B preparation bypassed live role, stage or callback ownership"
            );
            let result = worker.await?;
            if changed {
                assert!(result.is_err(), "phase changed during input released a candidate");
                phase(rig, operation, "mutually_confirmed")?;
            } else {
                let candidate = result?;
                assert_eq!(
                    candidate.install().operation_id.as_str(),
                    operation.as_str(),
                    "test: B preparation bypassed live role, stage or callback ownership"
                );
                assert!(
                    owner
                        .db
                        .lock()
                        .map_err(|_| "B durable owner")?
                        .as_ref()
                        .ok_or("B writer")?
                        .pairing_head()?
                        .is_some(),
                    "private reply did not retain the real B candidate"
                );
            }
            let mut late = bytes.as_slice();
            assert!(
                crate::bus::credentials::read_frame(&mut late, channel, 71).await.is_err(),
                "test: B preparation bypassed live role, stage or callback ownership"
            );
            assert_eq!(late.len(), bytes.len() - 5, "late phrase reached generic parser");
        }
        Ok(())
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_private_reply_demux_and_phrase_scope() -> TestResult {
        let hold = ClockHold::new();
        let outcome = crate::bus::credentials::contract_tests::deadline(Box::pin(async {
            crate::bus::credentials::contract_tests::required_demux_cases().await?;
            let (mut rig, operation) = Box::pin(attended_rig()).await?;
            let owner = rig.participant_b.clone();
            let request = request(&rig, &operation)?;
            let reservation = custody::pairing::load_reservation(&owner.root, &owner.account_id)?
                .ok_or("B reservation")?;
            let (outbound, mut prompts) = tokio::sync::mpsc::channel(4);
            let input = crate::bus::credentials::connection(owner.root.clone(), 71, outbound);
            let channel = input.channel();
            refuses_unattended(&rig, &request, reservation.frontend_generation, &mut prompts)?;
            Box::pin(consume_phrase(
                &mut rig,
                &request,
                reservation.frontend_generation,
                &mut prompts,
                &channel,
            ))
            .await?;
            rig.primary.lock().await?;
            rig.secondary.lock().await?;
            Ok(())
        }))
        .await;
        hold.finish().await?;
        outcome
    }
}

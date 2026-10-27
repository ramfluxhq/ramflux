// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Serialized proof/session admission and operation execution.
use super::{
    BindingMode, BranchProofV3, CUSTODY_REQUEST_PATH, CustodyMeshRequest, CustodyPeer,
    CustodyProofAction, CustodyPublication, CustodyRefusal, CustodyServerFrame, CustodyService,
    CustodySession, CustodySessionAction, Envelope, Origin, ProofChannel, Publication,
    RelayAcceptance, RootQualifiedDeviceRef, Scope, VerifiedRecord, custody_action_hash,
    custody_session_action_hash, holder, invalid, object_hash, persistence, target,
    validate_bundle, verify_branch_proof_v3, verify_node_identity_record,
};
pub(super) struct ProofAttempt {
    pub action: CustodyProofAction,
    pub proof: Box<Envelope<BranchProofV3>>,
    pub receipt: Option<Box<Envelope<RelayAcceptance>>>,
    pub connection_id: String,
}
pub(super) struct SessionRequest {
    pub session_id: String,
    pub request: Box<ramflux_protocol::SignedRequest>,
    pub action: CustodySessionAction,
    pub connection_id: String,
}
struct Possession<'a> {
    publication: &'a CustodyPublication,
    authority: &'a VerifiedRecord,
    holder: String,
    source: std::net::IpAddr,
}
impl CustodyService {
    pub(super) fn challenge(
        &self,
        scope: Scope<'_>,
        request: CustodyMeshRequest,
    ) -> Result<CustodyServerFrame, CustodyRefusal> {
        let CustodyMeshRequest::Challenge {
            device_ref,
            action,
            binding_mode,
            client_source,
            connection_id,
        } = request
        else {
            return Err(CustodyRefusal::InvalidInput);
        };
        let Scope { peer, now, tick, origin, .. } = scope;
        if !self.node.envelope().body.channel_binding_modes.contains(&binding_mode)
            || (binding_mode == BindingMode::NoChannelBinding && !self.allow_unbound)
        {
            return Err(CustodyRefusal::BindingRefused);
        }
        if binding_mode == BindingMode::DirectExporter && matches!(origin, Origin::Proxy) {
            return Err(CustodyRefusal::BindingRefused);
        } // Mesh is never the client-facing hop.
        let holder = holder(peer, &connection_id)?;
        let challenge = self.leases().issue(
            crate::custody_sessions::ChallengeIntent {
                device: device_ref,
                action_hash: custody_action_hash(&action).map_err(invalid)?,
                holder,
                source: client_source,
                audience: self.audience.clone(),
                mode: binding_mode,
            },
            now,
            tick,
        )?;
        Ok(CustodyServerFrame::Challenge { challenge })
    }
    pub(super) fn prove(
        &self,
        scope: Scope<'_>,
        attempt: ProofAttempt,
    ) -> Result<CustodyServerFrame, CustodyRefusal> {
        let ProofAttempt { ref proof, ref receipt, ref connection_id, .. } = attempt;
        let Scope { router, store, peer, now, tick, origin, .. } = scope;
        let holder = holder(peer, connection_id)?;
        let challenge = self.leases().challenge(&proof.body.challenge_nonce, tick)?;
        if challenge.device != proof.body.device_ref
            || challenge.action_hash != custody_action_hash(&attempt.action).map_err(invalid)?
            || challenge.holder != holder
        {
            return Err(CustodyRefusal::BindingRefused);
        }
        let publication = match &attempt.action {
            CustodyProofAction::Publish { publication } => CustodyPublication {
                record: publication.record.clone(),
                compacted_ids: publication.compacted_ids.clone(),
            },
            _ => router
                .custody_record(&proof.body.device_ref.account_anchor, now)
                .map_err(invalid)?
                .ok_or(CustodyRefusal::AuthorityUnavailable)?,
        };
        let current = !matches!(attempt.action, CustodyProofAction::Publish { .. });
        let authority = router
            .verify_custody_possession_authority(&publication, now, current)
            .map_err(invalid)?;
        let historical = receipt
            .as_ref()
            .map(|receipt| {
                let record = store
                    .custody_node_history(&receipt.body.node_identity_record_hash)
                    .map_err(persistence)?
                    .ok_or(CustodyRefusal::AuthorityUnavailable)?;
                verify_node_identity_record(
                    &record,
                    &self.node.envelope().body.node_id,
                    &self.node.envelope().body.node_signing_public_key,
                    now,
                )
                .map_err(invalid)
            })
            .transpose()?;
        let channel = match proof.body.binding_mode {
            BindingMode::HomeRelayReceipt => ProofChannel::HomeRelayReceipt {
                receipt: receipt.as_deref().ok_or(CustodyRefusal::BindingRefused)?,
                historical_node: historical.as_ref().ok_or(CustodyRefusal::BindingRefused)?,
                current_node: &self.node,
            },
            BindingMode::NoChannelBinding => ProofChannel::NoChannelBinding {
                operator_opt_in: self.allow_unbound,
                receiving_node: &self.node,
            },
            BindingMode::DirectExporter => {
                let Origin::ClientTls(Some(actual)) = origin else {
                    return Err(CustodyRefusal::BindingRefused);
                };
                ProofChannel::DirectExporter { observed_hash: actual, receiving_node: &self.node }
            }
        };
        verify_branch_proof_v3(
            &authority,
            proof,
            &challenge.challenge,
            attempt.action.capability(),
            channel,
            now,
        )
        .map_err(|_| CustodyRefusal::BindingRefused)?;
        let source = challenge.source.parse().map_err(invalid)?;
        if matches!(attempt.action, CustodyProofAction::Publish { .. })
            && !router.custody_anchor_known(&publication.record.body.account_anchor)
            && let Err(error) = store.check_custody_new_principal_budget(source, now)
        {
            self.leases().reject(&proof.body.challenge_nonce);
            return Err(if matches!(error, crate::NodeCoreError::Capacity { .. }) {
                CustodyRefusal::Capacity
            } else {
                persistence(error)
            });
        }
        // Refused new-principal budgets cannot fill successful-proof replay storage.
        // No durable write precedes possession and single-use admission.
        self.leases().consume(
            &proof.body.challenge_nonce,
            &proof.body.proof_id,
            std::time::Instant::now(),
        )?;
        self.finish_proof(
            scope,
            attempt,
            Possession { publication: &publication, authority: &authority, holder, source },
        )
    }
    fn finish_proof(
        &self,
        scope: Scope<'_>,
        attempt: ProofAttempt,
        possession: Possession<'_>,
    ) -> Result<CustodyServerFrame, CustodyRefusal> {
        if let Some(permit) = scope.permit {
            let principal = attempt.proof.body.device_ref.account_anchor.clone();
            permit
                .try_grant(&principal, || self.finish_admitted_proof(scope, attempt, possession))
                .ok_or(CustodyRefusal::Busy)?
        } else {
            self.finish_admitted_proof(scope, attempt, possession)
        }
    }
    fn finish_admitted_proof(
        &self,
        scope: Scope<'_>,
        attempt: ProofAttempt,
        possession: Possession<'_>,
    ) -> Result<CustodyServerFrame, CustodyRefusal> {
        let Possession { publication, authority, holder, source } = possession;
        let Scope { router, store, now, tick, .. } = scope;
        let now = now.saturating_add(tick.elapsed().as_secs());
        let tick = std::time::Instant::now();
        let proof = attempt.proof;
        match attempt.action {
            CustodyProofAction::HomeMigration { .. } => Err(CustodyRefusal::Unsupported),
            CustodyProofAction::Publish { .. } => {
                router.publish_custody_record_from(publication, now, store, source).map_err(
                    |e| {
                        if matches!(e, crate::NodeCoreError::PrincipalIdTaken) {
                            CustodyRefusal::PrincipalIdTaken
                        } else if matches!(e, crate::NodeCoreError::Capacity { .. }) {
                            CustodyRefusal::Capacity
                        } else {
                            persistence(e)
                        }
                    },
                )?;
                Ok(CustodyServerFrame::Published {
                    record_hash: object_hash(&publication.record).map_err(invalid)?,
                })
            }
            CustodyProofAction::Register { prekey_bundle } => {
                validate_bundle(
                    authority,
                    &proof.body.device_ref,
                    &prekey_bundle,
                    "register",
                    now,
                )?;
                let delivery = target(&proof.body.device_ref)?;
                store.record_custody_prekey(&delivery, &prekey_bundle).map_err(persistence)?;
                Ok(CustodyServerFrame::Registered {
                    device_ref: proof.body.device_ref,
                    target_delivery_id: delivery,
                })
            }
            CustodyProofAction::OpenSession => {
                let delivery = target(&proof.body.device_ref)?;
                let bundle = store
                    .custody_prekey(&delivery)
                    .map_err(persistence)?
                    .ok_or(CustodyRefusal::AuthorityUnavailable)?;
                validate_bundle(authority, &proof.body.device_ref, &bundle, "message", now)?;
                let session = CustodySession {
                    session_id: String::new(),
                    target_delivery_id: delivery,
                    device_ref: proof.body.device_ref.clone(),
                    record_hash: proof.body.record_hash.clone(),
                    proof_hash: object_hash(&proof).map_err(invalid)?,
                    binding_mode: proof.body.binding_mode,
                    expires_at: proof.body.expires_at.min(now.saturating_add(300)),
                };
                let session = self.leases().open(session, holder, now, tick)?;
                Ok(CustodyServerFrame::SessionEstablished { session })
            }
        }
    }
    pub(super) fn request(
        &self,
        scope: Scope<'_>,
        attempt: SessionRequest,
    ) -> Result<CustodyServerFrame, CustodyRefusal> {
        let SessionRequest { ref session_id, ref request, ref action, ref connection_id } = attempt;
        let Scope { router, peer, now, tick, .. } = scope;
        let session =
            self.leases().session(session_id, &holder(peer, connection_id)?, now, tick)?;
        let publication = router
            .custody_record(&session.device_ref.account_anchor, now)
            .map_err(invalid)?
            .ok_or(CustodyRefusal::AuthorityUnavailable)?;
        let authority =
            router.verify_custody_possession_authority(&publication, now, true).map_err(invalid)?;
        if object_hash(&publication.record).map_err(invalid)? != session.record_hash {
            return Err(CustodyRefusal::UpdateRequired);
        }
        let cert = authority.authorize(&session.device_ref, "message", now).map_err(invalid)?;
        let source =
            RootQualifiedDeviceRef::from_custody_record(&authority, &session.device_ref.device_id)
                .map_err(invalid)?;
        if request.schema != "ramflux.signed_request.v1"
            || request.domain != ramflux_protocol::domain::SIGNED_REQUEST
            || request.version != 1
            || request.path != CUSTODY_REQUEST_PATH
            || request.method != ramflux_protocol::HttpMethod::POST
            || request.device_proof_hash != session.proof_hash
            || request.body_hash != custody_session_action_hash(action).map_err(invalid)?
            || request.source_device_id != session.device_ref.device_id
        {
            return Err(CustodyRefusal::InvalidInput);
        }
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::signed_bytes(&request).map_err(invalid)?,
            &request.signed.signature,
            &cert.branch_signing_public_key,
        )
        .map_err(invalid)?;
        ramflux_protocol::ReplayGuard::new()
            .check_signed_request(&source, request, i64::try_from(now).map_err(invalid)?)
            .map_err(invalid)?;
        self.leases().request(session_id, &request.nonce)?;
        self.perform_action(scope, &session, &authority, &source, attempt.action)
    }
    fn perform_action(
        &self,
        scope: Scope<'_>,
        session: &CustodySession,
        authority: &VerifiedRecord,
        source: &RootQualifiedDeviceRef,
        action: CustodySessionAction,
    ) -> Result<CustodyServerFrame, CustodyRefusal> {
        let Scope { router, store, now, .. } = scope;
        let cert = authority.authorize(&session.device_ref, "message", now).map_err(invalid)?;
        match action {
            CustodySessionAction::HomeMigration { .. } => Err(CustodyRefusal::Unsupported),
            CustodySessionAction::Lookup { device_ref } => {
                let p = router
                    .custody_record(&device_ref.account_anchor, now)
                    .map_err(invalid)?
                    .ok_or(CustodyRefusal::AuthorityUnavailable)?;
                let a =
                    router.verify_custody_possession_authority(&p, now, true).map_err(invalid)?;
                let delivery = target(&device_ref)?;
                let bundle = store
                    .custody_prekey(&delivery)
                    .map_err(persistence)?
                    .ok_or(CustodyRefusal::AuthorityUnavailable)?;
                validate_bundle(&a, &device_ref, &bundle, "message", now)?;
                let custodian_publication = if p.record.body.master_certificate.body.custody_kind
                    == ramflux_protocol::custody::CustodyKind::ExternalHuman
                {
                    let human = router
                        .custody_record(
                            &p.record
                                .body
                                .master_certificate
                                .body
                                .primary_device_ref
                                .account_anchor,
                            now,
                        )
                        .map_err(invalid)?
                        .ok_or(CustodyRefusal::AuthorityUnavailable)?;
                    Some(Publication { record: human.record, compacted_ids: human.compacted_ids })
                } else {
                    None
                };
                Ok(CustodyServerFrame::Peer {
                    peer: Box::new(CustodyPeer {
                        custodian_publication,
                        publication: Publication {
                            record: p.record,
                            compacted_ids: p.compacted_ids,
                        },
                        device_ref,
                        target_delivery_id: delivery,
                        prekey_bundle: bundle,
                    }),
                })
            }
            CustodySessionAction::Submit { envelope } => crate::custody_delivery::submit(
                router,
                store,
                crate::custody_delivery::DeliveryAuthority { authority, session, source },
                *envelope,
                now,
            ),
            CustodySessionAction::Inbox { after_seq, limit } => {
                if limit == 0 || limit > 100 {
                    return Err(CustodyRefusal::InvalidInput);
                }
                let inbox = router.mvp1_inbox_at(
                    &session.target_delivery_id,
                    after_seq,
                    limit as usize,
                    i64::try_from(now).map_err(invalid)?,
                );
                let entries = inbox
                    .entries
                    .iter()
                    .map(serde_json::to_value)
                    .collect::<Result<_, _>>()
                    .map_err(invalid)?;
                Ok(CustodyServerFrame::Inbox { entries })
            }
            CustodySessionAction::Close => {
                self.leases().close(&session.session_id);
                Ok(CustodyServerFrame::Closed)
            }
            CustodySessionAction::Ack { ack } => {
                Self::ack(scope, session, &cert.branch_signing_public_key, &ack)
            }
        }
    }
    fn ack(
        scope: Scope<'_>,
        session: &CustodySession,
        branch_key: &str,
        ack: &ramflux_protocol::Ack,
    ) -> Result<CustodyServerFrame, CustodyRefusal> {
        let Scope { router, store, now, .. } = scope;

        if ack.schema != ramflux_protocol::domain::ACK
            || ack.domain != ramflux_protocol::domain::ACK
            || ack.version != 1
            || ack.receiver_device_id != session.device_ref.device_id
            || ack.received_at.abs_diff(i64::try_from(now).map_err(invalid)?) > 300
        {
            return Err(CustodyRefusal::InvalidInput);
        }
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::signed_bytes(ack).map_err(invalid)?,
            &ack.signed.signature,
            branch_key,
        )
        .map_err(invalid)?;
        let cursor =
            router.apply_ack_for_target(&session.target_delivery_id, ack).map_err(invalid)?;
        if let Err(error) = store.record_ack_increment(&cursor, &ack.envelope_id) {
            tracing::error!(%error,"custody ACK persistence failed; terminating to avoid a state fork");
            std::process::abort();
        }
        Ok(CustodyServerFrame::Acked {
            inbox_seq: cursor.last_acknowledged_inbox_seq.ok_or(CustodyRefusal::InvalidInput)?,
        })
    }
}

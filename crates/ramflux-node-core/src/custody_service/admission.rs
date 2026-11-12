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
use ramflux_protocol::custody::DeviceRef;
use ramflux_protocol::custody::pairing::PairingWire;
/// Proxy ids whose receipts may vouch for `web_origin_bound` proofs (comma-separated).
/// Unset by default, so the authority refuses the web mode until an operator opts in.
pub(crate) const WEB_PROXY_IDS_ENV: &str = "RAMFLUX_CUSTODY_WEB_PROXY_IDS";

/// The only proof actions a web device may run: open a session, manage its own prekeys.
pub(crate) fn web_action_allowed(action: &CustodyProofAction) -> bool {
    matches!(
        action,
        CustodyProofAction::OpenSession
            | CustodyProofAction::Register { .. }
            | CustodyProofAction::RegisterUpdate { .. }
            | CustodyProofAction::PrekeyStatus { .. }
    )
}
pub(super) struct ProofAttempt {
    pub action: CustodyProofAction,
    pub proof: Box<Envelope<BranchProofV3>>,
    pub receipt: Option<Box<Envelope<RelayAcceptance>>>,
    pub connection_id: String,
    /// Present only for a proof relayed by the gateway's web listener.
    pub web: Option<ramflux_protocol::custody::WebOriginBindingV1>,
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
        if matches!(action, CustodyProofAction::HomeMigration { .. })
            && (binding_mode == BindingMode::NoChannelBinding || self.migration.is_none())
        {
            return Err(CustodyRefusal::BindingRefused);
        }
        if matches!(
            action,
            CustodyProofAction::PairingIssue { .. } | CustodyProofAction::PairingCreate { .. }
        ) && self.pairing.is_none()
        {
            return Err(CustodyRefusal::Unsupported);
        }
        if !self.node.envelope().body.channel_binding_modes.contains(&binding_mode)
            || (binding_mode == BindingMode::NoChannelBinding && !self.allow_unbound)
        {
            return Err(CustodyRefusal::BindingRefused);
        }
        if binding_mode == BindingMode::DirectExporter && matches!(origin, Origin::Proxy) {
            return Err(CustodyRefusal::BindingRefused);
        } // Mesh is never the client-facing hop.
        // A web device reaches the authority only through the gateway's web listener, and
        // only to open a session or manage its own prekeys. No account authority here.
        if binding_mode == BindingMode::WebOriginBound
            && !(matches!(origin, Origin::Proxy) && web_action_allowed(&action))
        {
            return Err(CustodyRefusal::BindingRefused);
        }
        let holder = holder(peer, &connection_id)?;
        let challenge = match self.leases().issue(
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
        ) {
            Ok(challenge) => challenge,
            Err(refusal) => return Ok(refusal.into_frame()),
        };
        Ok(CustodyServerFrame::Challenge { challenge })
    }
    pub(super) fn prove(
        &self,
        scope: Scope<'_>,
        attempt: ProofAttempt,
    ) -> Result<CustodyServerFrame, CustodyRefusal> {
        let ProofAttempt { ref proof, ref receipt, ref connection_id, ref web, .. } = attempt;
        // The web context and the web mode travel together or not at all.
        if web.is_some() != (proof.body.binding_mode == BindingMode::WebOriginBound) {
            return Err(CustodyRefusal::BindingRefused);
        }
        let Scope { router, store, peer, now, tick, origin, .. } = scope;
        if web.is_some() {
            self.web_proxy(receipt.as_deref(), &attempt.action, origin)?;
        }
        let holder = holder(peer, connection_id)?;
        let challenge = self.leases().challenge(&proof.body.challenge_nonce, tick)?;
        if challenge.device != proof.body.device_ref
            || challenge.action_hash != custody_action_hash(&attempt.action).map_err(invalid)?
            || challenge.holder != holder
        {
            return Err(CustodyRefusal::BindingRefused);
        }
        let publication = match &attempt.action {
            CustodyProofAction::Publish { publication }
            | CustodyProofAction::HomeMigration { publication, .. } => CustodyPublication {
                record: publication.record.clone(),
                compacted_ids: publication.compacted_ids.clone(),
            },
            _ => router
                .custody_record(&proof.body.device_ref.account_anchor, now)
                .map_err(invalid)?
                .ok_or(CustodyRefusal::AuthorityUnavailable)?,
        };
        let authority = self.possession_authority(
            router,
            &publication,
            &attempt.action,
            proof.body.binding_mode,
            now,
        )?;
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
            BindingMode::WebOriginBound => {
                ProofChannel::WebOriginBound {
                    receipt: receipt.as_deref().ok_or(CustodyRefusal::BindingRefused)?,
                    context: web.as_ref().ok_or(CustodyRefusal::BindingRefused)?,
                    historical_node: historical.as_ref().ok_or(CustodyRefusal::BindingRefused)?,
                    current_node: &self.node,
                }
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
            return super::publication_failure(error).response();
        }
        // Refused new-principal budgets cannot fill successful-proof replay storage.
        // No durable write precedes possession and single-use admission.
        if let Err(refusal) = self.leases().consume(
            &proof.body.challenge_nonce,
            &proof.body.proof_id,
            tick + tick.elapsed(),
        ) {
            return Ok(refusal.into_frame());
        }
        self.finish_proof(
            scope,
            attempt,
            Possession { publication: &publication, authority: &authority, holder, source },
        )
    }
    /// Web/native proxy-role separation. A web proof is accepted only over the mesh, only
    /// for an allow-listed action, and only with a receipt from a proxy id the operator
    /// listed for the web listener. With no id listed, every web proof is refused.
    fn web_proxy(
        &self,
        receipt: Option<&Envelope<RelayAcceptance>>,
        action: &CustodyProofAction,
        origin: &Origin,
    ) -> Result<(), CustodyRefusal> {
        let receipt = receipt.ok_or(CustodyRefusal::BindingRefused)?;
        let listed = crate::environment::var(WEB_PROXY_IDS_ENV).is_ok_and(|ids| {
            ids.split(',').map(str::trim).any(|id| !id.is_empty() && id == receipt.body.relay_id)
        });
        if !matches!(origin, Origin::Proxy) || !web_action_allowed(action) || !listed {
            return Err(CustodyRefusal::BindingRefused);
        }
        Ok(())
    }
    fn possession_authority(
        &self,
        router: &crate::RouterCore,
        publication: &CustodyPublication,
        action: &CustodyProofAction,
        binding_mode: BindingMode,
        now: u64,
    ) -> Result<VerifiedRecord, CustodyRefusal> {
        let current = !matches!(*action, CustodyProofAction::Publish { .. });
        if matches!(*action, CustodyProofAction::HomeMigration { .. }) {
            if self.migration.is_none() || binding_mode == BindingMode::NoChannelBinding {
                return Err(CustodyRefusal::BindingRefused);
            }
            if ramflux_protocol::canonical_json_bytes(&publication).map_err(invalid)?.len()
                > ramflux_protocol::custody::MAX_CUSTODY_FRAME_BYTES
            {
                return Err(CustodyRefusal::Capacity);
            }
            if matches!(
                action,
                CustodyProofAction::HomeMigration {
                    purpose: ramflux_protocol::custody::MigrationPurpose::Read,
                    ..
                }
            ) {
                router.verify_custody_possession_authority(publication, now, false).map_err(invalid)
            } else {
                router.verify_migration_possession_authority(publication, now).map_err(invalid)
            }
        } else {
            router.verify_custody_possession_authority(publication, now, current).map_err(invalid)
        }
    }
    fn finish_proof(
        &self,
        scope: Scope<'_>,
        attempt: ProofAttempt,
        possession: Possession<'_>,
    ) -> Result<CustodyServerFrame, CustodyRefusal> {
        // Keep every publication failure as Err until the listener's grant transaction ends.
        // A hinted refusal is a response frame, but is never successful authentication.
        let result = if let Some(permit) = scope.permit {
            let principal = attempt.proof.body.device_ref.account_anchor.clone();
            self.finish_listener_grant(permit, &principal, || {
                self.finish_admitted_proof(scope, attempt, possession)
            })
        } else {
            self.finish_admitted_proof(scope, attempt, possession)
        };
        result.or_else(super::ProofFailure::response)
    }
    fn finish_listener_grant(
        &self,
        permit: &crate::CustodyIngressPermit,
        principal: &str,
        grant: impl FnOnce() -> Result<CustodyServerFrame, super::ProofFailure>,
    ) -> Result<CustodyServerFrame, super::ProofFailure> {
        let mut opened = None;
        match permit.try_grant(principal, || {
            let result = grant();
            if let Ok(CustodyServerFrame::SessionEstablished { session }) = &result {
                opened = Some(session.session_id.clone());
            }
            result
        }) {
            Ok(result) => result,
            Err(refusal) => {
                // Still under service admission: close before any refusal/ACK is returned.
                if let Some(id) = opened {
                    self.leases().close(&id);
                }
                Ok(refusal.into_frame())
            }
        }
    }
    fn finish_admitted_proof(
        &self,
        scope: Scope<'_>,
        attempt: ProofAttempt,
        possession: Possession<'_>,
    ) -> Result<CustodyServerFrame, super::ProofFailure> {
        let Possession { publication, authority, holder, source } = possession;
        let Scope { router, store, now, tick, .. } = scope;
        let now = now.saturating_add(tick.elapsed().as_secs());
        let tick = tick + tick.elapsed();
        let proof = attempt.proof;
        let _home = if matches!(
            attempt.action,
            CustodyProofAction::Register { .. } | CustodyProofAction::OpenSession
        ) {
            Some(home_operation(scope, &proof.body.device_ref, &proof.body.challenge_nonce, now)?)
        } else {
            None
        };
        match attempt.action {
            CustodyProofAction::PrekeyStatus { .. } | CustodyProofAction::RegisterUpdate { .. } => {
                Err(CustodyRefusal::Unsupported.into())
            }
            CustodyProofAction::PairingIssue { request } => {
                self.finish_pairing_issue(&proof.body.device_ref, authority, *request)
            }
            CustodyProofAction::PairingCreate { request } => {
                self.finish_pairing_create(&proof.body.device_ref, authority, *request)
            }
            CustodyProofAction::HomeMigration { control_hash, publication, purpose } => {
                let session = CustodySession {
                    session_id: String::new(),
                    target_delivery_id: target(&proof.body.device_ref)?,
                    device_ref: proof.body.device_ref.clone(),
                    record_hash: proof.body.record_hash.clone(),
                    proof_hash: object_hash(&proof).map_err(invalid)?,
                    binding_mode: proof.body.binding_mode,
                    expires_at: proof.body.expires_at.min(now.saturating_add(30)),
                };
                let session = self.leases().open_migration(
                    session,
                    holder,
                    now,
                    tick,
                    crate::custody_sessions::MigrationGrant {
                        control_hash,
                        purpose,
                        source,
                        publication: *publication,
                    },
                )?;
                Ok(CustodyServerFrame::SessionEstablished { session })
            }
            CustodyProofAction::Publish { .. } => {
                router
                    .publish_custody_record_from(publication, now, store, source)
                    .map_err(super::publication_failure)?;
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
    fn finish_pairing_issue(
        &self,
        device_ref: &DeviceRef,
        authority: &VerifiedRecord,
        mut request: ramflux_protocol::custody::pairing::native::Issue,
    ) -> Result<CustodyServerFrame, super::ProofFailure> {
        request.normalize();
        request.validate().map_err(|_| CustodyRefusal::InvalidInput)?;
        require_current_primary(device_ref, authority, &request.spec.primary_ref)?;
        let store = self.pairing.as_ref().ok_or(CustodyRefusal::Unsupported)?;
        let mut store = store.lock().map_err(|_| CustodyRefusal::PersistenceUnavailable)?;
        match store.issue(request.spec) {
            Ok(issued) => Ok(pairing_frame(
                ramflux_protocol::custody::pairing::native::NativeReply::Issued(Box::new(issued)),
            )),
            Err(error) => Ok(pairing_failure(error)),
        }
    }
    fn finish_pairing_create(
        &self,
        device_ref: &DeviceRef,
        authority: &VerifiedRecord,
        mut request: ramflux_protocol::custody::pairing::native::Create,
    ) -> Result<CustodyServerFrame, super::ProofFailure> {
        request.normalize();
        request.validate().map_err(|_| CustodyRefusal::InvalidInput)?;
        require_current_primary(device_ref, authority, &request.spec.primary_ref)?;
        let store = self.pairing.as_ref().ok_or(CustodyRefusal::Unsupported)?;
        let mut store = store.lock().map_err(|_| CustodyRefusal::PersistenceUnavailable)?;
        match store.create(request) {
            Ok(created) => Ok(pairing_frame(
                ramflux_protocol::custody::pairing::native::NativeReply::Created(Box::new(created)),
            )),
            Err(error) => Ok(pairing_failure(error)),
        }
    }
    pub(super) fn request(
        &self,
        scope: Scope<'_>,
        attempt: SessionRequest,
        admission: std::sync::MutexGuard<'_, ()>,
    ) -> Result<CustodyServerFrame, CustodyRefusal> {
        let SessionRequest { ref session_id, ref request, ref action, ref connection_id } = attempt;
        let Scope { router, peer, now, tick, .. } = scope;
        let session =
            self.leases().session(session_id, &holder(peer, connection_id)?, now, tick)?;
        let grant = self.leases().migration_grant(session_id)?;
        let publication = session_publication(router, &session, grant.as_ref(), now)?;
        let authority = authority_for_request(
            router,
            &publication,
            grant.as_ref().map(|grant| grant.purpose),
            now,
        )?;
        if object_hash(&publication.record).map_err(invalid)? != session.record_hash {
            return Err(CustodyRefusal::UpdateRequired);
        }
        let cert = authority
            .authorize(
                &session.device_ref,
                grant.as_ref().map_or("message", |grant| grant.purpose.capability()),
                now,
            )
            .map_err(invalid)?;
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
        if let Some(grant) = grant {
            let CustodySessionAction::HomeMigration { request: migration } = action else {
                return Err(CustodyRefusal::BindingRefused);
            };
            if !grant.purpose.allows(migration.control.body.action)
                || migration.control.body.requester != session.device_ref
                || migration.control.body.authority_record_hash != session.record_hash
                || ramflux_protocol::home_migration::message_hash(&migration.control)
                    .map_err(invalid)?
                    != grant.control_hash
                || session.binding_mode == BindingMode::NoChannelBinding
            {
                return Err(CustodyRefusal::BindingRefused);
            }
            self.leases().request(session_id, &request.nonce)?;
            self.leases().close(session_id);
            // Consume the one-use grant before releasing admission; peer calls never
            // hold this service-wide mutex across a network exchange.
            drop(admission);
            return self
                .migration
                .as_ref()
                .ok_or(CustodyRefusal::Unsupported)?
                .execute(
                    router,
                    scope.store,
                    *migration.clone(),
                    crate::home_migration_service::MigrationCaller {
                        publication,
                        purpose: grant.purpose,
                        source: grant.source,
                    },
                    now,
                )
                .map(|response| CustodyServerFrame::HomeMigration {
                    response: Box::new(response),
                });
        }
        if matches!(action, CustodySessionAction::HomeMigration { .. }) {
            return Err(CustodyRefusal::BindingRefused);
        }
        let _home =
            if matches!(action, CustodySessionAction::Ack { .. } | CustodySessionAction::Close) {
                None
            } else {
                Some(home_operation(scope, &session.device_ref, &request.nonce, now)?)
            };
        self.leases().request(session_id, &request.nonce)?;
        // Authenticated submit persistence and retry waits use mailbox ownership;
        // they must not retain the service-wide admission lock.
        if matches!(action, CustodySessionAction::Submit { .. }) {
            drop(admission);
        }
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
        let lease = store.acquire_acknowledgement(&session.target_delivery_id).map_err(
            |error| match error {
                crate::NodeCoreError::HomeMigration(reason) => {
                    CustodyRefusal::HomeMigration { reason, nack: None }
                }
                _ => CustodyRefusal::PersistenceUnavailable,
            },
        )?;
        let cursor =
            router.apply_ack_for_target(&session.target_delivery_id, ack).map_err(|error| {
                match error {
                    crate::NodeCoreError::AckBackpressureRetry => CustodyRefusal::Busy,
                    other => invalid(other),
                }
            })?;
        if let Err(error) = store.record_leased_ack(&cursor, &ack.envelope_id, lease) {
            tracing::error!(%error,"custody ACK persistence failed; terminating to avoid a state fork");
            std::process::abort();
        }
        Ok(CustodyServerFrame::Acked {
            inbox_seq: cursor.last_acknowledged_inbox_seq.ok_or(CustodyRefusal::InvalidInput)?,
        })
    }
}

fn require_current_primary(
    device_ref: &DeviceRef,
    authority: &VerifiedRecord,
    spec_primary: &DeviceRef,
) -> Result<(), CustodyRefusal> {
    let current = &authority.envelope().body.master_certificate.body.primary_device_ref;
    if device_ref != current || spec_primary != current {
        return Err(CustodyRefusal::BindingRefused);
    }
    Ok(())
}

fn pairing_frame(
    reply: ramflux_protocol::custody::pairing::native::NativeReply,
) -> CustodyServerFrame {
    CustodyServerFrame::Pairing {
        reply: Box::new(ramflux_protocol::custody::pairing::native::PairingReply {
            schema: "ramflux.pairing.PairingReply.v2".into(),
            version: 2,
            reply,
        }),
    }
}

fn pairing_failure(error: crate::pairing_relay::PairingRelayError) -> CustodyServerFrame {
    pairing_frame(ramflux_protocol::custody::pairing::native::NativeReply::Failure(
        ramflux_protocol::custody::pairing::native::Failure {
            schema: "ramflux.pairing.Failure.v2".into(),
            version: 2,
            code: error.code().into(),
            retry_after_ms: match error {
                crate::pairing_relay::PairingRelayError::Busy { retry_after_ms } => {
                    Some(retry_after_ms)
                }
                _ => None,
            },
        },
    ))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod population_tests;
fn authority_for_request(
    router: &crate::RouterCore,
    publication: &CustodyPublication,
    purpose: Option<ramflux_protocol::custody::MigrationPurpose>,
    now: u64,
) -> Result<VerifiedRecord, CustodyRefusal> {
    match purpose {
        Some(ramflux_protocol::custody::MigrationPurpose::Manage) => {
            router.verify_migration_possession_authority(publication, now).map_err(invalid)
        }
        Some(ramflux_protocol::custody::MigrationPurpose::Read) => {
            router.verify_custody_possession_authority(publication, now, false).map_err(invalid)
        }
        None => router.verify_custody_possession_authority(publication, now, true).map_err(invalid),
    }
}

fn home_refusal(
    router: &crate::RouterCore,
    store: &crate::RouterRedbStore,
    device: &ramflux_protocol::custody::DeviceRef,
    nonce: &str,
    now: u64,
    error: crate::NodeCoreError,
) -> CustodyRefusal {
    match error {
        crate::NodeCoreError::HomeMigration(reason) => router
            .migration_owner_refusal(store, device, nonce, reason, now)
            .unwrap_or(CustodyRefusal::PersistenceUnavailable),
        error => persistence(error),
    }
}

fn session_publication(
    router: &crate::RouterCore,
    session: &CustodySession,
    grant: Option<&crate::custody_sessions::MigrationGrant>,
    now: u64,
) -> Result<CustodyPublication, CustodyRefusal> {
    if let Some(grant) = grant {
        Ok(CustodyPublication {
            record: grant.publication.record.clone(),
            compacted_ids: grant.publication.compacted_ids.clone(),
        })
    } else {
        router
            .custody_record(&session.device_ref.account_anchor, now)
            .map_err(invalid)?
            .ok_or(CustodyRefusal::AuthorityUnavailable)
    }
}

fn home_operation(
    scope: Scope<'_>,
    device: &ramflux_protocol::custody::DeviceRef,
    nonce: &str,
    now: u64,
) -> Result<crate::SubmissionLease, CustodyRefusal> {
    scope
        .store
        .acquire_home_operation(&device.account_anchor)
        .map_err(|error| home_refusal(scope.router, scope.store, device, nonce, now, error))
}

#[cfg(test)]
mod dm_fs_v3_tests;

#[cfg(test)]
mod web_action_tests {
    use super::{CustodyProofAction, web_action_allowed};

    #[test]
    fn proof_actions_outside_open_session_and_own_prekey_ops_are_refused_for_web_devices() {
        assert!(web_action_allowed(&CustodyProofAction::OpenSession));
        assert!(web_action_allowed(&CustodyProofAction::Register {
            prekey_bundle: serde_json::Value::Null,
        }));
        // Publication, home migration and pairing carry account authority.
        let refused = [
            r#"{"operation":"pairing_issue"}"#,
            r#"{"operation":"pairing_create"}"#,
            r#"{"operation":"publish"}"#,
            r#"{"operation":"home_migration"}"#,
        ];
        for text in refused {
            // Shapes that do not parse are refused earlier, at the decoder.
            if let Ok(action) = serde_json::from_str::<CustodyProofAction>(text) {
                assert!(!web_action_allowed(&action), "{text}");
            }
        }
    }
}

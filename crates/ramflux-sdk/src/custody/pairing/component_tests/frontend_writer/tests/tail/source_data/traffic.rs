// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Direct real custody frames after handoff. TLS/Fedwire is covered in federation fixtures.
use super::*;
use ramflux_crypto::custody::{branch_exporter_hash, sign_branch_proof_v3};
use ramflux_node_core::{CustodyService, CustodyTlsContext};
use ramflux_protocol::{custody::*, encode_base64url};

pub(super) fn both_branches(rig: &Rig) -> TestResult {
    let node = crate::custody::network_tests::node(rig.now, encode_base64url([29; 32]))
        .map_err(|error| error.to_string())?;
    let service = CustodyService::new(node, false, &rig.node.disk, crate::custody::network_now()?)?;
    for participant in [&rig.participant_a, &rig.participant_b] {
        let scope = Scope {
            rig,
            service: &service,
            participant,
            connection: encode_base64url(ramflux_crypto::random_32()?),
        };
        let session = scope.open()?;
        scope.inbox(&session)?;
    }
    Ok(())
}
struct Scope<'a> {
    rig: &'a Rig,
    service: &'a CustodyService,
    participant: &'a LocalPairingParticipant,
    connection: String,
}
impl Scope<'_> {
    fn frame(
        &self,
        frame: &CustodyClientFrame,
        exporter: Option<[u8; 32]>,
    ) -> Result<CustodyServerFrame, Box<dyn std::error::Error>> {
        let request = decode(&serde_json::to_vec(frame)?, MAX_CUSTODY_FRAME_BYTES)?;
        let reply = self.service.tls(
            &self.rig.node.core,
            &self.rig.node.disk,
            request,
            CustodyTlsContext {
                connection_id: &self.connection,
                remote_ip: "127.0.0.1",
                mode: BindingMode::DirectExporter,
                exporter,
            },
            crate::custody::network_now()?,
        );
        Ok(decode(&serde_json::to_vec(&reply)?, MAX_CUSTODY_FRAME_BYTES)?)
    }
    fn prove(
        &self,
        action: CustodyProofAction,
    ) -> Result<CustodyServerFrame, Box<dyn std::error::Error>> {
        let now = crate::custody::network_now()?;
        let account = crate::custody::load_account(
            &self.participant.root,
            &self.participant.account_id,
            now,
        )?;
        let (reference, credentials) = account.credentials(
            self.participant.vault.as_ref(),
            account.local_device_id()?,
            now,
        )?;
        let response = self.frame(
            &CustodyClientFrame::Challenge {
                device_ref: reference.clone(),
                action: action.clone(),
            },
            None,
        )?;
        let CustodyServerFrame::Challenge { challenge } = response else {
            return Err("test: live branch challenge refused".into());
        };
        let certificate = account
            .record()
            .body
            .devices
            .iter()
            .find(|device| device.device_id == reference.device_id)
            .and_then(|device| device.branch_certificate.as_ref())
            .ok_or("test: branch certificate missing")?;
        let proof = sign_branch_proof_v3(
            &credentials.signing,
            BranchProofV3 {
                schema: ramflux_protocol::domain::BRANCH_PROOF_V3.into(),
                version: 3,
                device_ref: reference,
                certificate_hash: object_hash(certificate)?,
                record_hash: object_hash(account.record())?,
                proof_id: encode_base64url(ramflux_crypto::random_32()?),
                challenge_nonce: challenge.challenge_nonce,
                action_hash: challenge.action_hash,
                audience: challenge.audience,
                binding_mode: BindingMode::DirectExporter,
                transport_binding: branch_exporter_hash(&[19; 32]),
                issued_at: now,
                expires_at: challenge.expires_at.min(now + 60),
            },
        )?;
        self.frame(&CustodyClientFrame::Prove { action, proof: Box::new(proof) }, Some([19; 32]))
    }
    fn open(&self) -> Result<CustodySession, Box<dyn std::error::Error>> {
        let now = crate::custody::network_now()?;
        let account = crate::custody::load_account(
            &self.participant.root,
            &self.participant.account_id,
            now,
        )?;
        let (reference, credentials) = account.credentials(
            self.participant.vault.as_ref(),
            account.local_device_id()?,
            now,
        )?;
        let registered = self.prove(CustodyProofAction::Register {
            prekey_bundle: serde_json::to_value(credentials.prekey_bundle()?)?,
        })?;
        assert!(
            matches!(registered, CustodyServerFrame::Registered { .. }),
            "test: post-handoff registration refused"
        );
        let CustodyServerFrame::SessionEstablished { session } =
            self.prove(CustodyProofAction::OpenSession)?
        else {
            return Err("test: post-handoff session refused".into());
        };
        assert_eq!(
            session.device_ref, reference,
            "test: live traffic used another device's branch"
        );
        Ok(session)
    }
    fn inbox(&self, session: &CustodySession) -> TestResult {
        let now = crate::custody::network_now()?;
        let account = crate::custody::load_account(
            &self.participant.root,
            &self.participant.account_id,
            now,
        )?;
        let (reference, credentials) = account.credentials(
            self.participant.vault.as_ref(),
            account.local_device_id()?,
            now,
        )?;
        let action = CustodySessionAction::Inbox { after_seq: 0, limit: 10 };
        let nonce = encode_base64url(ramflux_crypto::random_32()?);
        let mut request = ramflux_protocol::SignedRequest {
            schema: ramflux_protocol::domain::SIGNED_REQUEST.into(),
            version: 1,
            domain: ramflux_protocol::domain::SIGNED_REQUEST.into(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: "branch".into(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: String::new(),
            },
            source_device_id: reference.device_id,
            request_id: nonce.clone(),
            method: ramflux_protocol::HttpMethod::POST,
            path: CUSTODY_REQUEST_PATH.into(),
            device_proof_hash: session.proof_hash.clone(),
            body_hash: custody_session_action_hash(&action)?,
            nonce,
            created_at: i64::try_from(now)?,
            expires_at: i64::try_from(now + 60)?,
        };
        request.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
            &credentials.signing,
            &request,
        )?;
        let response = self.frame(
            &CustodyClientFrame::Request {
                session_id: session.session_id.clone(),
                request: Box::new(request),
                action,
            },
            Some([19; 32]),
        )?;
        assert!(
            matches!(response, CustodyServerFrame::Inbox { .. }),
            "test: live branch traffic stopped after handoff"
        );
        Ok(())
    }
}

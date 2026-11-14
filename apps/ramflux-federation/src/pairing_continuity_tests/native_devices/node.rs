// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Independently observed real node authority and branch-scoped native proof transport.
use super::*;
use ramflux_sdk::custody::pairing::PairingAuthorityQuery;

pub(super) struct Access {
    pub(super) service: Arc<ramflux_node_core::CustodyService>,
    pub(super) router: Arc<ramflux_node_core::RouterCore>,
    pub(super) redb: Arc<ramflux_node_core::RouterRedbStore>,
    node: ramflux_crypto::custody::VerifiedNodeRecord,
    proxy: ramflux_crypto::DeviceBranch,
}
impl Access {
    pub(super) fn new(node: &NodeMesh) -> Self {
        Self {
            service: node.service.clone(),
            router: node.router.clone(),
            redb: node.redb.clone(),
            node: node.node.clone(),
            proxy: node.proxy_branch.clone(),
        }
    }
    pub(super) fn prove(
        &self,
        device: &device::Local,
        action: CustodyProofAction,
    ) -> Result<CustodyServerFrame, SdkError> {
        let now = wall().map_err(|error| SdkError::LocalBus(error.to_string()))?;
        let account = custody::load_account(device.root.path(), &device.id, now)?;
        let record = match &action {
            CustodyProofAction::Publish { publication }
            | CustodyProofAction::HomeMigration { publication, .. } => &publication.record,
            _ => account.record(),
        };
        let (branch, _, reference) = device.vault.local_branch(record)?;
        let challenge = self.service.mesh(
            &self.router,
            &self.redb,
            CustodyMeshRequest::Challenge {
                device_ref: reference.clone(),
                action: action.clone(),
                binding_mode: BindingMode::HomeRelayReceipt,
                client_source: "192.0.2.1".into(),
                connection_id: device.connection.clone(),
            },
            "ramflux-gateway",
            now,
        );
        let CustodyServerFrame::Challenge { challenge } = challenge else {
            return Ok(challenge);
        };
        let certificate = record
            .body
            .devices
            .iter()
            .find(|value| value.device_id == reference.device_id)
            .and_then(|value| value.branch_certificate.as_ref())
            .ok_or(SdkError::CustodySetupInvalid)?;
        let proof = sign_branch_proof_v3(
            &branch,
            BranchProofV3 {
                schema: ramflux_protocol::domain::BRANCH_PROOF_V3.into(),
                version: 3,
                device_ref: reference,
                certificate_hash: object_hash(certificate)?,
                record_hash: object_hash(record)?,
                proof_id: encode_base64url(random_32()?),
                challenge_nonce: challenge.challenge_nonce,
                action_hash: challenge.action_hash,
                audience: challenge.audience,
                binding_mode: BindingMode::HomeRelayReceipt,
                transport_binding: branch_exporter_hash(&[5; 32]),
                issued_at: now,
                expires_at: challenge.expires_at.min(now + 60),
            },
        )?;
        let receipt = sign_proxy_acceptance(
            &self.proxy.signing_key,
            &self.node,
            &proof,
            &branch_exporter_hash(&[5; 32]),
            encode_base64url(random_32()?),
            now,
        )?;
        Ok(self.service.mesh(
            &self.router,
            &self.redb,
            CustodyMeshRequest::Prove {
                action,
                proof: Box::new(proof),
                receipt: Some(Box::new(receipt)),
                connection_id: device.connection.clone(),
            },
            "ramflux-gateway",
            now,
        ))
    }
}
impl PairingAuthorityQuery for Access {
    fn current_authority(
        &self,
        anchor: &str,
    ) -> Result<ramflux_protocol::custody::CustodyAuthority, SdkError> {
        let value = self
            .router
            .custody_record(anchor, wall().map_err(|error| SdkError::LocalBus(error.to_string()))?)
            .map_err(|error| SdkError::LocalBus(error.to_string()))?
            .ok_or(SdkError::PairingCode("NotFound"))?;
        Ok(ramflux_protocol::custody::CustodyAuthority {
            publication: Publication { record: value.record, compacted_ids: value.compacted_ids },
            custodian_publication: None,
        })
    }
}

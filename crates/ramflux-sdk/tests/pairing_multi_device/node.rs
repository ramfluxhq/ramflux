// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real node custody service with serialized direct frames; no HTTP/Fedwire claim.
use super::{ResultOf, vault::Vault};
use ramflux_crypto::custody::{branch_exporter_hash, sign_branch_proof_v3};
use ramflux_node_core::{CustodyService, CustodyTlsContext, RouterCore, RouterRedbStore};
use ramflux_protocol::{custody::*, encode_base64url};
use ramflux_sdk::{
    SdkError,
    custody::{
        self,
        pairing::{NodeHeadPersist, PairingAuthorityQuery, ProofPairingNative},
    },
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

pub struct Node {
    pub identity: ramflux_crypto::custody::VerifiedNodeRecord,
    pub router: RouterCore,
    pub store: RouterRedbStore,
    pub service: CustodyService,
    pub clock: Arc<ramflux_node_core::pairing_relay::TestPairingClock>,
    pub relay: Arc<Mutex<ramflux_node_core::pairing_relay::PairingRelayStore>>,
    _root: tempfile::TempDir,
}
pub fn now() -> Result<u64, SdkError> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SdkError::CustodySetupInvalid)?
        .as_secs())
}
fn invalid() -> SdkError {
    SdkError::CustodySetupInvalid
}
impl Node {
    pub fn open() -> ResultOf<Arc<Self>> {
        use ramflux_node_core::pairing_relay::*;
        let root = tempfile::tempdir()?;
        let router = RouterCore::new();
        let store = RouterRedbStore::open_without_wal(root.path().join("node.redb"))?;
        store.bootstrap_router(&router)?;
        let time = now()?;
        let seed = [7; 32];
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let node = ramflux_crypto::custody::sign_node_identity_record(
            &key,
            NodeIdentityRecord {
                schema: ramflux_protocol::domain::CUSTODY_NODE_RECORD.into(),
                version: 1,
                node_id: "pairing-test-node".into(),
                node_signing_public_key: encode_base64url(key.verifying_key().to_bytes()),
                client_tls_certificate_sha256: Some(encode_base64url([8; 32])),
                epoch: 1,
                previous_record_hash: None,
                issued_at: time,
                receipt_keys: vec![],
                revoked_receipt_key_ids: vec![],
                proxy_keys: vec![],
                revoked_proxy_key_ids: vec![],
                channel_binding_modes: vec![BindingMode::DirectExporter],
            },
        )?;
        let node = ramflux_crypto::custody::verify_node_identity_record(
            &node,
            "pairing-test-node",
            &encode_base64url(key.verifying_key().to_bytes()),
            time,
        )?;
        let clock = TestPairingClock::new(time);
        let relay = Arc::new(Mutex::new(PairingRelayStore::new(PairingRelayConfig {
            clock: clock.clone(),
            node_seed: seed,
            public_origin: "https://relay.example:443".into(),
        })?));
        let service = CustodyService::new(node.clone(), false, &store, time)?
            .with_pairing_relay(relay.clone());
        Ok(Arc::new(Self { identity: node, router, store, service, clock, relay, _root: root }))
    }
    pub fn frame(
        &self,
        connection: &str,
        frame: &CustodyClientFrame,
        exporter: Option<[u8; 32]>,
    ) -> Result<CustodyServerFrame, SdkError> {
        // Exercise the public native wire grammar in both directions.
        let bytes = serde_json::to_vec(frame)?;
        let frame = decode(&bytes, MAX_CUSTODY_FRAME_BYTES)?;
        let reply = self.service.tls(
            &self.router,
            &self.store,
            frame,
            CustodyTlsContext {
                connection_id: connection,
                remote_ip: "127.0.0.1",
                mode: BindingMode::DirectExporter,
                exporter,
            },
            now()?,
        );
        Ok(decode(&serde_json::to_vec(&reply)?, MAX_CUSTODY_FRAME_BYTES)?)
    }
}
impl NodeHeadPersist for Node {
    fn persist_head(&self, publication: &Publication, time: u64) -> Result<String, SdkError> {
        let record = self
            .router
            .publish_custody_record(
                &ramflux_node_core::CustodyPublication {
                    record: publication.record.clone(),
                    compacted_ids: publication.compacted_ids.clone(),
                },
                time,
                &self.store,
            )
            .map_err(|error| SdkError::LocalBus(error.to_string()))?;
        Ok(object_hash(&record)?)
    }
}
impl PairingAuthorityQuery for Node {
    fn current_authority(&self, anchor: &str) -> Result<CustodyAuthority, SdkError> {
        let value = self
            .router
            .custody_record(anchor, now()?)
            .map_err(|error| SdkError::LocalBus(error.to_string()))?
            .ok_or(SdkError::PairingCode("NotFound"))?;
        Ok(CustodyAuthority {
            publication: Publication { record: value.record, compacted_ids: value.compacted_ids },
            custodian_publication: None,
        })
    }
}
#[derive(Clone)]
pub struct Endpoint {
    pub node: Arc<Node>,
    pub root: PathBuf,
    pub account: String,
    pub vault: Arc<Vault>,
    pub connection: String,
}
impl Endpoint {
    pub fn native(&self) -> Arc<ProofPairingNative> {
        let endpoint = self.clone();
        Arc::new(ProofPairingNative::new(Arc::new(move |action| {
            let endpoint = endpoint.clone();
            Box::pin(async move { endpoint.prove(action) })
        })))
    }
    pub fn branch(
        &self,
    ) -> Result<(ramflux_crypto::DeviceBranch, ramflux_crypto::X25519KeyPair, DeviceRef), SdkError>
    {
        let account = custody::load_account(&self.root, &self.account, now()?)?;
        self.vault.local_branch(account.record())
    }

    pub fn prove(&self, action: CustodyProofAction) -> Result<CustodyServerFrame, SdkError> {
        let account = custody::load_account(&self.root, &self.account, now()?)?;
        let (branch, _, reference) = self.branch()?;
        let challenge = self.node.frame(
            &self.connection,
            &CustodyClientFrame::Challenge {
                device_ref: reference.clone(),
                action: action.clone(),
            },
            None,
        )?;
        let CustodyServerFrame::Challenge { challenge } = challenge else { return Ok(challenge) };
        let record = match &action {
            CustodyProofAction::Publish { publication } => &publication.record,
            _ => account.record(),
        };
        let certificate = record
            .body
            .devices
            .iter()
            .find(|device| device.device_id == reference.device_id)
            .and_then(|device| device.branch_certificate.as_ref())
            .ok_or_else(invalid)?;
        let exporter = [19; 32];
        let time = now()?;
        let proof = sign_branch_proof_v3(
            &branch,
            BranchProofV3 {
                schema: ramflux_protocol::domain::BRANCH_PROOF_V3.into(),
                version: 3,
                device_ref: reference,
                certificate_hash: object_hash(certificate)?,
                record_hash: object_hash(record)?,
                proof_id: encode_base64url(ramflux_crypto::random_32()?),
                challenge_nonce: challenge.challenge_nonce,
                action_hash: challenge.action_hash,
                audience: challenge.audience,
                binding_mode: BindingMode::DirectExporter,
                transport_binding: branch_exporter_hash(&exporter),
                issued_at: time,
                expires_at: challenge.expires_at.min(time + 60),
            },
        )?;
        self.node.frame(
            &self.connection,
            &CustodyClientFrame::Prove { action, proof: Box::new(proof) },
            Some(exporter),
        )
    }
}

impl Endpoint {
    pub fn open_session(&self) -> Result<CustodySession, SdkError> {
        let (branch, agreement, _) = self.branch()?;
        let secret = zeroize::Zeroizing::new(agreement.secret.to_bytes());
        let signed_seed = zeroize::Zeroizing::new(ramflux_crypto::blake3_keyed_derive(
            &secret,
            b"ramflux.identity.custody_signed_prekey.v1",
        ));
        let signed = ramflux_crypto::X25519KeyPair::from_seed(*signed_seed);
        let bundle = ramflux_crypto::create_prekey_bundle(
            &branch,
            &agreement,
            "custody-prekey-v1",
            &signed,
            None,
            None,
        )?;
        let registered = self
            .prove(CustodyProofAction::Register { prekey_bundle: serde_json::to_value(bundle)? })?;
        if !matches!(registered, CustodyServerFrame::Registered { .. }) {
            return Err(SdkError::LocalBus(format!(
                "test: own branch registration refused: {registered:?}"
            )));
        }
        match self.prove(CustodyProofAction::OpenSession)? {
            CustodyServerFrame::SessionEstablished { session } => Ok(session),
            reply => {
                Err(SdkError::LocalBus(format!("test: own branch session refused: {reply:?}")))
            }
        }
    }
    pub fn inbox(&self, session: &CustodySession) -> Result<CustodyServerFrame, SdkError> {
        let (branch, _, reference) = self.branch()?;
        let time = now()?;
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
            created_at: i64::try_from(time).map_err(|_| invalid())?,
            expires_at: i64::try_from(time + 60).map_err(|_| invalid())?,
        };
        request.signed.signature =
            ramflux_crypto::sign_protocol_object_with_device_branch(&branch, &request)?;
        self.node.frame(
            &self.connection,
            &CustodyClientFrame::Request {
                session_id: session.session_id.clone(),
                request: Box::new(request),
                action,
            },
            Some([19; 32]),
        )
    }
}

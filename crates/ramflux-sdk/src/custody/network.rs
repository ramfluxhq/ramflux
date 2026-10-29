// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit native transport. Born-v3 accounts never enter legacy gateway authentication.
use super::{BornAccount, BranchCredentials, PrimaryVault, node_pins::NodePins};
use crate::SdkError;
use ramflux_crypto::custody::{branch_exporter_hash, sign_branch_proof_v3};
use ramflux_protocol::custody::{
    BindingMode, BranchProofV3, CUSTODY_REQUEST_PATH, CustodyClientFrame, CustodyPeer,
    CustodyProofAction, CustodyRefusal, CustodyServerFrame, CustodySession, CustodySessionAction,
    DeviceRef, MAX_CUSTODY_FRAME_BYTES, custody_session_action_hash, decode, object_hash,
};
use ramflux_transport::GatewayTcpTlsStream;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub struct CustodyNetworkConfig {
    pub account_root: PathBuf,
    pub account_id: String,
    pub device_id: String,
    pub gateway_address: SocketAddr,
    pub server_name: String,
    pub ca_certificate: PathBuf,
    /// Existing receiving-node trust anchor; never populated from a discovery response.
    pub node_id: String,
    pub node_public_key: String,
    pub audience: String,
    pub binding_mode: BindingMode,
    pub allow_no_channel_binding: bool,
    /// Explicit temporary non-forward-secret DM opt-in; normal clients leave this false.
    pub allow_experimental_native_dm: bool,
    pub timeout: Duration,
}
/// Owns a live TLS connection and its session; neither is serializable or backed up.
pub struct CustodyConnection<S = GatewayTcpTlsStream> {
    pub(super) account: BornAccount,
    pub(super) device: DeviceRef,
    pub(super) credentials: BranchCredentials,
    pub(super) stream: S,
    pub(super) pins: NodePins,
    pub(super) session: Option<CustodySession>,
    pub(super) timeout: Duration,
    pub(super) experimental_native_dm: bool,
    mode: BindingMode,
    audience: String,
}
pub(crate) fn now() -> Result<u64, SdkError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SdkError::CustodySetupInvalid)?
        .as_secs())
}
fn invalid() -> SdkError {
    SdkError::CustodySetupInvalid
}
fn random() -> Result<String, SdkError> {
    Ok(ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?))
}
pub(super) fn fields() -> ramflux_protocol::SignedFields {
    ramflux_protocol::SignedFields {
        signing_key_id: "custody-branch-v3".into(),
        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
        signature: String::new(),
    }
}
impl CustodyConnection<GatewayTcpTlsStream> {
    /// Establish an experimental standalone native connection.
    /// # Errors
    /// Rejects unavailable credentials, invalid node pins, channel binding and router refusals.
    pub async fn connect(
        config: CustodyNetworkConfig,
        vault: Arc<dyn PrimaryVault>,
    ) -> Result<Self, SdkError> {
        let prepared = Self::prepare(&config, vault).await?;
        let (_, tls) = ramflux_transport::TcpTlsGatewayClient::connect(
            "0.0.0.0:0".parse().map_err(|_| invalid())?,
            config.gateway_address,
            &config.server_name,
            &config.ca_certificate,
            config.timeout,
        )
        .await?;
        Self::authenticate_stream(config, tls.into_tls_stream(), prepared).await
    }
}
impl<S: ramflux_transport::GatewaySessionTransport + Send> CustodyConnection<S> {
    pub(crate) async fn prepare(
        config: &CustodyNetworkConfig,
        vault: Arc<dyn PrimaryVault>,
    ) -> Result<(BornAccount, DeviceRef, BranchCredentials), SdkError> {
        if config.binding_mode == BindingMode::NoChannelBinding && !config.allow_no_channel_binding
        {
            return Err(CustodyRefusal::BindingRefused.into());
        }
        let root = config.account_root.clone();
        let account_id = config.account_id.clone();
        let device_id = config.device_id.clone();
        tokio::task::spawn_blocking(move || {
            let account = super::load_account(&root, &account_id, now()?)?;
            let (device, credentials) = account.credentials(vault.as_ref(), &device_id, now()?)?;
            Ok::<_, SdkError>((account, device, credentials))
        })
        .await
        .map_err(|_| invalid())?
    }

    pub(crate) async fn authenticate_stream(
        config: CustodyNetworkConfig,
        mut stream: S,
        prepared: (BornAccount, DeviceRef, BranchCredentials),
    ) -> Result<Self, SdkError> {
        let (account, device, credentials) = prepared;
        let open = CustodyClientFrame::CustodyOpen { binding_mode: config.binding_mode };
        let response = exchange(&mut stream, &open, config.timeout).await?;
        let CustodyServerFrame::NodeIdentity { record, audience, binding_mode, .. } = response
        else {
            return Err(invalid());
        };
        if audience != config.audience
            || binding_mode != config.binding_mode
            || !record.body.channel_binding_modes.contains(&binding_mode)
        {
            return Err(CustodyRefusal::BindingRefused.into());
        }
        if binding_mode == BindingMode::DirectExporter {
            let expected = record
                .body
                .client_tls_certificate_sha256
                .as_deref()
                .ok_or(CustodyRefusal::BindingRefused)?;
            stream.verify_custody_certificate_pin(expected)?;
        }
        let pins = super::discovery::authenticate(&config, &mut stream, *record).await?;
        if binding_mode == BindingMode::NoChannelBinding {
            tracing::warn!(node_id=%config.node_id,"custody connection explicitly uses no_channel_binding");
            let log_root = config.account_root.clone();
            tokio::task::spawn_blocking(move || super::node_pins::log_unbound(&log_root))
                .await
                .map_err(|_| invalid())??;
        }
        let mut connection = Self {
            account,
            device,
            credentials,
            stream,
            pins,
            session: None,
            timeout: config.timeout,
            experimental_native_dm: config.allow_experimental_native_dm,
            mode: binding_mode,
            audience,
        };
        connection.register().await?;
        connection.persist_live(&config.account_root).await?;
        Ok(connection)
    }
    pub(crate) async fn into_gateway_parts(
        mut self,
    ) -> Result<(S, BornAccount, DeviceRef, BranchCredentials), SdkError> {
        let session_id = self.session.take().ok_or(CustodyRefusal::SessionRequired)?.session_id;
        let frame = CustodyClientFrame::GatewayHandoff { session_id };
        self.stream.send_frame(&serde_json::to_vec(&frame)?).await?;
        Ok((self.stream, self.account, self.device, self.credentials))
    }

    async fn register(&mut self) -> Result<(), SdkError> {
        let publication = self.account.publication();
        let expected_hash = object_hash(&publication.record)?;
        let response =
            self.prove(CustodyProofAction::Publish { publication: Box::new(publication) }).await?;
        if !matches!(response, CustodyServerFrame::Published { record_hash } if record_hash == expected_hash)
        {
            return Err(invalid());
        }
        let bundle = self.prekey_bundle()?;
        if !matches!(
            self.prove(CustodyProofAction::Register {
                prekey_bundle: serde_json::to_value(&bundle)?
            })
            .await?,
            CustodyServerFrame::Registered { device_ref, target_delivery_id }
                if device_ref == self.device && target_delivery_id == ramflux_protocol::qualified_device_id(&self.device.account_anchor, &self.device.device_id)?
        ) {
            return Err(invalid());
        }
        let CustodyServerFrame::SessionEstablished { session } =
            self.prove(CustodyProofAction::OpenSession).await?
        else {
            return Err(invalid());
        };
        if session.device_ref != self.device
            || session.binding_mode != self.mode
            || session.record_hash != object_hash(self.account.record())?
        {
            return Err(invalid());
        }
        self.session = Some(session);
        Ok(())
    }
    async fn persist_live(&mut self, root: &std::path::Path) -> Result<(), SdkError> {
        let root = root.to_path_buf();
        let mut selected = self.account.clone();
        self.account = tokio::task::spawn_blocking(move || {
            selected.mark_live(&root)?;
            Ok::<_, SdkError>(selected)
        })
        .await
        .map_err(|_| invalid())??;
        Ok(())
    }

    pub(super) fn require_experimental_dm(&self) -> Result<(), SdkError> {
        if self.experimental_native_dm { Ok(()) } else { Err(CustodyRefusal::Unsupported.into()) }
    }
    #[must_use]
    pub fn session(&self) -> Option<&CustodySession> {
        self.session.as_ref()
    }
    #[must_use]
    pub fn account(&self) -> &BornAccount {
        &self.account
    }
    /// User-visible warning for explicitly opted-in unbound connections.
    #[must_use]
    pub fn security_warning(&self) -> Option<&'static str> {
        (self.mode == BindingMode::NoChannelBinding)
            .then_some("This connection does not bind account proofs to the TLS channel.")
    }
    pub(super) fn signed_prekey(&self) -> ramflux_crypto::X25519KeyPair {
        ramflux_crypto::X25519KeyPair::from_seed(*self.credentials.signed_prekey_seed())
    }
    pub(super) fn prekey_bundle(&self) -> Result<ramflux_crypto::PrekeyBundle, SdkError> {
        self.credentials.prekey_bundle()
    }
    async fn prove(&mut self, action: CustodyProofAction) -> Result<CustodyServerFrame, SdkError> {
        let response = exchange(
            &mut self.stream,
            &CustodyClientFrame::Challenge {
                device_ref: self.device.clone(),
                action: action.clone(),
            },
            self.timeout,
        )
        .await?;
        let CustodyServerFrame::Challenge { challenge } = response else { return Err(invalid()) };
        if challenge.binding_mode != self.mode
            || challenge.audience != self.audience
            || challenge.action_hash != ramflux_protocol::custody::custody_action_hash(&action)?
        {
            return Err(CustodyRefusal::BindingRefused.into());
        }
        let nonce: [u8; 32] = ramflux_protocol::decode_base64url(&challenge.challenge_nonce)
            .map_err(|_| invalid())?
            .try_into()
            .map_err(|_| invalid())?;
        // Mandatory even when an operator and the client explicitly choose no binding.
        let material = self.stream.custody_exporter(&nonce)?;
        let certificate = self
            .account
            .record()
            .body
            .devices
            .iter()
            .find(|d| d.device_id == self.device.device_id)
            .and_then(|d| d.branch_certificate.as_ref())
            .ok_or_else(invalid)?;
        let issued = now()?;
        let proof = sign_branch_proof_v3(
            &self.credentials.signing,
            BranchProofV3 {
                schema: ramflux_protocol::domain::BRANCH_PROOF_V3.into(),
                version: 3,
                device_ref: self.device.clone(),
                certificate_hash: object_hash(certificate)?,
                record_hash: object_hash(self.account.record())?,
                proof_id: random()?,
                challenge_nonce: challenge.challenge_nonce,
                action_hash: challenge.action_hash,
                audience: challenge.audience,
                binding_mode: self.mode,
                transport_binding: branch_exporter_hash(&material),
                issued_at: issued,
                expires_at: challenge.expires_at.min(issued.saturating_add(300)),
            },
        )?;
        exchange(
            &mut self.stream,
            &CustodyClientFrame::Prove { action, proof: Box::new(proof) },
            self.timeout,
        )
        .await
    }
    /// Send an operation with branch possession and the established connection-bound proof hash.
    /// # Errors
    /// Rejects expired/changed authority, disconnect, replay and typed service refusals.
    pub async fn request(
        &mut self,
        action: CustodySessionAction,
    ) -> Result<CustodyServerFrame, SdkError> {
        let session = self.session.as_ref().ok_or(CustodyRefusal::SessionRequired)?;
        let clock = now()?;
        if clock > session.expires_at {
            return Err(CustodyRefusal::SessionExpired.into());
        }
        let created = i64::try_from(clock).map_err(|_| invalid())?;
        let mut request = ramflux_protocol::SignedRequest {
            schema: "ramflux.signed_request.v1".into(),
            version: 1,
            domain: ramflux_protocol::domain::SIGNED_REQUEST.into(),
            ext: ramflux_protocol::Ext::default(),
            signed: fields(),
            source_device_id: self.device.device_id.clone(),
            request_id: random()?,
            method: ramflux_protocol::HttpMethod::POST,
            path: CUSTODY_REQUEST_PATH.into(),
            device_proof_hash: session.proof_hash.clone(),
            body_hash: custody_session_action_hash(&action)?,
            nonce: random()?,
            created_at: created,
            expires_at: created.checked_add(60).ok_or_else(invalid)?,
        };
        request.signed.signature = ramflux_crypto::sign_protocol_object_with_device_branch(
            &self.credentials.signing,
            &request,
        )?;
        exchange(
            &mut self.stream,
            &CustodyClientFrame::Request {
                session_id: session.session_id.clone(),
                request: Box::new(request),
                action,
            },
            self.timeout,
        )
        .await
    }
    /// Fetch and independently validate the peer's current complete authority and prekeys.
    /// # Errors
    /// Rejects stale/fenced heads, substituted keys or an inactive peer branch.
    pub async fn lookup(&mut self, reference: &DeviceRef) -> Result<CustodyPeer, SdkError> {
        let CustodyServerFrame::Peer { peer } =
            self.request(CustodySessionAction::Lookup { device_ref: reference.clone() }).await?
        else {
            return Err(invalid());
        };
        if peer.device_ref != *reference
            || peer.publication.record.body.account_anchor != reference.account_anchor
        {
            return Err(invalid());
        }
        let pins = self.pins.clone();
        let publication = peer.publication.clone();
        let device = reference.clone();
        let bundle = peer.prekey_bundle.clone();
        let custodian = peer.custodian_publication.clone();
        tokio::task::spawn_blocking(move || {
            pins.observe_peer(&publication, &device, &bundle, custodian.as_ref(), now()?)
        })
        .await
        .map_err(|_| invalid())??;
        Ok(*peer)
    }
}
pub(super) async fn exchange<S: ramflux_transport::GatewaySessionTransport + ?Sized>(
    stream: &mut S,
    request: &CustodyClientFrame,
    timeout: Duration,
) -> Result<CustodyServerFrame, SdkError> {
    tokio::time::timeout(timeout, async {
        let bytes = serde_json::to_vec(request)?;
        if bytes.len() > MAX_CUSTODY_FRAME_BYTES {
            return Err(invalid());
        }
        stream.send_frame(&bytes).await?;
        let bytes = stream.recv_custody_frame().await?;
        let response: CustodyServerFrame = decode(&bytes, MAX_CUSTODY_FRAME_BYTES)?;
        if let CustodyServerFrame::Refused { code } = response {
            return Err(code.into());
        }
        Ok::<_, SdkError>(response)
    })
    .await
    .map_err(|_| SdkError::CustodyNetwork(CustodyRefusal::SessionExpired))?
}

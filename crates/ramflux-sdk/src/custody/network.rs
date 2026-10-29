// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit native transport. Born-v3 accounts never enter legacy gateway authentication.
use super::{BornAccount, BranchCredentials, PrimaryVault, node_pins::NodePins};
use crate::SdkError;
use ramflux_crypto::custody::{branch_exporter_hash, sign_branch_proof_v3};
use ramflux_protocol::custody::{
    BindingMode, BranchProofV3, CUSTODY_REQUEST_PATH, CustodyClientFrame, CustodyPeer,
    CustodyProofAction, CustodyRefusal, CustodyServerFrame, CustodySession, CustodySessionAction,
    DeviceRef, MAX_CUSTODY_FRAME_BYTES, Publication, custody_session_action_hash, decode,
    object_hash,
};
use ramflux_transport::{GatewayTcpTlsStream, read_custody_tcp_frame, write_custody_tcp_frame};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct LocalAuthority {
    account: BornAccount,
    device: DeviceRef,
    credentials: BranchCredentials,
}
struct OpenTransport {
    stream: GatewayTcpTlsStream,
    pins: NodePins,
}
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
pub struct CustodyConnection {
    pub(super) account: BornAccount,
    pub(super) device: DeviceRef,
    pub(super) credentials: BranchCredentials,
    pub(super) stream: GatewayTcpTlsStream,
    pub(super) pins: NodePins,
    pub(super) session: Option<CustodySession>,
    pub(super) timeout: Duration,
    pub(super) experimental_native_dm: bool,
    mode: BindingMode,
    audience: String,
}
pub(super) fn now() -> Result<u64, SdkError> {
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
impl CustodyConnection {
    /// Publish, register and establish a session using the current locally verified v3 record.
    /// # Errors
    /// Rejects missing custody state, keychain failure, node-pin changes, exporter failure and
    /// non-Busy router refusals. Busy retries use fresh TLS/challenges, bounded jittered
    /// backoff and one account-local flight for at most 90 seconds. No legacy or weaker mode is tried.
    pub async fn connect(
        config: CustodyNetworkConfig,
        vault: Arc<dyn PrimaryVault>,
    ) -> Result<Self, SdkError> {
        Box::pin(Self::connect_inner(config, vault)).await
    }
    async fn connect_inner(
        config: CustodyNetworkConfig,
        vault: Arc<dyn PrimaryVault>,
    ) -> Result<Self, SdkError> {
        if config.binding_mode == BindingMode::NoChannelBinding && !config.allow_no_channel_binding
        {
            return Err(CustodyRefusal::BindingRefused.into());
        }
        let mut budget = super::retry::Budget::new();
        let _flight =
            super::retry::single_flight(&config.account_root, &config.account_id, &mut budget)
                .await?;
        let root = config.account_root.clone();
        let account_id = config.account_id.clone();
        let device_id = config.device_id.clone();
        let authority = budget
            .attempt(async move {
                tokio::task::spawn_blocking(move || {
                    let account = super::load_account(&root, &account_id, now()?)?;
                    let (device, credentials) =
                        account.credentials(vault.as_ref(), &device_id, now()?)?;
                    Ok::<_, SdkError>(LocalAuthority { account, device, credentials })
                })
                .await
                .map_err(|_| invalid())?
            })
            .await?;
        let opened = budget.until_ready(|| Self::open_transport(&config)).await?;
        let mut connection = Self::from_authority(authority, opened, &config);
        let actions = connection.registration_actions()?;
        let mut next = 0;
        loop {
            match budget.attempt(connection.register(&actions, &mut next)).await {
                Ok(()) => {
                    budget.attempt(connection.persist_live(&config.account_root)).await?;
                    return Ok(connection);
                }
                Err(error) if super::retry::is_busy(&error) => {
                    // Drop the refused stream before waiting: it can hold H or A, and
                    // the gateway closes a Busy exchange. A new TLS exporter and a
                    // fresh challenge/proof are mandatory even for the same action.
                    let authority = connection.into_authority();
                    budget.pause().await?;
                    let opened = budget.until_ready(|| Self::open_transport(&config)).await?;
                    connection = Self::from_authority(authority, opened, &config);
                }
                Err(error) => return Err(error),
            }
        }
    }
    async fn open_transport(config: &CustodyNetworkConfig) -> Result<OpenTransport, SdkError> {
        let (_, tls) = ramflux_transport::TcpTlsGatewayClient::connect(
            "0.0.0.0:0".parse().map_err(|_| invalid())?,
            config.gateway_address,
            &config.server_name,
            &config.ca_certificate,
            config.timeout,
        )
        .await?;
        let mut stream = tls.into_tls_stream();
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
            ramflux_transport::verify_custody_peer_certificate(&stream, expected)?;
        }
        let pins = super::discovery::authenticate(config, &mut stream, *record).await?;
        if binding_mode == BindingMode::NoChannelBinding {
            tracing::warn!(node_id=%config.node_id,"custody connection explicitly uses no_channel_binding");
            let log_root = config.account_root.clone();
            tokio::task::spawn_blocking(move || super::node_pins::log_unbound(&log_root))
                .await
                .map_err(|_| invalid())??;
        }
        Ok(OpenTransport { stream, pins })
    }
    fn from_authority(
        authority: LocalAuthority,
        opened: OpenTransport,
        config: &CustodyNetworkConfig,
    ) -> Self {
        Self {
            account: authority.account,
            device: authority.device,
            credentials: authority.credentials,
            stream: opened.stream,
            pins: opened.pins,
            session: None,
            timeout: config.timeout,
            experimental_native_dm: config.allow_experimental_native_dm,
            mode: config.binding_mode,
            audience: config.audience.clone(),
        }
    }
    fn into_authority(self) -> LocalAuthority {
        let Self { account, device, credentials, stream, .. } = self;
        drop(stream);
        LocalAuthority { account, device, credentials }
    }
    fn registration_actions(&self) -> Result<[CustodyProofAction; 3], SdkError> {
        Ok([
            CustodyProofAction::Publish {
                publication: Box::new(Publication {
                    record: self.account.record().clone(),
                    compacted_ids: None,
                }),
            },
            CustodyProofAction::Register {
                prekey_bundle: serde_json::to_value(self.prekey_bundle()?)?,
            },
            CustodyProofAction::OpenSession,
        ])
    }
    async fn register(
        &mut self,
        actions: &[CustodyProofAction; 3],
        next: &mut usize,
    ) -> Result<(), SdkError> {
        while let Some(action) = actions.get(*next) {
            let response = self.prove(action.clone()).await?;
            match (*next, response) {
                (0, CustodyServerFrame::Published { .. })
                | (1, CustodyServerFrame::Registered { .. }) => {}
                (2, CustodyServerFrame::SessionEstablished { session }) => {
                    if session.device_ref != self.device
                        || session.binding_mode != self.mode
                        || session.record_hash != object_hash(self.account.record())?
                    {
                        return Err(invalid());
                    }
                    self.session = Some(session);
                }
                _ => return Err(invalid()),
            }
            *next += 1;
        }
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
        // Domain-separated branch-only derivation keeps the prekey stable across reconnects
        // without adding a portable credential file or involving the primary signer.
        let secret = zeroize::Zeroizing::new(self.credentials.agreement.secret.to_bytes());
        let seed = zeroize::Zeroizing::new(ramflux_crypto::blake3_keyed_derive(
            &secret,
            b"ramflux.identity.custody_signed_prekey.v1",
        ));
        ramflux_crypto::X25519KeyPair::from_seed(*seed)
    }
    pub(super) fn prekey_bundle(&self) -> Result<ramflux_crypto::PrekeyBundle, SdkError> {
        let signed = self.signed_prekey();
        Ok(ramflux_crypto::create_prekey_bundle(
            &self.credentials.signing,
            &self.credentials.agreement,
            "custody-prekey-v1",
            &signed,
            None,
            None,
        )?)
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
        let material = ramflux_transport::custody_tcp_exporter(&self.stream, &nonce)?;
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
pub(super) async fn exchange(
    stream: &mut GatewayTcpTlsStream,
    request: &CustodyClientFrame,
    timeout: Duration,
) -> Result<CustodyServerFrame, SdkError> {
    tokio::time::timeout(timeout, async {
        write_custody_tcp_frame(stream, &serde_json::to_vec(request)?).await?;
        let bytes = read_custody_tcp_frame(stream).await?;
        let response: CustodyServerFrame = decode(&bytes, MAX_CUSTODY_FRAME_BYTES)?;
        if let CustodyServerFrame::Refused { code } = response {
            return Err(code.into());
        }
        Ok::<_, SdkError>(response)
    })
    .await
    .map_err(|_| SdkError::CustodyNetwork(CustodyRefusal::SessionExpired))?
}

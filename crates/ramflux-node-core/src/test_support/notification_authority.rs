// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native custody fixtures and a transport adapter driving the real authority endpoints.

use crate::{
    GatewayRedbStore, NodeCoreError, NotifyRedbStore, RouterRedbStore,
    send_authority::{
        AuthorityReadReply, AuthorityReadRequest, AuthorityRpc, AuthorityScope,
        SEND_AUTHORITY_BOOT_PATH, SEND_AUTHORITY_PATH, SEND_AUTHORITY_STATE_PATH,
        SendAuthorityError, reservation,
    },
};
use std::{
    sync::{Arc, Mutex, Weak},
    time::Instant,
};

pub const ROUTER: &str = "spiffe://authority-test/ramflux-router";
pub const GATEWAY: &str = "spiffe://authority-test/ramflux-gateway/gateway";
pub const NOTIFY: &str = "spiffe://authority-test/ramflux-notify";
fn error(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::SnapshotSerialization(error.to_string())
}

pub struct NativeDevice {
    pub publication: crate::CustodyPublication,
    pub branch: ramflux_crypto::DeviceBranch,
    pub primary: ramflux_crypto::custody::SelfSigningKey,
    pub target: String,
}
impl NativeDevice {
    /// # Errors
    /// Rejects invalid fixture input or authority construction.
    pub fn new(principal: &str, seed: u8, now: u64) -> Result<Self, NodeCoreError> {
        Self::with_custodian(principal, seed, now, None)
    }

    /// # Errors
    /// Rejects an invalid external primary reference or native genesis.
    pub fn with_custodian(
        principal: &str,
        seed: u8,
        now: u64,
        custodian: Option<ramflux_protocol::custody::DeviceRef>,
    ) -> Result<Self, NodeCoreError> {
        use ramflux_crypto::custody::{
            GenesisInput, MasterKey, RecoveryPhrase, SelfSigningKey, create_genesis,
        };
        if seed > 240 {
            return Err(SendAuthorityError::Invalid.into());
        }
        let master =
            MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[seed; 32]).map_err(error)?)
                .map_err(error)?;
        let primary = SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new([seed + 1; 32]));
        let branch = ramflux_crypto::create_device_branch(principal, "primary", 1, [seed + 2; 32]);
        let agreement = ramflux_crypto::X25519KeyPair::from_seed([seed + 3; 32]);
        let record = create_genesis(
            &master,
            &primary,
            &branch,
            &agreement,
            GenesisInput {
                principal_kind: if custodian.is_some() {
                    ramflux_protocol::PrincipalKind::HeadlessAi
                } else {
                    ramflux_protocol::PrincipalKind::Human
                },
                display_name: "Test Human".into(),
                issued_at: now,
                master_cert_id: ramflux_protocol::encode_base64url([seed + 4; 32]),
                branch_cert_id: ramflux_protocol::encode_base64url([seed + 5; 32]),
                external_human_primary: custodian,
            },
        )
        .map_err(error)?;
        let target = ramflux_protocol::qualified_device_id(&record.body.account_anchor, "primary")
            .map_err(error)?;
        Ok(Self {
            publication: crate::CustodyPublication { record, compacted_ids: None },
            branch,
            primary,
            target,
        })
    }

    /// # Errors
    /// Refuses malformed current authority or an invalid revocation transition.
    pub fn revoked(&self, now: u64) -> Result<crate::CustodyPublication, NodeCoreError> {
        let verified =
            ramflux_crypto::custody::verify_record(&self.publication.record, now, None, None)
                .map_err(error)?;
        Ok(crate::CustodyPublication {
            record: self.primary.revoke_device(&verified, "primary", now).map_err(error)?,
            compacted_ids: None,
        })
    }

    /// # Errors
    /// Returns invalid call-contract or signature construction errors.
    pub fn call_start(
        &self,
        target: &Self,
        event: &str,
        reference: u8,
        now: u64,
    ) -> Result<ramflux_protocol::SignedCallIntentV1, NodeCoreError> {
        use ramflux_protocol::{
            CallIntentAction, CallIntentKind, CallIntentV1, GATEWAY_CALL_INTENT_AUDIENCE,
            SignedCallIntentV1, WakeSignatureAlg, call_intent_signing_bytes, encode_base64url,
        };
        let body = CallIntentV1 {
            version: 1,
            signing_key_id: encode_base64url(self.branch.signing_key.verifying_key().to_bytes()),
            signature_alg: WakeSignatureAlg::Ed25519,
            audience: GATEWAY_CALL_INTENT_AUDIENCE.into(),
            sender_device: self.target.clone(),
            sender_epoch: 1,
            target_device: target.target.clone(),
            target_epoch: 1,
            target_delivery_id: target.target.clone(),
            call_ref: encode_base64url([reference; 16]),
            source_event_id: event.into(),
            kind: CallIntentKind::OneToOne,
            action: CallIntentAction::Start,
            seq: 0,
            created_at: now,
            issued_at: now,
            expires_at: now + 30,
            start_digest: None,
        };
        let signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &call_intent_signing_bytes(&body).map_err(error)?,
            &self.branch,
        );
        Ok(SignedCallIntentV1 { body, signature })
    }
}

type ReadObserver =
    dyn Fn(&AuthorityReadRequest, &AuthorityReadReply) -> Result<(), NodeCoreError> + Send + Sync;
#[derive(Default)]
pub struct AuthorityNetwork {
    router: Mutex<Weak<RouterRedbStore>>,
    gateway: Mutex<Weak<GatewayRedbStore>>,
    notify: Mutex<Weak<NotifyRedbStore>>,
    observer: Mutex<Option<Arc<ReadObserver>>>,
    now: std::sync::atomic::AtomicU64,
}
impl AuthorityNetwork {
    pub fn set_time(&self, now: u64) {
        self.now.store(now, std::sync::atomic::Ordering::SeqCst);
    }
    fn now(&self) -> u64 {
        let now = self.now.load(std::sync::atomic::Ordering::SeqCst);
        if now == 0 { crate::now_unix_seconds() } else { now }
    }
    /// # Errors
    /// A poisoned observer slot refuses the fixture hook.
    pub fn observe_reads<F>(&self, observe: F) -> Result<(), NodeCoreError>
    where
        F: Fn(&AuthorityReadRequest, &AuthorityReadReply) -> Result<(), NodeCoreError>
            + Send
            + Sync
            + 'static,
    {
        *self.observer.lock().map_err(error)? = Some(Arc::new(observe));
        Ok(())
    }

    pub fn bind(
        &self,
        router: &Arc<RouterRedbStore>,
        gateway: &Arc<GatewayRedbStore>,
        notify: &Arc<NotifyRedbStore>,
    ) {
        *self.router.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Arc::downgrade(router);
        *self.gateway.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Arc::downgrade(gateway);
        *self.notify.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Arc::downgrade(notify);
    }
    #[must_use]
    pub fn origin(self: &Arc<Self>, identity: &str) -> Arc<dyn AuthorityRpc> {
        Arc::new(OriginRpc { network: Arc::clone(self), identity: identity.into() })
    }

    /// # Errors
    /// Drives the same durable router/gateway current/fence/publish readers as the services.
    pub fn read(
        &self,
        request: &AuthorityReadRequest,
    ) -> Result<AuthorityReadReply, NodeCoreError> {
        let reply = match &request.scope {
            AuthorityScope::Owner { .. } => {
                let store = self
                    .router
                    .lock()
                    .map_err(error)?
                    .upgrade()
                    .ok_or(SendAuthorityError::Closed)?;
                store.notify_owner_read(request)
            }
            AuthorityScope::Call { .. } => {
                let store = self
                    .gateway
                    .lock()
                    .map_err(error)?
                    .upgrade()
                    .ok_or(SendAuthorityError::Closed)?;
                store.call_authority_read(request)
            }
            _ => Err(SendAuthorityError::Invalid.into()),
        }?;
        let observer = self.observer.lock().map_err(error)?.clone();
        if let Some(observer) = observer {
            observer(request, &reply)?;
        }
        Ok(reply)
    }
}
struct OriginRpc {
    network: Arc<AuthorityNetwork>,
    identity: String,
}
impl AuthorityRpc for OriginRpc {
    fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
        deadline: Instant,
    ) -> Result<serde_json::Value, NodeCoreError> {
        if deadline <= Instant::now() {
            return Err(SendAuthorityError::Closed.into());
        }
        let notify = self
            .network
            .notify
            .lock()
            .map_err(error)?
            .upgrade()
            .ok_or(SendAuthorityError::Closed)?;
        let bytes = ramflux_protocol::canonical_json_bytes(body).map_err(error)?;
        if bytes.len() > 8192 {
            return Err(SendAuthorityError::Capacity.into());
        }
        let store = notify.send_authority();
        let value = match path {
            SEND_AUTHORITY_BOOT_PATH => serde_json::to_value(store.boot_reply(
                &self.identity,
                &ramflux_protocol::parse_i_json(&bytes).map_err(error)?,
            )?),
            SEND_AUTHORITY_STATE_PATH => serde_json::to_value(store.state_reply(
                &self.identity,
                &ramflux_protocol::parse_i_json(&bytes).map_err(error)?,
            )?),
            reservation::RESERVATION_PATH => {
                serde_json::to_value(notify.authority_reservation_reply(
                    &self.identity,
                    &ramflux_protocol::parse_i_json(&bytes).map_err(error)?,
                    self.network.now(),
                )?)
            }
            reservation::RESERVATIONS_PATH => serde_json::to_value(store.reservations_reply(
                &self.identity,
                &ramflux_protocol::parse_i_json(&bytes).map_err(error)?,
            )?),
            SEND_AUTHORITY_PATH => serde_json::to_value(store.control_reply(
                &self.identity,
                &ramflux_protocol::parse_i_json(&bytes).map_err(error)?,
                |query| self.network.read(query),
                self.network.now(),
            )?),
            _ => return Err(SendAuthorityError::Invalid.into()),
        }
        .map_err(error)?;
        Ok(value)
    }
}

use crate::{
    ApnsProviderCredential, DevicePushRoute, ProviderCredential, PushProviderKind, RouterCore,
};
pub type FixtureResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// The agent profile the agent's own primary key signs over the agent and custodian records.
fn agent_profile(
    agent: &NativeDevice,
    agent_verified: &ramflux_crypto::custody::VerifiedRecord,
    human_verified: &ramflux_crypto::custody::VerifiedRecord,
    now: u64,
) -> FixtureResult<ramflux_protocol::agent_profile::AgentProfileEnvelope> {
    use ramflux_protocol::agent_profile::AgentProfileV1;
    let record = &agent.publication.record;
    let human_body = &human_verified.envelope().body;
    let body = AgentProfileV1 {
        schema: ramflux_protocol::domain::AGENT_PROFILE.into(),
        version: 1,
        agent_anchor: record.body.account_anchor.clone(),
        agent_custody_hash: ramflux_protocol::custody::object_hash(record)?,
        custodian_anchor: human_body.account_anchor.clone(),
        custodian_primary: human_body.master_certificate.body.primary_device_ref.clone(),
        kind: "headless_ai".into(),
        profile_epoch: 1,
        responsibility: "Research".into(),
        provider: "local".into(),
        model: "model".into(),
        persona_version: 1,
        persona_hash: ramflux_protocol::encode_base64url([7; 32]),
    };
    Ok(agent.primary.sign_agent_profile(body, agent_verified, human_verified, now)?)
}

/// The create plan for `agent`, every field copied from the agent's genesis record.
fn agent_plan(
    human: &NativeDevice,
    agent: &NativeDevice,
    now: u64,
) -> FixtureResult<ramflux_protocol::custody::RegisterPlan> {
    use ramflux_protocol::custody::{
        AgentRegisterProfile, DeviceRef, REGISTER_PLAN_SCHEMA, RegisterPlan, RegisterPurpose,
        object_hash,
    };
    let human_body = &human.publication.record.body;
    let record = &agent.publication.record;
    let device = record.body.devices.first().ok_or("test: agent device")?;
    let branch = &device.branch_certificate.as_ref().ok_or("test: agent branch")?.body;
    let certificate = &record.body.master_certificate.body;
    let agent_anchor = record.body.account_anchor.clone();
    Ok(RegisterPlan {
        schema: REGISTER_PLAN_SCHEMA.into(),
        version: 1,
        request_id: "native-agent-request".into(),
        purpose: RegisterPurpose::Create,
        owner_anchor: human_body.account_anchor.clone(),
        human_head_hash: object_hash(&human.publication.record)?,
        human_primary: human_body.master_certificate.body.primary_device_ref.clone(),
        desktop: DeviceRef {
            account_anchor: human_body.account_anchor.clone(),
            device_id: "desktop".into(),
            device_epoch: 1,
        },
        agent_anchor: agent_anchor.clone(),
        principal_id: record.body.principal_id.clone(),
        agent_device: DeviceRef {
            account_anchor: agent_anchor,
            device_id: device.device_id.clone(),
            device_epoch: device.device_epoch,
        },
        master_public_key: certificate.master_public_key.clone(),
        self_signing_public_key: certificate.self_signing_public_key.clone(),
        branch_signing_public_key: branch.branch_signing_public_key.clone(),
        agreement_public_key: branch.agreement_identity_public_key.clone(),
        capabilities: branch.capabilities.clone(),
        display_name: record.body.profile.display_name.clone(),
        certificate_issued_at: certificate.issued_at,
        branch_not_before: branch.not_before,
        branch_expires_at: branch.expires_at,
        master_cert_id: certificate.cert_id.clone(),
        branch_cert_id: branch.cert_id.clone(),
        profile: AgentRegisterProfile {
            responsibility: "Research".into(),
            provider: "local".into(),
            model: "model".into(),
            persona_version: 1,
            persona_hash: ramflux_protocol::encode_base64url([7; 32]),
            profile_epoch: 1,
        },
        issued_at: now,
        expires_at: now + ramflux_protocol::custody::REGISTER_TTL_SECONDS,
        previous_agent_head_hash: None,
        previous_master_certificate_hash: None,
        next_range: 1,
    })
}
pub struct NativeScenario {
    pub router: Arc<RouterCore>,
    pub router_store: Arc<RouterRedbStore>,
    pub gateway: Arc<GatewayRedbStore>,
    pub notify: Arc<NotifyRedbStore>,
    pub network: Arc<AuthorityNetwork>,
}
impl NativeScenario {
    /// # Errors
    /// Returns native fixture or real durable endpoint setup failures.
    pub fn new(path: &std::path::Path) -> FixtureResult<Self> {
        Self::open(path, false)
    }
    /// # Errors
    /// Returns native fixture or real durable endpoint setup failures with WAL recovery enabled.
    pub fn new_with_wal(path: &std::path::Path) -> FixtureResult<Self> {
        Self::open(path, true)
    }
    fn open(path: &std::path::Path, wal: bool) -> FixtureResult<Self> {
        let router_store = Arc::new(RouterRedbStore::open_without_wal(path.join("router.redb"))?);
        let router = if let Some(router) = router_store.load_router()? {
            Arc::new(router)
        } else {
            let router = Arc::new(RouterCore::new());
            router_store.bootstrap_router(&router)?;
            router
        };
        let gateway = Arc::new(GatewayRedbStore::open(path.join("gateway.redb"))?);
        let mut notify = if wal {
            const WAL_SHARDS: usize = 2;
            NotifyRedbStore::open_with_wal_shard_count(
                path.join("notify.redb"),
                path.join("notify.wal"),
                WAL_SHARDS,
            )?
        } else {
            NotifyRedbStore::open_without_wal(path.join("notify.redb"))?
        };
        let network = Arc::new(AuthorityNetwork::default());
        let reader = Arc::clone(&network);
        notify.set_send_authority_reader(move |query, _deadline| reader.read(query));
        let actual_router = Arc::clone(&router);
        notify.set_push_route_authorizer(move |owner| {
            let current = actual_router.mvp1_device_auth_key_checked(&owner.target_delivery_id)?;
            Ok(crate::push_route_owner_is_current(owner, current.as_ref()))
        });
        notify.send_authority().configure_local_writer(NOTIFY.into())?;
        notify
            .send_authority()
            .configure_origins(12, &[ROUTER.into(), GATEWAY.into(), NOTIFY.into()])?;
        notify.restore_notification_authority()?;
        let notify = Arc::new(notify);
        network.bind(&router_store, &gateway, &notify);
        router_store.configure_owner_send_authority(network.origin(ROUTER))?;
        gateway.configure_call_send_authority(network.origin(GATEWAY))?;
        Ok(Self { router, router_store, gateway, notify, network })
    }
    /// # Errors
    /// Returns the real native component or durable store error.
    pub fn publish(&self, device: &NativeDevice, now: u64) -> FixtureResult {
        self.router.publish_custody_record(&device.publication, now, &self.router_store)?;
        Ok(())
    }
    /// Publishes `agent`, a headless record whose custodian is `human` (already published), through
    /// the real `AgentPublish` admission. The profile, plan and decision are built with the real
    /// agent-profile and register-decision signers; nothing is mocked.
    /// # Errors
    /// Returns the real crypto, protocol or admission refusal.
    pub fn publish_agent(
        &self,
        human: &NativeDevice,
        agent: &NativeDevice,
        now: u64,
    ) -> FixtureResult {
        use crate::custody_authority::agent_publish::AgentPublishInput;
        use ramflux_protocol::custody::{
            AgentDecisionRequest, RegisterOutcome, encode_register_plan, register_plan_hash,
        };
        let human_verified =
            ramflux_crypto::custody::verify_record(&human.publication.record, now, None, None)?;
        let record = &agent.publication.record;
        let agent_verified =
            ramflux_crypto::custody::verify_record(record, now, None, Some(&human_verified))?;
        let profile = agent_profile(agent, &agent_verified, &human_verified, now)?;
        let plan = agent_plan(human, agent, now)?;
        let ttl = ramflux_protocol::custody::REGISTER_TTL_SECONDS;
        let decision = ramflux_crypto::custody::sign_register_decision_request(
            &human.branch,
            &AgentDecisionRequest {
                plan_bytes: encode_register_plan(&plan)?,
                plan_hash: register_plan_hash(&plan)?,
                decision: RegisterOutcome::Approve,
                signer: plan.human_primary.clone(),
                issued_at: now,
                expires_at: now + ttl,
            },
        )?;
        let input = AgentPublishInput {
            publication: &agent.publication,
            agent_profile: &profile,
            plan: &plan,
            authorization: &decision,
        };
        self.router.publish_agent_custody_record(
            &input,
            now,
            &self.router_store,
            std::net::IpAddr::from([127, 0, 0, 1]),
        )?;
        Ok(())
    }
    /// # Errors
    /// Returns the real native component or durable store error.
    pub fn route(&self, device: &NativeDevice, token: &str, now: u64) -> FixtureResult {
        let owner = self
            .router
            .mvp1_device_auth_key_checked(&device.target)?
            .ok_or("test: current native owner missing")?;
        self.notify.register_authenticated_push_route(
            &owner,
            &DevicePushRoute {
                device_delivery_id: device.target.clone(),
                provider: PushProviderKind::Apns,
                credential_id: Some("apns".into()),
                token: token.into(),
                endpoint: "https://localhost:1/push".into(),
                webpush_p256dh: None,
                webpush_auth: None,
                registered_at_ms: now,
                sealed: false,
                needs_reseal: false,
                unserved_until_ms: 0,
                expires_at: now + 3600,
                route_generation: 0,
                route_tag: "AAAAAAAAAAAAAAAAAAAAAA".into(),
                environment: crate::PushRouteEnvironment::Production,
                capability: crate::PushRouteCapability::Alert,
            },
        )?;
        Ok(())
    }
    /// # Errors
    /// Returns the real native component or durable store error.
    pub fn call_wake(
        &self,
    ) -> FixtureResult<(NativeDevice, NativeDevice, ramflux_protocol::SignedWakeV2)> {
        let now = crate::now_unix_seconds();
        let caller = NativeDevice::new("caller.example", 10, now)?;
        let target = NativeDevice::new("target.example", 30, now)?;
        self.publish(&caller, now)?;
        self.publish(&target, now)?;
        self.notify.update_provider_credential(&ProviderCredential::Apns(
            ApnsProviderCredential {
                credential_id: "apns".into(),
                team_id: "team".into(),
                key_id: "key".into(),
                p8_key_ref: "literal:fixture".into(),
                topic: "test.example".into(),
                sandbox: true,
                provider_ca_pem_ref: None,
            },
        ))?;
        self.route(&target, "token-one", now)?;
        let start = caller.call_start(&target, "invite", 71, now)?;
        let digest = ramflux_protocol::call_intent_digest(&start)?;
        self.gateway.admit_verified_call_intent_with_expiry(
            &crate::CallIntentAdmission {
                signed: &start,
                start_digest: &digest,
                envelope_id: "invite",
                source_identity: &caller.target,
                source_epoch: 1,
                encrypted_invite: b"encrypted invite",
            },
            now + 600,
        )?;
        let wake_id = ramflux_protocol::encode_base64url([72; 16]);
        self.gateway.bind_call_wake_id(&caller.target, 1, "invite", &target.target, &wake_id)?;
        let body = ramflux_protocol::WakeV2 {
            version: 2,
            signing_key_id: ramflux_protocol::encode_base64url(
                caller.branch.signing_key.verifying_key().to_bytes(),
            ),
            signature_alg: ramflux_protocol::WakeSignatureAlg::Ed25519,
            audience: ramflux_protocol::NOTIFY_WAKE_AUDIENCE.into(),
            action: ramflux_protocol::WakeAction::Enqueue,
            wake_id,
            target_delivery_id: target.target.clone(),
            target_owner_epoch: 1,
            source_event_id: "invite".into(),
            class: ramflux_protocol::WakeClass::CallWake,
            created_at: now,
            expires_at: now + 30,
            call_intent_digest: Some(digest),
        };
        let signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &ramflux_protocol::wake_signing_bytes(&body)?,
            &caller.branch,
        );
        let signed = ramflux_protocol::SignedWakeV2 { body, signature };
        Ok((caller, target, signed))
    }

    /// # Errors
    /// Returns the real native component or durable store error.
    pub fn prepared(
        &self,
    ) -> FixtureResult<(NativeDevice, NativeDevice, crate::PreparedProviderPush)> {
        let (caller, target, signed) = self.call_wake()?;
        let now = crate::now_unix_seconds();
        self.notify.claim_signed_wake(&signed, signed.body.expires_at)?;
        let projected = crate::project_wake_v2(&signed, now)?;
        let (_, mut pushes) =
            self.notify.queue_wake_for_push(&target.target, &projected, now, false)?;
        if pushes.len() != 1 {
            return Err("native route preparation did not select one provider".into());
        }
        let prepared = pushes.pop().ok_or("test: selected provider missing")?;
        if !self.notify.begin_wake_send(&prepared.payload.wake_id)? {
            return Err("first durable attempt refused".into());
        }
        Ok((caller, target, prepared))
    }
}

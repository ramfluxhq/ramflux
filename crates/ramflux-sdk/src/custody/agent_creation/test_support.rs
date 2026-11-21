// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared support of the in-crate agent creation end-to-end tests (`e2e_tests`).
//!
//! Real in these tests: the test node is a real `ramflux_node_core` `CustodyService` and
//! `RouterCore` behind real TLS (`custody::network_tests`); the human account is published to that
//! node through the production `connect_for_proof` + `prove(Publish)` path; the agent account is
//! connected through the production `CustodyConnection::connect` path; the own-device packets are
//! sealed by the SDK and carried through the real `RouterCore` and `RouterRedbStore`
//! (`client::native_test_support::router`); the creation code and the crypto are the production
//! code.
//!
//! Fixtures: the primary phone and its paired desktop are the native fixtures of
//! `client::shared_group::tests` (`native_person`, `native_sibling`), not network-paired devices,
//! and the packets are not carried by a gateway session. The node record pinned by the SDK
//! accounts is `network_tests::node` (the test node), not the native fixture's key.

use crate::bus::dispatch::surface_transport::fixture::RecordingGateway;
use crate::bus::own_device_copy;
use crate::bus::state::LocalBusAccountState;
use crate::client::native_test_support::bus::receive_copy;
use crate::client::native_test_support::router::publish_router_envelope;
use crate::client::shared_group::tests::{
    install_native_directories, native_person, native_sibling,
};
use crate::custody::agent_creation::{
    AgentCreationRecord, AgentCreationStore, AgentSteps, PrimarySigning, commit_approved,
    complete_with_receipt, primary_sign_decision,
};
use crate::custody::network_tests::{ReplyFault, Root, start_server_with_faults};
use crate::custody::{CustodyConnection, CustodyNetworkConfig, PrimaryVault};
use crate::{GatewayInboxEntry, GatewaySessionEngine, RamfluxClient, SdkError};
use ramflux_node_core::{RouterCore, RouterRedbStore};
use ramflux_protocol::AGENT_CUSTODY_AUTHORIZATION_CAPABILITY;
use ramflux_protocol::custody::{
    AgentPublishReceipt, BindingMode, CustodyProofAction, CustodyServerFrame, Publication,
    RegisterOutcome, RegisterPlan, decode_register_plan, object_hash, register_plan_hash,
};
use ramflux_protocol::message as g;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The primary phone and the paired desktop of one human account, both native fixtures.
pub(crate) struct Pair {
    pub(crate) phone: LocalBusAccountState,
    pub(crate) laptop: LocalBusAccountState,
}

/// Builds the phone and the desktop of one human. The desktop is enrolled from the phone
/// (`native_sibling`), so the phone's record already names the desktop branch.
pub(crate) fn pair(id: &str) -> Result<Pair, SdkError> {
    let mut phone = native_person(&format!("owner-{id}"), "phone")?;
    let laptop = native_sibling(&mut phone, &format!("laptop-{id}"), "laptop")?;
    install_native_directories(&[&phone, &laptop])?;
    crate::client::native_test_support::bus::seed_pair(&phone.client, &laptop.client)?;
    Ok(Pair { phone, laptop })
}

/// The clock of the test: the SDK test clock when pinned, otherwise the system clock.
pub(crate) fn now() -> TestResult<u64> {
    Ok(crate::custody::network_now()?)
}

/// The capability list of a node that advertises agent custody authorization.
pub(crate) fn capable() -> Vec<String> {
    vec![AGENT_CUSTODY_AUTHORIZATION_CAPABILITY.to_owned()]
}

/// The agent creation body of a desktop request (one persona, one config, owner-only access).
pub(crate) fn create_body(confirmed: Option<bool>) -> g::AgentCreate {
    g::AgentCreate {
        persona: Some(g::AgentPersona {
            name: "Support agent".into(),
            avatar: String::new(),
            responsibility: "answers questions".into(),
        }),
        host: None,
        config: Some(g::AgentConfigData {
            provider: "openai".into(),
            model: "gpt".into(),
            prompt: None,
            autonomy: "full".into(),
            tools: vec!["*".into()],
            enabled: Some(true),
            limits: None,
        }),
        confirmed,
        access: Some(g::AgentAccessPolicy {
            dm: "owner".into(),
            group_inviters: "owner".into(),
            allowed_humans: Vec::new(),
        }),
        role: "named".into(),
    }
}

/// The decision body the phone sends for one request.
pub(crate) fn decide_body(
    request_id: &str,
    request_hash: &str,
    approved: Option<bool>,
) -> g::AgentCreationDecide {
    g::AgentCreationDecide {
        request_id: request_id.into(),
        request_hash: request_hash.into(),
        approved,
    }
}

/// The primary vault of a native account (the vault of its fixture).
pub(crate) fn vault_of(client: &RamfluxClient) -> Result<Arc<dyn PrimaryVault>, SdkError> {
    client.born_v3_vault.clone().ok_or(SdkError::CustodyVaultUnavailable)
}

/// The data root of a native account.
pub(crate) fn root_of(account: &LocalBusAccountState) -> TestResult<PathBuf> {
    let material = account.client.native_bus_fixture.as_ref().ok_or("native bus fixture")?;
    Ok(material.root.0.to_path_buf())
}

/// The desktop's creation store for its human account.
pub(crate) fn store_of(root: &Path, human: &str) -> Result<AgentCreationStore, SdkError> {
    AgentCreationStore::open(root.to_path_buf(), human)
}

/// The real test node: a `CustodyService` behind TLS (`network_tests`), accepting exactly the
/// connections a test makes and carrying at most one armed reply fault.
pub(crate) struct TestNode {
    _temporary: ramflux_test_support::TestPath,
    address: SocketAddr,
    ca: PathBuf,
    server: Option<tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>>,
}

impl TestNode {
    /// Starts the node for exactly `connections` client connections (at most 4).
    pub(crate) async fn start(connections: u8, fault: Option<ReplyFault>) -> TestResult<Self> {
        let temporary = ramflux_test_support::TestPath::new()?;
        let root = Root(temporary.child("node"));
        std::fs::create_dir(&root.0)?;
        let (address, ca, server) = start_server_with_faults(&root, fault, connections)
            .await
            .map_err(|error| error.to_string())?;
        Ok(Self { _temporary: temporary, address, ca, server: Some(server) })
    }

    /// The custody client config of one account on this node (the `network_tests::node` pins).
    pub(crate) fn config(
        &self,
        root: &Path,
        account_id: &str,
        device_id: &str,
    ) -> CustodyNetworkConfig {
        CustodyNetworkConfig {
            pairing_admission: None,
            account_root: root.to_path_buf(),
            account_id: account_id.into(),
            device_id: device_id.into(),
            gateway_address: self.address,
            server_name: "localhost".into(),
            ca_certificate: self.ca.clone(),
            node_id: "node".into(),
            node_public_key: ramflux_crypto::fixture_public_key_base64url(),
            audience: "node".into(),
            binding_mode: BindingMode::DirectExporter,
            allow_no_channel_binding: false,
            timeout: Duration::from_secs(15),
        }
    }

    /// Publishes the account's current record over real TLS. The node must answer `Published`
    /// with the hash of exactly that record.
    pub(crate) async fn publish_current(
        &self,
        root: &Path,
        account_id: &str,
        device_id: &str,
        vault: Arc<dyn PrimaryVault>,
    ) -> TestResult {
        let config = self.config(root, account_id, device_id);
        let mut connection = CustodyConnection::connect_for_proof(config, vault).await?;
        let publication: Publication = connection.account().publication();
        let expected = object_hash(&publication.record)?;
        let frame = connection
            .prove(CustodyProofAction::Publish { publication: Box::new(publication) })
            .await?;
        match frame {
            CustodyServerFrame::Published { record_hash } if record_hash == expected => Ok(()),
            other => Err(format!("test: node refused the publication: {other:?}").into()),
        }
    }

    /// Waits for the server task after every client connection has closed.
    pub(crate) async fn finish(mut self) -> TestResult {
        let server = self.server.take().ok_or("test: node already finished")?;
        server.await?.map_err(|error| error.to_string())?;
        Ok(())
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}

/// The own-device router of the test: a real `RouterCore` over a real `RouterRedbStore`.
pub(crate) struct OwnRouter {
    router: RouterCore,
    store: RouterRedbStore,
    _temporary: ramflux_test_support::TestPath,
}

impl OwnRouter {
    pub(crate) fn new() -> TestResult<Self> {
        let temporary = ramflux_test_support::TestPath::new()?;
        let router = RouterCore::new();
        let store = RouterRedbStore::open(temporary.join("router.redb"))?;
        store.save_router(&router)?;
        Ok(Self { router, store, _temporary: temporary })
    }

    /// Carries the one packet staged on `source` through the real router to `target`, then reads
    /// it back from the target's inbox page and applies it with the own-device receive path.
    pub(crate) async fn route(
        &self,
        source: &mut LocalBusAccountState,
        target: &mut LocalBusAccountState,
        sequence: u64,
    ) -> TestResult {
        let packet = outbound(source, sequence).await?;
        let target_id = packet.target_delivery_id.clone();
        self.store.initialize_inbox(&target_id)?;
        let sender = source.client.owned_device_identity()?;
        let queued =
            publish_router_envelope(&self.router, &self.store, &sender, packet.envelope).await?;
        let page = self.router.resume_page(&target_id, 0, 64, crate::time::now_unix_timestamp())?;
        let read = page
            .entries
            .into_iter()
            .map(|record| record.entry)
            .find(|entry| entry.envelope.envelope_id == queued.envelope.envelope_id)
            .ok_or("test: the routed packet is not on the target inbox page")?;
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: read.inbox_seq,
            target_delivery_id: read.target_delivery_id,
            envelope: read.envelope,
        };
        assert!(receive_copy(&mut target.client, &target.gateway_config, &entry).await?);
        Ok(())
    }
}

/// Flushes the one staged packet of `source` and returns it as the inbox entry the router gets.
async fn outbound(
    source: &mut LocalBusAccountState,
    sequence: u64,
) -> Result<GatewayInboxEntry, Box<dyn std::error::Error>> {
    let gateway = RecordingGateway::new(Arc::default());
    let attempted = gateway.attempted.clone();
    let engine =
        GatewaySessionEngine::with_test_transport(source.gateway_config.clone(), Box::new(gateway));
    source.install_test_session(engine);
    assert_eq!(own_device_copy::flush(source).await?, 1, "one staged packet leaves the outbox");
    let packet = attempted.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(0);
    Ok(GatewayInboxEntry {
        forwarded: false,
        inbox_seq: sequence,
        target_delivery_id: packet.target_delivery_id.clone(),
        envelope: packet,
    })
}

/// The store steps and the activation of one creation, run by the desktop with the real node.
/// The supervisor runs the same steps (`bus/agent_advance.rs` `SupervisorSteps`); here activation
/// is the production `CustodyConnection::connect` of the committed agent account.
pub(crate) struct DesktopSteps<'a> {
    pub(crate) node: &'a TestNode,
    pub(crate) root: &'a Path,
    pub(crate) human: &'a str,
    pub(crate) vault: Arc<dyn PrimaryVault>,
    pub(crate) connections: Vec<CustodyConnection>,
}

impl AgentSteps for DesktopSteps<'_> {
    fn commit(
        &mut self,
        request_id: &str,
        now: u64,
    ) -> impl std::future::Future<Output = Result<AgentCreationRecord, SdkError>> {
        let result = store_of(self.root, self.human).and_then(|store| {
            commit_approved(&store, self.vault.as_ref(), self.human, request_id, &capable(), now)
        });
        std::future::ready(result)
    }

    fn is_live(&self, _account_id: &str) -> bool {
        false
    }

    async fn activate(&mut self, record: &AgentCreationRecord) -> Result<(), SdkError> {
        let account_id = record.account_id.as_deref().ok_or(SdkError::CustodySetupInvalid)?;
        let plan: RegisterPlan = decode_register_plan(&record.plan_bytes()?)
            .map_err(|_| SdkError::CustodySetupInvalid)?;
        let config = self.node.config(self.root, account_id, &plan.agent_device.device_id);
        let connection = CustodyConnection::connect(config, self.vault.clone()).await?;
        self.connections.push(connection);
        Ok(())
    }

    fn complete(
        &mut self,
        request_id: &str,
    ) -> impl std::future::Future<Output = Result<AgentCreationRecord, SdkError>> {
        let result = store_of(self.root, self.human)
            .and_then(|store| complete_with_receipt(&store, request_id));
        std::future::ready(result)
    }
}

/// The receipt the desktop saved for a completed request (`AgentPublishing::save_receipt`).
pub(crate) fn saved_receipt(record: &AgentCreationRecord) -> TestResult<AgentPublishReceipt> {
    let encoded = record.receipt_b64.as_deref().ok_or("test: the receipt is saved")?;
    let bytes = ramflux_protocol::decode_base64url(encoded).map_err(|_| "test: receipt base64")?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// A later approval of the primary phone for the stored plan: the same signing as
/// `agent_creation_decide` (`client/agent_custody_calls.rs` `sign_primary_decision`), with the
/// phone's human record and its branch reference. A different instant gives a different decision.
pub(crate) fn later_primary_decision(
    phone: &LocalBusAccountState,
    phone_root: &Path,
    plan_bytes: &[u8],
    now: u64,
) -> TestResult<Vec<u8>> {
    let plan = decode_register_plan(plan_bytes)?;
    let human = phone.client.born_v3_account.as_deref().ok_or("test: the phone human record")?;
    let record = human.record();
    let account_id = phone.client.account_db()?.local_account_id.clone();
    let reference = crate::custody::custody_vault_reference(
        phone_root,
        &account_id,
        &record.body.account_anchor,
    )?;
    let branch_reference = format!("branch:{reference}");
    let public = record.body.master_certificate.body.self_signing_public_key.clone();
    let fixture = phone.client.native_bus_fixture.as_ref().ok_or("test: the phone fixture")?;
    fixture.vault.arm_agent_decision(&register_plan_hash(&plan)?)?;
    let signing = PrimarySigning {
        primary_device: &plan.human_primary,
        primary_reference: &reference,
        expected_primary_public_key: &public,
        branch_reference: &branch_reference,
        principal_id: &record.body.principal_id,
    };
    let vault = vault_of(&phone.client)?;
    Ok(primary_sign_decision(vault.as_ref(), &signing, plan_bytes, RegisterOutcome::Approve, now)?)
}

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
use crate::client::native_test_support::bus::seed_pair;
use crate::client::native_test_support::router::publish_router_envelope;
use crate::client::shared_group::tests::native_person_keeping_phrase;
use crate::client::shared_group::tests::{
    install_native_directories, native_person, native_sibling,
};
use crate::custody::agent_creation::{
    AgentCreationRecord, AgentCreationStore, AgentSteps, BeginInput, BeginOutcome, PrimarySigning,
    begin, commit_approved, complete_with_receipt, primary_sign_decision,
};
use crate::custody::load_account;
use crate::custody::network_tests::{ReplyFault, Root, start_server_with_faults};
use crate::custody::vault::AGENT_MASTER_PREFIX;
use crate::custody::{CustodyConnection, CustodyNetworkConfig, PrimaryVault};
use crate::{GatewayInboxEntry, GatewaySessionEngine, RamfluxClient, SdkError};
use ramflux_crypto::custody::{
    CooperativeTransferInput, MasterKey, RecoveryPhrase, SelfSigningKey,
    cooperative_transfer_preserving_devices, verify_record,
};
use ramflux_node_core::{RouterCore, RouterRedbStore};
use ramflux_protocol::AGENT_CUSTODY_AUTHORIZATION_CAPABILITY;
use ramflux_protocol::custody::{
    AgentPublishReceipt, BindingMode, CustodyProofAction, CustodyServerFrame, DeviceRef,
    Publication, RegisterOutcome, RegisterPlan, decode_register_plan, object_hash,
    register_plan_hash,
};
use ramflux_protocol::custody::{DeviceSet, Envelope};
use ramflux_protocol::message as g;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

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
    /// Starts the node for exactly `connections` client connections (at most 8).
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

    fn commit_rebind(
        &mut self,
        request_id: &str,
        now: u64,
    ) -> impl std::future::Future<Output = Result<AgentCreationRecord, SdkError>> {
        let result = (|| {
            let store = store_of(self.root, self.human)?;
            let human = load_account(self.root, self.human, now)?;
            crate::custody::agent_creation::commit_rebind(
                &store,
                self.vault.as_ref(),
                human.record(),
                request_id,
                &capable(),
                now,
            )
        })();
        std::future::ready(result)
    }

    /// Stage D R2: the rebind publication through the proof-only connection. The connection is kept
    /// in `connections` so the test can see that it opened no session.
    async fn publish_rebind(&mut self, request_id: &str) -> Result<AgentCreationRecord, SdkError> {
        let store = store_of(self.root, self.human)?;
        let record = store.load(request_id)?.ok_or(SdkError::CustodySetupInvalid)?;
        let plan: RegisterPlan = decode_register_plan(&record.plan_bytes()?)
            .map_err(|_| SdkError::CustodySetupInvalid)?;
        let account_id = record.account_id.clone().ok_or(SdkError::CustodySetupInvalid)?;
        let config = self.node.config(self.root, &account_id, &plan.agent_device.device_id);
        let connection = CustodyConnection::publish_rebind(config, self.vault.clone()).await?;
        self.connections.push(connection);
        store.load(request_id)?.ok_or(SdkError::CustodySetupInvalid)
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
    primary_decision_as(phone, phone_root, plan_bytes, &plan.human_primary, now)
}

/// The phone signs the decision for `primary` as the signer: the plan names the real primary, so
/// any other device or owner is refused by the signing itself.
pub(crate) fn primary_decision_as(
    phone: &LocalBusAccountState,
    phone_root: &Path,
    plan_bytes: &[u8],
    primary: &DeviceRef,
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
        primary_device: primary,
        primary_reference: &reference,
        expected_primary_public_key: &public,
        branch_reference: &branch_reference,
        principal_id: &record.body.principal_id,
    };
    let vault = vault_of(&phone.client)?;
    Ok(primary_sign_decision(vault.as_ref(), &signing, plan_bytes, RegisterOutcome::Approve, now)?)
}

// Request and state helpers of the end-to-end tests: the creation on the desktop, the phone's
// decision through the router, and the closed-request probes.
/// Creates a request on the desktop with `vault` and returns its saved desktop record.
pub(crate) fn desk_create(
    pair: &Pair,
    vault: &dyn PrimaryVault,
    at: u64,
) -> TestResult<AgentCreationRecord> {
    let laptop_root = root_of(&pair.laptop)?;
    let laptop_id = pair.laptop.client.account_db()?.local_account_id.clone();
    let status = pair.laptop.client.agent_create(vault, &create_body(Some(true)), at)?;
    store_of(&laptop_root, &laptop_id)?
        .load(&status.request_id)?
        .ok_or_else(|| "test: the desktop saved the request".into())
}

/// Carries the desktop's plan to the phone, has the phone decide, and carries the decision back.
pub(crate) async fn phone_decides(
    pair: &mut Pair,
    router: &OwnRouter,
    record: &AgentCreationRecord,
    approve: bool,
    at: u64,
) -> TestResult {
    router.route(&mut pair.laptop, &mut pair.phone, 1).await?;
    let phone_vault = vault_of(&pair.phone.client)?;
    let hash = record.request_hash.clone();
    let fixture = pair.phone.client.native_bus_fixture.as_ref().ok_or("test: the phone fixture")?;
    fixture.vault.arm_agent_decision(&hash)?;
    pair.phone.client.agent_creation_decide(
        phone_vault.as_ref(),
        &decide_body(&record.request_id, &hash, Some(approve)),
        at,
    )?;
    router.route(&mut pair.phone, &mut pair.laptop, 2).await
}

/// Whether one pending item of a request is still in the vault (master items are not probed).
pub(crate) fn item_present(vault: &dyn PrimaryVault, plan: &RegisterPlan, reference: &str) -> bool {
    if reference.starts_with(AGENT_MASTER_PREFIX) {
        false
    } else if reference.starts_with("agent-provisioning:") {
        vault.load_provisioning_secret(reference).is_ok()
    } else if reference.starts_with("branch:") {
        vault.load_branch(reference, &plan.principal_id, &plan.agent_device).is_ok()
    } else {
        vault.load_primary(reference).is_ok()
    }
}

/// The request holds its pending items before it closes.
pub(crate) fn assert_items_present(
    vault: &dyn PrimaryVault,
    plan: &RegisterPlan,
    before: &[String],
) {
    assert!(
        before.iter().any(|reference| item_present(vault, plan, reference)),
        "the open request holds its pending items"
    );
}

/// Every pending item of a closed request is gone, and the record names none.
pub(crate) fn assert_items_gone(
    vault: &dyn PrimaryVault,
    plan: &RegisterPlan,
    before: &[String],
    after: &AgentCreationRecord,
) {
    for reference in before {
        assert!(!item_present(vault, plan, reference), "pending item {reference} is deleted");
    }
    assert!(after.vault_refs.is_empty(), "the closed request names no pending item");
}

/// No agent account exists: no directory and no account entry on the desktop root.
pub(crate) fn assert_no_account(root: &Path, agent_id: &str, at: u64) {
    assert!(!root.join("custody_accounts").join(agent_id).exists(), "no agent account directory");
    assert!(load_account(root, agent_id, at).is_err(), "no agent account entry");
}

/// `begin` again with the request's own id, rebuilt from its stored plan. The machine returns the
/// saved request and creates no second anchor.
pub(crate) fn begin_again(
    store: &AgentCreationStore,
    vault: &dyn PrimaryVault,
    record: &AgentCreationRecord,
    at: u64,
) -> TestResult<BeginOutcome> {
    let plan = decode_register_plan(&record.plan_bytes()?)?;
    let input = BeginInput {
        request_id: plan.request_id.clone(),
        owner_anchor: plan.owner_anchor.clone(),
        human_head_hash: plan.human_head_hash.clone(),
        human_primary: plan.human_primary.clone(),
        desktop: plan.desktop.clone(),
        principal_id: plan.principal_id.clone(),
        display_name: plan.display_name.clone(),
        profile: plan.profile.clone(),
        primary_branch_expires_at: plan.branch_expires_at,
    };
    Ok(begin(store, vault, &input, at)?)
}

/// The retry with the same operation id returns the saved plan, keeps the account identifier and
/// the request hash: no second anchor is created.
pub(crate) fn assert_retry_creates_no_second_anchor(
    store: &AgentCreationStore,
    vault: &dyn PrimaryVault,
    record: &AgentCreationRecord,
    at: u64,
) -> TestResult {
    let outcome = begin_again(store, vault, record, at)?;
    let kept = store.load(&record.request_id)?.ok_or("test: the record is kept")?;
    assert_eq!(outcome.plan_bytes, record.plan_bytes()?, "the retry returns the saved plan");
    assert_eq!(kept.account_id, record.account_id, "the retry names the same account");
    assert_eq!(kept.request_hash, record.request_hash, "the retry keeps the request hash");
    Ok(())
}

/// The desktop record of a request, read back from its store.
pub(crate) fn desk_record(pair: &Pair, request_id: &str) -> TestResult<AgentCreationRecord> {
    let laptop_id = pair.laptop.client.account_db()?.local_account_id.clone();
    store_of(&root_of(&pair.laptop)?, &laptop_id)?
        .load(request_id)?
        .ok_or_else(|| "test: the desktop record".into())
}

/// Device id of the second sibling that becomes the new primary in a transfer test.
pub(crate) const NEW_PRIMARY_DEVICE: &str = "primary-two";

/// A human with three devices: the primary phone (old primary), the paired desktop and a second
/// sibling that becomes the new primary. The phone's recovery words are kept so the master signs
/// the transfer. FIXTURE: the three devices are native fixtures (`native_person`, `native_sibling`).
pub(crate) struct Transfer {
    pub(crate) pair: Pair,
    pub(crate) new_primary: LocalBusAccountState,
    pub(crate) master: MasterKey,
    /// A fourth device for the second transfer (`transfer_fixture_two` only).
    pub(crate) third: Option<LocalBusAccountState>,
}

/// Device id of the fourth device of the two-transfer test.
pub(crate) const THIRD_PRIMARY_DEVICE: &str = "primary-three";

/// Builds the three devices of one human. Nothing is transferred yet. The laptop was enrolled
/// before the second sibling, so after that enrollment it follows the human's newest authority and
/// manifest (FIXTURE: the store write of `replace_rebound_authority`, not the pairing refresh).
pub(crate) fn transfer_fixture(id: &str) -> TestResult<Transfer> {
    let (mut phone, phrase) = native_person_keeping_phrase(&format!("owner-{id}"), "phone")?;
    let mut laptop = native_sibling(&mut phone, &format!("laptop-{id}"), "laptop")?;
    let new_primary = native_sibling(&mut phone, &format!("primary-two-{id}"), NEW_PRIMARY_DEVICE)?;
    let now = now()?;
    let phone_root = root_of(&phone)?;
    let phone_id = phone.client.account_db()?.local_account_id.clone();
    let laptop_root = root_of(&laptop)?;
    let laptop_id = laptop.client.account_db()?.local_account_id.clone();
    let newest = load_account(&phone_root, &phone_id, now)?.record().clone();
    crate::custody::store::replace_rebound_authority(&laptop_root, &laptop_id, &newest, None, now)?;
    refresh(&mut laptop.client, &laptop_root, &laptop_id, now)?;
    let manifest =
        phone.client.native_bus_fixture.as_ref().ok_or("test: the phone fixture")?.manifest.clone();
    laptop.client.native_bus_fixture.as_mut().ok_or("test: the laptop fixture")?.manifest =
        manifest;
    install_native_directories(&[&phone, &laptop, &new_primary])?;
    seed_pair(&phone.client, &laptop.client)?;
    seed_pair(&phone.client, &new_primary.client)?;
    seed_pair(&laptop.client, &new_primary.client)?;
    let master = MasterKey::from_phrase(&RecoveryPhrase::parse(phrase.as_str())?)?;
    Ok(Transfer { pair: Pair { phone, laptop }, new_primary, master, third: None })
}

/// The human of the two-transfer test: the three devices of `transfer_fixture` and a fourth
/// sibling (`THIRD_PRIMARY_DEVICE`). Every earlier sibling adopts the newest authority and manifest
/// (FIXTURE, the same store write as `transfer_fixture`).
pub(crate) fn transfer_fixture_two(id: &str) -> TestResult<Transfer> {
    let mut t = transfer_fixture(id)?;
    let now = now()?;
    let third =
        native_sibling(&mut t.pair.phone, &format!("primary-three-{id}"), THIRD_PRIMARY_DEVICE)?;
    let phone_root = root_of(&t.pair.phone)?;
    let phone_id = t.pair.phone.client.account_db()?.local_account_id.clone();
    let newest = load_account(&phone_root, &phone_id, now)?.record().clone();
    let manifest = t
        .pair
        .phone
        .client
        .native_bus_fixture
        .as_ref()
        .ok_or("test: the phone fixture")?
        .manifest
        .clone();
    for (root, id, client) in [
        (
            root_of(&t.pair.laptop)?,
            t.pair.laptop.client.account_db()?.local_account_id.clone(),
            &mut t.pair.laptop.client,
        ),
        (
            root_of(&t.new_primary)?,
            t.new_primary.client.account_db()?.local_account_id.clone(),
            &mut t.new_primary.client,
        ),
    ] {
        crate::custody::store::replace_rebound_authority(&root, &id, &newest, None, now)?;
        refresh(client, &root, &id, now)?;
        client.native_bus_fixture.as_mut().ok_or("test: the sibling fixture")?.manifest =
            manifest.clone();
    }
    install_native_directories(&[&t.pair.phone, &t.pair.laptop, &t.new_primary, &third])?;
    seed_pair(&t.pair.laptop.client, &third.client)?;
    t.third = Some(third);
    Ok(t)
}

/// The real primary transfer P0 -> P1 (`cooperative_transfer_preserving_devices`). The transferred
/// authority is written to all three roots with `replace_rebound_authority`, the new primary's vault
/// holds the successor primary key, and each client re-reads its unlocked human account from disk.
/// FIXTURE: the disk write is the store function, not the pairing refresh (`pairing/activate.rs`).
pub(crate) fn transfer_primary(t: &mut Transfer, now: u64) -> TestResult<Envelope<DeviceSet>> {
    transfer_primary_to(t, now, NEW_PRIMARY_DEVICE, [31_u8; 32])
}

/// The real transfer of the human's primary to `destination` (a device of the fixture), signed by
/// the master with the new `successor` key. Every device's authority and cache adopts the result.
pub(crate) fn transfer_primary_to(
    t: &mut Transfer,
    now: u64,
    destination: &str,
    successor_seed: [u8; 32],
) -> TestResult<Envelope<DeviceSet>> {
    let successor = SelfSigningKey::from_vault_seed(&Zeroizing::new(successor_seed));
    let phone_root = root_of(&t.pair.phone)?;
    let phone_id = t.pair.phone.client.account_db()?.local_account_id.clone();
    let current_account = load_account(&phone_root, &phone_id, now)?;
    let current = verify_record(current_account.record(), now, None, None)?;
    let anchor = current_account.record().body.account_anchor.clone();
    let epoch = current_account
        .record()
        .body
        .devices
        .iter()
        .find(|entry| entry.device_id == destination)
        .map(|entry| entry.device_epoch)
        .ok_or("test: the new primary is a device of the human")?;
    let transferred = cooperative_transfer_preserving_devices(
        &t.master,
        &successor,
        &current,
        CooperativeTransferInput {
            destination: DeviceRef {
                account_anchor: anchor.clone(),
                device_id: destination.into(),
                device_epoch: epoch,
            },
            fresh_destination: None,
            highest_observed_range: 0,
            issued_at: now + 1,
            master_cert_id: ramflux_protocol::encode_base64url([36_u8; 32]),
        },
    )?;
    let new_primary = if destination == NEW_PRIMARY_DEVICE {
        &mut t.new_primary
    } else {
        t.third.as_mut().ok_or("test: the fourth device is in this fixture")?
    };
    let new_root = root_of(new_primary)?;
    let new_id = new_primary.client.account_db()?.local_account_id.clone();
    let reference = crate::custody::custody_vault_reference(&new_root, &new_id, &anchor)?;
    vault_of(&new_primary.client)?.store_new(&reference, &successor)?;
    // Every device of the human keeps its authority and cache in step with the transfer.
    let mut devices: Vec<&mut LocalBusAccountState> = vec![&mut t.pair.phone, &mut t.pair.laptop];
    devices.push(&mut t.new_primary);
    if let Some(third) = t.third.as_mut() {
        devices.push(third);
    }
    for device in devices {
        let root = root_of(device)?;
        let id = device.client.account_db()?.local_account_id.clone();
        crate::custody::store::replace_rebound_authority(&root, &id, &transferred, None, now)?;
        refresh(&mut device.client, &root, &id, now)?;
        adopt(&mut device.client, &transferred)?;
    }
    Ok(transferred)
}

/// Re-reads the unlocked human account of one client from its root.
fn refresh(client: &mut RamfluxClient, root: &Path, id: &str, now: u64) -> TestResult {
    client.born_v3_account = Some(Box::new(load_account(root, id, now)?));
    Ok(())
}

/// Puts the transferred authority into the client's own directory cache: its native manifest
/// carries the human record, and the directory observes it (the cache must not stay behind the
/// durable authority, `identity_authority/custody_directory.rs` `require_owned_custody_floor`).
fn adopt(client: &mut RamfluxClient, transferred: &Envelope<DeviceSet>) -> TestResult {
    let manifest = {
        let material = client.native_bus_fixture.as_mut().ok_or("test: the native fixture")?;
        let mut custody = material.manifest.custody.as_deref().cloned().ok_or("test: custody")?;
        custody.publication.record = transferred.clone();
        let rebuilt = crate::prekey::SdkDeviceManifestResponse::from_native(custody)?;
        material.manifest = rebuilt.clone();
        rebuilt
    };
    client.persist_observed_identity_directory_now(&manifest)?;
    Ok(())
}

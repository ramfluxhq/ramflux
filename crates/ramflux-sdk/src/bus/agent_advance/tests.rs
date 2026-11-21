// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Activation of a committed agent through the supervisor: the same entry point the creation
//! confirmation uses (`Supervisor::activate_native`), reached by the advance step. The home node
//! of the human account decides where the agent is homed and whose capabilities gate the commit
//! (controller decision r11 item 2).
use crate::SdkError;
use crate::custody::PrimaryVault;
use crate::custody::agent_creation::tests::{
    HUMAN, HumanFixture, Phone, account_id_of, approve_for_human, begin_for_human,
    human_fixture_with, owner_anchor, phone,
};
use crate::custody::agent_creation::{
    AgentCreationRecord, AgentCreationState, AgentCreationStore, RebindBinding, RebindEntry,
};
use crate::custody::memory_vault::MemoryPrimaryVault;
use crate::node::NodeStore;
use ramflux_protocol::custody::DeviceRef;
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const HUMAN_SECRET: &[u8] = b"human data secret";
const DEFAULT_NODE: &str = "default-node";
const HOME_NODE: &str = "home-node";

/// A node profile, with or without the agent custody authorization capability.
fn node(node_id: &str, capable: bool) -> crate::NodeProfile {
    crate::NodeProfile {
        discovery_url: format!("https://{node_id}"),
        node_id: node_id.to_owned(),
        node_public_key: ramflux_protocol::encode_base64url([7_u8; 32]),
        pin_source: crate::NodePinSource::Operator,
        ca_cert_pem: "test CA".to_owned(),
        gateway: crate::NodeGateway {
            quic_addr: "127.0.0.1:1".to_owned(),
            tcp_addr: "127.0.0.1:1".to_owned(),
            server_name: node_id.to_owned(),
        },
        relay: crate::NodeRelay {
            quic_addr: "127.0.0.1:1".to_owned(),
            server_name: node_id.to_owned(),
        },
        prekey_http_url: format!("https://{node_id}"),
        signaling_turn_addr: String::new(),
        protocol_versions: Vec::new(),
        client_capabilities: if capable {
            vec![ramflux_protocol::AGENT_CUSTODY_AUTHORIZATION_CAPABILITY.to_owned()]
        } else {
            Vec::new()
        },
        discovered_at: 1,
        expires_at: u64::MAX,
        enabled: true,
        builtin: false,
        safety_warnings: std::collections::BTreeSet::new(),
    }
}

fn node_store(profiles: Vec<crate::NodeProfile>, default: Option<&str>) -> NodeStore {
    NodeStore {
        default_node_id: default.map(str::to_owned),
        profiles: profiles.into_iter().map(|profile| (profile.node_id.clone(), profile)).collect(),
        ..NodeStore::default()
    }
}

/// A human account with one authorized agent request, and the node store saved on its root.
struct Setup {
    fixture: HumanFixture,
    store: AgentCreationStore,
    desk: Arc<MemoryPrimaryVault>,
    account_id: String,
    config: crate::LocalBusConfig,
}

fn authorized_request(
    request_id: &str,
    nodes: &NodeStore,
) -> Result<Setup, Box<dyn std::error::Error>> {
    let fixture = human_fixture_with(Some(HUMAN_SECRET))?;
    let root = fixture.root.0.to_path_buf();
    let store = AgentCreationStore::open(root.clone(), HUMAN)?;
    let desk = Arc::new(MemoryPrimaryVault::default());
    let phone: Phone = phone(&owner_anchor())?;
    let outcome = begin_for_human(&fixture, &store, &desk, request_id, None)?;
    let authorized = approve_for_human(&fixture, &phone, &store, &desk, &outcome)?;
    let account_id = account_id_of(&authorized)?;
    nodes.save(&root)?;
    let mut config = crate::LocalBusConfig::new(root.join("activate.sock"), &root);
    config.custody_vault = Some(desk.clone());
    Ok(Setup { fixture, store, desk, account_id, config })
}

fn human_passphrase() -> Zeroizing<String> {
    Zeroizing::new(String::from_utf8_lossy(HUMAN_SECRET).into_owned())
}

/// The agent's data passphrase: the provisioning secret the request names.
fn agent_passphrase(
    desk: &MemoryPrimaryVault,
    record: &AgentCreationRecord,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let reference = record
        .vault_refs
        .iter()
        .find(|reference| reference.starts_with("agent-provisioning:"))
        .ok_or("the request names its provisioning secret")?;
    let secret = desk.load_provisioning_secret(reference)?;
    Ok(Zeroizing::new(std::str::from_utf8(&secret)?.to_owned()))
}

/// The home node the agent account stores, read from its own account database.
fn stored_agent_node(
    root: &Path,
    account_id: &str,
    passphrase: &Zeroizing<String>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mut client = crate::RamfluxClient::new();
    client.open_account_index(root)?;
    client.unlock_account(account_id, passphrase.as_bytes())?;
    Ok(client.account_db()?.load_actor_state::<String>("account/node-id")?)
}

#[tokio::test]
async fn advance_activates_an_approved_agent_on_the_open_human_account() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(async {
            let nodes = node_store(vec![node(DEFAULT_NODE, true)], Some(DEFAULT_NODE));
            let setup = authorized_request("req-activate", &nodes)?;
            let now = setup.fixture.now;
            let supervisor = crate::bus::supervisor::Supervisor::new(setup.config.clone())?;
            supervisor
                .activate_native(HUMAN, human_passphrase(), Some(DEFAULT_NODE.into()))
                .await?;
            let outcomes = supervisor.advance_agent_creations(HUMAN, now + 2).await?;
            assert!(supervisor.account_is_open(&setup.account_id), "agent open after advance");
            assert_eq!(outcomes.len(), 1, "one pending request: {outcomes:?}");
            assert!(
                matches!(outcomes[0].1, Ok(AgentCreationState::PublicationPending)),
                "{outcomes:?}"
            );
            drop(supervisor);

            // Restart: a new supervisor on the same root re-unlocks the human and advances again.
            let restarted = crate::bus::supervisor::Supervisor::new(setup.config.clone())?;
            restarted.activate_native(HUMAN, human_passphrase(), None).await?;
            let again = restarted.advance_agent_creations(HUMAN, now + 3).await?;
            assert!(
                matches!(again.as_slice(), [(_, Ok(AgentCreationState::PublicationPending))]),
                "after restart: {again:?}"
            );
            let record = setup.store.load("req-activate")?.ok_or("the request is stored")?;
            let agent_text = agent_passphrase(&setup.desk, &record)?;
            restarted.activate_native(&setup.account_id, agent_text, None).await?;
            drop(restarted);
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
}

#[tokio::test]
async fn advance_homes_the_agent_on_the_human_home_node() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(async {
            // The default node differs from the home node: the agent must land on the home node.
            let nodes = node_store(
                vec![node(DEFAULT_NODE, true), node(HOME_NODE, true)],
                Some(DEFAULT_NODE),
            );
            let setup = authorized_request("req-home", &nodes)?;
            let root = setup.fixture.root.0.to_path_buf();
            let supervisor = crate::bus::supervisor::Supervisor::new(setup.config.clone())?;
            supervisor.activate_native(HUMAN, human_passphrase(), Some(HOME_NODE.into())).await?;
            let outcomes = supervisor.advance_agent_creations(HUMAN, setup.fixture.now + 2).await?;
            assert!(
                matches!(outcomes.as_slice(), [(_, Ok(AgentCreationState::PublicationPending))]),
                "{outcomes:?}"
            );
            drop(supervisor);
            let record = setup.store.load("req-home")?.ok_or("the request is stored")?;
            let agent_text = agent_passphrase(&setup.desk, &record)?;
            assert_eq!(
                stored_agent_node(&root, &setup.account_id, &agent_text)?.as_deref(),
                Some(HOME_NODE),
                "the agent is homed on the human home node, not on the default node"
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
}

#[tokio::test]
async fn advance_checks_the_home_node_capability_and_never_the_default_node() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(async {
            // The default node advertises the capability; the home node does not. The commit
            // must refuse, because only the home node's capabilities count.
            let nodes = node_store(
                vec![node(DEFAULT_NODE, true), node(HOME_NODE, false)],
                Some(DEFAULT_NODE),
            );
            let setup = authorized_request("req-capability", &nodes)?;
            let supervisor = crate::bus::supervisor::Supervisor::new(setup.config.clone())?;
            supervisor.activate_native(HUMAN, human_passphrase(), Some(HOME_NODE.into())).await?;
            let outcomes = supervisor.advance_agent_creations(HUMAN, setup.fixture.now + 2).await?;
            assert!(
                matches!(outcomes.as_slice(), [(_, Err(SdkError::AgentCustodyUnsupported))]),
                "{outcomes:?}"
            );
            let record = setup.store.load("req-capability")?.ok_or("the request is stored")?;
            assert_eq!(
                record.state,
                AgentCreationState::Authorized,
                "the request stays authorized"
            );
            assert!(!setup.store.account_committed(&setup.account_id)?, "nothing is committed");
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
}

#[tokio::test]
async fn advance_without_a_home_node_stays_authorized_and_commits_nothing() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(async {
            // No node is known, so the human account cannot have stored a home node.
            let nodes = NodeStore::default();
            let setup = authorized_request("req-no-home", &nodes)?;
            let supervisor = crate::bus::supervisor::Supervisor::new(setup.config.clone())?;
            supervisor.activate_native(HUMAN, human_passphrase(), None).await?;
            let outcomes = supervisor.advance_agent_creations(HUMAN, setup.fixture.now + 2).await?;
            assert!(
                matches!(outcomes.as_slice(), [(_, Err(SdkError::NoNodeSelected))]),
                "{outcomes:?}"
            );
            let record = setup.store.load("req-no-home")?.ok_or("the request is stored")?;
            assert_eq!(
                record.state,
                AgentCreationState::Authorized,
                "the request stays authorized"
            );
            assert!(!setup.store.account_committed(&setup.account_id)?, "nothing is committed");
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
}

/// Stage D3 (decision r18 item 1): an observation that moves an agent to R closes its open session
/// through the account.lock path, and a later advance does not activate it while it stays paused.
#[tokio::test]
async fn a_paused_agent_is_closed_on_the_observation_and_not_reactivated() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(async {
            let nodes = node_store(vec![node(DEFAULT_NODE, true)], Some(DEFAULT_NODE));
            let setup = authorized_request("req-paused", &nodes)?;
            let now = setup.fixture.now;
            let supervisor = crate::bus::supervisor::Supervisor::new(setup.config.clone())?;
            supervisor
                .activate_native(HUMAN, human_passphrase(), Some(DEFAULT_NODE.into()))
                .await?;
            supervisor.advance_agent_creations(HUMAN, now + 2).await?;
            assert!(supervisor.account_is_open(&setup.account_id), "the agent is connected");

            // The agent is complete under a primary that is no longer current: the inventory holds
            // the approved binding of a different device, so the observation moves it to R.
            let mut record = setup.store.load("req-paused")?.ok_or("the record")?;
            record.state = AgentCreationState::Complete;
            setup.store.save(&record)?;
            setup.store.save_rebind(&RebindEntry {
                agent_account_id: setup.account_id.clone(),
                binding: RebindBinding::Live,
                bound_primary: DeviceRef {
                    account_anchor: setup.fixture.anchor.clone(),
                    device_id: "desktop-device".into(),
                    device_epoch: 1,
                },
                master_range: 1,
                request_id: None,
                failure: None,
            })?;
            supervisor.advance_agent_creations(HUMAN, now + 3).await?;
            assert!(!supervisor.account_is_open(&setup.account_id), "the paused agent is closed");
            let entry = setup.store.load_rebind(&setup.account_id)?.ok_or("the entry")?;
            assert_eq!(entry.binding, RebindBinding::RebindPending, "the pause is recorded");

            // A creation that is still pending for the paused agent is not activated by the advance.
            record.state = AgentCreationState::PublicationPending;
            setup.store.save(&record)?;
            let again = supervisor.advance_agent_creations(HUMAN, now + 4).await?;
            assert!(
                !supervisor.account_is_open(&setup.account_id),
                "the paused agent stays closed"
            );
            assert!(
                matches!(again.as_slice(), [(_, Ok(AgentCreationState::PublicationPending))]),
                "the advance leaves the paused request as it is: {again:?}"
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
}

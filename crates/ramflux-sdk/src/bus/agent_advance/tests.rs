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

/// Stage E0 (decision r20): the activation guard refuses an agent whose rebind is pending (R) or
/// committed (C) with the typed reason `rebind_pending`, before any account is opened. A bound
/// agent (B) is not refused by the guard.
#[tokio::test]
async fn activation_refuses_an_agent_whose_rebind_is_pending_or_committed() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(async {
            let nodes = node_store(vec![node(DEFAULT_NODE, true)], Some(DEFAULT_NODE));
            let setup = authorized_request("req-guard", &nodes)?;
            let supervisor = crate::bus::supervisor::Supervisor::new(setup.config.clone())?;
            for binding in [RebindBinding::RebindPending, RebindBinding::Committed] {
                setup.store.save_rebind(&RebindEntry {
                    agent_account_id: setup.account_id.clone(),
                    binding,
                    bound_primary: DeviceRef {
                        account_anchor: setup.fixture.anchor.clone(),
                        device_id: "desktop-device".into(),
                        device_epoch: 1,
                    },
                    master_range: 2,
                    request_id: None,
                    failure: None,
                })?;
                let refused = supervisor
                    .activate_native(
                        &setup.account_id,
                        Zeroizing::new("not the agent passphrase".into()),
                        Some(DEFAULT_NODE.into()),
                    )
                    .await;
                assert!(
                    matches!(refused, Err(SdkError::AgentCreationRefused("rebind_pending"))),
                    "{binding:?} must be refused by the guard"
                );
                assert!(!supervisor.account_is_open(&setup.account_id), "{binding:?}: not opened");
            }
            // A bound agent passes the guard: the failure is the passphrase, not the rebind token.
            setup.store.save_rebind(&RebindEntry {
                agent_account_id: setup.account_id.clone(),
                binding: RebindBinding::Bound,
                bound_primary: DeviceRef {
                    account_anchor: setup.fixture.anchor.clone(),
                    device_id: "desktop-device".into(),
                    device_epoch: 1,
                },
                master_range: 2,
                request_id: None,
                failure: None,
            })?;
            let passed = supervisor
                .activate_native(
                    &setup.account_id,
                    Zeroizing::new("not the agent passphrase".into()),
                    Some(DEFAULT_NODE.into()),
                )
                .await;
            assert!(
                !matches!(passed, Err(SdkError::AgentCreationRefused("rebind_pending"))),
                "a bound agent is not refused by the guard"
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
}

/// Stage E0 (decision r20): the supervisor path of a committed rebind. The desktop's human account
/// is activated on its real root with the node profile of the real test node, and one advance
/// commits the authorized rebind, publishes it through the supervisor's proof connection (no
/// session), and connects the agent again under binding B. The fixture (the transfer, the approval
/// by the new primary, the adopted authority) is the R3 fixture; the node, the store, the vault
/// and the publication are the real components. The R3 fixture builds its own runtime, so the
/// test is synchronous and the supervisor part runs on a `LocalSet` afterwards.
#[test]
fn a_committed_rebind_is_published_by_the_supervisor_and_reaches_b() -> TestResult {
    use crate::custody::agent_creation::test_support::transfer_fixture;
    let mut t = transfer_fixture("supervisor-rebind")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(tokio::task::LocalSet::new().run_until(supervisor_publishes_the_rebind(&mut t)))
}

async fn supervisor_publishes_the_rebind(
    t: &mut crate::custody::agent_creation::test_support::Transfer,
) -> TestResult {
    use crate::custody::agent_creation::e2e_tests::rebind::{
        approve_rebind, bind_transfer_and_observe,
    };
    use crate::custody::agent_creation::test_support::{OwnRouter, TestNode, now};
    let router = OwnRouter::new()?;
    let node = TestNode::start(8, None).await?;
    let observed = bind_transfer_and_observe(t, &node, &router).await?;
    let request_id = approve_rebind(t, &router, &observed.desk_store, &observed.agent_id).await?;

    // The desktop's node store names the test node, so the human's home node is that node.
    node_store(vec![node.profile()?], Some("node")).save(&observed.desk_root)?;
    let mut config =
        crate::LocalBusConfig::new(observed.desk_root.join("activate.sock"), &observed.desk_root);
    config.custody_vault = Some(observed.desk_vault.clone());
    // Fixture: the test node is a direct custody endpoint, so it is reached with DirectExporter.
    config.rebind_binding_mode = Some(ramflux_protocol::custody::BindingMode::DirectExporter);
    let supervisor = crate::bus::supervisor::Supervisor::new(config)?;
    // The desktop (sibling) fixture's data passphrase (`client/native_test_support/sibling.rs:66`).
    let passphrase = Zeroizing::new("native sibling data passphrase".to_owned());
    supervisor
        .activate_native(&observed.desk_id, passphrase, Some("node".into()))
        .await
        .map_err(|error| format!("activate the human: {error}"))?;

    let outcomes = supervisor
        .advance_agent_creations(&observed.desk_id, now()?)
        .await
        .map_err(|error| format!("advance: {error}"))?;
    assert!(
        matches!(outcomes.as_slice(), [(id, Ok(AgentCreationState::Complete))] if *id == request_id),
        "the rebind reaches complete through the supervisor: {outcomes:?}"
    );
    let entry = observed
        .desk_store
        .load_rebind(&observed.agent_id)?
        .ok_or("the inventory entry of the agent")?;
    assert_eq!(entry.binding, RebindBinding::Bound, "the agent is bound (B)");
    assert!(supervisor.account_is_open(&observed.agent_id), "the agent connects under B");
    // The node is dropped, not finished: the supervisor's own gateway session also dials this
    // address, and the custody-only fixture server reports that traffic when it finishes. The
    // publication outcome above is the assertion that matters here.
    drop(node);
    Ok(())
}

/// AGENT-IDENTITY-01 E0 unlock guard (decision r21), passphrase route: `account.unlock` with the
/// agent's REAL passphrase is refused with `rebind_pending` for a pending (R) and a committed (C)
/// rebind, and the account is not opened. The guard runs before the actor is started, so the
/// passphrase is never checked for a paused agent.
#[tokio::test(flavor = "current_thread")]
async fn passphrase_unlock_refuses_a_paused_agent_with_its_real_passphrase() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(async {
            let nodes = node_store(vec![node(DEFAULT_NODE, true)], Some(DEFAULT_NODE));
            let setup = authorized_request("req-unlock-passphrase", &nodes)?;
            let record = setup
                .store
                .load("req-unlock-passphrase")?
                .ok_or("the creation request is stored")?;
            let passphrase = agent_passphrase(&setup.desk, &record)?;
            let supervisor = crate::bus::supervisor::Supervisor::new(setup.config.clone())?;
            let (outbound, _receiver) = tokio::sync::mpsc::channel(8);
            let connection = crate::bus::state::LocalBusConnectionState::new(1, outbound);
            for binding in [RebindBinding::RebindPending, RebindBinding::Committed] {
                setup.store.save_rebind(&RebindEntry {
                    agent_account_id: setup.account_id.clone(),
                    binding,
                    bound_primary: DeviceRef {
                        account_anchor: setup.fixture.anchor.clone(),
                        device_id: "desktop-device".into(),
                        device_epoch: 1,
                    },
                    master_range: 2,
                    request_id: None,
                    failure: None,
                })?;
                let frame = crate::LocalBusFrame::request(
                    format!("unlock-{binding:?}"),
                    Some(setup.account_id.clone()),
                    "account",
                    "account.unlock",
                    serde_json::json!({ "passphrase": passphrase.as_str() }),
                );
                let refused = supervisor.request(frame, &connection).await;
                assert!(
                    matches!(refused, Err(SdkError::AgentCreationRefused("rebind_pending"))),
                    "{binding:?}: the passphrase unlock must be refused by the guard"
                );
                assert!(!supervisor.account_is_open(&setup.account_id), "{binding:?}: not opened");
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
}

/// The agent record of an advanced creation, seeded in state `U` as the completing desktop writes it,
/// with the creation marked complete. Returns the agent anchor and the record store.
fn complete_with_record(
    setup: &Setup,
    request_id: &str,
) -> Result<(String, crate::agent_record::AgentRecordStore), Box<dyn std::error::Error>> {
    let mut record = setup.store.load(request_id)?.ok_or("the creation request is stored")?;
    record.state = AgentCreationState::Complete;
    setup.store.save(&record)?;
    let plan = ramflux_protocol::custody::decode_register_plan(&record.plan_bytes()?)
        .map_err(|_| "the stored plan decodes")?;
    let records = crate::agent_record::AgentRecordStore::at(setup.store.agent_record_dir());
    let author = DeviceRef {
        account_anchor: setup.fixture.anchor.clone(),
        device_id: "desktop-device".into(),
        device_epoch: 1,
    };
    crate::agent_record::seed_for_test(&records, &plan.agent_anchor, &author, setup.fixture.now)?;
    Ok((plan.agent_anchor, records))
}

/// A confirmed or unconfirmed `agent.delete` request frame for the human account.
fn delete_frame(anchor: &str, confirmed: bool) -> crate::LocalBusFrame {
    crate::LocalBusFrame::request(
        format!("delete-{confirmed}"),
        Some(HUMAN.to_owned()),
        "agent",
        "agent.delete",
        serde_json::json!({ "agent_anchor": anchor, "confirmed": confirmed }),
    )
}

/// AGENT-IDENTITY-01 F1 (a), decision r23: `agent.delete` closes the agent's running session before
/// the local state goes. The close happens only for a confirmed delete of a stored record in `U`; an
/// unconfirmed delete leaves the session open. Through the routed method the session is closed and
/// the local account directory is removed. The record retirement that follows needs the owner
/// device's native enrolment, which this custody-level fixture does not have (it is covered by
/// `agent_delete_in_u_removes_the_vault_items_and_retires_on_both_roots`), so the reply of the routed
/// call is not asserted here.
#[tokio::test(flavor = "current_thread")]
async fn agent_delete_closes_the_running_session_before_removing_local_state() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(async {
            let nodes = node_store(vec![node(DEFAULT_NODE, true)], Some(DEFAULT_NODE));
            let setup = authorized_request("req-delete", &nodes)?;
            let now = setup.fixture.now;
            let supervisor = crate::bus::supervisor::Supervisor::new(setup.config.clone())?;
            supervisor
                .activate_native(HUMAN, human_passphrase(), Some(DEFAULT_NODE.into()))
                .await?;
            supervisor.advance_agent_creations(HUMAN, now + 2).await?;
            assert!(supervisor.account_is_open(&setup.account_id), "the agent is connected");
            let (anchor, _records) = complete_with_record(&setup, "req-delete")?;
            let directory = setup.fixture.root.0.join("custody_accounts").join(&setup.account_id);

            let mutation =
                |anchor: &str, confirmed: Option<bool>| ramflux_protocol::message::AgentMutation {
                    agent_anchor: anchor.to_owned(),
                    base_revision: None,
                    incarnation: None,
                    confirmed,
                };
            for refused in [mutation(&anchor, None), mutation(&anchor, Some(false))] {
                supervisor.close_agent_before_delete(HUMAN, &refused).await?;
                assert!(
                    supervisor.account_is_open(&setup.account_id),
                    "an unconfirmed delete keeps the session"
                );
            }
            let unknown = mutation(&ramflux_protocol::encode_base64url([7_u8; 32]), Some(true));
            supervisor.close_agent_before_delete(HUMAN, &unknown).await?;
            assert!(
                supervisor.account_is_open(&setup.account_id),
                "a delete of another agent keeps the session"
            );
            assert!(directory.is_dir(), "nothing was removed so far");

            let mut confirmed = delete_frame(&anchor, true);
            let _ = crate::bus::agent_methods::respond(&mut confirmed, &supervisor).await?;
            assert!(!supervisor.account_is_open(&setup.account_id), "the session is closed");
            assert!(!directory.exists(), "the local account directory is removed after the close");
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
}

/// AGENT-IDENTITY-01 F1 (b), decision r23: a retired agent is refused at activation and at the
/// passphrase unlock with the typed reason `agent_retired`, by account id (resolved to the anchor
/// through the creation records), before any directory lookup can report an unknown account. The
/// passphrase is the agent's real one, so the refusal is the guard and not a wrong secret.
#[tokio::test(flavor = "current_thread")]
async fn activation_and_unlock_refuse_a_retired_agent() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(async {
            let nodes = node_store(vec![node(DEFAULT_NODE, true)], Some(DEFAULT_NODE));
            let setup = authorized_request("req-retired", &nodes)?;
            let record =
                setup.store.load("req-retired")?.ok_or("the creation request is stored")?;
            let passphrase = agent_passphrase(&setup.desk, &record)?;
            let (anchor, records) = complete_with_record(&setup, "req-retired")?;
            let supervisor = crate::bus::supervisor::Supervisor::new(setup.config.clone())?;

            // Before the retirement the guard passes: the account is not refused by it.
            assert!(
                supervisor.refuse_unusable_agent(&setup.account_id).is_ok(),
                "an agent in U passes the guard"
            );

            let current = records.load(&anchor)?.ok_or("the record")?;
            let author = DeviceRef {
                account_anchor: setup.fixture.anchor.clone(),
                device_id: "desktop-device".into(),
                device_epoch: 1,
            };
            crate::agent_record::retire(
                &records,
                &anchor,
                &current.identity,
                &author,
                setup.fixture.now,
            )?;

            let refused = supervisor
                .activate_native(&setup.account_id, passphrase.clone(), Some(DEFAULT_NODE.into()))
                .await;
            assert!(
                matches!(refused, Err(SdkError::AgentCreationRefused("agent_retired"))),
                "activation of a retired agent is refused: {refused:?}"
            );
            let (outbound, _receiver) = tokio::sync::mpsc::channel(8);
            let connection = crate::bus::state::LocalBusConnectionState::new(1, outbound);
            let frame = crate::LocalBusFrame::request(
                "unlock-retired",
                Some(setup.account_id.clone()),
                "account",
                "account.unlock",
                serde_json::json!({ "passphrase": passphrase.as_str() }),
            );
            let refused = supervisor.request(frame, &connection).await;
            assert!(
                matches!(refused, Err(SdkError::AgentCreationRefused("agent_retired"))),
                "the passphrase unlock of a retired agent is refused"
            );
            assert!(!supervisor.account_is_open(&setup.account_id), "not opened");
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Activation of a committed agent through the supervisor: the same entry point the creation
//! confirmation uses (`Supervisor::activate_native`), reached by the advance step.
use crate::custody::PrimaryVault;
use crate::custody::agent_creation::tests::{
    HUMAN, account_id_of, approve_for_human, begin_for_human, human_fixture_with, owner_anchor,
    phone,
};
use crate::custody::agent_creation::{AgentCreationState, AgentCreationStore};
use std::sync::Arc;
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const HUMAN_SECRET: &[u8] = b"human data secret";

/// A node profile that advertises agent custody authorization, selected as the default node.
fn capable_node() -> crate::NodeProfile {
    crate::NodeProfile {
        discovery_url: "https://capable-node".to_owned(),
        node_id: "capable-node".to_owned(),
        node_public_key: ramflux_protocol::encode_base64url([7_u8; 32]),
        pin_source: crate::NodePinSource::Operator,
        ca_cert_pem: "test CA".to_owned(),
        gateway: crate::NodeGateway {
            quic_addr: "127.0.0.1:1".to_owned(),
            tcp_addr: "127.0.0.1:1".to_owned(),
            server_name: "capable-node".to_owned(),
        },
        relay: crate::NodeRelay {
            quic_addr: "127.0.0.1:1".to_owned(),
            server_name: "capable-node".to_owned(),
        },
        prekey_http_url: "https://capable-node".to_owned(),
        signaling_turn_addr: String::new(),
        protocol_versions: Vec::new(),
        client_capabilities: vec![
            ramflux_protocol::AGENT_CUSTODY_AUTHORIZATION_CAPABILITY.to_owned(),
        ],
        discovered_at: 1,
        expires_at: u64::MAX,
        enabled: true,
        builtin: false,
        safety_warnings: std::collections::BTreeSet::new(),
    }
}

#[tokio::test]
async fn advance_activates_an_approved_agent_on_the_open_human_account() -> TestResult {
    tokio::task::LocalSet::new()
        .run_until(async {
            let fixture = human_fixture_with(Some(HUMAN_SECRET))?;
            let root = fixture.root.0.to_path_buf();
            let store = AgentCreationStore::open(root.clone(), HUMAN)?;
            let desk = Arc::new(crate::custody::memory_vault::MemoryPrimaryVault::default());
            let phone = phone(&owner_anchor())?;
            let outcome = begin_for_human(&fixture, &store, &desk, "req-activate", None)?;
            let authorized = approve_for_human(&fixture, &phone, &store, &desk, &outcome)?;
            let account_id = account_id_of(&authorized)?;

            let node = capable_node();
            let nodes = crate::node::NodeStore {
                default_node_id: Some(node.node_id.clone()),
                profiles: std::collections::BTreeMap::from([(node.node_id.clone(), node)]),
                ..crate::node::NodeStore::default()
            };
            nodes.save(&root)?;
            let socket = root.join("activate.sock");
            let mut config = crate::LocalBusConfig::new(&socket, &root);
            config.custody_vault = Some(desk.clone());
            let supervisor = crate::bus::supervisor::Supervisor::new(config.clone())?;
            let passphrase = || Zeroizing::new(String::from_utf8_lossy(HUMAN_SECRET).into_owned());
            supervisor.activate_native(HUMAN, passphrase(), None).await?;
            let outcomes = supervisor.advance_agent_creations(HUMAN, fixture.now + 2).await?;
            assert!(supervisor.account_is_open(&account_id), "agent open after advance");
            assert_eq!(outcomes.len(), 1, "one pending request: {outcomes:?}");
            assert!(
                matches!(outcomes[0].1, Ok(AgentCreationState::PublicationPending)),
                "{outcomes:?}"
            );
            drop(supervisor);

            // Restart: a new supervisor on the same root re-unlocks the human and advances again.
            let restarted = crate::bus::supervisor::Supervisor::new(config)?;
            restarted.activate_native(HUMAN, passphrase(), None).await?;
            let again = restarted.advance_agent_creations(HUMAN, fixture.now + 3).await?;
            assert!(
                matches!(again.as_slice(), [(_, Ok(AgentCreationState::PublicationPending))]),
                "after restart: {again:?}"
            );
            let record = store.load("req-activate")?.ok_or("the request is stored")?;
            let reference = record
                .vault_refs
                .iter()
                .find(|reference| reference.starts_with("agent-provisioning:"))
                .ok_or("the request names its provisioning secret")?;
            let agent_secret = desk.load_provisioning_secret(reference)?;
            let agent_text = Zeroizing::new(std::str::from_utf8(&agent_secret)?.to_owned());
            restarted.activate_native(&account_id, agent_text, None).await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real phrase-created native authority and private prekeys for ordinary feature unit tests.
use crate::{
    GatewayCustodyConfig, GatewayQuicEndpointConfig, GatewaySessionConfig, RamfluxClient,
    custody::tests::{Root, TestVault, create_with_device},
    prekey::SdkDeviceManifestResponse,
};
use ramflux_protocol::custody::{CustodyManifest, CustodyManifestDevice, DeviceRef, Publication};
use std::sync::Arc;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
/// Where a fixture's account index lives and which guard cleans it up.
pub(crate) struct Home<'a> {
    pub(crate) root: Root,
    pub(crate) account_root: &'a std::path::Path,
}
pub(crate) struct Fixture {
    pub(crate) client: RamfluxClient,
    pub(crate) vault: Arc<TestVault>,
    pub(crate) manifest: SdkDeviceManifestResponse,
    pub(crate) config: GatewaySessionConfig,
    pub(crate) root: Root,
}
impl Fixture {
    pub(crate) async fn new(id: &str) -> TestResult<Self> {
        Self::with_device(id, "primary").await
    }
    pub(crate) async fn with_device(id: &str, device: &str) -> TestResult<Self> {
        Box::pin(Self::with_device_at(id, device, crate::custody::network_now()?)).await
    }
    /// A phrase-created native fixture that also returns its recovery words, so a test can derive
    /// the master key and sign a primary transfer. Test support only; production never keeps them.
    pub(crate) async fn with_device_keeping_phrase(
        id: &str,
        device: &str,
    ) -> TestResult<(Self, zeroize::Zeroizing<String>)> {
        let root = Root::new()?;
        let vault = Arc::new(TestVault::default());
        let now = crate::custody::network_now()?;
        let (account, phrase) = crate::custody::tests::create_with_device_and_phrase(
            &root.0,
            id,
            device,
            vault.as_ref(),
            now,
        )?;
        let record = account.record().clone();
        Ok((Self::finish_creation(root, vault, id, device, record).await?, phrase))
    }
    pub(super) async fn with_device_at(id: &str, device: &str, now: u64) -> TestResult<Self> {
        let root = Root::new()?;
        let vault = Arc::new(TestVault::default());
        let account = create_with_device(&root.0, id, device, vault.as_ref(), now)?;
        Self::finish_creation(root, vault, id, device, account.record().clone()).await
    }
    async fn finish_creation(
        root: Root,
        vault: Arc<TestVault>,
        id: &str,
        device: &str,
        record: ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>,
    ) -> TestResult<Self> {
        let mut client = RamfluxClient::new();
        client.open_account_index(&root.0)?;
        client.bind_device_unlock(
            std::path::Path::new(&root.0),
            vault.as_ref(),
            id,
            crate::client::device_unlock::DeviceSecret::Create,
        )?;
        client.seal_new_account_data(
            id,
            &record.body.account_anchor,
            b"native fixture data passphrase",
        )?;
        client.unlock_account(id, b"native fixture data passphrase")?;
        client.initialize_born_v3_branch(device, vault.clone()).await?;
        Self::ready(client, root, vault, id, device, record)
    }
    pub(crate) fn accept_peer(&self, peer: &Self) -> TestResult {
        self.client.persist_observed_identity_directory_now(&peer.manifest)?;
        self.client.establish_friend_link(
            &format!("authored-link:{}", peer.client.own_account_anchor()?),
            &self.client.own_account_anchor()?,
            &peer.client.own_account_anchor()?,
        )?;
        self.client.receive_generated_own_contact(&authored::authored_contact(self, peer)?)?;
        Ok(())
    }

    /// `principal` is the published id. Routed card tests keep it equal to the account id.
    pub(crate) async fn named(account: &str, principal: &str, device: &str) -> TestResult<Self> {
        let root = Root::new()?;
        let vault = Arc::new(TestVault::default());
        let now = crate::custody::network_now()?;
        let mut input = crate::custody::tests::input(account);
        input.principal_id = principal.into();
        input.device_id = device.into();
        let mut ceremony = crate::custody::CreationCeremony::begin(&root.0, input, now)?;
        let phrase = ceremony.show_once()?;
        let positions = ceremony.hidden_challenge()?;
        let created = ceremony.confirm(
            &crate::custody::tests::words(&phrase, positions)?,
            vault.as_ref(),
            now,
        )?;
        Box::pin(Self::finish_creation(root, vault, account, device, created.record().clone()))
            .await
    }
    pub(crate) async fn externally_custodied(id: &str) -> TestResult<Self> {
        Self::headless(&format!("principal-{id}"), "Example Human").await
    }

    /// An agent (`headless_ai`) account created through the REAL agent creation flow (decision
    /// D6): a human account on the same root, the desktop sibling, the primary's approval and the
    /// account commit are the production code (`create_test_agent`). The account id and the device
    /// id are chosen by the flow and are in `account_id` and `device`; `principal` is published.
    pub(crate) async fn headless(principal: &str, display_name: &str) -> TestResult<Self> {
        use crate::custody::agent_creation::test_agent::{AgentRequest, create_test_agent};
        let root = Root::new()?;
        let vault = Arc::new(TestVault::default());
        let now = crate::custody::network_now()?;
        let human = format!("custodian-{principal}");
        crate::custody::tests::create(&root.0, &human, vault.as_ref(), now)?;
        crate::custody::tests::mark_live(&root.0, &human, now)?;
        let created = create_test_agent(
            &AgentRequest {
                root: &root.0,
                human_account_id: &human,
                human_principal: &format!("principal-{human}"),
                human_vault: vault.as_ref(),
                arm_approval: &|plan_hash| vault.arm_agent_decision(plan_hash),
                agent_vault: vault.as_ref(),
                agent_principal: principal,
                display_name,
                request_id: "fixture-agent",
            },
            now,
        )?;
        let mut client = RamfluxClient::new();
        client.open_account_index(&root.0)?;
        client.unlock_account(&created.account_id, created.passphrase.as_bytes())?;
        client.initialize_born_v3_branch(&created.device_id, vault.clone()).await?;
        Self::ready(client, root, vault, &created.account_id, &created.device_id, created.record)
    }
    fn ready(
        client: RamfluxClient,
        root: Root,
        vault: Arc<TestVault>,
        id: &str,
        device: &str,
        record: ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>,
    ) -> TestResult<Self> {
        let account_root = root.0.to_path_buf();
        Self::ready_in(
            client,
            Home { root, account_root: &account_root },
            vault,
            id,
            device,
            record,
        )
    }
    /// `account_root` is the directory that holds the client's account index; `root` only owns
    /// the fixture's cleanup.
    pub(crate) fn ready_in(
        client: RamfluxClient,
        home: Home<'_>,
        vault: Arc<TestVault>,
        id: &str,
        device: &str,
        record: ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>,
    ) -> TestResult<Self> {
        let Home { root, account_root } = home;
        let anchor = record.body.account_anchor.clone();
        let identity = client.owned_device_identity()?;
        let bundle = client.load_x3dh_private_state(&identity)?.bundle;
        let manifest =
            SdkDeviceManifestResponse::from_native(CustodyManifest {
                publication: Publication { record, compacted_ids: None },
                custodian_publication: client
                    .born_v3_account
                    .as_ref()
                    .ok_or("test: native account")?
                    .custodian_publication(account_root, crate::custody::network_now()?)?,
                devices: vec![CustodyManifestDevice {
                    device_ref: DeviceRef {
                        account_anchor: anchor,
                        device_id: device.into(),
                        device_epoch: 1,
                    },
                    target_delivery_id: identity.storage_key().into(),
                    prekey_bundle: serde_json::to_value(bundle)?,
                    message_layer: None,
                }],
            })?;
        // The fixture models a directory manifest the account just fetched.
        let manifest = manifest.fetched_from(std::time::Instant::now());
        client.persist_fetched_identity_directory(&manifest)?;
        let endpoint = GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse()?,
            gateway_addr: "127.0.0.1:1".parse()?,
            server_name: "unused.example".into(),
            ca_cert: account_root.join("unused.pem"),
            principal_id: manifest.principal_id.clone(),
            device_id: device.into(),
            target_delivery_id: identity.storage_key().into(),
            prekey_http_url: None,
        };
        let mut config = GatewaySessionConfig::auto(endpoint)
            .with_native_custody(GatewayCustodyConfig {
                account_root: account_root.to_path_buf(),
                account_id: id.into(),
                node_id: "fixture-node".into(),
                node_public_key: ramflux_protocol::encode_base64url([7; 32]),
                vault: vault.clone(),
            })
            .with_account_identity(&client)?;
        // These local feature tests install the already certified branch as the live proof
        // handoff does. They create no network session and make no transport-proof claim.
        config.device_branch =
            Some(Arc::new(client.device_branch.as_ref().ok_or("branch")?.clone()));
        config.source_identity = Some(identity);
        assert!(client.identity_root.is_none());
        Ok(Self { client, vault, manifest, config, root })
    }
}

pub(crate) mod account;
pub(crate) mod history;
mod sibling;

#[path = "native_test_support/authored.rs"]
mod authored;
mod authored_delete;

mod authored_edit;

mod authored_epoch;

mod authored_group;

mod authored_edit_erasure;

pub(crate) mod live_own_copy;

mod generated_routes;

pub(crate) mod peer_control_send;

mod generation_zero_tests;

mod history_item_tests;

mod reaction_restore_tests;

pub(crate) mod watchdog;

pub(crate) mod activation_send;
#[cfg(all(ramflux_itest, not(ramflux_release_profile), not(ramflux_production)))]
mod local_search;

pub(crate) mod directory;

mod named;

pub(crate) mod sibling_erasure;

mod group_history;

pub(crate) mod bus;
pub(crate) mod pairing_history;
pub(crate) mod router;

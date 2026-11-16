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
        Self::named_kind(account, principal, device, ramflux_protocol::PrincipalKind::Human).await
    }

    pub(crate) async fn named_kind(
        account: &str,
        principal: &str,
        device: &str,
        kind: ramflux_protocol::PrincipalKind,
    ) -> TestResult<Self> {
        let root = Root::new()?;
        let vault = Arc::new(TestVault::default());
        let now = crate::custody::network_now()?;
        let mut input = crate::custody::tests::input(account);
        input.principal_id = principal.into();
        input.device_id = device.into();
        input.principal_kind = kind;
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
        Self::headless(id, &format!("principal-{id}"), "primary", "Example Human").await
    }

    /// Headless account with a live human custodian on the same root.
    pub(crate) async fn headless(
        account: &str,
        principal: &str,
        device: &str,
        display_name: &str,
    ) -> TestResult<Self> {
        let root = Root::new()?;
        let vault = Arc::new(TestVault::default());
        let now = crate::custody::network_now()?;
        let custodian = format!("custodian-{account}");
        crate::custody::tests::create(&root.0, &custodian, vault.as_ref(), now)?;
        crate::custody::tests::mark_live(&root.0, &custodian, now)?;
        let mut input = crate::custody::tests::input(account);
        input.principal_id = principal.into();
        input.device_id = device.into();
        input.display_name = display_name.into();
        input.principal_kind = ramflux_protocol::PrincipalKind::HeadlessAi;
        input.custodian_account_id = Some(custodian);
        let mut ceremony = crate::custody::CreationCeremony::begin(&root.0, input, now)?;
        let phrase = ceremony.show_once()?;
        let positions = ceremony.hidden_challenge()?;
        let created = ceremony.confirm_with_passphrase(
            &crate::custody::tests::words(&phrase, positions)?,
            vault.as_ref(),
            now,
            b"external fixture passphrase",
        )?;
        let mut client = RamfluxClient::new();
        client.open_account_index(&root.0)?;
        client.unlock_account(account, b"external fixture passphrase")?;
        client.initialize_born_v3_branch(device, vault.clone()).await?;
        Self::ready(client, root, vault, account, device, created.record().clone())
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

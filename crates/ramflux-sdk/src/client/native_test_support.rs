// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real phrase-created native authority and private prekeys for ordinary feature unit tests.
use crate::{
    GatewayCustodyConfig, GatewayQuicEndpointConfig, GatewaySessionConfig, RamfluxClient,
    custody::tests::{Root, TestVault},
    prekey::SdkDeviceManifestResponse,
};
use ramflux_protocol::custody::{CustodyManifest, CustodyManifestDevice, DeviceRef, Publication};
use std::sync::Arc;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
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
        Self::named(id, &format!("principal-{id}"), device).await
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
        let anchor = created.record().body.account_anchor.clone();
        let mut client = RamfluxClient::new();
        client.open_account_index(&root.0)?;
        client.seal_new_account_data(account, &anchor, b"native fixture data passphrase")?;
        client.unlock_account(account, b"native fixture data passphrase")?;
        client.initialize_born_v3_branch(device, vault.clone()).await?;
        Self::ready(client, root, vault, account, device, created.record().clone())
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
        crate::custody::tests::create(&root.0, "custodian", vault.as_ref(), now)?;
        crate::custody::tests::mark_live(&root.0, "custodian", now)?;
        let mut input = crate::custody::tests::input(account);
        input.principal_id = principal.into();
        input.device_id = device.into();
        input.display_name = display_name.into();
        input.principal_kind = ramflux_protocol::PrincipalKind::HeadlessAi;
        input.custodian_account_id = Some("custodian".into());
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
                    .custodian_publication(&root.0, crate::custody::network_now()?)?,
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
        client.persist_fetched_identity_directory(&manifest)?;
        let endpoint = GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse()?,
            gateway_addr: "127.0.0.1:1".parse()?,
            server_name: "unused.example".into(),
            ca_cert: root.0.join("unused.pem"),
            principal_id: manifest.principal_id.clone(),
            device_id: device.into(),
            target_delivery_id: identity.storage_key().into(),
            prekey_http_url: None,
        };
        let mut config = GatewaySessionConfig::auto(endpoint)
            .with_native_custody(GatewayCustodyConfig {
                account_root: root.0.to_path_buf(),
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

mod history;
mod sibling;

#[path = "native_test_support/authored.rs"]
mod authored;

mod authored_edit;

mod authored_epoch;

mod authored_group;

mod authored_edit_erasure;

mod live_own_copy;

mod generated_routes;

mod peer_control_send;

mod generation_zero_tests;

mod history_item_tests;

mod reaction_restore_tests;

pub(crate) mod watchdog;

#[cfg(all(ramflux_itest, not(ramflux_release_profile), not(ramflux_production)))]
mod local_search;
pub(crate) mod pairing_history;

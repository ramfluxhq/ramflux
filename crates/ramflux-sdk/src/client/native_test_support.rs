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
        let root = Root::new()?;
        let vault = Arc::new(TestVault::default());
        let now = crate::custody::network_now()?;
        let account = create_with_device(&root.0, id, device, vault.as_ref(), now)?;
        let anchor = account.record().body.account_anchor.clone();
        let mut client = RamfluxClient::new();
        client.open_account_index(&root.0)?;
        client.seal_new_account_data(id, &anchor, b"native fixture data passphrase")?;
        client.unlock_account(id, b"native fixture data passphrase")?;
        client.initialize_born_v3_branch(device, vault.clone()).await?;
        let identity = client.owned_device_identity()?;
        let bundle = client.load_x3dh_private_state(&identity)?.bundle;
        let manifest = SdkDeviceManifestResponse::from_native(CustodyManifest {
            publication: Publication { record: account.record().clone(), compacted_ids: None },
            custodian_publication: None,
            devices: vec![CustodyManifestDevice {
                device_ref: DeviceRef {
                    account_anchor: anchor,
                    device_id: device.into(),
                    device_epoch: 1,
                },
                target_delivery_id: identity.storage_key().into(),
                prekey_bundle: serde_json::to_value(bundle)?,
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
                account_root: root.0.clone(),
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

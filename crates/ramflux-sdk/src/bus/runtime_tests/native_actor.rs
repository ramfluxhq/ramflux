// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native generation-1 account pair for actor tests. Both accounts live in one data root; each
//! actor reopens its account from disk inside its own thread, exactly as a restart does.
use super::*;
use crate::client::native_test_support::{
    Fixture, activation_send::tests::publish_layer_four, bus,
};
use crate::custody::tests::{Root, TestVault};

type Case<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PASSPHRASE: &[u8] = b"native fixture data passphrase";

#[derive(Clone)]
pub(super) struct Side {
    pub(super) id: &'static str,
    pub(super) device: String,
    pub(super) root_commitment: String,
    pub(super) storage_key: String,
    vault: Arc<TestVault>,
    config: GatewaySessionConfig,
    pub(super) manifest: crate::prekey::SdkDeviceManifestResponse,
}

pub(super) struct Pair {
    pub(super) alice: Side,
    pub(super) bob: Side,
    pub(super) data_root: PathBuf,
    directory: tokio::task::JoinHandle<()>,
    _roots: (Root, Root),
}
impl Drop for Pair {
    fn drop(&mut self) {
        self.directory.abort();
    }
}

fn side(id: &'static str, fixture: Fixture) -> Case<(Side, Root)> {
    let Fixture { client, vault, manifest, config, root } = fixture;
    let identity = client.owned_device_identity()?;
    let side = Side {
        id,
        device: identity.device_id().to_owned(),
        root_commitment: identity.root_commitment().to_owned(),
        storage_key: identity.storage_key().to_owned(),
        vault,
        config,
        manifest,
    };
    // The actor opens its own connection; the fixture's must not stay open beside it.
    drop(client);
    Ok((side, root))
}

/// Two native accounts that know each other: seeded pair sessions, cached directories and
/// accepted friend links in both directions.
pub(super) async fn pair() -> Case<Pair> {
    let mut alice = Box::pin(Fixture::with_principal("alice", "device-alice", "alice")).await?;
    Box::pin(publish_layer_four(&mut alice)).await?;
    let mut bob = Box::pin(alice.peer_at_same_home("bob", "device-bob", "bob")).await?;
    Box::pin(publish_layer_four(&mut bob)).await?;
    alice.client.persist_observed_identity_directory_now(&bob.manifest)?;
    bob.client.persist_observed_identity_directory_now(&alice.manifest)?;
    bus::seed_pair(&alice.client, &bob.client)?;
    let alice_root = alice.client.owned_device_identity()?.root_commitment().to_owned();
    let bob_root = bob.client.owned_device_identity()?.root_commitment().to_owned();
    alice.client.establish_friend_link("friend", &alice_root, &bob_root)?;
    bob.client.establish_friend_link("friend", &bob_root, &alice_root)?;
    let data_root = alice.root.0.to_path_buf();
    // Both directories are served by one loopback gateway double: recipients are re-verified
    // against it, exactly as a live account does before it seals.
    let (address, directory) = crate::bus::dispatch::surface_transport::fixture::directory(
        &data_root,
        BTreeMap::from([
            (alice_root, serde_json::to_value(&alice.manifest)?),
            (bob_root, serde_json::to_value(&bob.manifest)?),
        ]),
    )
    .await?;
    for fixture in [&mut alice, &mut bob] {
        fixture.config.transport_kind = GatewaySessionTransportKind::TcpTls;
        fixture.config.gateway_addr = address;
        fixture.config.tcp_gateway_addr = Some(address);
        fixture.config.server_name = "test-gateway".into();
        fixture.config.ca_cert = data_root.join("ca.pem");
    }
    let (alice, alice_home) = side("alice", alice)?;
    let (bob, bob_home) = side("bob", bob)?;
    Ok(Pair { alice, bob, data_root, directory, _roots: (alice_home, bob_home) })
}

impl Pair {
    /// The direct conversation both accounts share.
    pub(super) fn conversation(&self) -> Case<String> {
        Ok(ramflux_protocol::message::dm_scope::derive(
            &self.alice.root_commitment,
            &self.bob.root_commitment,
        )?)
    }
}

impl Side {
    /// A `message.submit` body carrying plaintext to `to`; the account seals real generation-1
    /// content for it.
    pub(super) fn submit_body(
        &self,
        to: &Side,
        conversation: &str,
        ids: (&str, &str),
        text: &[u8],
        created_at: i64,
    ) -> serde_json::Value {
        serde_json::json!({
            "conversation_id": conversation, "message_id": ids.0, "envelope_id": ids.1,
            "source_principal_id": self.id, "sender_id": self.device,
            "recipient_principal_commitment": to.root_commitment, "recipient_device_id": to.device,
            "target_delivery_id": to.storage_key, "encrypted_body_base64": "",
            "plaintext_body_base64": ramflux_protocol::encode_base64url(text),
            "created_at": created_at, "ttl": 60
        })
    }

    /// The `message.submit` request frame for `submit_body`.
    pub(super) fn submit_request(
        &self,
        to: &Side,
        conversation: &str,
        request_id: &str,
        ids: (&str, &str),
        text: &[u8],
    ) -> LocalBusFrame {
        let now = now_unix_timestamp();
        request(
            request_id,
            self.id,
            "message.submit",
            self.submit_body(to, conversation, ids, text, now),
        )
    }

    /// The actor's account: reopened from disk on the actor thread, directory of `peer` cached
    /// as freshly fetched, gateway replaced by the test double.
    pub(super) fn initializer(
        &self,
        data_root: &Path,
        peer: &crate::prekey::SdkDeviceManifestResponse,
        gateway: impl ramflux_transport::GatewaySessionTransport + Send + 'static,
    ) -> AccountInitializer {
        let root = data_root.to_path_buf();
        let id = self.id;
        let device = self.device.clone();
        let vault = Arc::clone(&self.vault);
        let config = self.config.clone();
        let peer = peer.clone();
        let own = self.manifest.clone();
        Box::new(move |index| {
            let mut client = RamfluxClient::new();
            client.account_index = Some(index);
            client.open_account_index(&root)?;
            client.unlock_account(id, PASSPHRASE)?;
            client.initialize_born_v3_branch_for_fixture(&device, vault.as_ref())?;
            let branch = client.device_branch.clone().ok_or(SdkError::CustodySetupInvalid)?;
            client.persist_observed_identity_directory_now(&own)?;
            client.persist_observed_identity_directory_now(&peer)?;
            // `with_account_identity` marks networking ready but clears these two; the session
            // needs both to sign and open.
            let mut config = config.with_account_identity(&client)?;
            config.device_branch = Some(Arc::new(branch));
            config.source_identity = Some(client.owned_device_identity()?);
            let anchor = client.own_account_anchor()?;
            let engine = GatewaySessionEngine::with_test_transport(config, Box::new(gateway));
            let mut account = LocalBusAccountState::new(client, engine, anchor);
            let mut setup = LocalBusConfig::new(root.join("fixture.sock"), root);
            setup.custody_vault = Some(vault);
            account.native_setup = Some(setup);
            Ok(account)
        })
    }
}

/// A second client on the same account database, as another process or thread would hold it.
pub(super) fn second_client(data_root: &Path, side: &Side) -> Result<RamfluxClient, SdkError> {
    let mut client = RamfluxClient::new();
    client.open_account_index(data_root)?;
    client.unlock_account(side.id, PASSPHRASE)?;
    client.initialize_born_v3_branch_for_fixture(&side.device, side.vault.as_ref())?;
    Ok(client)
}

pub(super) fn gateway(
    blocked: Option<GatewayBlock>,
    cancelled: Arc<AtomicBool>,
    submits: Arc<AtomicUsize>,
    cancelled_notice: Option<oneshot::Sender<()>>,
) -> Gateway {
    Gateway { last: None, pending_cursor: None, blocked, cancelled, submits, cancelled_notice }
}

pub(super) fn stall(entered: oneshot::Sender<()>, envelope: &str) -> GatewayBlock {
    GatewayBlock { entered, submit_envelope: Some(envelope.to_owned()), relay_token: false }
}

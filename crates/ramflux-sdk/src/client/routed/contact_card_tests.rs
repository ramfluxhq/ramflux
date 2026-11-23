// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A card exported by one account resolves a fresh peer through signed node discovery.
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub(super) struct Origin {
    url: String,
    record: ramflux_protocol::WellKnownClientRecord,
    requests: Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<Result<(), SdkError>>,
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Origin {
    pub(super) async fn new(directory: &Directory) -> Result<Self, SdkError> {
        Self::named(directory, "contact.test").await
    }
    async fn named(directory: &Directory, node_id: &str) -> Result<Self, SdkError> {
        Self::bound(directory, node_id, "127.0.0.1:0", None).await
    }
    pub(super) async fn with_manifests(
        directory: &Directory,
        node_id: &str,
        manifests: Arc<std::sync::Mutex<Vec<crate::prekey::SdkDeviceManifestResponse>>>,
    ) -> Result<Self, SdkError> {
        Self::serve(directory, node_id, "127.0.0.1:0", None, Some(manifests)).await
    }
    async fn bound(
        directory: &Directory,
        node_id: &str,
        bind: &str,
        host: Option<&str>,
    ) -> Result<Self, SdkError> {
        Self::serve(directory, node_id, bind, host, None).await
    }
    async fn serve(
        directory: &Directory,
        node_id: &str,
        bind: &str,
        host: Option<&str>,
        manifests: Option<Arc<std::sync::Mutex<Vec<crate::prekey::SdkDeviceManifestResponse>>>>,
    ) -> Result<Self, SdkError> {
        let listener = tokio::net::TcpListener::bind(bind).await?;
        let addr = listener.local_addr()?;
        let url = host.map_or_else(
            || format!("http://{addr}"),
            |host| format!("http://{host}:{}", addr.port()),
        );
        let now = now_unix_timestamp().unsigned_abs();
        let mut record = ramflux_protocol::WellKnownClientRecord {
            schema: ramflux_protocol::WELL_KNOWN_CLIENT_SCHEMA.into(),
            node_id: node_id.into(),
            node_public_key: ramflux_crypto::public_key_base64url_from_seed(&[91; 32]),
            node_ca_cert_pem: std::fs::read_to_string(&directory.ca)?,
            gateway_quic_addr: directory.addr.to_string(),
            gateway_tcp_addr: directory.addr.to_string(),
            gateway_server_name: "directory.test".into(),
            relay_quic_addr: "127.0.0.1:17447".into(),
            relay_server_name: "relay.test".into(),
            prekey_http_url: url.clone(),
            signaling_turn_addr: "127.0.0.1:3478".into(),
            protocol_versions: vec!["message-schema.v1".into()],
            client_capabilities: vec!["prekey".into()],
            version: "0.2.0 (abcdef123456)".to_owned(),
            updated_at: now,
            expires_at: now + 3600,
            signature: String::new(),
        };
        record.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_protocol::client_discovery_signing_bytes(&record)?,
            [91; 32],
        );
        let record_body = serde_json::to_vec(&record)?;
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = requests.clone();
        let proxy_request = format!("GET {url}/.well-known/ramflux/client ");
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0_u8; 4096];
                let n = stream.read(&mut buf).await?;
                observed.fetch_add(1, Ordering::SeqCst);
                let request = String::from_utf8_lossy(&buf[..n]);
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let payload = if path.starts_with("/.well-known/ramflux/client")
                    || request.starts_with(&proxy_request)
                {
                    record_body.clone()
                } else if let Some(commitment) = path.strip_prefix("/mvp1/device-manifest/") {
                    manifest_payload(manifests.as_ref(), commitment)?
                } else {
                    return Err(invalid("unexpected discovery request"));
                };
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",payload.len()).as_bytes()).await?;
                stream.write_all(&payload).await?;
                stream.shutdown().await?;
            }
            Ok(())
        });
        Ok(Self { url, record, requests, task })
    }
}
fn manifest_payload(
    manifests: Option<&Arc<std::sync::Mutex<Vec<crate::prekey::SdkDeviceManifestResponse>>>>,
    commitment: &str,
) -> Result<Vec<u8>, SdkError> {
    let manifests = manifests.ok_or_else(|| invalid("manifest request without a directory"))?;
    let records = manifests.lock().map_err(|_| invalid("directory mutex"))?;
    let manifest = records
        .iter()
        .find(|manifest| manifest.principal_commitment == commitment)
        .ok_or_else(|| invalid("manifest"))?;
    Ok(serde_json::to_vec(manifest)?)
}

pub(super) fn install_native_home(
    origin: &Origin,
    state: &mut LocalBusDaemonState,
    id: &str,
) -> Result<(), SdkError> {
    let mut profile = crate::node::NodeProfile::from_record(
        origin.record.clone(),
        now_unix_timestamp().unsigned_abs(),
    );
    profile.discovery_url.clone_from(&origin.url);
    let node_id = profile.node_id.clone();
    state.nodes.profiles.insert(node_id.clone(), profile);
    let account = state.accounts.get(id).ok_or_else(|| invalid("account"))?;
    account.client.account_db()?.persist_actor_state("account/node-id", &node_id)?;
    Ok(())
}

fn mismatched_native_card(
    sender: &crate::client::native_test_support::Fixture,
    origin: &Origin,
) -> Result<String, SdkError> {
    let now = crate::custody::network_now()?;
    let account =
        sender.client.born_v3_account.as_ref().ok_or_else(|| invalid("native account"))?;
    let record = account.record();
    let signed = account.sign_contact_card(
        sender.vault.as_ref(),
        ramflux_protocol::custody::ContactCardV3 {
            version: 3,
            principal_id: record.body.principal_id.clone(),
            account_anchor: record.body.account_anchor.clone(),
            master_public_key: record.body.master_certificate.body.master_public_key.clone(),
            master_certificate: record.body.master_certificate.clone(),
            authority_head_hash: ramflux_protocol::custody::object_hash(record)?,
            authority_epoch: record.body.device_set_epoch,
            devices: record.body.devices.clone(),
            node_url: origin.url.clone(),
            node_key_fingerprint: "0".repeat(64),
            display_name: record.body.profile.display_name.clone(),
            issued_at: now,
            expires_at: now.saturating_add(7 * 24 * 60 * 60),
        },
        now,
    )?;
    Ok(crate::contact_card_native::encode(
        &signed,
        i64::try_from(now).map_err(|_| invalid("clock"))?,
    )?
    .0)
}

fn born_card_state(
    alice: &mut crate::client::native_test_support::Fixture,
    bob: &mut crate::client::native_test_support::Fixture,
    directory: &Directory,
) -> Result<LocalBusDaemonState, SdkError> {
    let mut accounts = BTreeMap::new();
    for fixture in [&mut *alice, &mut *bob] {
        let mut config = fixture.config.clone();
        config.transport_kind = GatewaySessionTransportKind::TcpTls;
        config.gateway_addr = directory.addr;
        config.tcp_gateway_addr = Some(directory.addr);
        config.server_name = "directory.test".into();
        config.ca_cert.clone_from(&directory.ca);
        let engine = GatewaySessionEngine::with_test_transport(
            config,
            Box::new(DirectorySession {
                captured: directory.captured.clone(),
                incoming: directory.incoming.clone(),
                acknowledged: directory.acknowledged.clone(),
                records: directory.records.clone(),
                unavailable: directory.unavailable.clone(),
                responses: VecDeque::new(),
            }),
        );
        let id = fixture.client.account_db()?.local_account_id.clone();
        accounts.insert(
            id,
            LocalBusAccountState::new(
                std::mem::take(&mut fixture.client),
                engine,
                fixture.manifest.principal_commitment.clone(),
            ),
        );
    }
    Ok(LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(alice.root.0.join("bus.sock"), &alice.root.0),
        accounts,
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    })
}

#[tokio::test]
async fn an_exported_card_pins_the_root_and_resolves_a_fresh_contact_without_safety_verifying_it()
-> Result<(), SdkError> {
    let mut alice = crate::client::native_test_support::Fixture::named("alice", "alice", "alice")
        .await
        .map_err(|error| invalid(&error.to_string()))?;
    let mut bob = crate::client::native_test_support::Fixture::named("bob", "bob", "bob")
        .await
        .map_err(|error| invalid(&error.to_string()))?;
    let directory =
        Directory::from_records(&alice.root.0, vec![alice.manifest.clone(), bob.manifest.clone()])
            .await?;
    let origin = Origin::new(&directory).await?;
    let wrong = mismatched_native_card(&alice, &origin)?;
    let vault = alice.vault.clone();
    let mut s = born_card_state(&mut alice, &mut bob, &directory)?;
    s.config.custody_vault = Some(vault);
    install_native_home(&origin, &mut s, "alice")?;
    install_native_home(&origin, &mut s, "bob")?;
    let exported = call(&mut s, "alice", "contact.card.export", json!({})).await?;
    let card = exported["card"].as_str().ok_or_else(|| invalid("card"))?;
    let link = exported["link"].as_str().ok_or_else(|| invalid("link"))?;
    let parsed = crate::parse_contact_card(card, now_unix_timestamp())?;
    assert_eq!(
        parsed.root_commitment,
        s.accounts.get("alice").ok_or_else(|| invalid("account"))?.principal_commitment
    );
    assert_eq!(
        crate::parse_contact_card(link, now_unix_timestamp())?.root_commitment,
        parsed.root_commitment
    );
    let error = call(&mut s, "bob", "contact.add", json!({"card":wrong}))
        .await
        .err()
        .ok_or_else(|| invalid("wrong node accepted"))?;
    assert!(matches!(error, SdkError::ContactInput(crate::ContactReason::NodeFingerprintMismatch)));
    assert_eq!(
        s.accounts.get("bob").ok_or_else(|| invalid("account"))?.client.friend_links()?.len(),
        0
    );
    let added = call(&mut s, "bob", "contact.add", json!({"card":link})).await?;
    assert_eq!(added["contact"]["principal_id"], "alice");
    assert_eq!(added["contact"]["root_commitment"], parsed.root_commitment);
    assert_eq!(added["contact"]["reachable"], true);
    assert_eq!(added["contact"]["verified"], false);
    let safety = call(
        &mut s,
        "bob",
        "contact.safety_number",
        json!({"contact_identity_commitment":parsed.root_commitment}),
    )
    .await?;
    assert_eq!(safety["safety_number"].as_array().map(Vec::len), Some(12));
    call(&mut s, "bob", "contact.verify", json!({"expected": safety["expected"]})).await?;
    let contacts = call(&mut s, "bob", "contact.list", json!({})).await?;
    assert_eq!(contacts["contacts"][0]["verified"], true);
    assert_eq!(contacts["contacts"][0]["root_commitment"], parsed.root_commitment);
    Ok(())
}

fn resigned_native_card(
    state: &LocalBusDaemonState,
    id: &str,
    node_url: &str,
    fingerprint: &str,
) -> Result<String, SdkError> {
    let account = state.accounts.get(id).ok_or_else(|| invalid("account"))?;
    let born = account.client.born_v3_account.as_ref().ok_or_else(|| invalid("native account"))?;
    let record = born.record();
    let now = crate::custody::network_now()?;
    let vault = state.config.custody_vault.as_ref().ok_or_else(|| invalid("vault"))?;
    let signed = born.sign_contact_card(
        vault.as_ref(),
        ramflux_protocol::custody::ContactCardV3 {
            version: 3,
            principal_id: record.body.principal_id.clone(),
            account_anchor: record.body.account_anchor.clone(),
            master_public_key: record.body.master_certificate.body.master_public_key.clone(),
            master_certificate: record.body.master_certificate.clone(),
            authority_head_hash: ramflux_protocol::custody::object_hash(record)?,
            authority_epoch: record.body.device_set_epoch,
            devices: record.body.devices.clone(),
            node_url: node_url.into(),
            node_key_fingerprint: fingerprint.into(),
            display_name: record.body.profile.display_name.clone(),
            issued_at: now,
            expires_at: now.saturating_add(7 * 24 * 60 * 60),
        },
        now,
    )?;
    Ok(crate::contact_card_native::encode(
        &signed,
        i64::try_from(now).map_err(|_| invalid("clock"))?,
    )?
    .0)
}

#[tokio::test]
async fn a_card_for_another_home_node_pins_that_home() -> Result<(), SdkError> {
    let mut a = crate::client::native_test_support::Fixture::named("alice", "alice", "alice")
        .await
        .map_err(native_account)?;
    let mut b = crate::client::native_test_support::Fixture::named("bob", "bob", "bob")
        .await
        .map_err(native_account)?;
    let directory =
        Directory::from_records(&a.root.0, vec![a.manifest.clone(), b.manifest.clone()]).await?;
    let home = Origin::new(&directory).await?;
    let foreign =
        Origin::with_manifests(&directory, "foreign.test", directory.records.clone()).await?;
    let vault = a.vault.clone();
    let mut s = born_state(&mut a, &mut b, &directory)?;
    s.config.custody_vault = Some(vault);
    install_native_home(&home, &mut s, "alice")?;
    install_native_home(&home, &mut s, "bob")?;
    let exported = call(&mut s, "alice", "contact.card.export", json!({})).await?;
    let body = crate::parse_contact_card(
        exported["card"].as_str().ok_or_else(|| invalid("card"))?,
        now_unix_timestamp(),
    )?;
    let card = resigned_native_card(&s, "alice", &foreign.url, &body.node.key_fingerprint)?;
    let added = call(&mut s, "bob", "contact.add", json!({"card":card})).await?;
    assert_eq!(added["contact"]["principal_id"], "alice");
    assert!(foreign.requests.load(Ordering::SeqCst) >= 1, "signed home record was not fetched");
    let client = &s.accounts.get("bob").ok_or_else(|| invalid("bob"))?.client;
    let identity = client
        .account_db()?
        .client_record("identity", "alice")?
        .ok_or_else(|| invalid("identity"))?;
    assert_eq!(identity["home_node_id"], "foreign.test");
    Ok(())
}

#[tokio::test]
async fn node_add_confirm_and_card_export_use_origins_from_discovery_urls_with_paths()
-> Result<(), SdkError> {
    let mut a = crate::client::native_test_support::Fixture::named("alice", "alice", "alice")
        .await
        .map_err(native_account)?;
    let mut b = crate::client::native_test_support::Fixture::named("bob", "bob", "bob")
        .await
        .map_err(native_account)?;
    let directory =
        Directory::from_records(&a.root.0, vec![a.manifest.clone(), b.manifest.clone()]).await?;
    let origin = Origin::new(&directory).await?;
    let vault = a.vault.clone();
    let mut s = born_state(&mut a, &mut b, &directory)?;
    s.config.custody_vault = Some(vault);
    let added = crate::bus::dispatch::node::dispatch_node_bus_request(
        &request(
            "alice",
            "node.add",
            json!({"url":format!("{}/start?private=value#section",origin.url)}),
        ),
        &mut s,
    )
    .await?
    .response_body;
    assert_eq!(added["node"]["discovery_url"], origin.url);
    let confirmed = crate::bus::dispatch::node::dispatch_node_bus_request(
        &request("alice", "node.confirm", json!({"node_id":origin.record.node_id})),
        &mut s,
    )
    .await?
    .response_body;
    assert_eq!(confirmed["discovery_url"], origin.url);
    assert_eq!(
        crate::node::NodeStore::load(&s.config.data_root, &[])?.profiles[&origin.record.node_id]
            .discovery_url,
        origin.url
    );
    install_native_home(&origin, &mut s, "alice")?;
    install_native_home(&origin, &mut s, "bob")?;
    // An older in-memory profile must also produce an importable card.
    s.nodes
        .profiles
        .get_mut(&origin.record.node_id)
        .ok_or_else(|| invalid("profile"))?
        .discovery_url = format!("{}/legacy?private=value", origin.url);
    let exported = call(&mut s, "alice", "contact.card.export", json!({})).await?;
    let card = exported["card"].as_str().ok_or_else(|| invalid("card"))?;
    assert_eq!(crate::parse_contact_card(card, now_unix_timestamp())?.node.url, origin.url);
    let added = call(&mut s, "bob", "contact.add", json!({"card":card})).await?;
    assert_eq!(added["contact"]["reachable"], true);
    Ok(())
}

#[path = "contact_locator_tests.rs"]
mod locator;

#[tokio::test]
async fn legacy_card_origin_case_and_trailing_slash_still_resolve_the_pinned_home()
-> Result<(), SdkError> {
    let mut a = crate::client::native_test_support::Fixture::named("alice", "alice", "alice")
        .await
        .map_err(native_account)?;
    let mut b = crate::client::native_test_support::Fixture::named("bob", "bob", "bob")
        .await
        .map_err(native_account)?;
    let directory =
        Directory::from_records(&a.root.0, vec![a.manifest.clone(), b.manifest.clone()]).await?;
    let origin =
        Origin::bound(&directory, "contact.test", "127.0.0.1:0", Some("localhost")).await?;
    let vault = a.vault.clone();
    let mut state = born_state(&mut a, &mut b, &directory)?;
    state.config.custody_vault = Some(vault);
    install_native_home(&origin, &mut state, "alice")?;
    install_native_home(&origin, &mut state, "bob")?;
    let exported = call(&mut state, "alice", "contact.card.export", json!({})).await?;
    let card = crate::parse_contact_card(
        exported["card"].as_str().ok_or_else(|| invalid("card"))?,
        now_unix_timestamp(),
    )?;
    let legacy = resigned_native_card(
        &state,
        "alice",
        &format!("{}/", origin.url.to_uppercase()),
        &card.node.key_fingerprint,
    )?;
    let added = call(&mut state, "bob", "contact.add", json!({"card":legacy})).await?;
    assert_eq!(added["contact"]["principal_id"], "alice");
    assert_eq!(added["contact"]["reachable"], true);
    Ok(())
}

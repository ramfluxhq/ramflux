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
    async fn bound(
        directory: &Directory,
        node_id: &str,
        bind: &str,
        host: Option<&str>,
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
            node_public_key: ramflux_crypto::public_key_base64url_from_seed([91; 32]),
            node_ca_cert_pem: std::fs::read_to_string(&directory.ca)?,
            gateway_quic_addr: directory.addr.to_string(),
            gateway_tcp_addr: directory.addr.to_string(),
            gateway_server_name: "directory.test".into(),
            relay_quic_addr: "127.0.0.1:17447".into(),
            relay_server_name: "relay.test".into(),
            prekey_http_url: url.clone(),
            signaling_turn_addr: "127.0.0.1:3478".into(),
            protocol_versions: vec!["v1".into()],
            client_capabilities: vec!["prekey".into()],
            updated_at: now,
            expires_at: now + 3600,
            signature: String::new(),
        };
        record.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_protocol::client_discovery_signing_bytes(&record)?,
            [91; 32],
        );
        let body = serde_json::to_vec(&record)?;
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = requests.clone();
        let proxy_request = format!("GET {url}/.well-known/ramflux/client ");
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0_u8; 4096];
                let n = stream.read(&mut buf).await?;
                observed.fetch_add(1, Ordering::SeqCst);
                let request = String::from_utf8_lossy(&buf[..n]);
                assert!(
                    request.starts_with("GET /.well-known/ramflux/client ")
                        || request.starts_with(&proxy_request)
                );
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await?;
                stream.write_all(&body).await?;
                stream.shutdown().await?;
            }
            Ok(())
        });
        Ok(Self { url, record, requests, task })
    }
    pub(super) fn configure(&self, s: &mut LocalBusDaemonState, id: &str) -> Result<(), SdkError> {
        let mut profile = crate::node::NodeProfile::from_record(
            self.record.clone(),
            now_unix_timestamp().unsigned_abs(),
        );
        profile.discovery_url = self.url.clone();
        s.nodes.profiles.insert(profile.node_id.clone(), profile);
        let account = s.accounts.get(id).ok_or_else(|| invalid("account"))?;
        let root = account.client.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        // The directory fixture starts with an already enrolled, authenticated account.
        account.client.record_owned_proof_published(now_unix_timestamp())?;
        let gateway = GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().map_err(|_| invalid("addr"))?,
            gateway_addr: account.gateway_config.gateway_addr,
            server_name: account.gateway_config.server_name.clone(),
            ca_cert: account.gateway_config.ca_cert.clone(),
            principal_id: id.into(),
            device_id: id.into(),
            target_delivery_id: id.into(),
            prekey_http_url: None,
        };
        let manifest: crate::bus::protocol::LocalBusPersistedAccount = serde_json::from_value(
            json!({"node_id":self.record.node_id,"schema":"ramflux.local_bus.account.v1","local_account_id":id,"principal_id":id,"principal_commitment":account.principal_commitment,"device_id":id,"target_delivery_id":id,"account_secret":"contact-test-secret","root_seed":root.signing_key.to_bytes(),"device_seed":account.client.device_branch.as_ref().ok_or_else(|| invalid("device"))?.signing_key.to_bytes(),"client_mode":"attended_cli","gateway":gateway}),
        )?;
        crate::bus::daemon::write_local_bus_account_manifest(&s.config.data_root, &manifest)?;
        Ok(())
    }
}
#[tokio::test]
async fn an_exported_card_pins_the_root_and_resolves_a_fresh_contact_without_safety_verifying_it()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let directory = Directory::new(&a, &b).await?;
    let origin = Origin::new(&directory).await?;
    let mut s = state(&mut a, &mut b, &directory)?;
    origin.configure(&mut s, "alice")?;
    origin.configure(&mut s, "bob")?;
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
    let mut wrong_node = parsed.clone();
    wrong_node.node.key_fingerprint = "0".repeat(64);
    let seed = s
        .accounts
        .get("alice")
        .ok_or_else(|| invalid("account"))?
        .client
        .identity_root
        .as_ref()
        .ok_or(SdkError::IdentityRootMissing)?
        .signing_key
        .to_bytes();
    let (wrong, _) =
        crate::contact_card::encode_contact_card(wrong_node, seed, now_unix_timestamp())?;
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
    call(
        &mut s,
        "bob",
        "contact.verify",
        json!({"contact_identity_commitment":parsed.root_commitment}),
    )
    .await?;
    let contacts = call(&mut s, "bob", "contact.list", json!({})).await?;
    assert_eq!(contacts["contacts"][0]["verified"], true);
    assert_eq!(contacts["contacts"][0]["root_commitment"], parsed.root_commitment);
    Ok(())
}

#[tokio::test]
async fn a_card_for_another_home_node_is_rejected_before_contact_or_route_publication()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let directory = Directory::new(&a, &b).await?;
    let home = Origin::new(&directory).await?;
    let foreign = Origin::named(&directory, "foreign.test").await?;
    let mut s = state(&mut a, &mut b, &directory)?;
    home.configure(&mut s, "alice")?;
    home.configure(&mut s, "bob")?;
    let exported = call(&mut s, "alice", "contact.card.export", json!({})).await?;
    let mut body = crate::parse_contact_card(
        exported["card"].as_str().ok_or_else(|| invalid("card"))?,
        now_unix_timestamp(),
    )?;
    body.node.url = foreign.url.clone();
    let root = s
        .accounts
        .get("alice")
        .ok_or_else(|| invalid("account"))?
        .client
        .identity_root
        .as_ref()
        .ok_or(SdkError::IdentityRootMissing)?;
    let (card, _) = crate::contact_card::encode_contact_card(
        body,
        root.signing_key.to_bytes(),
        now_unix_timestamp(),
    )?;
    let error = call(&mut s, "bob", "contact.add", json!({"card":card}))
        .await
        .err()
        .ok_or_else(|| invalid("foreign home accepted"))?;
    assert!(matches!(error, SdkError::ContactHomeNodeUnsupported));
    assert_eq!(
        foreign.requests.load(Ordering::SeqCst),
        0,
        "foreign locator was contacted before rejection"
    );
    let wire = crate::bus::io::local_bus_error_body(&error);
    assert_eq!(wire.code, "ValidationFailed");
    assert_eq!(wire.reason_code.as_deref(), Some("invalid_card"));
    let client = &s.accounts.get("bob").ok_or_else(|| invalid("bob"))?.client;
    assert_eq!(client.friend_links()?.len(), 0);
    assert!(client.account_db()?.client_record("identity", "alice")?.is_none());
    Ok(())
}

#[tokio::test]
async fn node_add_confirm_and_card_export_use_origins_from_discovery_urls_with_paths()
-> Result<(), SdkError> {
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let directory = Directory::new(&a, &b).await?;
    let origin = Origin::new(&directory).await?;
    let mut s = state(&mut a, &mut b, &directory)?;
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
    origin.configure(&mut s, "alice")?;
    origin.configure(&mut s, "bob")?;
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
    let mut a = Fixture::new("alice", 21)?;
    let mut b = Fixture::new("bob", 31)?;
    let directory = Directory::new(&a, &b).await?;
    let origin =
        Origin::bound(&directory, "contact.test", "127.0.0.1:0", Some("localhost")).await?;
    let mut state = state(&mut a, &mut b, &directory)?;
    origin.configure(&mut state, "alice")?;
    origin.configure(&mut state, "bob")?;
    let exported = call(&mut state, "alice", "contact.card.export", json!({})).await?;
    let mut card = crate::parse_contact_card(
        exported["card"].as_str().ok_or_else(|| invalid("card"))?,
        now_unix_timestamp(),
    )?;
    card.node.url = format!("{}/", origin.url.to_uppercase());
    let seed = state.accounts["alice"]
        .client
        .identity_root
        .as_ref()
        .ok_or(SdkError::IdentityRootMissing)?
        .signing_key
        .to_bytes();
    let (legacy, _) = crate::contact_card::encode_contact_card(card, seed, now_unix_timestamp())?;
    let added = call(&mut state, "bob", "contact.add", json!({"card":legacy})).await?;
    assert_eq!(added["contact"]["principal_id"], "alice");
    assert_eq!(added["contact"]["reachable"], true);
    Ok(())
}

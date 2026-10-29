// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary card export uses certified native authority and keeps immutable contact pins.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
#[tokio::test]
async fn native_ordinary_card_export_and_import_selector_keep_the_master_anchor() -> TestResult {
    let native = Fixture::new("native-card").await?;
    let root = native.root.0.clone();
    let anchor = native.manifest.principal_commitment.clone();
    native.client.account_db()?.persist_actor_state("account/node-id", &"home")?;
    let now = crate::custody::network_now()?;
    let profile: crate::NodeProfile = serde_json::from_value(json!({
        "discovery_url":"https://node.example", "node_id":"home", "node_public_key":ramflux_crypto::fixture_public_key_base64url(),
        "pin_source":"tofu", "ca_cert_pem":"", "gateway":{"quic_addr":"127.0.0.1:1","tcp_addr":"127.0.0.1:1","server_name":"localhost"},
        "relay":{"quic_addr":"127.0.0.1:1","server_name":"localhost"}, "prekey_http_url":"https://node.example",
        "discovered_at":now,"expires_at":now+3600,"enabled":true,"builtin":false
    }))?;
    let mut config = LocalBusConfig::new(root.join("bus.sock"), &root);
    config.custody_vault = Some(native.vault.clone());
    let mut nodes = crate::node::NodeStore::default();
    nodes.profiles.insert("home".into(), profile);
    let state = LocalBusDaemonState {
        config,
        account_index: None,
        nodes,
        accounts: BTreeMap::from([(
            "native-card".into(),
            LocalBusAccountState::disconnected(native.client, native.config, anchor.clone()),
        )]),
        active_account_id: Some("native-card".into()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    let response = export(&state, "native-card")?.response_body;
    let text = response["card"].as_str().ok_or("card")?;
    let parsed = crate::parse_contact_card(text, i64::try_from(now)?)?;
    assert_eq!(parsed.root_commitment, anchor);
    assert_eq!(parsed.version, 3);
    let account = local_bus_account(&state, "native-card")?;
    assert!(account.client.identity_root.is_none());
    let mut request = LocalBusFrame::request(
        "import",
        Some("native-card".into()),
        "contact",
        "contact.card.import",
        json!({"card":text}),
    );
    let selector = parse_selector(&request, account)?;
    assert_eq!(selector.card.ok_or("parsed card")?.version, 3);
    account.client.account_db()?.persist_client_record("identity", &parsed.principal_id,
        &json!({"contact_identity_commitment":ramflux_protocol::encode_base64url([99;32]),"root_source":"card"}))?;
    assert!(matches!(
        parse_selector(&request, account),
        Err(SdkError::ContactInput(ContactReason::AnchorMismatch))
    ));
    request.body = json!({"card":legacy_card(i64::try_from(now)?)?});
    assert!(matches!(parse_selector(&request, account), Err(SdkError::CustodyModeDowngrade)));
    Ok(())
}

fn legacy_card(now: i64) -> TestResult<String> {
    let public = ramflux_crypto::public_key_base64url_from_seed([7; 32]);
    let body = ContactCardBody {
        version: 1,
        principal_id: "legacy-peer".into(),
        root_commitment: crate::identity_root_public_key_commitment(&public)?,
        root_public_key: public,
        node: ContactNode {
            url: "https://node.example".into(),
            key_fingerprint: crate::contact_node_fingerprint(
                &ramflux_crypto::fixture_public_key_base64url(),
            )?,
        },
        display_name: Some("Legacy test peer".into()),
        kind_asserted: Some("human".into()),
        issued_at: now,
        expires_at: now + 3600,
        native_authority: None,
    };
    Ok(crate::contact_card::encode_contact_card(body, [7; 32], now)?.0)
}

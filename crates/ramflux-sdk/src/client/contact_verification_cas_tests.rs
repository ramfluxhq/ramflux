// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{
    test_before_cas_transaction, test_clear_cas_hooks, test_fail_cas_commit, test_interrupt_cas_at,
};
use crate::client::native_test_support::{Fixture, TestResult};
use crate::{ContactReason, RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use serde_json::json;

fn compared_expected(
    client: &RamfluxClient,
    commitment: &str,
) -> TestResult<g::ExpectedContactSafety> {
    let value = super::compared_safety_json(client, commitment)?;
    let expected = value.get("expected").cloned().ok_or("public snapshot omits expected")?;
    Ok(serde_json::from_value(expected)?)
}

struct ClearHooks;
impl Drop for ClearHooks {
    fn drop(&mut self) {
        test_clear_cas_hooks();
    }
}

async fn linked() -> TestResult<(Fixture, Fixture, String)> {
    let local = Fixture::new("cas-local").await?;
    let peer = Fixture::new("cas-peer").await?;
    local.client.persist_fetched_identity_directory(&peer.manifest)?;
    let own = local.client.own_account_anchor()?;
    let peer_root = peer.manifest.principal_commitment.clone();
    local.client.establish_friend_link("cas-link", &own, &peer_root)?;
    Ok((local, peer, peer_root))
}

fn absent(client: &RamfluxClient, commitment: &str) -> TestResult {
    let db = client.account_db()?;
    assert!(!db.actor_state_exists(&format!("identity/contact_safety_confirmation/{commitment}"))?);
    assert!(!db.actor_state_exists(&format!("identity/contact_safety_origin_inner/{commitment}"))?);
    assert!(!db.actor_state_exists(&format!("identity/safety_verified_set/{commitment}"))?);
    assert!(db.contact_verification(commitment)?.is_none());
    assert!(
        !db.journal_after(0, 64)?
            .iter()
            .any(|event| event.body["reason"] == "contact_safety_verified")
    );
    Ok(())
}

fn expect_reason(error: &SdkError, reason: ContactReason) {
    assert!(matches!(error, SdkError::ContactInput(found) if *found == reason), "{error:?}");
}

#[tokio::test]
async fn verify_cas_records_only_compared_material() -> TestResult {
    let _hooks = ClearHooks;
    let (local, peer, peer_root) = linked().await?;
    absent(&local.client, &peer_root)?;
    let shortcut = local.client.mark_contact_safety_verified(&peer_root, "primary");
    expect_reason(&shortcut.expect_err("test: shortcut"), ContactReason::ExpectedSafetyRequired);
    let safety = local.client.contact_safety_number(&peer_root)?;
    let recorded = RamfluxClient::record_contact_safety_verified(&peer_root, "primary", &safety);
    expect_reason(&recorded.expect_err("test: record"), ContactReason::ExpectedSafetyRequired);
    absent(&local.client, &peer_root)?;
    let mut expected = compared_expected(&local.client, &peer_root)?;
    expected.algorithm_version = None;
    expect_reason(
        &local
            .client
            .compare_and_record_contact_safety_verified(&expected)
            .expect_err("test: algorithm"),
        ContactReason::ExpectedSafetyRequired,
    );
    expected.algorithm_version = Some(2);
    expected.link_id.clear();
    expect_reason(
        &local
            .client
            .compare_and_record_contact_safety_verified(&expected)
            .expect_err("test: empty"),
        ContactReason::ExpectedSafetyRequired,
    );
    let expected = compared_expected(&local.client, &peer_root)?;
    for mutate in [
        "self",
        "contact",
        "safety",
        "devices",
        "lineage",
        "self_head",
        "contact_head",
        "principal",
        "link",
    ] {
        let mut bad = expected.clone();
        match mutate {
            "self" => bad.self_identity_commitment.push('x'),
            "contact" => bad.contact_identity_commitment.push('x'),
            "safety" => bad.safety_number_hash.push('x'),
            "devices" => bad.contact_device_set_hash.push('x'),
            "lineage" => bad.contact_lineage_head.push('x'),
            "self_head" => bad.self_authority_head.push('x'),
            "contact_head" => bad.contact_authority_head.push('x'),
            "principal" => bad.principal_id.push('x'),
            "link" => bad.link_id = "missing-link".into(),
            _ => {}
        }
        let error = local
            .client
            .compare_and_record_contact_safety_verified(&bad)
            .expect_err("test: mismatch");
        if mutate == "link" {
            assert_ne!(error.to_string().len(), 0);
        } else {
            expect_reason(&error, ContactReason::SafetyMaterialMismatch);
        }
        absent(&local.client, &peer_root)?;
    }
    let result = local.client.compare_and_record_contact_safety_verified(&expected)?;
    assert_eq!(result.verification_state, "verified");
    assert_eq!(local.client.contact_safety_number(&peer_root)?.verification_state, "verified");
    assert_eq!(local.client.contact_entry(&peer.manifest.principal_id)?["verified"], true);
    provisional_replacement().await?;
    signed_set_match()?;
    Ok(())
}

async fn provisional_replacement() -> TestResult {
    let local = Fixture::new("cas-provisional-local").await?;
    let peer = Fixture::new("cas-provisional-peer").await?;
    let own = local.client.own_account_anchor()?;
    let peer_root = peer.manifest.principal_commitment.clone();
    let old = ramflux_protocol::encode_base64url([0x11; 32]);
    let principal = peer.manifest.principal_id.clone();
    local.client.account_db()?.persist_client_record(
        "identity",
        &principal,
        &json!({
            "id": principal,
            "principal_id": principal,
            "contact_identity_commitment": old,
            "root_source": "lookup",
            "devices": []
        }),
    )?;
    local.client.establish_friend_link("provisional-link", &own, &old)?;
    let directory =
        ManifestDirectory::serve(&local.root.0, [local.manifest.clone(), peer.manifest.clone()])
            .await?;
    let preview = local
        .client
        .preview_contact_safety(&directory.config(&local.config), &principal, &peer_root)
        .await?;
    let mut expected: g::ExpectedContactSafety =
        serde_json::from_value(preview.get("expected").cloned().ok_or("preview expected")?)?;
    assert_eq!(expected.replace_provisional_root.as_deref(), Some(old.as_str()));
    let pinned =
        local.client.account_db()?.client_record("identity", &principal)?.ok_or("identity")?;
    assert_eq!(pinned["contact_identity_commitment"], json!(old), "preview leaves the lookup pin");
    let mut missing = expected.clone();
    missing.replace_provisional_root = None;
    let refused =
        local.client.compare_and_record_contact_safety_verified(&missing).expect_err("test: pin");
    assert!(matches!(refused, SdkError::ContactConfirmationRequired(_)));
    absent(&local.client, &peer_root)?;
    assert_eq!(
        local.client.account_db()?.client_record("identity", &principal)?.ok_or("identity")?["contact_identity_commitment"],
        json!(old)
    );
    expected.replace_provisional_root = Some("other-pin".into());
    expect_reason(
        &local
            .client
            .compare_and_record_contact_safety_verified(&expected)
            .expect_err("test: wrong pin"),
        ContactReason::RootConflict,
    );
    expected.replace_provisional_root = Some(old);
    let result = local.client.compare_and_record_contact_safety_verified(&expected)?;
    assert_eq!(result.verification_state, "verified");
    assert_eq!(
        local.client.account_db()?.client_record("identity", &principal)?.ok_or("identity")?["contact_identity_commitment"],
        json!(peer_root),
        "compare-and-record is the only pin change"
    );
    assert!(
        local
            .client
            .account_db()?
            .journal_after(0, 64)?
            .iter()
            .any(|event| event.body["reason"] == "provisional_root_replaced")
    );
    Ok(())
}

struct SignedActor {
    client: RamfluxClient,
    _path: ramflux_test_support::TestPath,
}

fn signed_set_match() -> TestResult {
    let owner = signed_actor("alice", "alice-device", 11, 12)?;
    let peer = signed_actor("bob", "bob-device", 21, 22)?;
    let own_manifest = crate::client::identity_authority::test_support::manifest(&owner.client)?;
    let peer_manifest = crate::client::identity_authority::test_support::manifest(&peer.client)?;
    owner.client.observe_device_manifest_json(
        serde_json::to_value(&own_manifest)?,
        &own_manifest.principal_commitment,
    )?;
    owner.client.observe_device_manifest_json(
        serde_json::to_value(&peer_manifest)?,
        &peer_manifest.principal_commitment,
    )?;
    owner.client.persist_root_verified_directory(&own_manifest)?;
    owner.client.persist_root_verified_directory(&peer_manifest)?;
    owner.client.establish_friend_link(
        "signed-link",
        &own_manifest.principal_commitment,
        &peer_manifest.principal_commitment,
    )?;
    let result = super::verify_linked_contact(&owner.client, &peer_manifest.principal_commitment)?;
    assert_eq!(result.verification_state, "verified");
    assert_eq!(
        result
            .safety_confirmation
            .as_ref()
            .and_then(|c| c.expected.as_ref())
            .map(|e| e.algorithm_version),
        Some(Some(1))
    );
    Ok(())
}

fn signed_actor(
    principal: &str,
    id: &str,
    root_seed: u8,
    device_seed: u8,
) -> Result<SignedActor, SdkError> {
    let path = ramflux_test_support::TestPath::new().expect("test: directory").child(format!(
        "rf-cas-signed-{}-{}",
        std::process::id(),
        root_seed
    ));
    let mut client = RamfluxClient::new();
    client.create_identity_root(principal, [root_seed; 32]);
    client.create_device_branch(principal, id, 1, [device_seed; 32]);
    client.open_account_index(&path)?;
    client.create_account(id, id)?;
    client.unlock_account(id, b"test-secret")?;
    client.initialize_and_publish_prekey_bundle(principal, id, id, [device_seed; 32], None)?;
    Ok(SignedActor { client, _path: path })
}

#[tokio::test]
async fn verify_cas_orders_authority_updates_and_rolls_back() -> TestResult {
    let _hooks = ClearHooks;
    let (local, peer, peer_root) = linked().await?;
    let expected = compared_expected(&local.client, &peer_root)?;
    let own_vault = std::sync::Arc::clone(&local.vault);
    let own_manifest = local.manifest.clone();
    test_before_cas_transaction(Box::new(move |client| {
        advance_authenticated_head(&own_vault, client, &own_manifest)
    }));
    expect_reason(
        &local
            .client
            .compare_and_record_contact_safety_verified(&expected)
            .expect_err("test: own authority barrier"),
        ContactReason::SafetyMaterialMismatch,
    );
    absent(&local.client, &peer_root)?;
    let expected = compared_expected(&local.client, &peer_root)?;
    let peer_vault = std::sync::Arc::clone(&peer.vault);
    let peer_manifest = peer.manifest.clone();
    test_before_cas_transaction(Box::new(move |client| {
        advance_authenticated_head(&peer_vault, client, &peer_manifest)
    }));
    expect_reason(
        &local
            .client
            .compare_and_record_contact_safety_verified(&expected)
            .expect_err("test: peer authority barrier"),
        ContactReason::SafetyMaterialMismatch,
    );
    absent(&local.client, &peer_root)?;
    let expected = compared_expected(&local.client, &peer_root)?;
    for step in 1..=5 {
        test_interrupt_cas_at(step);
        let error = local
            .client
            .compare_and_record_contact_safety_verified(&expected)
            .expect_err("test: interrupt");
        assert!(
            matches!(error, SdkError::LocalBus(ref message) if message.contains("interrupted"))
        );
        absent(&local.client, &peer_root)?;
        test_interrupt_cas_at(0);
    }
    test_fail_cas_commit(true);
    let failed = local
        .client
        .compare_and_record_contact_safety_verified(&expected)
        .expect_err("test: commit");
    assert!(matches!(failed, SdkError::LocalBus(ref message) if message.contains("commit failed")));
    absent(&local.client, &peer_root)?;
    test_fail_cas_commit(false);
    let restored = super::verify_linked_contact(&local.client, &peer_root)?;
    assert_eq!(restored.verification_state, "verified");
    assert_eq!(restored.sibling_delivery_pending, Some(false));
    Ok(())
}

fn advance_authenticated_head(
    vault: &crate::custody::tests::TestVault,
    client: &RamfluxClient,
    manifest: &crate::prekey::SdkDeviceManifestResponse,
) -> Result<(), SdkError> {
    let mut native = manifest
        .custody
        .as_ref()
        .ok_or_else(|| SdkError::LocalBus("fixture custody absent".into()))?
        .as_ref()
        .clone();
    let primary = vault
        .primary_for_public_key(
            &native.publication.record.body.master_certificate.body.self_signing_public_key,
        )
        .map_err(|error| SdkError::LocalBus(error.to_string()))?;
    let mut body = native.publication.record.body.clone();
    body.previous_record_hash =
        Some(ramflux_protocol::custody::object_hash(&native.publication.record)?);
    body.device_set_epoch = body.device_set_epoch.saturating_add(1);
    native.publication.record =
        primary.sign_record(body).map_err(|error| SdkError::LocalBus(error.to_string()))?;
    client.observe_custody_manifest(
        &native,
        &manifest.principal_commitment,
        crate::custody::network_now()?,
    )
}

struct ManifestDirectory {
    address: std::net::SocketAddr,
    ca: std::path::PathBuf,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for ManifestDirectory {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl ManifestDirectory {
    async fn serve(
        root: &std::path::Path,
        manifests: impl IntoIterator<Item = crate::prekey::SdkDeviceManifestResponse>,
    ) -> TestResult<Self> {
        let records = manifests
            .into_iter()
            .map(|manifest| (manifest.principal_commitment.clone(), manifest))
            .collect::<std::collections::BTreeMap<_, _>>();
        let certified = rcgen::generate_simple_self_signed(vec!["directory.test".into()])?;
        let ca = root.join("cas-preview-ca.pem");
        std::fs::write(&ca, certified.cert.pem())?;
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("tls versions: {error}"))?
        .with_no_client_auth()
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der())
                .into(),
        )
        .map_err(|error| format!("tls identity: {error}"))?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
            loop {
                let Ok((socket, _)) = listener.accept().await else { break };
                let Ok(mut stream) = acceptor.accept(socket).await else { continue };
                let Ok(len) = tokio::io::AsyncReadExt::read_u32(&mut stream).await else {
                    continue;
                };
                if len > 1_048_576 {
                    continue;
                }
                let mut bytes = vec![0; len as usize];
                if tokio::io::AsyncReadExt::read_exact(&mut stream, &mut bytes).await.is_err() {
                    continue;
                }
                let Ok(request) =
                    serde_json::from_slice::<ramflux_transport::GatewayQuicRequest>(&bytes)
                else {
                    continue;
                };
                let commitment = request.path.strip_prefix("/mvp1/device-manifest/");
                let body = records
                    .get(commitment.unwrap_or_default())
                    .map(serde_json::to_value)
                    .transpose()
                    .ok()
                    .flatten()
                    .unwrap_or(serde_json::Value::Null);
                let Ok(response) = serde_json::to_vec(&ramflux_transport::GatewayQuicResponse {
                    status: 200,
                    body,
                }) else {
                    continue;
                };
                let Ok(count) = u32::try_from(response.len()) else { continue };
                if tokio::io::AsyncWriteExt::write_u32(&mut stream, count).await.is_err()
                    || tokio::io::AsyncWriteExt::write_all(&mut stream, &response).await.is_err()
                {
                    continue;
                }
                let _ = tokio::io::AsyncWriteExt::flush(&mut stream).await;
            }
        });
        Ok(Self { address, ca, server })
    }

    fn config(&self, gateway: &crate::GatewaySessionConfig) -> crate::GatewaySessionConfig {
        let mut config = gateway.clone();
        config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
        config.gateway_addr = self.address;
        config.tcp_gateway_addr = Some(self.address);
        config.server_name = "directory.test".into();
        config.ca_cert = self.ca.clone();
        config.timeout = std::time::Duration::from_secs(5);
        config
    }
}

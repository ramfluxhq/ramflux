// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{test_before_cas_transaction, test_clear_cas_hooks, test_interrupt_cas_at};
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
    let before = local.client.account_db()?.test_table_fingerprints(&[])?;
    let preview = local
        .client
        .preview_contact_safety(&directory.config(&local.config), &principal, &peer_root)
        .await?;
    assert_eq!(
        local.client.account_db()?.test_table_fingerprints(&[])?,
        before,
        "preview writes nothing before confirmation"
    );
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

#[tokio::test]
async fn held_manifest_cap_refuses_another_unconfirmed_preview() -> TestResult {
    let local = Fixture::new("cas-hold-cap").await?;
    let cap = super::super::contact_safety_preview::HELD_MANIFEST_CAP;
    for index in 0..cap {
        let mut manifest = local.manifest.clone();
        manifest.principal_commitment = format!("hold-{index:02}");
        local.client.hold_compared_manifests([manifest])?;
    }
    let mut overflow = local.manifest.clone();
    overflow.principal_commitment = "hold-overflow".into();
    let refused = local.client.hold_compared_manifests([overflow]).expect_err("test: cap");
    assert!(
        matches!(refused, SdkError::InboundRejected(ref message) if message == "held manifest cap exceeded"),
        "{refused:?}"
    );
    assert_eq!(local.client.held_manifests.borrow().len(), cap);
    let mut replacement = local.manifest.clone();
    replacement.principal_commitment = "hold-00".into();
    local.client.hold_compared_manifests([replacement])?;
    assert_eq!(local.client.held_manifests.borrow().len(), cap);
    local.client.release_held_manifests();
    assert_eq!(local.client.held_manifests.borrow().len(), 0);
    for index in 0..cap {
        let mut manifest = local.manifest.clone();
        manifest.principal_commitment = format!("refill-{index:02}");
        local.client.hold_compared_manifests([manifest])?;
    }
    assert_eq!(local.client.held_manifests.borrow().len(), cap);
    let mut again = local.manifest.clone();
    again.principal_commitment = "refill-overflow".into();
    let refused_again =
        local.client.hold_compared_manifests([again]).expect_err("test: refill cap");
    assert!(
        matches!(
            refused_again,
            SdkError::InboundRejected(ref message) if message == "held manifest cap exceeded"
        ),
        "{refused_again:?}"
    );
    Ok(())
}

#[tokio::test]
async fn verified_row_without_confirmation_is_rejected() -> TestResult {
    let (local, _peer, peer_root) = linked().await?;
    local.client.account_db()?.mark_contact_verified(
        ramflux_storage::ContactVerificationUpdate {
            contact_identity_commitment: &peer_root,
            safety_number_hash: "verified-safety",
            device_set_hash: "stamp",
            lineage_head: "lineage",
            verified_at: crate::time::now_unix_timestamp(),
            verified_by_device_id: "primary",
        },
    )?;
    let missing = local.client.contact_safety_number(&peer_root);
    assert!(
        matches!(
            missing,
            Err(SdkError::InboundRejected(ref message)) if message == "safety confirmation missing"
        ),
        "{missing:?}"
    );
    Ok(())
}

#[tokio::test]
async fn equivocation_fence_survives_compare_rollback() -> TestResult {
    let _hooks = ClearHooks;
    let (local, peer, peer_root) = linked().await?;
    let conflict = resigned_custody(&peer.vault, &peer.manifest, false)?;
    let anchor = custody_anchor(&conflict)?;
    assert_eq!(conflict.principal_commitment, peer_root);
    assert_eq!(anchor, peer_root);
    let held = conflict.clone();
    test_before_cas_transaction(Box::new(move |client| {
        client.hold_compared_manifests([held.clone()])?;
        Ok(())
    }));
    let expected = compared_expected(&local.client, &peer_root)?;
    let error = local
        .client
        .compare_and_record_contact_safety_verified(&expected)
        .expect_err("test: equivocation");
    assert!(
        matches!(
            error,
            SdkError::InboundRejected(ref message)
                if message == "identity authority: custody authority equivocation fenced"
        ),
        "{error:?}"
    );
    absent(&local.client, &peer_root)?;
    let row = local
        .client
        .account_db()?
        .load_actor_state::<serde_json::Value>(&format!("identity/custody/{anchor}"))?
        .ok_or("fence row")?;
    let conflicts =
        row.pointer(&format!("/pins/accounts/{anchor}/conflicts")).ok_or("conflicts")?;
    assert!(conflicts.as_object().is_some_and(|entries| !entries.is_empty()), "{row}");
    Ok(())
}

#[tokio::test]
async fn authority_file_advances_when_compare_commits() -> TestResult {
    let (local, _peer, peer_root) = linked().await?;
    let account_id =
        local.client.born_v3_account.as_ref().ok_or("born account")?.local_account_id().to_owned();
    let path = local
        .client
        .account_index()?
        .root()
        .join("custody_accounts")
        .join(account_id)
        .join("authority.json");
    let before = std::fs::read(&path)?;
    let mut next = resigned_custody(&local.vault, &local.manifest, true)?;
    let own = local.client.own_account_anchor()?;
    next.principal_commitment.clone_from(&own);
    let head = ramflux_protocol::custody::object_hash(
        &next.custody.as_ref().ok_or("custody")?.publication.record,
    )?;
    local.client.hold_compared_manifests([next])?;
    let mut expected = compared_expected(&local.client, &peer_root)?;
    expected.self_authority_head = head;
    let result = local.client.compare_and_record_contact_safety_verified(&expected)?;
    assert_eq!(result.verification_state, "verified");
    let after = std::fs::read(&path)?;
    assert_ne!(before, after, "the own authority file moves after the compare commit");
    Ok(())
}

fn custody_anchor(manifest: &crate::prekey::SdkDeviceManifestResponse) -> Result<String, SdkError> {
    Ok(manifest
        .custody
        .as_ref()
        .ok_or_else(|| SdkError::LocalBus("fixture custody absent".into()))?
        .publication
        .record
        .body
        .account_anchor
        .clone())
}

fn resigned_custody(
    vault: &crate::custody::tests::TestVault,
    manifest: &crate::prekey::SdkDeviceManifestResponse,
    next_epoch: bool,
) -> Result<crate::prekey::SdkDeviceManifestResponse, SdkError> {
    let mut next = manifest.clone();
    let mut native = next
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
    if next_epoch {
        body.previous_record_hash =
            Some(ramflux_protocol::custody::object_hash(&native.publication.record)?);
        body.device_set_epoch = body.device_set_epoch.saturating_add(1);
    } else {
        body.profile.display_name = "Another name".into();
    }
    native.publication.record =
        primary.sign_record(body).map_err(|error| SdkError::LocalBus(error.to_string()))?;
    next.custody = Some(Box::new(native));
    Ok(next)
}

#[tokio::test]
async fn verify_cas_orders_authority_updates_and_rolls_back() -> TestResult {
    let _hooks = ClearHooks;
    let (mut local, peer, peer_root) = linked().await?;
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
    let db = local.client.account_db()?;
    let before = db.test_table_fingerprints(&[])?;
    let (failed, commits) = db.reject_next_sqlite_commit(|| {
        local.client.compare_and_record_contact_safety_verified(&expected)
    })?;
    assert_eq!(commits, 1, "the rejected write is the compare-and-record commit: {failed:?}");
    assert!(matches!(failed, Err(SdkError::Storage(_))), "{failed:?}");
    assert_eq!(db.test_table_fingerprints(&[])?, before, "a rejected commit leaves no row");
    absent(&local.client, &peer_root)?;
    local.client.active_account_db.take();
    local.client.unlock_account("cas-local", b"native fixture data passphrase")?;
    absent(&local.client, &peer_root)?;
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

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group refusal contracts through the production bus dispatcher.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use serde_json::json;

fn daemon(account: LocalBusAccountState, root: &std::path::Path) -> LocalBusDaemonState {
    LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.join("bus.sock"), root.join("bus-data")),
        accounts: BTreeMap::from([("owner".into(), account)]),
        active_account_id: Some("owner".into()),
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    }
}

async fn request(
    state: &mut LocalBusDaemonState,
    body: serde_json::Value,
) -> Result<LocalBusDispatchResult, SdkError> {
    let frame = LocalBusFrame::request(
        "rename",
        Some("owner".into()),
        "ramflux.sdk.v1",
        "group.name.set",
        body,
    );
    let (outbound, _receiver) = mpsc::channel(8);
    let mut connection = LocalBusConnectionState::new(1, outbound);
    crate::bus::daemon::dispatch_local_bus_request(&frame, state, &mut connection).await
}

fn install_lease(
    account: &mut LocalBusAccountState,
    root: &std::path::Path,
    primary: &ramflux_crypto::custody::SelfSigningKey,
    expired: bool,
) -> TestResult {
    let now = crate::custody::network_now()?;
    let native = account.client.born_v3_account.as_ref().ok_or("native account")?;
    let id = native.local_account_id().to_owned();
    let mut body = native.record().body.clone();
    body.previous_record_hash = Some(ramflux_protocol::custody::object_hash(native.record())?);
    body.device_set_epoch += 1;
    let mut cert = body.devices[0].branch_certificate.as_ref().ok_or("branch")?.body.clone();
    cert.not_before = now - 1000;
    cert.expires_at = if expired { now - 301 } else { now + 3600 };
    cert.cert_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    body.devices[0].branch_certificate = Some(primary.certify_branch(cert)?);
    let authority = ramflux_protocol::custody::CustodyAuthority {
        publication: ramflux_protocol::custody::Publication {
            record: primary.sign_record(body)?,
            compacted_ids: None,
        },
        custodian_publication: None,
    };
    crate::custody::accept_publication(root, &id, &authority, now)?;
    account.client.born_v3_account = Some(Box::new(crate::custody::load_account(root, &id, now)?));
    Ok(())
}

#[tokio::test]
async fn native_group_lease_refusal_is_typed_over_bus_and_fresh_authority_clears_it() -> TestResult
{
    let fixture = Fixture::with_device("lease-owner", "owner-device").await?;
    let primary = fixture.vault.primary_for_public_key(
        &fixture
            .manifest
            .custody
            .as_ref()
            .ok_or("custody")?
            .publication
            .record
            .body
            .master_certificate
            .body
            .self_signing_public_key,
    )?;
    fixture.client.shared_group_create_with_primary(
        "group",
        "thread",
        None,
        &fixture.config.target_delivery_id,
        Some(&primary),
    )?;
    let mut account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config,
        fixture.manifest.principal_commitment,
    );
    let mut setup = LocalBusConfig::new(fixture.root.0.join("bus.sock"), fixture.root.0.clone());
    setup.custody_vault = Some(fixture.vault);
    account.native_setup = Some(setup);
    let mut state = daemon(account, &fixture.root.0);
    install_lease(
        state.accounts.get_mut("owner").ok_or("owner")?,
        &fixture.root.0,
        &primary,
        true,
    )?;
    let result = Box::pin(request(&mut state, json!({"group_id":"group","name":"Renewed"}))).await;
    let error = result.err().ok_or("expired lease accepted")?;
    assert!(matches!(error, SdkError::Crypto(CryptoError::GroupLeaseUnavailable)));
    let wire = crate::bus::io::local_bus_error_body(&error);
    assert_eq!(wire.code, "GroupLeaseUnavailable");
    assert!(wire.message.contains("refresh branch authority"));
    install_lease(
        state.accounts.get_mut("owner").ok_or("owner")?,
        &fixture.root.0,
        &primary,
        false,
    )?;
    assert_eq!(
        Box::pin(request(&mut state, json!({"group_id":"group","name":"Renewed"})))
            .await?
            .response_body["name"],
        "Renewed"
    );
    Ok(())
}

#[tokio::test]
async fn group_bus_generic_refusals_preserve_legacy_codes_and_type_only_native_accounts()
-> TestResult {
    let fixture = Fixture::new("native-refusal").await?;
    let root = fixture.root.0.clone();
    let primary = fixture.vault.primary_for_public_key(
        &fixture
            .manifest
            .custody
            .as_ref()
            .ok_or("custody")?
            .publication
            .record
            .body
            .master_certificate
            .body
            .self_signing_public_key,
    )?;
    fixture.client.shared_group_create_with_primary(
        "group",
        "thread",
        None,
        &fixture.config.target_delivery_id,
        Some(&primary),
    )?;
    let native = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config,
        fixture.manifest.principal_commitment,
    );
    let legacy = super::tests::account_state(
        "legacy-refusal",
        "legacy",
        "legacy-owner",
        "legacy-device",
        [81; 32],
    )?;
    legacy.client.shared_group_create(
        "group",
        "thread",
        None,
        &legacy.gateway_config.target_delivery_id,
    )?;
    for (account, expected) in [(legacy, "ValidationFailed"), (native, "GroupRenameRefused")] {
        let mut state = daemon(account, &root);
        let error = Box::pin(request(
            &mut state,
            json!({"group_id":"group","name":"Denied","actor_id":"foreign-device"}),
        ))
        .await
        .err()
        .ok_or("invalid group rename accepted")?;
        assert_eq!(crate::bus::io::local_bus_error_body(&error).code, expected);
    }
    Ok(())
}

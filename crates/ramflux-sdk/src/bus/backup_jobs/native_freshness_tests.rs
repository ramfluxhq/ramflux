// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real encrypted archive round-trip followed by connect-only directory refresh.
use super::*;
use crate::bus::{connection_manager::AccountWork, couriers::head_refresh};
use crate::client::identity_authority::HeadUse;
use crate::prekey::SdkDeviceManifestResponse;
use std::collections::{BTreeMap, BTreeSet};

#[tokio::test(flavor = "current_thread")]
async fn restored_account_has_empty_freshness_and_refreshes_on_connect() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let root = Root::new()?;
            let vault = TestVault::default();
            let native = create(&root.0, "account", &vault, crate::custody::network_now()?)?;
            let own = SdkDeviceManifestResponse::from_native(
                ramflux_protocol::custody::CustodyManifest {
                    publication: native.publication(),
                    custodian_publication: None,
                    devices: Vec::new(),
                },
            )?;
            let peer = crate::client::native_test_support::Fixture::new("restored-peer").await?;
            let manifests = vec![own.clone(), peer.manifest.clone()];
            let mut data = RamfluxClient::new();
            data.open_account_index(&root.0)?;
            data.seal_new_account_data(
                "account",
                &own.principal_commitment,
                LOCAL_SECRET.as_bytes(),
            )?;
            data.unlock_account("account", LOCAL_SECRET.as_bytes())?;
            data.establish_friend_link(
                "restore-link",
                &own.principal_commitment,
                &peer.manifest.principal_commitment,
            )?;
            data.account_db()?.persist_actor_state("restore/freshness-proof", &true)?;
            drop(data);

            // The actual client captured by the backup actor has fresh own AND peer observations.
            let source_root = root.0.clone();
            let source_manifests = manifests.clone();
            let initializer: AccountInitializer = Box::new(move |index| {
                let account = initialize(&source_root, index)?;
                for manifest in source_manifests {
                    account.client.persist_fetched_identity_directory(&manifest)?;
                    account.client.require_fresh_custody_head(
                        HeadUse::NewAuthorization,
                        &manifest.principal_commitment,
                        &manifest
                            .custody
                            .as_ref()
                            .ok_or(SdkError::CustodySetupInvalid)?
                            .publication
                            .record,
                    )?;
                }
                Ok(account)
            });
            let config = LocalBusConfig::new(root.0.join("source.sock"), &root.0);
            let source = Supervisor::from_initializers(
                &config,
                vec![("account".into(), initializer)],
                Some("account".into()),
            )?;
            let archive = root.0.join("fresh-heads.rfb");
            make_archive(&source, &archive).await?;
            source.shutdown().await?;

            // Remove a backed-up row: its return proves install merged the real archive.
            let account = initialize(&root.0, AccountIndex::open(&root.0)?)?;
            account.client.account_db()?.remove_actor_state("restore/freshness-proof")?;
            drop(account);
            let target = supervisor(&root.0)?;
            let id = verify(&target, &archive).await?;
            call(&target, "account.restore.install", None, json!({"job_id":id})).await?;
            finished(&target, &id, crate::backup::BackupJobState::Done).await?;
            target.shutdown().await?;

            let mut restored = initialize(&root.0, AccountIndex::open(&root.0)?)?;
            assert_eq!(
                restored
                    .client
                    .account_db()?
                    .load_actor_state::<bool>("restore/freshness-proof")?,
                Some(true)
            );
            for manifest in &manifests {
                assert!(
                    restored
                        .client
                        .native_head_freshness
                        .borrow()
                        .observation(&manifest.principal_commitment)
                        .is_none(),
                    "archive or reopen must not restore observations"
                );
                assert!(
                    restored
                        .client
                        .require_fresh_custody_head(
                            HeadUse::NewAuthorization,
                            &manifest.principal_commitment,
                            &manifest.custody.as_ref().ok_or("custody")?.publication.record
                        )
                        .is_err(),
                    "restored evidence is not fresh authorization"
                );
            }
            refresh_on_connect(&mut restored, &manifests, &root.0).await?;
            Ok(())
        }))
        .await
}

async fn refresh_on_connect(
    restored: &mut LocalBusAccountState,
    manifests: &[SdkDeviceManifestResponse],
    root: &Path,
) -> TestResult {
    let expected: BTreeSet<_> = manifests.iter().map(|m| m.principal_commitment.clone()).collect();
    let directories: BTreeMap<_, _> = manifests
        .iter()
        .map(|m| Ok((m.principal_commitment.clone(), serde_json::to_value(m)?)))
        .collect::<Result<_, serde_json::Error>>()?;
    let (address, server) =
        crate::bus::dispatch::surface_transport::fixture::directory(root, directories).await?;
    restored.gateway_config.transport_kind = crate::GatewaySessionTransportKind::TcpTls;
    restored.gateway_config.gateway_addr = address;
    restored.gateway_config.tcp_gateway_addr = Some(address);
    restored.gateway_config.server_name = "test-gateway".into();
    restored.gateway_config.ca_cert = root.join("ca.pem");
    let (handle, _io) = crate::bus::connection_manager::tests::fixture().await?;
    restored.connection = Some(handle.clone());
    let (writer, mut receiver) = mpsc::channel(2);
    // Real directory fetches with a scripted Live session; no demand or timer can satisfy this.
    let child = tokio::spawn(head_refresh::run_without_timer(handle.test_context(), writer));
    let mut fetched = BTreeSet::new();
    while fetched.len() < expected.len() {
        let work = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await?
            .ok_or("writer closed")?;
        let AccountWork::Directory(work) = work else {
            return Err("wrong work".into());
        };
        let super::super::super::couriers::directory::DirectoryWork::HeadRefresh(work) = *work
        else {
            return Err("wrong directory work".into());
        };
        if let head_refresh::Work::Apply { root, outcome, .. } = &work {
            assert!(outcome.is_ok(), "connect must fetch verified directory over TLS");
            assert!(fetched.insert(root.clone()), "connect fetches each root once");
        }
        head_refresh::apply_work(restored, work);
    }
    assert_eq!(fetched, expected, "restored contact must participate in connect sweep");
    for manifest in manifests {
        restored.client.require_fresh_custody_head(
            HeadUse::NewAuthorization,
            &manifest.principal_commitment,
            &manifest.custody.as_ref().ok_or("custody")?.publication.record,
        )?;
    }
    child.abort();
    let _ = child.await;
    handle.stop().await;
    server.abort();
    Ok(())
}

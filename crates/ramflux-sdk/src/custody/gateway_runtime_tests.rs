// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native admission success wakes real contact receive without an intervening client request.

use super::{Fixture, Point, Result, budgets, ordinary};
use crate::bus::{native_actor::NativeActor, runtime_limits::RuntimeTimeouts};
use crate::prelude::*;

fn manifest(client: &RamfluxClient) -> Result<crate::prekey::SdkDeviceManifestResponse> {
    let account = client.born_v3_account.as_ref().ok_or("native account")?;
    let identity = client.owned_device_identity()?;
    let bundle = client.load_x3dh_private_state(&identity)?.bundle;
    Ok(crate::prekey::SdkDeviceManifestResponse::from_native(
        ramflux_protocol::custody::CustodyManifest {
            publication: account.publication(),
            custodian_publication: None,
            devices: vec![ramflux_protocol::custody::CustodyManifestDevice {
                device_ref: ramflux_protocol::custody::DeviceRef {
                    account_anchor: identity.root_commitment().into(),
                    device_id: identity.device_id().into(),
                    device_epoch: 1,
                },
                target_delivery_id: identity.storage_key().into(),
                prekey_bundle: serde_json::to_value(bundle)?,
                message_layer: None,
            }],
        },
    )?)
}
#[tokio::test(flavor = "current_thread")]
async fn inbound_contact_request_lands_once_admission_succeeds_without_a_client_command()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    LocalSet::new()
        .run_until(Box::pin(crate::bus::connection_manager::tests::watchdog(Box::pin(async {
            let fixture = Box::pin(Fixture::with_mode(&[Point::Open, Point::Open], true))
                .await
                .map_err(|error| error as Box<dyn std::error::Error>)?;
            let (client, config) =
                Box::pin(budgets::native_config(&fixture, budgets::Origin::ExplicitEngine)).await?;
            let own = manifest(&client).map_err(|error| error as Box<dyn std::error::Error>)?;
            let peer = Box::pin(crate::client::native_test_support::Fixture::new("contact-source"))
                .await?;
            let entry =
                Box::pin(crate::client::contact_requests::native_tests::request_entry(&peer, &own))
                    .await?;
            fixture.script.lock().map_err(|_| "script lock")?.ordinary =
                Some(ordinary::SessionScript {
                    inbox: vec![entry],
                    manifests: std::collections::BTreeMap::from([
                        (own.principal_commitment.clone(), own),
                        (peer.manifest.principal_commitment.clone(), peer.manifest.clone()),
                    ]),
                    received: Vec::new(),
                    held_ack: None,
                });
            let reader = client.account_db()?.open_reader()?;
            let actor = Box::pin(NativeActor::start(
                client,
                config,
                b"native budget fixture".to_vec(),
                RuntimeTimeouts::held_for_test(),
            ))
            .await?;
            // Observe durable storage only: no bus read, mutation or manual receive wake is issued.
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    let errors =
                        fixture.script.lock().map_err(|_| "script lock")?.protocol_errors.clone();
                    if !errors.is_empty() {
                        return Err(format!("native server errors: {errors:?}").into());
                    }
                    let acked = {
                        let script = fixture.script.lock().map_err(|_| "script lock")?;
                        script.ordinary.as_ref().is_some_and(|session| {
                            session
                                .received
                                .iter()
                                .any(|frame| matches!(frame, crate::GatewayClientFrame::Ack { .. }))
                        })
                    };
                    if reader
                        .contact_request(&peer.manifest.principal_commitment, "inbound")?
                        .is_some()
                        && acked
                    {
                        return Ok::<_, Box<dyn std::error::Error>>(());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await??;
            let row = reader
                .contact_request(&peer.manifest.principal_commitment, "inbound")?
                .ok_or("inbound request")?;
            assert_eq!(row.state, "pending");
            {
                let script = fixture.script.lock().map_err(|_| "script lock")?;
                assert_eq!(script.busy_at, vec![Point::Open, Point::Open]);
                let session = script.ordinary.as_ref().ok_or("session")?;
                assert_eq!(
                    session
                        .received
                        .iter()
                        .filter(|frame| matches!(frame, crate::GatewayClientFrame::Ack { .. }))
                        .count(),
                    1
                );
                assert!(
                    session
                        .received
                        .iter()
                        .any(|frame| matches!(frame, crate::GatewayClientFrame::Resume { .. }))
                );
            }
            assert_eq!(reader.pending_contact_requests()?.len(), 1);
            let wall = std::time::Instant::now();
            actor.stop().await?;
            assert!(wall.elapsed() < Duration::from_secs(1));

            fixture.server.abort();
            Ok(())
        }))))
        .await
}

#[path = "gateway_runtime_lock_tests.rs"]
mod lock;

#[path = "gateway_runtime_keyed_tests.rs"]
mod keyed;

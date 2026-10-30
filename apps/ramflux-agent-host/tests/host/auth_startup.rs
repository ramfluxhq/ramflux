// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Scripted wire responses make authentication races independent of scheduler timing.
use super::support::{Fixture, TestResult};
use ramflux_agent_host::{AgentHost, Error, RfdBus, RuleEngine};
use ramflux_sdk::{LocalBusErrorBody, LocalBusFrame, LocalBusFrameKind};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn startup_and_reconnect_authentication_races_retry_identity_before_resuming() -> TestResult {
    for code in ["Unauthenticated", "NotAuthenticated"] {
        for racing_method in ["account.status", "device.list", "identity.directory"] {
            let f = Fixture::new()?;
            let listener = tokio::net::UnixListener::bind(&f.config.socket)?;
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await?;
                // Two interrupted starts followed by a complete authenticated start.
                for attempt in 0..3 {
                    for method in [
                        "account.status",
                        "device.list",
                        "identity.directory",
                        "bus.subscribe",
                        "conversation.directory",
                        "group.list",
                    ] {
                        let len = socket.read_u32().await?;
                        let mut bytes = vec![0; usize::try_from(len)?];
                        socket.read_exact(&mut bytes).await?;
                        let mut frame: LocalBusFrame = serde_json::from_slice(&bytes)?;
                        assert_eq!(frame.method, method);
                        let racing = attempt < 2 && method == racing_method;
                        frame.kind = if racing {
                            LocalBusFrameKind::Error
                        } else {
                            LocalBusFrameKind::Response
                        };
                        frame.ok = Some(!racing);
                        frame.body = match method {
                            "account.status" => {
                                json!({"account_id":"agent","local_account_id":"agent","state":"unlocked","networking":"live","display_name":"Agent","principal_id":"agent","principal_kind":"headless_ai","authority_blocked":false,"local_device_authorized":true,"principal_commitment":"commitment","device_id":"device","target_delivery_id":"target","node_id":"node","session_id":"session","active_transport_kind":"quic","pending_deliveries":0})
                            }
                            "device.list" => {
                                json!({"principal_id":"agent","local_device_id":"device","devices":[{"device_id":"device"}]})
                            }
                            "identity.directory" => {
                                json!({"identities":[{"principal_id":"agent","is_self":true,"kind":"headless_ai"}],"next_cursor":null})
                            }
                            "bus.subscribe" => json!({"head_seq":1}),
                            "conversation.directory" => {
                                json!({"conversations":[],"next_cursor":null})
                            }
                            _ => json!({"groups":[],"next_cursor":null}),
                        };
                        if racing {
                            frame.error = Some(LocalBusErrorBody {
                                code: code.into(),
                                message: "redacted".into(),
                                details: None,
                                reason_code: None,
                                retry_after_ms: None,
                                cause: None,
                            });
                        }
                        let bytes = serde_json::to_vec(&frame)?;
                        socket.write_u32(u32::try_from(bytes.len())?).await?;
                        socket.write_all(&bytes).await?;
                        if racing {
                            break;
                        }
                    }
                }
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            });
            let mut bus = RfdBus::connect(&f.config.socket, "agent").await?;
            let mut host = AgentHost::new(f.config.clone(), RuleEngine::new(&f.config)?)?;
            for _ in 0..2 {
                let error = host.start(&mut bus).await.err().ok_or("race accepted")?;
                assert!(matches!(error, Error::Bus));
                assert!(!error.stops_host());
                assert_eq!(host.checkpoint().cursor, None);
            }
            host.start(&mut bus).await?;
            assert_eq!(host.checkpoint().cursor, Some(1));
            server.await?.map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

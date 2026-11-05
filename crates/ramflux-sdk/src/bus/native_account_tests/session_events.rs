// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real daemon publication with a session drain and explicitly held reconnect.
use super::*;
use crate::bus::connection_manager::{SessionConnector, SessionFuture, tests::seeded_engine};
use crate::{GatewayClientFrame, GatewayServerFrame, GatewaySessionConfig, GatewaySessionEngine};
use tokio::sync::{Semaphore, mpsc};

type Input = mpsc::UnboundedSender<Vec<u8>>;
struct Sessions {
    permits: Semaphore,
    opened: mpsc::UnboundedSender<Input>,
}
impl SessionConnector for Sessions {
    fn connect(
        &self,
        config: GatewaySessionConfig,
        _deadline: tokio::time::Instant,
    ) -> SessionFuture<'_, GatewaySessionEngine> {
        Box::pin(async move {
            self.permits.acquire().await.map_err(|_| crate::SdkError::NetworkingPending)?.forget();
            let (engine, mut io) = seeded_engine(
                config,
                &crate::bus::runtime_limits::RuntimeTimeouts::held_for_test(),
            );
            self.opened.send(io.input.clone()).map_err(|_| crate::SdkError::NetworkingPending)?;
            tokio::spawn(async move {
                while let Some(frame) = io.output.recv().await {
                    let response = match frame {
                        GatewayClientFrame::Heartbeat { now } => {
                            GatewayServerFrame::Heartbeat { now }
                        }
                        GatewayClientFrame::Cursor { .. } => {
                            GatewayServerFrame::Cursor { cursor: None }
                        }
                        GatewayClientFrame::Resume { .. } => {
                            GatewayServerFrame::Resume { entries: Vec::new() }
                        }
                        _ => continue,
                    };
                    if let Ok(bytes) = serde_json::to_vec(&response) {
                        let _ = io.input.send(bytes);
                    }
                }
            });
            Ok(engine)
        })
    }
}

async fn session_event(events: &mut LocalBusClient, expected: &str) -> Result<LocalBusFrame> {
    let mut seen = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = events.next_event().await?;
            if event.body["session"]["state"] == expected {
                return Ok::<_, crate::SdkError>(event);
            }
            seen.push(event.body);
        }
    })
    .await;
    match result {
        Ok(result) => Ok(result?),
        Err(_) => Err(format!("missing {expected} session event; observed {seen:?}").into()),
    }
}

pub(super) async fn disconnect_and_reconnect() -> Result {
    let fixture = crate::client::native_test_support::Fixture::new("session-bus").await?;
    let root = fixture.root;
    crate::custody::tests::mark_live(&root.0, "session-bus", crate::custody::network_now()?)?;
    drop(fixture.client);
    let directory = Directory::start(&root.0, serde_json::to_value(&fixture.manifest)?).await?;
    let profile =
        node_profile_with_ca("localhost", &directory.address.to_string(), 7, &directory.ca_pem);
    let mut nodes = crate::node::NodeStore {
        default_node_id: Some(profile.node_id.clone()),
        ..Default::default()
    };
    nodes.profiles.insert(profile.node_id.clone(), profile);
    nodes.save(&root.0)?;
    let socket = root.0.join("session-events.sock");
    let (opened, mut sessions) = mpsc::unbounded_channel();
    let connector = Arc::new(Sessions { permits: Semaphore::new(1), opened });
    let mut config = LocalBusConfig::new(&socket, &root.0);
    config.custody_vault = Some(fixture.vault);
    config.test_suppress_receive_timers = true;
    config.test_session_connector = Some(connector.clone());
    let (stop, receiver) = watch::channel(false);
    let flow = async {
        let _stop = Stop(stop);
        let mut bus = connect(&socket).await?;
        bus.request(
            Some("session-bus".into()),
            "account",
            "account.unlock",
            json!({"passphrase":"native fixture data passphrase"}),
        )
        .await?;
        let mut events = connect(&socket).await?;
        events
            .request(
                Some("session-bus".into()),
                "stream",
                "bus.subscribe",
                json!({"topics":["account.networking.changed"],"since_seq":0}),
            )
            .await?;
        let live = session_event(&mut events, "live").await?;
        assert_eq!(live.body["state"], "live");
        assert!(live.body["networking_reason"].is_null());
        let input = tokio::time::timeout(Duration::from_secs(10), sessions.recv())
            .await?
            .ok_or("first session")?;
        input.send(serde_json::to_vec(&GatewayServerFrame::Drain {
            session_id: "test-session".into(),
            reason: "rotate".into(),
        })?)?;
        let pending = session_event(&mut events, "networking_pending").await?;
        assert_eq!(pending.body["state"], "live");
        assert!(pending.body["networking_reason"].is_null());
        assert_eq!(connector.permits.available_permits(), 0);
        assert!(sessions.try_recv().is_err(), "reconnect must stay held until publication");
        connector.permits.add_permits(1);
        let restored = session_event(&mut events, "live").await?;
        assert_eq!(restored.body["state"], "live");
        assert!(restored.body["networking_reason"].is_null());
        assert_ne!(live.body["session"]["generation"], restored.body["session"]["generation"]);
        assert!(live.seq < pending.seq && pending.seq < restored.seq);
        // No account.status request participates in observing any session transition.
        bus.request(Some("session-bus".into()), "account", "account.lock", json!({})).await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (server, flow) = tokio::join!(crate::serve_local_bus_until(config, receiver), flow);
    server?;
    flow
}

struct Directory {
    address: std::net::SocketAddr,
    ca_pem: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Directory {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Directory {
    async fn start(root: &std::path::Path, manifest: serde_json::Value) -> Result<Self> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let ca_pem = cert.cert.pem();
        let tls = ramflux_transport::MeshTlsConfig {
            ca_cert: root.join("directory-ca.pem"),
            service_cert: root.join("directory-cert.pem"),
            service_key: root.join("directory-key.pem"),
        };
        std::fs::write(&tls.ca_cert, &ca_pem)?;
        std::fs::write(&tls.service_cert, &ca_pem)?;
        std::fs::write(&tls.service_key, cert.signing_key.serialize_pem())?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            ramflux_transport::tcp_gateway_server_config(&tls)?,
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let manifest = manifest.clone();
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(socket).await else { return };
                    let mut stream = ramflux_transport::GatewayTcpTlsStream::Server(stream);
                    let Ok(bytes) = ramflux_transport::read_custody_tcp_frame(&mut stream).await
                    else {
                        return;
                    };
                    let Ok(request) =
                        serde_json::from_slice::<ramflux_transport::GatewayQuicRequest>(&bytes)
                    else {
                        return;
                    };
                    let response = ramflux_transport::GatewayQuicResponse {
                        status: if request.path.starts_with("/mvp1/device-manifest/") {
                            200
                        } else {
                            404
                        },
                        body: manifest,
                    };
                    let _ =
                        ramflux_transport::write_gateway_session_json(&mut stream, &response).await;
                });
            }
        });
        Ok(Self { address, ca_pem, task })
    }
}

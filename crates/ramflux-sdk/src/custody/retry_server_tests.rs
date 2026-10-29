// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual TLS retries retain progress and regenerate exporter-bound one-use proofs.
use crate::custody::{
    CreationCeremony, CustodyConnection, CustodyNetworkConfig, memory_vault::MemoryPrimaryVault,
};
use ramflux_protocol::custody::*;
use std::{
    collections::VecDeque,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use zeroize::Zeroizing;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    Open,
    RegisterChallenge,
    RegisterProve,
}
#[derive(Default)]
struct Script {
    busy: VecDeque<Point>,
    accepted: usize,
    publish_proofs: usize,
    proofs: Vec<(String, String, String)>,
    busy_at: Vec<Point>,
}
struct Fixture {
    _root: tempfile::TempDir,
    config: CustodyNetworkConfig,
    vault: Arc<MemoryPrimaryVault>,
    script: Arc<Mutex<Script>>,
    server: tokio::task::JoinHandle<Result>,
}
impl Fixture {
    async fn new(points: &[Point]) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let vault = Arc::new(MemoryPrimaryVault::default());
        create(root.path(), &vault)?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let tls = ramflux_transport::MeshTlsConfig {
            ca_cert: root.path().join("ca.pem"),
            service_cert: root.path().join("server.pem"),
            service_key: root.path().join("server.key"),
        };
        std::fs::write(&tls.ca_cert, cert.cert.pem())?;
        std::fs::write(&tls.service_cert, cert.cert.pem())?;
        std::fs::write(&tls.service_key, cert.signing_key.serialize_pem())?;
        let now = crate::custody::network::now()?;
        let node = crate::custody::network_tests::node(
            now,
            ramflux_transport::custody_certificate_file_hash(&tls.service_cert)?,
        )?;
        let router = Arc::new(ramflux_node_core::RouterCore::new());
        let store =
            Arc::new(ramflux_node_core::RouterRedbStore::open(root.path().join("router.redb"))?);
        store.save_router(&router)?;
        let service = Arc::new(ramflux_node_core::CustodyService::new(node, false, &store, now)?);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            ramflux_transport::tcp_gateway_server_config(&tls)?,
        ));
        let script = Arc::new(Mutex::new(Script {
            busy: points.iter().copied().collect(),
            ..Script::default()
        }));
        let context = Arc::new(Context { router, store, service, script: Arc::clone(&script) });
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await?;
                context.script.lock().map_err(|_| "script lock")?.accepted += 1;
                let stream = acceptor.accept(socket).await?;
                handle(stream, &context).await?;
            }
        });
        let config = CustodyNetworkConfig {
            account_root: root.path().into(),
            account_id: "alice".into(),
            device_id: "primary".into(),
            gateway_address: address,
            server_name: "localhost".into(),
            ca_certificate: tls.ca_cert,
            node_id: "node".into(),
            node_public_key: ramflux_crypto::fixture_public_key_base64url(),
            audience: "node".into(),
            binding_mode: BindingMode::DirectExporter,
            allow_no_channel_binding: false,
            allow_experimental_native_dm: false,
            timeout: Duration::from_secs(5),
        };
        Ok(Self { _root: root, config, vault, script, server })
    }
}
fn create(root: &Path, vault: &MemoryPrimaryVault) -> Result {
    let now = crate::custody::network::now()?;
    let mut ceremony =
        CreationCeremony::begin(true, root, crate::custody::tests::input("alice"), now)?;
    let phrase = ceremony.show_once()?;
    let words: Vec<_> =
        phrase.split_whitespace().map(|word| Zeroizing::new(word.to_owned())).collect();
    drop(phrase);
    let positions = ceremony.hidden_challenge()?;
    let selected = std::array::from_fn(|n| words[usize::from(positions[n] - 1)].clone());
    ceremony.confirm(&selected, vault, now)?;
    Ok(())
}
struct Context {
    router: Arc<ramflux_node_core::RouterCore>,
    store: Arc<ramflux_node_core::RouterRedbStore>,
    service: Arc<ramflux_node_core::CustodyService>,
    script: Arc<Mutex<Script>>,
}
struct Disconnect<'a>(&'a ramflux_node_core::CustodyService, String);
impl Drop for Disconnect<'_> {
    fn drop(&mut self) {
        self.0.disconnect("direct-tls", &self.1);
    }
}
async fn handle(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    context: &Context,
) -> Result {
    let mut stream = ramflux_transport::GatewayTcpTlsStream::Server(stream);
    let connection = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    let _disconnect = Disconnect(&context.service, connection.clone());
    loop {
        let bytes = match ramflux_transport::read_custody_tcp_frame(&mut stream).await {
            Ok(bytes) => bytes,
            Err(ramflux_transport::TransportError::Io(error))
                if error.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let frame: CustodyClientFrame = decode(&bytes, MAX_CUSTODY_FRAME_BYTES)?;
        let point = match &frame {
            CustodyClientFrame::CustodyOpen { .. } => Some(Point::Open),
            CustodyClientFrame::Challenge {
                action: CustodyProofAction::Register { .. }, ..
            } => Some(Point::RegisterChallenge),
            CustodyClientFrame::Prove { action: CustodyProofAction::Register { .. }, .. } => {
                Some(Point::RegisterProve)
            }
            _ => None,
        };
        let exporter = if let CustodyClientFrame::Prove { proof, action } = &frame {
            let nonce = ramflux_protocol::decode_base64url(&proof.body.challenge_nonce)?
                .try_into()
                .map_err(|_| "nonce")?;
            let material = ramflux_transport::custody_tcp_exporter(&stream, &nonce)?;
            let mut script = context.script.lock().map_err(|_| "script lock")?;
            script.proofs.push((
                proof.body.proof_id.clone(),
                proof.body.challenge_nonce.clone(),
                proof.body.transport_binding.clone(),
            ));
            if matches!(action, CustodyProofAction::Publish { .. }) {
                script.publish_proofs += 1;
            }
            Some(material)
        } else {
            None
        };
        let refused = {
            let mut script = context.script.lock().map_err(|_| "script lock")?;
            if point.is_some() && script.busy.front().copied() == point {
                let hit = script.busy.pop_front().ok_or("script point")?;
                script.busy_at.push(hit);
                true
            } else {
                false
            }
        };
        // Gateway A admission can return Busy after durable registration. Exercise
        // that uncertain result as well as refusals before open/challenge work.
        let committed = if !refused || point == Some(Point::RegisterProve) {
            Some(context.service.tls(
                &context.router,
                &context.store,
                frame,
                ramflux_node_core::CustodyTlsContext {
                    connection_id: &connection,
                    remote_ip: "127.0.0.1",
                    mode: BindingMode::DirectExporter,
                    exporter,
                },
                crate::custody::network::now()?,
            ))
        } else {
            None
        };
        let response = if refused {
            if point == Some(Point::RegisterProve) {
                assert!(matches!(committed, Some(CustodyServerFrame::Registered { .. })));
            }
            CustodyServerFrame::Refused { code: CustodyRefusal::Busy }
        } else {
            committed.ok_or("missing service response")?
        };
        ramflux_transport::write_custody_tcp_frame(&mut stream, &serde_json::to_vec(&response)?)
            .await?;
        if refused {
            return Ok(());
        }
    }
}
#[tokio::test]
async fn custody_busy_open_challenge_and_prove_resume_without_republishing_or_reusing_proofs()
-> Result {
    tokio::time::timeout(Duration::from_secs(30), async {
        let fixture =
            Fixture::new(&[Point::Open, Point::RegisterChallenge, Point::RegisterProve]).await?;
        let connection = CustodyConnection::connect(fixture.config, fixture.vault).await?;
        assert_eq!(connection.account().state(), crate::custody::CreationState::Live);
        assert!(connection.session().is_some());
        let script = fixture.script.lock().map_err(|_| "script lock")?;
        assert_eq!(script.busy_at, [Point::Open, Point::RegisterChallenge, Point::RegisterProve]);
        assert_eq!(script.accepted, 4);
        assert_eq!(script.publish_proofs, 1);
        assert_eq!(script.proofs.len(), 4);
        for column in 0..3 {
            let distinct: std::collections::BTreeSet<_> = script
                .proofs
                .iter()
                .map(|proof| match column {
                    0 => &proof.0,
                    1 => &proof.1,
                    _ => &proof.2,
                })
                .collect();
            assert_eq!(distinct.len(), script.proofs.len());
        }
        fixture.server.abort();
        Ok(())
    })
    .await?
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed group state preserves verified federation routes through the actual HTTP forward adapter.
use super::*;
use crate::bus::runtime_tests;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Federation {
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    delivered: Arc<Mutex<Vec<ramflux_protocol::Envelope>>>,
}
impl Federation {
    fn new(
        manifest: crate::prekey::SdkDeviceManifestResponse,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let url = format!("http://{}", listener.local_addr()?);
        let stop = Arc::new(AtomicBool::new(false));
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let alive = stop.clone();
        let messages = delivered.clone();
        let worker = std::thread::spawn(move || {
            while !alive.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if let Err(error) = serve(stream, &manifest, &messages) {
                            eprintln!("federation fixture: {error}");
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self { url, stop, worker: Some(worker), delivered })
    }
    fn route(&self) -> LocalBusFederationRoute {
        LocalBusFederationRoute {
            federation_url: self.url.clone(),
            source_node_id: "source-node".into(),
            target_node_id: "peer-node".into(),
            required_capability: "opaque_event".into(),
            admin_token: None,
            recipient_prekey_url: Some(self.url.clone()),
        }
    }
}
impl Drop for Federation {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn serve(
    mut stream: TcpStream,
    manifest: &crate::prekey::SdkDeviceManifestResponse,
    delivered: &Mutex<Vec<ramflux_protocol::Envelope>>,
) -> TestResult {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut first = String::new();
    reader.read_line(&mut first)?;
    let mut length = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line.trim().is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':')
            && key.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse::<usize>()?;
        }
    }
    if length > 2 * 1024 * 1024 {
        return Err("oversized fixture request".into());
    }
    let body = if first
        .starts_with(&format!("GET /mvp1/device-manifest/{} ", manifest.principal_commitment))
    {
        serde_json::to_value(manifest)?
    } else if first.starts_with("POST /s8/federation/forward ") {
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes)?;
        let request: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(request["source_node_id"], "source-node");
        assert_eq!(request["target_node_id"], "peer-node");
        let envelope: ramflux_protocol::Envelope =
            serde_json::from_value(request["envelope"].clone())?;
        let target = envelope.target_delivery_id.clone();
        delivered.lock().map_err(|_| "delivery lock")?.push(envelope);
        json!({"accepted":true,"source_node_id":"source-node","target_node_id":"peer-node","delivery":{"outcome":"online","target_delivery_id":target,"inbox_seq":1,"cursor":null}})
    } else {
        return Err(format!("unexpected fixture route {first}").into());
    };
    let bytes = serde_json::to_vec(&body)?;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    )?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}
#[tokio::test]
async fn shared_group_member_add_keeps_federation_hints_and_forwards_state_to_current_siblings()
-> TestResult {
    let root = runtime_tests::root("group-federation");
    let mut source = runtime_tests::account(
        &root.join("source"),
        "sender",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    let super::dm_tests::PeerFixture { peers, config, directory, .. } =
        super::dm_tests::peer_fixture(&root, &mut source).await?;
    source.gateway_config = config.clone();
    source.target_delivery_id = config.target_delivery_id.clone();
    let peer_root = peers[0].client.owned_device_identity()?.root_commitment().to_owned();
    let remote = source
        .client
        .account_db()?
        .load_actor_state(&format!("identity/manifest-root/{peer_root}"))?
        .ok_or(StorageError::GroupPermissionDenied)?;
    let federation = Federation::new(remote)?;
    let local = Arc::new(Mutex::new(Vec::new()));
    source.put_engine(GatewaySessionEngine::with_test_transport(
        config,
        Box::new(super::fixture::RecordingGateway::new(local.clone())),
    ));
    source.client.shared_group_create(
        "group",
        "group-thread",
        Some("Federated name".into()),
        "sender",
    )?;
    let request = LocalBusFrame::request(
        "add",
        Some("sender".into()),
        "group",
        "group.member.add",
        json!({"group_id":"group","actor_id":"device-sender","member_id":"device-peer-one","member_principal_commitment":peer_root,"role":"member","federation":federation.route()}),
    );
    assert!(crate::bus::shared_group_sync::dispatch(&request, &mut source).await?.is_some());
    let routes = source.client.group_member_routes("group")?;
    let remote = routes
        .iter()
        .filter(|route| route.member_principal_commitment.as_deref() == Some(&peer_root))
        .collect::<Vec<_>>();
    assert_eq!(remote.len(), 2);
    assert!(remote.iter().all(|route| {
        route.federation.as_ref().is_some_and(|hint| hint.federation_url == federation.url)
    }));
    let unknown = ramflux_protocol::encode_base64url([9; 32]);
    assert!(
        source
            .client
            .persist_shared_group_federation_route("group", &unknown, &federation.route())
            .is_err()
    );
    assert_eq!(crate::bus::shared_group_sync::flush(&mut source).await?, 2);
    assert_eq!(local.lock().map_err(|_| "local lock")?.len(), 0);
    let delivered = federation.delivered.lock().map_err(|_| "remote lock")?.clone();
    assert_eq!(delivered.len(), 2);
    let signing = ramflux_protocol::encode_base64url(
        source
            .client
            .device_branch
            .as_ref()
            .ok_or(SdkError::IdentityRootMissing)?
            .signing_key
            .verifying_key()
            .to_bytes(),
    );
    for envelope in delivered {
        let entry = GatewayInboxEntry {
            forwarded: false,
            inbox_seq: 1,
            target_delivery_id: envelope.target_delivery_id.clone(),
            envelope,
        };
        ramflux_crypto::verify_canonical_signature(
            &ramflux_protocol::envelope_sender_signed_bytes(&entry.envelope)?,
            &entry.envelope.signed.signature,
            &signing,
        )?;
        assert_eq!(
            entry.envelope.payload_hash,
            ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::ENVELOPE,
                entry.envelope.encrypted_payload.as_bytes()
            )
        );
    }
    directory.abort();
    drop((source, peers, federation));
    std::fs::remove_dir_all(root)?;
    Ok(())
}

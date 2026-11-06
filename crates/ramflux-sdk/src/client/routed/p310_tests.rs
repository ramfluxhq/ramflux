// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! P3.10 activates the five public caller policies together, each through its real entry point.
use super::selector_reopen::Case;
use super::session_record::{AcceptanceHook, Wire};
use super::*;
use crate::bus::protocol::LocalBusMessageAttachmentInput;
use ramflux_transport::{GatewayQuicRequest, GatewayQuicResponse, MeshTlsConfig};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::sync::{Arc, Mutex};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Puts = Arc<Mutex<Vec<(String, usize)>>>;
const PUT_CHUNK: &str = "/relay/v1/object/put_chunk";

/// A real server-auth QUIC listener that decodes `put_chunk` frames and records what it stored.
struct Relay {
    addr: std::net::SocketAddr,
    ca: PathBuf,
    root: PathBuf,
    puts: Puts,
    task: tokio::task::JoinHandle<()>,
}
impl Relay {
    fn start(expected: &[&str]) -> Result<Self, Box<dyn std::error::Error>> {
        let root = PathBuf::from("/tmp").join(format!(
            "rf-p310-relay-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        std::fs::create_dir_all(&root)?;
        let mut ca = CertificateParams::new(Vec::<String>::new())?;
        ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
        ca.distinguished_name.push(rcgen::DnType::CommonName, "p310-relay-ca");
        let ca_key = KeyPair::generate()?;
        let ca_pem = ca.self_signed(&ca_key)?.pem();
        let issuer = Issuer::new(ca, ca_key);
        let mut leaf = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?;
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate()?;
        let cert = leaf.signed_by(&key, &issuer)?;
        let tls = MeshTlsConfig {
            ca_cert: root.join("ca.pem"),
            service_cert: root.join("service.pem"),
            service_key: root.join("key.pem"),
        };
        std::fs::write(&tls.ca_cert, ca_pem)?;
        std::fs::write(&tls.service_cert, cert.pem())?;
        std::fs::write(&tls.service_key, key.serialize_pem())?;
        let endpoint = quinn::Endpoint::server(
            ramflux_transport::quic_gateway_server_config(&tls)?,
            "127.0.0.1:0".parse()?,
        )?;
        let addr = endpoint.local_addr()?;
        let puts = Puts::default();
        let expected = expected.iter().map(ToString::to_string).collect::<Vec<_>>();
        let task = tokio::spawn(serve(endpoint, puts.clone(), expected));
        Ok(Self { addr, ca: tls.ca_cert, root, puts, task })
    }
    fn options(&self, principal: &str) -> RelayTransferOptions {
        RelayTransferOptions {
            relay_endpoint: "https://relay.invalid".into(),
            token_provider: RelayTokenProvider::GatewayIssued,
            interrupt_after_chunks: None,
            relay_quic_peer_addr: Some(self.addr.to_string()),
            relay_quic_server_name: Some("localhost".into()),
            relay_quic_ca_cert: Some(self.ca.clone()),
            relay_owner_home_node_id: Some("home.invalid".into()),
            relay_owner_principal_id: Some(principal.into()),
            relay_audience_node_id: Some("relay.invalid".into()),
        }
    }
    fn stored(&self) -> Result<Vec<(String, usize)>, Box<dyn std::error::Error>> {
        Ok(self.puts.lock().map_err(|_| "relay record poisoned")?.clone())
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
async fn serve(endpoint: quinn::Endpoint, puts: Puts, expected: Vec<String>) {
    while let Some(incoming) = endpoint.accept().await {
        let (puts, expected) = (puts.clone(), expected.clone());
        tokio::spawn(async move {
            let Ok(connection) = incoming.await else { return };
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                let Ok(request) =
                    ramflux_transport::read_quic_json_frame::<GatewayQuicRequest>(&mut recv).await
                else {
                    continue;
                };
                let response = put_chunk(&request, &puts, &expected);
                let _ = ramflux_transport::write_quic_json_frame(&mut send, &response).await;
            }
        });
    }
}
fn rejected(reason: &str) -> GatewayQuicResponse {
    GatewayQuicResponse { status: 400, body: serde_json::json!({ "error": reason }) }
}
/// Decodes the frame and checks object id, chunk binding and length before acknowledging.
fn put_chunk(
    request: &GatewayQuicRequest,
    puts: &Puts,
    expected: &[String],
) -> GatewayQuicResponse {
    if request.path != PUT_CHUNK {
        return GatewayQuicResponse { status: 404, body: serde_json::json!({}) };
    }
    let body = &request.body;
    let text = |value: &serde_json::Value| value.as_str().map(str::to_owned);
    let (Some(object_id), Some(manifest), Some(chunk_id)) = (
        text(&body["token"]["object_id"]),
        text(&body["token"]["manifest_hash"]),
        text(&body["token"]["chunk_id"]),
    ) else {
        return rejected("token binding missing");
    };
    if !expected.contains(&object_id)
        || text(&body["pop"]["object_id"]).as_ref() != Some(&object_id)
    {
        return rejected("unexpected object id");
    }
    let Ok(bytes) = serde_json::from_value::<Vec<u8>>(body["encrypted_chunk"].clone()) else {
        return rejected("chunk bytes missing");
    };
    let Ok(payload) = serde_json::from_slice::<ramflux_sync::ChunkPayload>(&bytes) else {
        return rejected("chunk payload undecodable");
    };
    let hash = ramflux_sync::chunk_cipher_hash(&manifest, 0, &bytes);
    if text(&body["chunk_cipher_hash"]) != Some(hash) || payload.ciphertext.is_empty() {
        return rejected("chunk hash or length mismatch");
    }
    let Ok(mut puts) = puts.lock() else { return rejected("relay record poisoned") };
    puts.push((object_id.clone(), payload.ciphertext.len()));
    let stored = crate::prelude::SdkObjectRelayPutResponse {
        chunk_id,
        object_id,
        manifest_hash: manifest,
        expires_at: body["expires_at"].as_u64().unwrap_or(0),
        status: crate::prelude::SdkRelayChunkStatus::Available,
    };
    match serde_json::to_value(stored) {
        Ok(body) => GatewayQuicResponse { status: 200, body },
        Err(_) => rejected("response encoding failed"),
    }
}

fn attachment(id: &str) -> LocalBusMessageAttachmentInput {
    LocalBusMessageAttachmentInput {
        name: None,
        mime: None,
        object_id: id.into(),
        plaintext_base64: ramflux_protocol::encode_base64url(id.as_bytes()),
        chunk_size: 512 * 1024,
        relay_endpoint: "https://relay.invalid".into(),
        owner_home_node_id: None,
        relay_audience_node_id: None,
        relay_service_key_base64: None,
    }
}
/// Fences one outgoing reference through a second connection opened by path, as a concurrent
/// own-device erasure would.
fn fence_by_path(root: PathBuf, id: String, object: &'static str) -> AcceptanceHook {
    Box::new(move || {
        let fail = |error: SdkError| format!("{error:?}");
        let mut other = RamfluxClient::new();
        other.open_account_index(&root).map_err(fail)?;
        other.unlock_account(&id, b"routed-test").map_err(fail)?;
        let db = other.account_db().map_err(fail)?;
        let (stored, _) = db
            .load_object::<ramflux_sync::EncryptedObject>(object)
            .map_err(|error| error.to_string())?
            .ok_or("fence target is not staged")?;
        db.retain_object(
            object,
            &stored.manifest_hash,
            ramflux_storage::ObjectRetention::OwnDeviceTransport,
        )
        .map_err(|error| error.to_string())?;
        db.retire_transport_object(object, &stored.manifest_hash).map_err(|error| error.to_string())
    })
}

/// The own-outgoing policy through the real send entrypoint: real uploads, fence after the ACK.
async fn outgoing_after_ack_fence_is_consumed() -> TestResult {
    let ids = ["good-one", "refused", "good-two"];
    let relay = Relay::start(&ids)?;
    let mut c = Case::new()?;
    super::review::trust(&c.a, &c.b)?;
    super::review::trust(&c.b, &c.a)?;
    c.a.client.establish_friend_link(
        "outgoing",
        c.b.client.owned_device_identity()?.root_commitment(),
        c.a.client.owned_device_identity()?.root_commitment(),
    )?;
    c.a.client.node_relay_options = Some(relay.options("alice"));
    let hook = fence_by_path(c.a.root.clone(), c.a.id.clone(), "refused");
    let (mut engine, sent) = Wire::engine_with_hook(&c.a, &c.b, Some(hook))?;
    let message = super::r5::outgoing(&c.a, &c.b, "p310-send");
    let attachments = ids.map(attachment);
    let entry = Box::pin(c.a.client.send_plaintext_direct_message_with_attachments_via_gateway(
        &mut engine,
        &super::review::pool()?,
        message,
        b"p310 text",
        &attachments,
    ))
    .await?;
    assert_eq!(sent.lock().map_err(|_| "sent mutex")?.len(), 1, "one gateway acceptance");
    let opened = c.b.client.open_routed(&entry, "bob")?;
    let envelope: crate::dm::SdkDmAttachmentEnvelope = serde_json::from_slice(&opened.body)?;
    assert_eq!(envelope.attachments.len(), 3, "the recipient still receives every reference");
    let stored = relay.stored()?;
    assert_eq!(stored.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(), ids);
    assert!(stored.iter().all(|(_, length)| *length > 0));
    let db = c.a.client.account_db()?;
    assert!(matches!(
        db.check_object_access("refused"),
        Err(ramflux_storage::StorageError::ObjectErased)
    ));
    assert_eq!(db.actor_state_keys("attachment/reference/refused")?.len(), 0);
    for id in ["good-one", "good-two"] {
        assert_eq!(db.actor_state_keys(&format!("attachment/reference/{id}"))?.len(), 1);
        assert_eq!(c.a.client.decrypt_object(id)?, id.as_bytes());
    }
    assert_eq!(c.a.client.direct_messages("recovery-thread")?.len(), 1);
    assert_eq!(db.due_inbox_retries(i64::MAX)?.len(), 0);
    Ok(())
}

type Witness<'a> = std::pin::Pin<Box<dyn Future<Output = TestResult> + 'a>>;
async fn policy(name: &str, witness: Witness<'_>) -> TestResult {
    witness.await.map_err(|error| {
        format!("P3.10 policy `{name}` did not take the consuming path: {error}").into()
    })
}
#[tokio::test]
async fn p310_public_candidate_activation_is_atomic() -> TestResult {
    policy("routed receive", Box::pin(super::selector_reopen::payload_fenced_is_consumed()))
        .await?;
    policy("legacy direct receive", Box::pin(super::legacy_selector::mixed_fenced_is_consumed()))
        .await?;
    policy(
        "pending contact release",
        Box::pin(super::pending_selector::fenced_held_item_is_consumed()),
    )
    .await?;
    policy("own outgoing after send", Box::pin(outgoing_after_ack_fence_is_consumed())).await?;
    policy("own-copy historical page", Box::pin(async {
        crate::client::own_device_sync::historical_refusal_tests::historical_registration_is_consumed()
    }))
    .await
}

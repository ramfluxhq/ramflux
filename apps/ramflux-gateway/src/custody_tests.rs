// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Gateway receipt admission over actual TCP TLS and QUIC exporters, without containers.
use super::*;
use ramflux_crypto::custody::{
    GenesisInput, MasterKey, RecoveryPhrase, SelfSigningKey, create_genesis, sign_branch_proof_v3,
    sign_node_identity_record,
};
use ramflux_protocol::custody::*;
use std::{path::PathBuf, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct Fixture {
    root: PathBuf,
    tls: ramflux_transport::MeshTlsConfig,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "ramflux-proxy-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        std::fs::create_dir(&root)?;
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let tls = ramflux_transport::MeshTlsConfig {
            ca_cert: root.join("ca.pem"),
            service_cert: root.join("public.pem"),
            service_key: root.join("public.key"),
        };
        std::fs::write(&tls.ca_cert, cert.cert.pem())?;
        std::fs::write(&tls.service_cert, cert.cert.pem())?;
        std::fs::write(&tls.service_key, cert.signing_key.serialize_pem())?;
        Ok(Self { root, tls })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
struct AuthorityFixture {
    node: VerifiedNodeRecord,
    proxy_key: ed25519_dalek::SigningKey,
    branch: ramflux_crypto::DeviceBranch,
    publication: Publication,
}
fn authority(now: u64) -> Result<AuthorityFixture> {
    let node_key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let proxy_key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let record = sign_node_identity_record(
        &node_key,
        NodeIdentityRecord {
            schema: ramflux_protocol::domain::CUSTODY_NODE_RECORD.into(),
            version: 1,
            node_id: "test-node".into(),
            node_signing_public_key: ramflux_protocol::encode_base64url(
                node_key.verifying_key().to_bytes(),
            ),
            client_tls_certificate_sha256: None,
            epoch: 1,
            previous_record_hash: None,
            issued_at: now,
            receipt_keys: vec![],
            revoked_receipt_key_ids: vec![],
            proxy_keys: vec![ProxyKey {
                key_id: ramflux_protocol::encode_base64url([10; 32]),
                public_key: ramflux_protocol::encode_base64url(
                    proxy_key.verifying_key().to_bytes(),
                ),
                not_before: now - 1,
                sign_until: now + 300,
                overlap_until: now + 605_100,
                status: ReceiptKeyStatus::Active,
                proxy_id: "ramflux-gateway".into(),
                audiences: vec!["test-node".into()],
            }],
            revoked_proxy_key_ids: vec![],
            channel_binding_modes: vec![BindingMode::HomeRelayReceipt],
        },
    )?;
    let node = verify_node_identity_record(
        &record,
        "test-node",
        &record.body.node_signing_public_key,
        now,
    )?;
    let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[1; 32])?)?;
    let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([2; 32]));
    let branch = ramflux_crypto::create_device_branch("alice", "primary", 1, [3; 32]);
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([4; 32]);
    let publication = Publication {
        record: create_genesis(
            &master,
            &primary,
            &branch,
            &agreement,
            GenesisInput {
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                display_name: "Alice".into(),
                issued_at: now,
                master_cert_id: ramflux_protocol::encode_base64url([5; 32]),
                branch_cert_id: ramflux_protocol::encode_base64url([6; 32]),
                external_human_primary: None,
            },
        )?,
        compacted_ids: None,
    };
    Ok(AuthorityFixture { node, proxy_key, branch, publication })
}
fn exercise(
    fixture: &Fixture,
    client: impl Fn(&[u8; 32]) -> Result<[u8; 32]>,
    server: impl Fn(&[u8; 32]) -> Result<[u8; 32]>,
    foreign: impl Fn(&[u8; 32]) -> Result<[u8; 32]>,
) -> Result {
    let now = ramflux_node_core::now_unix_seconds();
    let AuthorityFixture { node, proxy_key, branch, publication } = authority(now)?;
    let reference = DeviceRef {
        account_anchor: publication.record.body.account_anchor.clone(),
        device_id: "primary".into(),
        device_epoch: 1,
    };
    let router = ramflux_node_core::RouterCore::new();
    let store = ramflux_node_core::RouterRedbStore::open(fixture.root.join("router.redb"))?;
    store.save_router(&router)?;
    let service = ramflux_node_core::CustodyService::new(node.clone(), false, &store, now)?;
    let mut proxy = Proxy {
        node,
        signer: Some(proxy_key),
        connection: ramflux_protocol::encode_base64url([11; 32]),
        mode: BindingMode::HomeRelayReceipt,
        session_ids: BTreeSet::new(),
        handoff_session: None,
        router: None,
        auth_deadline: tokio::time::Instant::now() + Duration::from_secs(10),
        authenticated: false,
    };
    let action = CustodyProofAction::Publish { publication: Box::new(publication.clone()) };
    let request = proxy.prepare(
        CustodyClientFrame::Challenge { device_ref: reference.clone(), action: action.clone() },
        None,
        "127.0.0.1".parse()?,
    )?;
    let CustodyServerFrame::Challenge { challenge } =
        service.mesh(&router, &store, request, "ramflux-gateway", now)
    else {
        return Err("challenge missing".into());
    };
    assert_eq!(challenge.action_hash, custody_action_hash(&action)?);
    assert_eq!(challenge.audience, "test-node");
    let nonce: [u8; 32] = ramflux_protocol::decode_base64url(&challenge.challenge_nonce)?
        .try_into()
        .map_err(|_| "nonce")?;
    let client = client(&nonce)?;
    let server = server(&nonce)?;
    let foreign = foreign(&nonce)?;
    assert_eq!(client, server);
    assert_ne!(client, foreign);
    let proof = sign_branch_proof_v3(
        &branch,
        BranchProofV3 {
            schema: ramflux_protocol::domain::BRANCH_PROOF_V3.into(),
            version: 3,
            device_ref: reference,
            certificate_hash: object_hash(
                publication.record.body.devices[0].branch_certificate.as_ref().ok_or("cert")?,
            )?,
            record_hash: object_hash(&publication.record)?,
            proof_id: ramflux_protocol::encode_base64url([12; 32]),
            challenge_nonce: challenge.challenge_nonce,
            action_hash: challenge.action_hash,
            audience: challenge.audience,
            binding_mode: BindingMode::HomeRelayReceipt,
            transport_binding: branch_exporter_hash(&client),
            issued_at: now,
            expires_at: now + 100,
        },
    )?;
    let frame = CustodyClientFrame::Prove { action: action.clone(), proof: Box::new(proof) };
    let error = proxy
        .prepare(frame.clone(), Some(&branch_exporter_hash(&foreign)), "127.0.0.1".parse()?)
        .err()
        .ok_or("relayed proof accepted")?;
    assert_eq!(error.downcast_ref::<CustodyRefusal>(), Some(&CustodyRefusal::BindingRefused));
    let signer = proxy.signer.replace(ed25519_dalek::SigningKey::from_bytes(&[99; 32]));
    assert!(
        proxy
            .prepare(frame.clone(), Some(&branch_exporter_hash(&server)), "127.0.0.1".parse()?)
            .is_err()
    );
    proxy.signer = signer;
    let request =
        proxy.prepare(frame.clone(), Some(&branch_exporter_hash(&server)), "127.0.0.1".parse()?)?;
    let mut other_connection = request.clone();
    if let CustodyMeshRequest::Prove { connection_id, .. } = &mut other_connection {
        *connection_id = ramflux_protocol::encode_base64url([13; 32]);
    }
    assert!(matches!(
        service.mesh(&router, &store, other_connection, "ramflux-gateway", now),
        CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused }
    ));
    assert!(matches!(
        service.mesh(&router, &store, request, "ramflux-gateway", now),
        CustodyServerFrame::Published { .. }
    ));
    let request =
        proxy.prepare(frame, Some(&branch_exporter_hash(&server)), "127.0.0.1".parse()?)?;
    assert!(matches!(
        service.mesh(&router, &store, request, "ramflux-gateway", now),
        CustodyServerFrame::Refused { code: CustodyRefusal::Replay }
    ));
    Ok(())
}
async fn tcp_pair(fixture: &Fixture) -> Result<(GatewayTcpTlsStream, GatewayTcpTlsStream)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        ramflux_transport::tcp_gateway_server_config(&fixture.tls)?,
    ));
    let server = async {
        let (socket, _) = listener.accept().await?;
        let mut tls = acceptor.accept(socket).await?;
        let mut ready = [0; 1];
        tls.read_exact(&mut ready).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(GatewayTcpTlsStream::Server(tls))
    };
    let client = async {
        let (_, tls) = ramflux_transport::TcpTlsGatewayClient::connect(
            "127.0.0.1:0".parse()?,
            address,
            "localhost",
            &fixture.tls.ca_cert,
            Duration::from_secs(5),
        )
        .await?;
        let mut tls = tls.into_tls_stream();
        tls.write_all(&[1]).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(tls)
    };
    let (server, client) = tokio::join!(server, client);
    Ok((client?, server?))
}
#[tokio::test]
async fn gateway_proxy_receipt_uses_actual_tcp_exporter_and_rejects_relay() -> Result {
    tokio::time::timeout(Duration::from_secs(20), async {
        let fixture = Fixture::new()?;
        let (client, server) = tcp_pair(&fixture).await?;
        let (_, foreign) = tcp_pair(&fixture).await?;
        exercise(
            &fixture,
            |nonce| Ok(ramflux_transport::custody_tcp_exporter(&client, nonce)?),
            |nonce| Ok(ramflux_transport::custody_tcp_exporter(&server, nonce)?),
            |nonce| Ok(ramflux_transport::custody_tcp_exporter(&foreign, nonce)?),
        )
    })
    .await?
}
#[tokio::test]
async fn gateway_proxy_receipt_uses_actual_quic_exporter_and_rejects_relay() -> Result {
    tokio::time::timeout(Duration::from_secs(20), async {
        let fixture = Fixture::new()?;
        let config = ramflux_transport::quic_gateway_server_config(&fixture.tls)?;
        let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse()?)?;
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        client.set_default_client_config(ramflux_transport::quic_gateway_client_config(
            &fixture.tls.ca_cert,
        )?);
        let mut pairs = Vec::new();
        for _ in 0..2 {
            let connection = client.connect(server.local_addr()?, "localhost")?;
            let accepted = async {
                server.accept().await.ok_or("incoming missing")?.await.map_err(Into::into)
            };
            let (outgoing, incoming): (_, Result<quinn::Connection>) =
                tokio::join!(connection, accepted);
            pairs.push((outgoing?, incoming?));
        }
        exercise(
            &fixture,
            |nonce| Ok(ramflux_transport::custody_quic_exporter(&pairs[0].0, nonce)?),
            |nonce| Ok(ramflux_transport::custody_quic_exporter(&pairs[0].1, nonce)?),
            |nonce| Ok(ramflux_transport::custody_quic_exporter(&pairs[1].1, nonce)?),
        )
    })
    .await?
}

#[tokio::test]
async fn dedicated_custody_tcp_accept_helper_closes_newcomer_before_tls_and_reuses_slot() -> Result
{
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new()?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
            ramflux_transport::tcp_gateway_server_config(&fixture.tls)?,
        ));
        let limiter =
            ramflux_node_core::CustodyIngressLimiter::with_pools(1, 1, 4, Duration::from_secs(10));
        let held = limiter
            .acquire("192.0.2.1".parse()?, None, std::time::Instant::now())
            .ok_or("holder")?;
        let server = async {
            let mut backoff = ramflux_node_core::ListenerAcceptBackoff::default();
            let (socket, _, permit) =
                ramflux_node_core::custody_accept_tcp(&listener, &limiter, &mut backoff).await;
            let mut tls = tokio::time::timeout_at(
                tokio::time::Instant::from_std(permit.auth_deadline()),
                acceptor.accept(socket),
            )
            .await??;
            tls.write_all(&[7]).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let client = async {
            let mut rejected = tokio::net::TcpStream::connect(address).await?;
            let mut byte = [0];
            assert_eq!(rejected.read(&mut byte).await?, 0);
            assert!(!held.is_revoked());
            drop(held);
            let (_, tls) = ramflux_transport::TcpTlsGatewayClient::connect(
                "127.0.0.1:0".parse()?,
                address,
                "localhost",
                &fixture.tls.ca_cert,
                Duration::from_secs(2),
            )
            .await?;
            let mut tls = tls.into_tls_stream();
            tls.read_exact(&mut byte).await?;
            assert_eq!(byte, [7]);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let (s, c) = tokio::join!(server, client);
        s?;
        c?;
        Ok(())
    })
    .await?
}
#[tokio::test]
async fn gateway_quic_full_handshake_pool_replies_busy_without_revoking_and_reuses_slot() -> Result
{
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = Fixture::new()?;
        let server = quinn::Endpoint::server(
            ramflux_transport::quic_gateway_server_config(&fixture.tls)?,
            "127.0.0.1:0".parse()?,
        )?;
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        client.set_default_client_config(ramflux_transport::quic_gateway_client_config(
            &fixture.tls.ca_cert,
        )?);
        let outgoing = client.connect(server.local_addr()?, "localhost")?;
        let incoming = async { server.accept().await.ok_or("incoming")?.await.map_err(Into::into) };
        let (outgoing, incoming): (_, Result<quinn::Connection>) = tokio::join!(outgoing, incoming);
        let outgoing = outgoing?;
        let incoming = incoming?;
        let limiter = ramflux_node_core::CustodyIngressLimiter::new(1);
        let held = limiter
            .acquire("192.0.2.1".parse()?, None, std::time::Instant::now())
            .ok_or("holder")?;
        let (mut tx, mut rx) = outgoing.open_bi().await?;
        tx.write_all(&[1]).await?;
        let (mut send, _recv) = incoming.accept_bi().await?;
        assert!(
            admit_quic(&mut send, &incoming, &limiter, std::time::Instant::now()).await?.is_none()
        );
        let refused: CustodyServerFrame = decode(&read_custody_tcp_frame(&mut rx).await?, 4096)?;
        assert_eq!(refused, busy());
        assert_eq!(rx.read(&mut [0]).await?, None);
        assert!(!held.is_revoked());
        drop(held);
        let (mut tx, _rx) = outgoing.open_bi().await?;
        tx.write_all(&[1]).await?;
        let (mut send, _recv) = incoming.accept_bi().await?;
        assert!(
            admit_quic(&mut send, &incoming, &limiter, std::time::Instant::now()).await?.is_some()
        );
        Ok(())
    })
    .await?
}

#[test]
fn custody_disabled_skips_pool_parsing_initialization_and_nofile_checks() -> anyhow::Result<()> {
    for key in [None, Some(std::ffi::OsStr::new(""))] {
        assert!(
            initialize_if_configured(key, || {
                anyhow::bail!("custody settings or nofile check must not run")
            })?
            .is_none()
        );
    }
    assert!(
        initialize_if_configured(Some(std::ffi::OsStr::new("configured")), || {
            anyhow::bail!("enabled custody checks run")
        })
        .is_err()
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn disabled_custody_starts_under_low_nofile_with_invalid_pool_settings() -> Result {
    const CHILD: &str = "RAMFLUX_TEST_DISABLED_CUSTODY_CHILD";
    if let Ok(mode) = std::env::var(CHILD) {
        if mode == "enabled" {
            let error = initialize().err().ok_or("enabled custody accepted low nofile")?;
            assert!(error.to_string().contains("RLIMIT_NOFILE soft=256"));
        } else {
            assert!(initialize()?.is_none());
        }
        return Ok(());
    }
    for mode in ["absent", "empty", "enabled"] {
        let mut child = std::process::Command::new("/bin/sh");
        child.args(["-c", "ulimit -n 256 && exec \"$@\"", "sh"])
            .arg(std::env::current_exe()?)
            .args(["--exact", "custody::tests::disabled_custody_starts_under_low_nofile_with_invalid_pool_settings", "--nocapture"])
            .env(CHILD, mode)
            .env_remove("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY")
            .env("RAMFLUX_CUSTODY_HANDSHAKE_POOL", "invalid")
            .env("RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS", "invalid");
        if mode == "empty" {
            child.env("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY", "");
        }
        if mode == "enabled" {
            child
                .env("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY", "configured")
                .env("RAMFLUX_CUSTODY_HANDSHAKE_POOL", "256")
                .env("RAMFLUX_CUSTODY_AUTHENTICATED_POOL", "1024")
                .env("RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS", "10000");
        }
        let output = child.output()?;
        assert!(
            output.status.success(),
            "mode={mode}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }
    Ok(())
}

#[test]
fn native_handoff_is_one_use_and_requires_the_exact_live_registered_authority() -> Result {
    let now = ramflux_node_core::now_unix_seconds();
    let AuthorityFixture { node, branch, publication, .. } = authority(now)?;
    let anchor = publication.record.body.account_anchor.clone();
    let session = CustodySession {
        session_id: ramflux_protocol::encode_base64url([31; 32]),
        device_ref: DeviceRef {
            account_anchor: anchor.clone(),
            device_id: "primary".into(),
            device_epoch: 1,
        },
        target_delivery_id: ramflux_protocol::qualified_device_id(&anchor, "primary")?,
        record_hash: object_hash(&publication.record)?,
        proof_hash: ramflux_protocol::encode_base64url([32; 32]),
        binding_mode: BindingMode::HomeRelayReceipt,
        expires_at: now + 100,
    };
    let key = ramflux_node_core::DeviceAuthKeyResponse {
        principal_id: "alice".into(),
        device_id: "primary".into(),
        device_epoch: 1,
        branch_public_key: ramflux_protocol::encode_base64url(
            branch.signing_key.verifying_key().to_bytes(),
        ),
        target_delivery_id: session.target_delivery_id.clone(),
        revoked: false,
        root_public_key: None,
        signed_device_set: None,
        custody_authority: Some(Box::new(CustodyAuthority {
            publication,
            custodian_publication: None,
        })),
    };
    let grant = || GatewayGrant {
        session: session.clone(),
        deadline: std::time::Instant::now() + Duration::from_secs(100),
    };
    let mut proxy = Proxy {
        node,
        signer: None,
        connection: ramflux_protocol::encode_base64url([33; 32]),
        mode: BindingMode::HomeRelayReceipt,
        session_ids: BTreeSet::from([session.session_id.clone()]),
        handoff_session: Some(grant()),
        authenticated: true,
        router: None,
        auth_deadline: tokio::time::Instant::now() + Duration::from_secs(100),
    };
    let taken = proxy.handoff(&session.session_id)?;
    assert!(proxy.handoff(&session.session_id).is_err());
    assert!(proxy.session_ids.is_empty());
    assert!(crate::session::native_handoff_matches(&key, Some(&taken), now)?);
    assert!(!crate::session::native_handoff_matches(&key, None, now)?);
    let mut mismatched = grant();
    mismatched.session.record_hash = ramflux_protocol::encode_base64url([34; 32]);
    assert!(!crate::session::native_handoff_matches(&key, Some(&mismatched), now)?);
    mismatched = grant();
    mismatched.session.device_ref.device_epoch += 1;
    assert!(!crate::session::native_handoff_matches(&key, Some(&mismatched), now)?);
    mismatched = grant();
    mismatched.deadline = std::time::Instant::now();
    assert!(!crate::session::native_handoff_matches(&key, Some(&mismatched), now)?);
    assert!(!crate::session::native_handoff_matches(&key, Some(&taken), now + 100)?);
    proxy.session_ids.insert(session.session_id.clone());
    proxy.handoff_session = Some(grant());
    assert!(proxy.handoff("wrong-session").is_err());
    assert!(proxy.handoff(&session.session_id).is_err());
    Ok(())
}

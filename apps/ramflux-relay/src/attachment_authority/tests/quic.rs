// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! The authority listener over a real in-process mesh QUIC connection (P25 N5b).
#![allow(clippy::expect_used)]
use super::*;
use crate::attachment_authority::{
    listener::{
        AuthorityListenerConfig, CHALLENGE_PATH, ChallengeMintRequest, ChallengeReply,
        MAX_WIRE_BODY, RENEW_PATH, RequesterWire,
    },
    quic::AuthorityQuicServer,
};
use ramflux_transport::{MeshTlsConfig, TransportError, mesh_quic_post_json_with_peer_ca_pems};
use std::{path::Path, process::Command, sync::Arc};

/// The application-close code in either transport error form:
/// `...ApplicationClose { error_code: 403 ...` or `closed by peer: ... (code 403)`.
fn close_code(message: &str) -> Option<u32> {
    ["error_code: ", "(code "].iter().find_map(|marker| {
        let rest = &message[message.find(marker)? + marker.len()..];
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    })
}

#[test]
fn close_code_reads_every_transport_error_form_exactly() {
    for (message, code) in [
        (
            "connection lost; detail=ConnectionLost(ApplicationClosed(ApplicationClose { error_code: 403, reason: b\"x\" }))",
            Some(403),
        ),
        ("closed by peer: router identity required (code 403)", Some(403)),
        ("closed by peer: other (code 4031)", Some(4031)),
        ("closed by peer: other (code 404)", Some(404)),
        (
            "connection lost; detail=ConnectionLost(ApplicationClosed(ApplicationClose { error_code: 0 }))",
            Some(0),
        ),
        ("some other failure", None),
    ] {
        assert_eq!(close_code(message), code, "{message}");
    }
}

struct Pki {
    ca_pem: String,
    relay: MeshTlsConfig,
    router: MeshTlsConfig,
    gateway: MeshTlsConfig,
    federation: MeshTlsConfig,
}

fn openssl(args: &[&str]) {
    let status = Command::new("openssl").args(args).status().unwrap();
    assert!(status.success(), "openssl {args:?}");
}
fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn service(root: &Path, ca_key: &Path, ca_cert: &Path, id: &str) -> MeshTlsConfig {
    let dir = root.join(id);
    std::fs::create_dir_all(&dir).unwrap();
    let (key, csr, cert, ext) =
        (dir.join("key.pem"), dir.join("req.csr"), dir.join("cert.pem"), dir.join("ext.cnf"));
    openssl(&["genpkey", "-algorithm", "ED25519", "-out", s(&key)]);
    openssl(&["req", "-new", "-key", s(&key), "-out", s(&csr), "-subj", &format!("/CN={id}")]);
    std::fs::write(
        &ext,
        format!(
            "subjectAltName = DNS:{id}, DNS:localhost, URI:spiffe://node-a/{id}\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n"
        ),
    )
    .unwrap();
    openssl(&[
        "x509",
        "-req",
        "-in",
        s(&csr),
        "-CA",
        s(ca_cert),
        "-CAkey",
        s(ca_key),
        "-CAcreateserial",
        "-out",
        s(&cert),
        "-days",
        "30",
        "-extfile",
        s(&ext),
    ]);
    MeshTlsConfig { ca_cert: ca_cert.to_path_buf(), service_cert: cert, service_key: key }
}
fn pki(name: &str) -> Pki {
    let root = path(name);
    std::fs::create_dir_all(&root).unwrap();
    let (ca_key, ca_cert) = (root.join("ca-key.pem"), root.join("ca.pem"));
    openssl(&["genpkey", "-algorithm", "ED25519", "-out", s(&ca_key)]);
    openssl(&[
        "req",
        "-x509",
        "-new",
        "-key",
        s(&ca_key),
        "-out",
        s(&ca_cert),
        "-days",
        "30",
        "-subj",
        "/CN=Authority Test CA",
    ]);
    let mk = |id: &str| service(&root, &ca_key, &ca_cert, id);
    Pki {
        ca_pem: std::fs::read_to_string(&ca_cert).unwrap(),
        relay: mk("ramflux-relay"),
        router: mk("ramflux-router"),
        gateway: mk("ramflux-gateway"),
        federation: mk("ramflux-federation"),
    }
}

fn wire(e: &Env) -> ChallengeMintRequest {
    let r = &e.g().grantee;
    ChallengeMintRequest {
        capability: e.cap.clone(),
        target_operation: e.target().canonical_bytes().unwrap(),
        requester: RequesterWire {
            account_anchor: r.account_anchor.clone(),
            device_id: r.device_id.clone(),
            device_epoch: r.device_epoch,
            signing_public_key: r.signing_public_key,
            home_node_id: r.home_node_id.clone(),
        },
        home_node: r.home_node_id.clone(),
        peer_node: r.home_node_id.clone(),
        home_verdict: Some(e.verdict()),
    }
}
fn post(
    addr: &str,
    pki: &Pki,
    client: &MeshTlsConfig,
    path: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    mesh_quic_post_json_with_peer_ca_pems(
        addr,
        path,
        client,
        "ramflux-relay",
        std::slice::from_ref(&pki.ca_pem),
        body,
    )
}
fn start(e: &Env, pki: &Pki) -> AuthorityQuicServer {
    start_with(e, pki, std::time::Duration::from_secs(10))
}
fn start_with(e: &Env, pki: &Pki, budget: std::time::Duration) -> AuthorityQuicServer {
    let issuer = SourceIssuer::new(e.f.registry.clone(), e.f.source_signer(), policy()).unwrap();
    let now = e.now;
    AuthorityQuicServer::start(
        &AuthorityListenerConfig { bind_addr: Some("127.0.0.1:0".into()) },
        &pki.relay,
        vec![pki.ca_pem.clone()],
        issuer,
        Arc::new(move || now),
        budget,
    )
    .unwrap()
    .expect("a configured listener binds")
}

#[test]
fn unconfigured_listener_binds_nothing() {
    let e = Env::new("quic-off");
    let pki = pki("quic-off");
    let issuer = SourceIssuer::new(e.f.registry.clone(), e.f.source_signer(), policy()).unwrap();
    let out = AuthorityQuicServer::start(
        &AuthorityListenerConfig::default(),
        &pki.relay,
        vec![pki.ca_pem.clone()],
        issuer,
        Arc::new(|| 0),
        std::time::Duration::from_secs(10),
    )
    .unwrap();
    assert!(out.is_none());
}

#[test]
fn router_identity_is_admitted_over_real_quic_and_other_services_are_refused() {
    let e = Env::new("quic-peers");
    let pki = pki("quic-peers");
    let server = start(&e, &pki);
    let addr = server.local_addr().to_string();
    let body = serde_json::to_value(wire(&e)).unwrap();

    // Gateway and federation hold valid mesh certificates but are the wrong services:
    // the connection is closed with code 403 before any stream is read, so even a body
    // over the cap is refused the same way (it never reaches size checks or decoding).
    let oversized = serde_json::Value::String("a".repeat(MAX_WIRE_BODY));
    for client in [&pki.gateway, &pki.federation] {
        for path in [CHALLENGE_PATH, RENEW_PATH] {
            for payload in [&body, &oversized] {
                let out = post(&addr, &pki, client, path, payload);
                assert!(
                    matches!(&out, Err(TransportError::Quic(m)) if close_code(m) == Some(403)),
                    "{path}: {out:?}"
                );
            }
        }
    }

    // The router: challenge, then the full renewal, through the lease-holding stream writer.
    let reply: ChallengeReply =
        serde_json::from_value(post(&addr, &pki, &pki.router, CHALLENGE_PATH, &body).unwrap())
            .unwrap();
    let ChallengeReply::Minted { challenge, .. } = reply else { panic!("{reply:?}") };
    let renew = e.build(e.g(), &e.cap, &e.target(), challenge, 7);
    let frame =
        post(&addr, &pki, &pki.router, RENEW_PATH, &serde_json::to_value(&renew).unwrap()).unwrap();
    assert!(matches!(
        serde_json::from_value::<RenewAdmitResponse>(frame).unwrap(),
        RenewAdmitResponse::Issued { .. }
    ));
    // A replay is a typed refusal frame, again over the same transport.
    let replay =
        post(&addr, &pki, &pki.router, RENEW_PATH, &serde_json::to_value(&renew).unwrap()).unwrap();
    assert!(matches!(
        serde_json::from_value::<RenewAdmitResponse>(replay).unwrap(),
        RenewAdmitResponse::Refused { code: RenewalRefusal::Replay }
    ));
    server.stop();
}

/// A JSON string body whose compact serialization is exactly `n` raw bytes.
fn body_of(n: usize) -> serde_json::Value {
    serde_json::Value::String("a".repeat(n - 2))
}

#[test]
fn the_sixteen_kib_cap_is_exact_on_received_bytes_through_real_quic() {
    let e = Env::new("quic-cap");
    let pki = pki("quic-cap");
    let server = start(&e, &pki);
    let addr = server.local_addr().to_string();
    assert_eq!(MAX_WIRE_BODY, 16384);
    for path in [CHALLENGE_PATH, RENEW_PATH] {
        // 16384 bytes reach the handler (a bare string is malformed, not oversized).
        let at_cap = post(&addr, &pki, &pki.router, path, &body_of(MAX_WIRE_BODY)).unwrap();
        // It was served by the handler as a typed refusal frame, not an HTTP-level error.
        assert!(at_cap.to_string().contains("Refused"), "{path}: {at_cap}");
        // 16385 bytes are refused as received, with a 413 and no decoding.
        let over = post(&addr, &pki, &pki.router, path, &body_of(MAX_WIRE_BODY + 1));
        assert!(
            matches!(over, Err(TransportError::HttpStatus { status: 413, .. })),
            "{path}: {over:?}"
        );
    }
    server.stop();
}

#[test]
fn a_held_ledger_writer_blocks_one_request_causally_and_the_listener_serves_after_release() {
    use ramflux_node_core::attachment::parked_writer_waiters;
    let e = Env::new("quic-held");
    let pki = pki("quic-held");
    let server = start(&e, &pki);
    let addr = server.local_addr().to_string();
    let body = serde_json::to_value(wire(&e)).unwrap();
    let holder = e.f.hold_ledger_writer();
    let before = parked_writer_waiters();
    let reply = std::thread::scope(|scope| {
        let client = scope.spawn(|| post(&addr, &pki, &pki.router, CHALLENGE_PATH, &body));
        // Causal barrier: the request is provably blocked on the ledger writer.
        let give_up = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while parked_writer_waiters() <= before {
            assert!(
                std::time::Instant::now() < give_up,
                "hang guard: request never reached the writer"
            );
            std::thread::yield_now();
        }
        assert!(!client.is_finished(), "the request waits for the writer");
        drop(holder);
        client.join().unwrap()
    });
    assert!(matches!(
        serde_json::from_value::<ChallengeReply>(reply.unwrap()).unwrap(),
        ChallengeReply::Minted { .. }
    ));
    // The serving thread was never stalled: the next request is served straight away.
    let next = post(&addr, &pki, &pki.router, CHALLENGE_PATH, &body).unwrap();
    assert!(matches!(
        serde_json::from_value::<ChallengeReply>(next).unwrap(),
        ChallengeReply::Minted { .. }
    ));
    server.stop();
}

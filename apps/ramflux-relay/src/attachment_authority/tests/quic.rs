// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! The authority listener over a real in-process mesh QUIC connection (P25 N5b).
#![allow(clippy::expect_used)]
use super::*;
use crate::attachment_authority::{
    listener::{
        AuthorityListenerConfig, CHALLENGE_PATH, ChallengeMintRequest, ChallengeReply, RENEW_PATH,
        RequesterWire,
    },
    quic::AuthorityQuicServer,
};
use ramflux_transport::{MeshTlsConfig, TransportError, mesh_quic_post_json_with_peer_ca_pems};
use std::{path::Path, process::Command, sync::Arc};

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
    let issuer = SourceIssuer::new(e.f.registry.clone(), e.f.source_signer(), policy()).unwrap();
    let now = e.now;
    AuthorityQuicServer::start(
        &AuthorityListenerConfig { bind_addr: Some("127.0.0.1:0".into()) },
        &pki.relay,
        vec![pki.ca_pem.clone()],
        issuer,
        Arc::new(move || now),
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
    // each is refused with 403 before the body is read, and nothing is consumed.
    for client in [&pki.gateway, &pki.federation] {
        for path in [CHALLENGE_PATH, RENEW_PATH] {
            let out = post(&addr, &pki, client, path, &body);
            assert!(
                matches!(out, Err(TransportError::HttpStatus { status: 403, .. })),
                "{path}: {out:?}"
            );
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

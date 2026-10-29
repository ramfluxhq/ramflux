// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-source native bootstrap diagnostics through gateway proof/receipt admission.
use super::*;
use ramflux_node_core::{
    CustodyIngressLimiter, CustodyIngressPermit, CustodyService, RouterCore, RouterRedbStore,
};
use std::time::Instant;

struct Account {
    branch: ramflux_crypto::DeviceBranch,
    agreement: ramflux_crypto::X25519KeyPair,
    publication: Publication,
}
impl Account {
    fn new(principal: &str, seed: u8) -> Result<Self> {
        let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[seed; 32])?)?;
        let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([seed + 1; 32]));
        let branch = ramflux_crypto::create_device_branch(principal, "primary", 1, [seed + 2; 32]);
        let agreement = ramflux_crypto::X25519KeyPair::from_seed([seed + 3; 32]);
        let record = create_genesis(
            &master,
            &primary,
            &branch,
            &agreement,
            GenesisInput {
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                display_name: principal.into(),
                issued_at: ramflux_node_core::now_unix_seconds(),
                master_cert_id: ramflux_protocol::encode_base64url([seed + 4; 32]),
                branch_cert_id: ramflux_protocol::encode_base64url([seed + 5; 32]),
                external_human_primary: None,
            },
        )?;
        Ok(Self { branch, agreement, publication: Publication { record, compacted_ids: None } })
    }
    fn reference(&self) -> DeviceRef {
        DeviceRef {
            account_anchor: self.publication.record.body.account_anchor.clone(),
            device_id: "primary".into(),
            device_epoch: 1,
        }
    }
    fn actions(&self) -> Result<[CustodyProofAction; 3]> {
        let bundle = ramflux_crypto::create_prekey_bundle(
            &self.branch,
            &self.agreement,
            "signed",
            &ramflux_crypto::X25519KeyPair::from_seed([30; 32]),
            None,
            None,
        )?;
        Ok([
            CustodyProofAction::Publish { publication: Box::new(self.publication.clone()) },
            CustodyProofAction::Register { prekey_bundle: serde_json::to_value(bundle)? },
            CustodyProofAction::OpenSession,
        ])
    }
}
struct Client {
    tls: GatewayTcpTlsStream,
    observed: GatewayTcpTlsStream,
    proxy: Proxy,
    permit: CustodyIngressPermit,
}
impl Client {
    async fn connect(
        fixture: &Fixture,
        limiter: &Arc<CustodyIngressLimiter>,
        node: &VerifiedNodeRecord,
    ) -> Result<Self> {
        let (tls, observed) = tcp_pair(fixture).await?;
        let permit = limiter
            .acquire("127.0.0.1".parse()?, None, Instant::now())
            .ok_or("handshake pool refusal")?;
        Ok(Self {
            tls,
            observed,
            permit,
            proxy: Proxy {
                node: node.clone(),
                signer: Some(ed25519_dalek::SigningKey::from_bytes(&[9; 32])),
                connection: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                mode: BindingMode::HomeRelayReceipt,
                session_ids: BTreeSet::new(),
                router: None,
                auth_deadline: tokio::time::Instant::now() + Duration::from_secs(10),
                authenticated: false,
            },
        })
    }
    fn prove(
        &self,
        account: &Account,
        action: CustodyProofAction,
        service: &CustodyService,
        router: &RouterCore,
        store: &RouterRedbStore,
    ) -> Result<CustodyServerFrame> {
        let now = ramflux_node_core::now_unix_seconds();
        let request = self.proxy.prepare(
            CustodyClientFrame::Challenge {
                device_ref: account.reference(),
                action: action.clone(),
            },
            None,
            "127.0.0.1".parse()?,
        )?;
        let response = service.mesh(router, store, request, "ramflux-gateway", now);
        let CustodyServerFrame::Challenge { challenge } = response else { return Ok(response) };
        let nonce = ramflux_protocol::decode_base64url(&challenge.challenge_nonce)?
            .try_into()
            .map_err(|_| "nonce")?;
        let material = ramflux_transport::custody_tcp_exporter(&self.tls, &nonce)?;
        let observed =
            branch_exporter_hash(&ramflux_transport::custody_tcp_exporter(&self.observed, &nonce)?);
        let proof = sign_branch_proof_v3(
            &account.branch,
            BranchProofV3 {
                schema: ramflux_protocol::domain::BRANCH_PROOF_V3.into(),
                version: 3,
                device_ref: account.reference(),
                certificate_hash: object_hash(
                    account.publication.record.body.devices[0]
                        .branch_certificate
                        .as_ref()
                        .ok_or("certificate")?,
                )?,
                record_hash: object_hash(&account.publication.record)?,
                proof_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
                challenge_nonce: challenge.challenge_nonce,
                action_hash: challenge.action_hash,
                audience: challenge.audience,
                binding_mode: BindingMode::HomeRelayReceipt,
                transport_binding: branch_exporter_hash(&material),
                issued_at: now,
                expires_at: now + 300,
            },
        )?;
        let request = self.proxy.prepare(
            CustodyClientFrame::Prove { action, proof: Box::new(proof) },
            Some(&observed),
            "127.0.0.1".parse()?,
        )?;
        let response = service.mesh(router, store, request, "ramflux-gateway", now);
        if matches!(
            response,
            CustodyServerFrame::Published { .. }
                | CustodyServerFrame::Registered { .. }
                | CustodyServerFrame::SessionEstablished { .. }
        ) {
            assert!(
                self.permit.mark_authenticated(&account.reference().account_anchor),
                "authenticated limiter refused"
            );
        }
        Ok(response)
    }
}
#[tokio::test]
async fn id02_same_ip_reconnect_busy_is_challenge_issuance_not_handshake_or_authenticated_capacity()
-> Result {
    let fixture = Fixture::new()?;
    let router = RouterCore::new();
    let store = RouterRedbStore::open(fixture.root.join("diagnosis.redb"))?;
    store.save_router(&router)?;
    let node = authority(ramflux_node_core::now_unix_seconds())?.node;
    let service =
        CustodyService::new(node.clone(), false, &store, ramflux_node_core::now_unix_seconds())?;
    let limiter = CustodyIngressLimiter::with_pools(256, 1024, 4, Duration::from_secs(10));
    let alice = Account::new("alice", 20)?;
    let bob = Account::new("bob", 40)?;
    // Both daemons connect concurrently from the same source, then bootstrap and
    // retain their sessions in the same order as the realnet client.
    let (a, b) = tokio::try_join!(
        Client::connect(&fixture, &limiter, &node),
        Client::connect(&fixture, &limiter, &node)
    )?;
    for (client, account) in [(&a, &alice), (&b, &bob)] {
        for action in account.actions()? {
            assert!(!matches!(
                client.prove(account, action, &service, &router, &store)?,
                CustodyServerFrame::Refused { .. }
            ));
        }
    }
    let impostor = Account::new("alice", 60)?;
    let attempt = Client::connect(&fixture, &limiter, &node).await?;
    assert_eq!(
        attempt.prove(&impostor, impostor.actions()?[0].clone(), &service, &router, &store)?,
        CustodyServerFrame::Refused { code: CustodyRefusal::PrincipalIdTaken }
    );
    service.disconnect("ramflux-gateway", &attempt.proxy.connection);
    drop(attempt);
    service.disconnect("ramflux-gateway", &a.proxy.connection);
    drop(a);
    let reconnect = Client::connect(&fixture, &limiter, &node).await?;
    let [publish, register, _] = alice.actions()?;
    assert!(matches!(
        reconnect.prove(&alice, publish, &service, &router, &store)?,
        CustodyServerFrame::Published { .. }
    ));
    assert_eq!(
        reconnect.prove(&alice, register, &service, &router, &store)?,
        CustodyServerFrame::Refused { code: CustodyRefusal::Busy }
    );
    assert!(!b.permit.is_revoked());
    assert!(!reconnect.permit.is_revoked());
    // The same-source ninth challenge is refused, while another IP in this /24
    // can still issue a challenge under the tiered window.
    let request = CustodyMeshRequest::Challenge {
        device_ref: alice.reference(),
        action: CustodyProofAction::OpenSession,
        binding_mode: BindingMode::HomeRelayReceipt,
        client_source: "127.0.0.2".into(),
        connection_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
    };
    assert!(matches!(
        service.mesh(
            &router,
            &store,
            request,
            "ramflux-gateway",
            ramflux_node_core::now_unix_seconds()
        ),
        CustodyServerFrame::Challenge { .. }
    ));
    let fresh =
        limiter.acquire("127.0.0.1".parse()?, None, Instant::now()).ok_or("H unexpectedly full")?;
    assert!(fresh.mark_authenticated("independent-account"), "A unexpectedly full");
    eprintln!(
        "tiered source window: challenge #9 (reconnect Register) Busy for the same IP; H and A have room; fresh IP in same /24 admitted"
    );
    Ok(())
}

#[path = "custody_gateway_tests.rs"]
mod gateway;

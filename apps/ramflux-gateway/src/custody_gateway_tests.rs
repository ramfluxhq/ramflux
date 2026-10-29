// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real SDK registration through gateway TLS, proxy receipts and authenticated router mesh.
use super::*;
use ramflux_sdk::custody::{
    CreateInput, CreationCeremony, CreationState, CustodyConnection, CustodyNetworkConfig,
};
use std::path::{Path, PathBuf};
#[path = "custody_test_vault.rs"]
mod vault;

struct Gateway {
    public: Fixture,
    accounts: PathBuf,
    address: std::net::SocketAddr,
    vault: Arc<vault::Vault>,
    router: Arc<RouterCore>,
    store: Arc<RouterRedbStore>,
    serving: tokio::task::JoinHandle<anyhow::Result<()>>,
    mesh: tokio::task::JoinHandle<anyhow::Result<()>>,
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.serving.abort();
        self.mesh.abort();
    }
}
impl Gateway {
    async fn new() -> Result<Self> {
        let public = Fixture::new()?;
        let accounts = public.root.join("accounts");
        std::fs::create_dir(&accounts)?;
        let router = Arc::new(RouterCore::new());
        let store = Arc::new(RouterRedbStore::open(public.root.join("router.redb"))?);
        store.save_router(&router)?;
        let now = ramflux_node_core::now_unix_seconds();
        // This test spans several minute windows. Its development proxy key
        // remains valid beyond the complete test timeout.
        let mut body = authority(now)?.node.envelope().body.clone();
        for proxy in &mut body.proxy_keys {
            proxy.sign_until = now + 600;
        }
        let record =
            sign_node_identity_record(&ed25519_dalek::SigningKey::from_bytes(&[8; 32]), body)?;
        let node = verify_node_identity_record(
            &record,
            "test-node",
            &ramflux_crypto::public_key_base64url_from_seed([8; 32]),
            now,
        )?;
        let service = Arc::new(CustodyService::new(node, false, &store, now)?);
        let (client, mesh) =
            start_mesh(&public.root, Arc::clone(&router), Arc::clone(&store), service)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mut context = crate::session::tests::test_gateway_context()?;
        context.router = client;
        let context = crate::serve::GatewayListenerContext {
            custody: crate::custody::initialize()?,
            node_id: "test-node".into(),
            gateway_id: "ramflux-gateway".into(),
            peers: context.peers,
            router: context.router,
            notify: context.notify,
            #[cfg(feature = "itest-local-mint")]
            relay_service_key: context.relay_service_key,
            state: context.state,
            store: context.store,
            hub: context.hub,
        };
        let serving = tokio::spawn(crate::serve::serve_gateway_tcp_listener(
            listener,
            ramflux_transport::tcp_gateway_server_config(&public.tls)?,
            context,
        ));
        Ok(Self { public, accounts, address, vault: Arc::default(), router, store, serving, mesh })
    }
    fn config(&self, id: &str) -> CustodyNetworkConfig {
        CustodyNetworkConfig {
            account_root: self.accounts.clone(),
            account_id: id.into(),
            device_id: "primary".into(),
            gateway_address: self.address,
            server_name: "localhost".into(),
            ca_certificate: self.public.tls.ca_cert.clone(),
            node_id: "test-node".into(),
            node_public_key: ramflux_crypto::public_key_base64url_from_seed([8; 32]),
            audience: "test-node".into(),
            binding_mode: BindingMode::HomeRelayReceipt,
            allow_no_channel_binding: false,
            timeout: Duration::from_secs(10),
        }
    }
    fn create_local(&self, id: &str, principal: &str) -> Result<ramflux_sdk::custody::BornAccount> {
        let now = ramflux_node_core::now_unix_seconds();
        let mut ceremony = CreationCeremony::begin(
            &self.accounts,
            CreateInput {
                local_account_id: id.into(),
                principal_id: principal.into(),
                device_id: "primary".into(),
                display_name: principal.into(),
                principal_kind: ramflux_protocol::PrincipalKind::Human,
                custodian_account_id: None,
            },
            now,
        )?;
        let phrase = ceremony.show_once()?;
        let words: Vec<_> =
            phrase.split_whitespace().map(|word| Zeroizing::new(word.to_owned())).collect();
        drop(phrase);
        let positions = ceremony.hidden_challenge()?;
        let selected = std::array::from_fn(|n| words[usize::from(positions[n] - 1)].clone());
        Ok(ceremony.confirm(&selected, self.vault.as_ref(), now)?)
    }
    fn provision(&self, n: u8) -> Result<String> {
        let id = format!("client-{n}");
        let account = self.create_local(&id, &id)?;
        // Known principals reconnect behind NAT. The independent durable
        // eight-new-principals-/24/day default is intentionally unchanged.
        self.router.publish_custody_record_from(
            &ramflux_node_core::CustodyPublication {
                record: account.record().clone(),
                compacted_ids: None,
            },
            ramflux_node_core::now_unix_seconds(),
            &self.store,
            format!("198.18.{n}.1").parse()?,
        )?;
        Ok(id)
    }
    async fn register(&self, id: &str) -> Result {
        let started = Instant::now();
        let connection = CustodyConnection::connect(self.config(id), self.vault.clone()).await?;
        assert_eq!(connection.account().state(), CreationState::Live);
        assert_eq!(
            connection.session().ok_or("missing session")?.binding_mode,
            BindingMode::HomeRelayReceipt
        );
        assert!(started.elapsed() <= Duration::from_secs(90));
        Ok(())
    }
}
fn start_mesh(
    root: &Path,
    router: Arc<RouterCore>,
    store: Arc<RouterRedbStore>,
    service: Arc<CustodyService>,
) -> Result<(crate::RouterMeshClient, tokio::task::JoinHandle<anyhow::Result<()>>)> {
    use crate::clients::tests::issue_test_ca_and_service_cert;
    let gateway = issue_test_ca_and_service_cert(root, "test-node", "ramflux-gateway")
        .map_err(|e| e.to_string())?;
    let peer = issue_test_ca_and_service_cert(root, "test-node", "ramflux-router")
        .map_err(|e| e.to_string())?;
    let server = ramflux_transport::MeshQuicServer::bind_with_pem_roots_provider(
        "127.0.0.1:0",
        &peer.tls,
        Arc::new(move || Ok(vec![gateway.ca_pem.clone()])),
    )?;
    let endpoint = server.local_addr()?.to_string();
    let client = crate::RouterMeshClient {
        endpoint: "127.0.0.1:0".into(),
        server_name: "ramflux-router".into(),
        tls: gateway.tls.clone(),
        client: ramflux_transport::MeshHttpClient::new(),
        async_mesh: Some(crate::RouterAsyncMeshClient {
            endpoint,
            server_name: "ramflux-router".into(),
            tls: gateway.tls,
            peer_ca_pems: vec![peer.ca_pem],
        }),
    };
    let serving = tokio::spawn(async move {
        loop {
            let connection = server.accept_connection().await?;
            let router = Arc::clone(&router);
            let store = Arc::clone(&store);
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                while let Ok(request)=ramflux_transport::MeshQuicServer::accept_json_or_postcard_request_on_connection(&connection).await{
                    let ramflux_transport::MeshQuicAcceptedWireRequest::Json(request)=request else{anyhow::bail!("expected custody JSON mesh request")};
                    anyhow::ensure!(request.request.path==CUSTODY_RPC_PATH,"unexpected custody RPC path");
                    let frame:CustodyMeshRequest=serde_json::from_value(request.request.body.clone())?;
                    let response=service.mesh(&router,&store,frame,"ramflux-gateway",ramflux_node_core::now_unix_seconds());
                    request.write_json_response(200,&response).await?;
                }
                Ok::<_, anyhow::Error>(())
            });
        }
    });
    Ok((client, serving))
}
#[tokio::test]
async fn ten_existing_sdk_clients_behind_one_ip_register_in_waves_with_ninety_seconds_per_flight()
-> Result {
    if !in_child("custody::tests::nat::gateway::ten_existing_sdk_clients_behind_one_ip_register_in_waves_with_ninety_seconds_per_flight").await? { return Ok(()); }
    tokio::time::timeout(Duration::from_secs(300),async{
        let gateway=Gateway::new().await?;
        let accounts=(0..10).map(|n|gateway.provision(n)).collect::<Result<Vec<_>>>()?;
        let started=Instant::now();let mut complete=0;
        // 30 challenges require two 16/IP minute windows. Each wave contains
        // three real concurrent SDK clients; each call retains its 90s budget.
        for wave in accounts.chunks(3){
            match wave{
                [a,b,c]=>{tokio::try_join!(gateway.register(a),gateway.register(b),gateway.register(c))?;complete+=3;}
                [last]=>{gateway.register(last).await?;complete+=1;}
                _=>return Err("unexpected client wave".into()),
            }
        }
        assert_eq!(complete,10);
        eprintln!("gateway NAT registration: {complete} SDK clients complete in {:?}; every flight <=90s; 16/IP/min, 32/share/min, unchanged H/A",started.elapsed());
        Ok(())
    }).await?
}

async fn in_child(name: &'static str) -> Result<bool> {
    const CHILD: &str = "RAMFLUX_TEST_GATEWAY_CUSTODY_NAT_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let executable = std::env::current_exe()?;
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(executable)
                .args(["--exact", name, "--nocapture"])
                .env(CHILD, "1")
                .env(
                    "RAMFLUX_CUSTODY_NODE_PUBLIC_KEY",
                    ramflux_crypto::public_key_base64url_from_seed([8; 32]),
                )
                .env(
                    "RAMFLUX_CUSTODY_PROXY_SIGNING_SEED",
                    ramflux_protocol::encode_base64url([9; 32]),
                )
                .env("RAMFLUX_CUSTODY_HANDSHAKE_POOL", "256")
                .env("RAMFLUX_CUSTODY_AUTHENTICATED_POOL", "1024")
                .env("RAMFLUX_CUSTODY_AUTHENTICATED_SESSIONS_PER_PRINCIPAL", "4")
                .env("RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS", "10000")
                .output()
        })
        .await??;
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        eprintln!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(false);
    }
    Ok(true)
}

#[tokio::test]
async fn id02_fresh_accounts_impostor_and_reconnect_complete_through_the_real_gateway() -> Result {
    if !in_child("custody::tests::nat::gateway::id02_fresh_accounts_impostor_and_reconnect_complete_through_the_real_gateway").await? { return Ok(()); }
    tokio::time::timeout(Duration::from_secs(120), async {
        let gateway = Gateway::new().await?;
        gateway.create_local("alice", "alice")?;
        gateway.create_local("bob", "bob")?;
        gateway.create_local("impostor", "alice")?;
        let alice = CustodyConnection::connect(gateway.config("alice"), gateway.vault.clone()).await?;
        let bob = CustodyConnection::connect(gateway.config("bob"), gateway.vault.clone()).await?;
        assert_eq!(alice.account().state(), CreationState::Live);
        assert_eq!(bob.account().state(), CreationState::Live);
        assert!(matches!(CustodyConnection::connect(gateway.config("impostor"), gateway.vault.clone()).await,
            Err(ramflux_sdk::SdkError::CustodyNetwork(CustodyRefusal::PrincipalIdTaken))));
        drop(alice);
        let started = Instant::now();
        let alice = CustodyConnection::connect(gateway.config("alice"), gateway.vault.clone()).await?;
        assert!(started.elapsed() <= Duration::from_secs(90));
        assert_eq!(alice.account().state(), CreationState::Live);
        assert_eq!(alice.session().ok_or("reconnect session")?.binding_mode, BindingMode::HomeRelayReceipt);
        eprintln!("id02 real gateway: Alice/Bob fresh bootstrap + impostor + Alice reconnect successful; reconnect {:?}, per-IP challenge tier at 16/min", started.elapsed());
        Ok(())
    }).await?
}

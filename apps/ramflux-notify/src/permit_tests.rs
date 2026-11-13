// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real TLS/H2 capture behind native router, gateway and notify authority.

use super::*;
use ramflux_node_core::{
    NodeCoreError, PreparedProviderPush,
    send_authority::{AuthorityReadPurpose, AuthorityScope},
    test_support::notification_authority::*,
};
use std::{
    cell::RefCell,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const WAIT: Duration = Duration::from_secs(5);
const BODY_LIMIT: usize = 16 * 1024;
type TokenAction = dyn Fn() -> TestResult + Send + Sync;
type IssueObserver = dyn Fn(bool) -> Result<(), NodeCoreError> + Send + Sync;
thread_local! {static OBSERVER:RefCell<Option<Arc<IssueObserver>>>=RefCell::new(None);}
fn observed(body: bool) -> Result<(), NodeCoreError> {
    OBSERVER.with(|slot| {
        let observer = slot.borrow().clone();
        observer.map_or(Ok(()), |observe| observe(body))
    })
}
pub(super) fn issued_headers() -> Result<(), NodeCoreError> {
    observed(false)
}
pub(super) fn issued_body() -> Result<(), NodeCoreError> {
    observed(true)
}
struct ObserveGuard;
impl Drop for ObserveGuard {
    fn drop(&mut self) {
        OBSERVER.with(|slot| slot.replace(None));
    }
}
fn observe_issue<F: Fn(bool) -> Result<(), NodeCoreError> + Send + Sync + 'static>(
    observe: F,
) -> ObserveGuard {
    OBSERVER.with(|slot| slot.replace(Some(Arc::new(observe))));
    ObserveGuard
}
fn failure(error: impl std::fmt::Display) -> NodeCoreError {
    NodeCoreError::ItestHttp(error.to_string())
}

#[derive(Debug)]
pub(super) struct Captured {
    pub(super) path: String,
    pub(super) body: Vec<u8>,
    pub(super) headers: std::collections::BTreeMap<String, String>,
}
pub(super) struct Peer {
    pub(super) port: u16,
    pub(super) ca_pem: String,
    pub(super) capture: mpsc::Receiver<Captured>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    done: mpsc::Receiver<Result<(), String>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Peer {
    pub(super) fn new(close_first: bool) -> TestResult<Self> {
        Self::with_token_action(close_first, None)
    }
    fn with_token_action(
        close_first: bool,
        token_action: Option<Arc<TokenAction>>,
    ) -> TestResult<Self> {
        ensure_ring_crypto_provider_installed();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let ca_pem = cert.pem();
        let mut tls = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(
            vec![cert.der().clone()],
            rustls_pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )?;
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let (sender, capture) = mpsc::sync_channel(4);
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let (finished, done) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let result=(||->TestResult{
                let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                runtime.block_on(async move{
                    let listener=tokio::net::TcpListener::from_std(listener)?;
                    tokio::select!{_ = shutdown=>Ok(()),result=tokio::time::timeout(Duration::from_secs(30),serve_peer(listener,acceptor,sender,close_first,token_action))=>result?}
                })
            })().map_err(|error|error.to_string());
            let _ = finished.try_send(result);
        });
        Ok(Self { port, ca_pem, capture, stop: Some(stop), done, thread: Some(thread) })
    }
    pub(super) fn close(&mut self) -> TestResult {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.done.recv_timeout(WAIT)?.map_err(|e| format!("test: provider worker failed: {e}"))?;
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| "test: provider worker panicked")?;
        }
        Ok(())
    }
}
async fn serve_peer(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    sender: mpsc::SyncSender<Captured>,
    close_first: bool,
    token_action: Option<Arc<TokenAction>>,
) -> TestResult {
    let mut tasks = tokio::task::JoinSet::new();
    let budget = Arc::new(tokio::sync::Semaphore::new(4));
    let mut connections = 0;
    loop {
        tokio::select! {
            accepted=listener.accept()=>{
                let (tcp,_)=accepted?;
                connections+=1;
                if close_first&&connections==1{drop(tcp);continue;}
                let Ok(permit)=Arc::clone(&budget).try_acquire_owned()else{drop(tcp);continue;};
                let acceptor=acceptor.clone();let sender=sender.clone();let token_action=token_action.clone();
                tasks.spawn(async move{
                    let _permit=permit;
                    let tls=tokio::time::timeout(WAIT,acceptor.accept(tcp)).await??;
                    let mut h2=h2::server::handshake(tls).await?;
                    while let Some(request)=tokio::time::timeout(WAIT,h2.accept()).await?{
                        let (request,mut respond)=request?;
                        let path=request.uri().path().to_owned();
                        let headers=request.headers().iter().map(|(key,value)|Ok((key.as_str().to_owned(),value.to_str()?.to_owned()))).collect::<TestResult<std::collections::BTreeMap<_,_>>>()?;
                        let mut body=request.into_body();let mut bytes=Vec::new();
                        while let Some(chunk)=tokio::time::timeout(WAIT,body.data()).await?{
                            let chunk=chunk?;
                            if bytes.len()+chunk.len()>BODY_LIMIT{return Err("test: provider body overflow".into());}
                            bytes.extend_from_slice(&chunk);
                            body.flow_control().release_capacity(chunk.len())?;
                        }
                        let token = path=="/token";
                        sender.try_send(Captured{path,body:bytes,headers})?;
                        if token && let Some(action)=&token_action { action()?; }
                        let response=http::Response::builder().status(200).body(())?;
                        let reply = if token {b"{\"access_token\":\"fixture-token\"}".as_slice()} else {b"{}".as_slice()};
                        respond.send_response(response,false)?.send_data(bytes::Bytes::copy_from_slice(reply),true)?;
                    }
                    Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
                });
            },
            Some(joined)=tasks.join_next(),if !tasks.is_empty()=>{let _=joined?;}
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ = self.close();
        }
    }
}

fn request_for(
    peer: &Peer,
    scenario: &NativeScenario,
    prepared: &PreparedProviderPush,
) -> TestResult<PreparedProviderPush> {
    let mut credential = prepared.credential.clone();
    let ramflux_node_core::ProviderCredential::Apns(ref mut apns) = credential else {
        return Err("test: APNs fixture required".into());
    };
    apns.p8_key_ref = format!("literal:{}", rcgen::KeyPair::generate()?.serialize_pem());
    apns.provider_ca_pem_ref = Some(format!("literal:{}", peer.ca_pem));
    scenario.notify.update_provider_credential(&credential)?;
    let mut route = prepared.route.clone();
    route.endpoint = format!("https://localhost:{}/push", peer.port);
    route.route_generation = 0;
    let owner = scenario
        .router
        .mvp1_device_auth_key_checked(&route.device_delivery_id)?
        .ok_or("test: native owner absent")?;
    scenario.notify.register_authenticated_push_route(&owner, &route)?;
    let entry = scenario
        .notify
        .load_state()?
        .and_then(|state| state.entry(&prepared.payload.wake_id).cloned())
        .ok_or("test: queued native wake absent")?;
    scenario
        .notify
        .prepare_provider_pushes_for_entry(&entry)?
        .pop()
        .ok_or_else(|| "test: prepared native push absent".into())
}

async fn send(
    mode: u8,
    scenario: &NativeScenario,
    prepared: &PreparedProviderPush,
) -> Result<ProviderHttpResponse, NodeCoreError> {
    if mode == 0 {
        send_provider_push_h2(&scenario.notify, prepared).await
    } else {
        let pool = ProviderH2ConnectionPool::from_env();
        send_provider_push_h2_pooled(&scenario.notify, prepared, &pool).await
    }
}

#[tokio::test(flavor = "current_thread")]
async fn permit_lookup_cancel_expiry() -> TestResult {
    tokio::time::timeout(Duration::from_secs(45), async {
        for mode in 0..3 {
            for cancel in [false, true] {
                let temp = tempfile::TempDir::new()?;
                let scenario = NativeScenario::new(temp.path())?;
                let (_, _, prepared) = scenario.prepared()?;
                let mut peer = Peer::new(mode == 2)?;
                let prepared = request_for(&peer, &scenario, &prepared)?;
                let notify = Arc::downgrade(&scenario.notify);
                let wake = prepared.payload.wake_id.clone();
                scenario.network.observe_reads(move |request, _| {
                    if request.purpose == AuthorityReadPurpose::Current
                        && matches!(request.scope, AuthorityScope::Owner { .. })
                    {
                        let notify = notify.upgrade().ok_or_else(|| {
                            ramflux_node_core::NodeCoreError::Redb(
                                "test: notify store closed during lookup".into(),
                            )
                        })?;
                        if cancel {
                            notify.cancel_pending_wake(&wake)?;
                        } else {
                            let utc = (u128::from(ramflux_node_core::now_unix_seconds()) + 2)
                                * 1_000_000_000;
                            notify
                                .send_authority()
                                .set_test_clock(Some(utc), Duration::from_secs(35))?;
                        }
                    }
                    Ok(())
                })?;
                assert!(
                    send(mode, &scenario, &prepared).await.is_err(),
                    "late native authority reached provider issue (mode {mode}, cancel {cancel})"
                );
                assert!(
                    peer.capture.try_recv().is_err(),
                    "provider captured a request after cancellation/original monotonic expiry"
                );
                peer.close()?;
            }
            let temp = tempfile::TempDir::new()?;
            let scenario = NativeScenario::new(temp.path())?;
            let (_, _, prepared) = scenario.prepared()?;
            let mut peer = Peer::new(mode == 2)?;
            let prepared = request_for(&peer, &scenario, &prepared)?;
            assert_eq!(
                send(mode, &scenario, &prepared).await?.status,
                200,
                "unchanged native authority did not issue"
            );
            let captured = peer.capture.recv_timeout(WAIT)?;
            assert_eq!(captured.path, "/push", "provider path changed");
            let body: serde_json::Value = serde_json::from_slice(&captured.body)?;
            assert_eq!(
                body.get("wake_id").and_then(serde_json::Value::as_str),
                Some(prepared.payload.wake_id.as_str()),
                "provider did not receive this exact opaque wake"
            );
            peer.close()?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn permit_issue_revoke_order() -> TestResult {
    tokio::time::timeout(Duration::from_secs(60),async{
        for mode in 0..2{
            for mutation in 0..4{
                let temp=tempfile::TempDir::new()?;
                let scenario=Arc::new(NativeScenario::new(temp.path())?);
                let (_,target,prepared)=scenario.prepared()?;
                let mut peer=Peer::new(false)?;
                let prepared=request_for(&peer,&scenario,&prepared)?;
                let events=Arc::new(Mutex::new(Vec::new()));
                let (headers,entered)=mpsc::sync_channel(1);
                let (release,resume)=mpsc::sync_channel(1);
                let resume=Arc::new(Mutex::new(resume));
                let trace=Arc::clone(&events);
                let _observer=observe_issue(move|body|{
                    trace.lock().map_err(failure)?.push(if body{"body"}else{"headers"});
                    if !body{
                        headers.try_send(()).map_err(failure)?;
                        resume.lock().map_err(failure)?.recv_timeout(WAIT).map_err(failure)?;
                    }
                    Ok(())
                });
                let owner=scenario.router.mvp1_device_auth_key_checked(&target.target)?.ok_or("test: owner missing")?;
                let copy=Arc::clone(&scenario);let trace=Arc::clone(&events);let credential=prepared.credential.clone();
                let (completed,result)=mpsc::sync_channel(1);
                let worker=std::thread::spawn(move||{
                    let outcome=(||->TestResult{
                        entered.recv_timeout(WAIT)?;
                        if !copy.notify.send_authority().gate_is_held_for_test(){return Err("test: headers were handed off without holding SendGate through the body boundary".into());}
                        release.try_send(())?;
                        match mutation{
                            0=>{copy.route(&target,"second-token",ramflux_node_core::now_unix_seconds())?;copy.route(&target,"third-token",ramflux_node_core::now_unix_seconds())?;},
                            1=>{copy.notify.delete_authenticated_push_routes_at(&owner,None,Some(10))?;copy.notify.delete_authenticated_push_routes_at(&owner,None,Some(11))?;},
                            2=>{
                                let mut credential=credential;
                                for key in ["second-key","third-key"]{
                                    if let ramflux_node_core::ProviderCredential::Apns(apns)=&mut credential{apns.key_id=key.into();}
                                    copy.notify.update_provider_credential(&credential)?;
                                }
                            },
                            _=>{let now=ramflux_node_core::now_unix_seconds();copy.router.publish_custody_record(&target.revoked(now)?,now,&copy.router_store)?;},
                        }
                        trace.lock().map_err(|e|e.to_string())?.push("committed");
                        Ok(())
                    })().map_err(|e|e.to_string());
                    let _=completed.try_send(outcome);
                });
                let response=send(mode,&scenario,&prepared).await?;
                assert_eq!(response.status,200,"an already issued native request was recalled");
                result.recv_timeout(WAIT)?.map_err(|e|format!("test: mutation failed: {e}"))?;
                worker.join().map_err(|_|"test: mutation worker panicked")?;
                assert_eq!(*events.lock().map_err(|e|e.to_string())?,vec!["headers","body","committed"],"a mutation committed before the complete synchronous handoff");
                assert!(!peer.capture.recv_timeout(WAIT)?.body.is_empty(),"provider did not capture the already issued body");
                assert!(send(mode,&scenario,&prepared).await.is_err(),"the old route/credential/owner was reusable after its mutation");
                assert!(peer.capture.try_recv().is_err(),"provider captured stale authority after mutation");
                peer.close()?;
            }
        }
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
    }).await??;
    Ok(())
}

async fn oauth_private_key(root: &std::path::Path) -> TestResult<String> {
    use std::io::Read;
    const PEM_LIMIT: u64 = 8192;
    let path = root.join("oauth-private.pem");
    let mut command = tokio::process::Command::new("openssl");
    command
        .args(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"])
        .arg(&path)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let status = tokio::time::timeout(WAIT, command.status()).await??;
    if !status.success() {
        return Err("test: RSA fixture generation failed".into());
    }
    let mut pem = String::new();
    std::fs::File::open(path)?.take(PEM_LIMIT + 1).read_to_string(&mut pem)?;
    if pem.len() > usize::try_from(PEM_LIMIT)? {
        return Err("test: RSA fixture exceeded its bound".into());
    }
    Ok(pem)
}

fn fcm_prepared(
    scenario: &NativeScenario,
    peer: &Peer,
    pem: &str,
) -> TestResult<PreparedProviderPush> {
    let (_, target, signed) = scenario.call_wake()?;
    let owner = scenario
        .router
        .mvp1_device_auth_key_checked(&target.target)?
        .ok_or("test: native FCM owner")?;
    scenario.notify.delete_authenticated_push_routes(&owner, None)?;
    let credential =
        ramflux_node_core::ProviderCredential::Fcm(ramflux_node_core::FcmProviderCredential {
            credential_id: "fcm".into(),
            project_id: "fixture".into(),
            service_account_json_ref: format!(
                "literal:{}",
                serde_json::json!({"client_email":"fixture@example.test","private_key":pem})
            ),
            oauth_scope: "https://www.googleapis.com/auth/firebase.messaging".into(),
            oauth_token_url: Some(format!("https://localhost:{}/token", peer.port)),
            provider_ca_pem_ref: Some(format!("literal:{}", peer.ca_pem)),
        });
    scenario.notify.update_provider_credential(&credential)?;
    let now = ramflux_node_core::now_unix_seconds();
    scenario.notify.register_authenticated_push_route(
        &owner,
        &ramflux_node_core::DevicePushRoute {
            device_delivery_id: target.target.clone(),
            provider: ramflux_node_core::PushProviderKind::Fcm,
            credential_id: Some("fcm".into()),
            token: "fcm-token".into(),
            endpoint: format!("https://localhost:{}/push", peer.port),
            webpush_p256dh: None,
            webpush_auth: None,
            registered_at: now,
            expires_at: now + 3600,
            route_generation: 0,
        },
    )?;
    scenario.notify.claim_signed_wake(&signed, signed.body.expires_at)?;
    let wake = ramflux_node_core::project_wake_v2(&signed, now)?;
    let (_, mut pushes) = scenario.notify.queue_wake_for_push(&target.target, &wake, now, false)?;
    let prepared = pushes.pop().ok_or("test: native FCM push")?;
    assert!(pushes.is_empty(), "FCM fixture prepared an unintended second provider");
    assert!(
        scenario.notify.begin_wake_send(&prepared.payload.wake_id)?,
        "native FCM attempt refused"
    );
    Ok(prepared)
}

#[tokio::test(flavor = "current_thread")]
async fn permit_real_oauth_wait_retains_cancellation_credential_and_original_budget() -> TestResult
{
    tokio::time::timeout(Duration::from_secs(60), async {
        let secrets = tempfile::TempDir::new()?;
        let pem = oauth_private_key(secrets.path()).await?;
        for pooled in [false, true] {
            for action in 0..4 {
                let root = tempfile::TempDir::new()?;
                let scenario = NativeScenario::new(root.path())?;
                let notify = Arc::downgrade(&scenario.notify);
                let callback: Arc<TokenAction> = Arc::new(move || {
                    let notify = notify.upgrade().ok_or("test: notify closed during OAuth")?;
                    match action {
                        0 => {}
                        1 => notify
                            .cancel_pending_wake(&ramflux_protocol::encode_base64url([72; 16]))?,
                        2 => {
                            let mut credential = notify
                                .load_state()?
                                .and_then(|state| state.provider_credential("fcm").cloned())
                                .ok_or("test: current FCM credential")?;
                            if let ramflux_node_core::ProviderCredential::Fcm(fcm) = &mut credential
                            {
                                fcm.project_id = "rotated".into();
                            }
                            notify.update_provider_credential(&credential)?;
                        }
                        _ => {
                            notify
                                .send_authority()
                                .set_test_clock(None, Duration::from_secs(35))?;
                        }
                    }
                    Ok(())
                });
                let mut peer = Peer::with_token_action(false, Some(callback))?;
                let prepared = fcm_prepared(&scenario, &peer, &pem)?;
                let result = if pooled {
                    send_provider_push_h2_pooled(
                        &scenario.notify,
                        &prepared,
                        &ProviderH2ConnectionPool::from_env(),
                    )
                    .await
                } else {
                    send_provider_push_h2(&scenario.notify, &prepared).await
                };
                let token = peer.capture.recv_timeout(WAIT)?;
                assert_eq!(token.path, "/token", "fixture never exercised the real OAuth request");
                if action == 0 {
                    assert!(
                        result.is_ok(),
                        "unchanged native OAuth positive control refused: {result:?}"
                    );
                    assert_eq!(
                        peer.capture.recv_timeout(WAIT)?.path,
                        "/push",
                        "OAuth positive control did not reach its provider"
                    );
                } else {
                    assert!(
                        result.is_err(),
                        "OAuth wait bypassed committed mutation/original budget (action {action})"
                    );
                    assert!(
                        peer.capture.try_recv().is_err(),
                        "revoked/expired native request reached the provider after OAuth"
                    );
                }
                peer.close()?;
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}

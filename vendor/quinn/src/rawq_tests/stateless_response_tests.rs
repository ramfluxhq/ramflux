// SPDX-License-Identifier: MIT OR Apache-2.0
//! Stateless allocation and real send-completion barriers with no admitted connection.
use super::*;
struct Fixture { server: Endpoint, client: Endpoint, incoming: Arc<Wire>, outgoing: Arc<Wire>, sender: StatelessResponseSender, runtime: Arc<RuntimeGate> }
async fn fixture(items: usize, bytes: usize, oversize: bool) -> Fixture {
    let a: SocketAddr = "127.0.0.1:12000".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:12001".parse().unwrap();
    let incoming = Arc::new(Wire::default());
    let outgoing = Arc::new(Wire::default());
    let server_socket = Arc::new(Socket {
        local: a,
        remote: b,
        inbound: incoming.clone(),
        outbound: outgoing.clone(),
    });
    let client_socket = Arc::new(Socket {
        local: b,
        remote: a,
        inbound: outgoing.clone(),
        outbound: incoming.clone(),
    });
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let mut server_config =
        ServerConfig::with_single_cert(vec![cert.cert.der().clone()], key).unwrap();
    let mut transport = TransportConfig::default();
    transport.initial_rtt(Duration::from_millis(10));
    let transport = Arc::new(transport);
    server_config.transport_config(transport.clone());
    let mut config = EndpointConfig::default();
    config
        .control_credit_limits(proto::ControlLimits {
            bytes: 32768,
            items: 32,
        })
        .unwrap();
    if oversize { config.supported_versions((0..20000).collect()); }
    let gate = Arc::new(Gate::default());
    let runtime=Arc::new(RuntimeGate { gate: gate.clone(), spawned: AtomicUsize::new(0) });
    let mut server = Endpoint::new_with_abstract_socket(
        config,
        Some(server_config),
        server_socket,
        runtime.clone(),
    )
    .unwrap();
    server
        .set_packet_queue_limits(PacketQueueLimits {
            owners: 4,
            bytes_total: 65536,
            items_total: 64,
            bytes_per_owner: 65536,
            items_per_owner: 64,
            bytes_per_source: 65536,
            items_per_source: 128,
        })
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut client = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        client_socket,
        Arc::new(TokioRuntime),
    )
    .unwrap();
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    client_config.transport_config(transport);
    client.set_default_client_config(client_config);
    let sender = server.set_stateless_response_limits(items, bytes).unwrap();
    Fixture { server, client, incoming, outgoing, sender, runtime }
}
fn inject(wire:&Wire, bytes:Vec<u8>) { wire.packets.lock().unwrap().push_back(bytes); if let Some(w)=wire.wake.lock().unwrap().take() {w.wake();} }
fn writable(wire:&Wire) { wire.write_blocked.store(false,Ordering::SeqCst); if let Some(w)=wire.write_wake.lock().unwrap().take() {w.wake();} }
fn negotiation() -> Vec<u8> { let mut v=vec![0xc0,0xfa,0xce,0xca,0xfe,8]; v.extend_from_slice(&[1;8]);v.push(8);v.extend_from_slice(&[2;8]);v.resize(1200,0);v }
async fn healthy(f:&Fixture)->(Connection,Connection) {
 let c=f.client.connect(f.server.local_addr().unwrap(),"localhost").unwrap();
 let accept=async{f.server.accept().await.unwrap().await.unwrap()};
 let(c,s)=timeout(Duration::from_secs(5),async{tokio::join!(c,accept)}).await.unwrap();(c.unwrap(),s)
}
pub(super) async fn run() {
 for (items,bytes) in [(2,2*65536),(4,2*65536)] {
  for mode in 0..3 {
   let f=fixture(items,bytes,false).await;
   let wire_before=f.outgoing.delivered.load(Ordering::SeqCst);
   f.outgoing.write_blocked.store(true,Ordering::SeqCst);
   let mut attempts=Vec::new();
   for _ in 0..9 {
    if mode==0 {inject(&f.incoming,negotiation());}
    else {
     attempts.push(f.client.connect(f.server.local_addr().unwrap(),"localhost").unwrap());
     let incoming=timeout(Duration::from_secs(5),f.server.accept()).await.unwrap().unwrap();
     if mode==1 {incoming.retry().unwrap();} else {incoming.refuse();}
    }
   }
   until(||f.sender.stats().full==7 && f.sender.ownership().1==1).await;
   let full=f.sender.stats();
   assert_eq!((full.items,full.bytes,full.metadata_bytes,full.allocations),(2,2*65536,2*512,2));
   assert_eq!(f.sender.ownership(),(1,1,1));
   assert!(f.outgoing.send_attempts.load(Ordering::SeqCst)>0,"actual sender reached blocked socket");
   assert_eq!(f.server.open_connections(),0);
   assert_eq!(f.runtime.spawned.load(Ordering::SeqCst),2,"exactly one endpoint driver plus one sender, independent of response count");
   drop(attempts);
   writable(&f.outgoing);
   until(||f.sender.stats().items==0).await;
   assert_eq!(f.outgoing.delivered.load(Ordering::SeqCst)-wire_before,2,"exactly the reserved response capacity reaches the wire after unblock");
   timeout(Duration::from_secs(5),f.client.wait_idle()).await.unwrap();
   loop {
       let mut accept=std::pin::pin!(f.server.accept());
       match std::future::poll_fn(|cx| Poll::Ready(accept.as_mut().poll(cx))).await {
           Poll::Ready(Some(incoming))=>incoming.ignore(),
           _=>break,
       }
   }
   let(c,s)=healthy(&f).await;
   assert_eq!(f.server.open_connections(),1);
   drop((c,s));
   f.server.close(0u32.into(),b"cancel");
   timeout(Duration::from_secs(5),f.sender.join()).await.unwrap();
   let full_before=f.sender.stats().full;
   inject(&f.incoming,negotiation());until(||f.sender.stats().closed==1).await;
   assert_eq!(f.sender.stats().full,full_before,"drain-time suppression is closed, not full");
   assert_eq!(f.sender.ownership(),(0,0,0));assert_eq!(f.sender.stats().bytes,0);
  }
 }
 // Oversize is rejected at the actual negotiation producer before slab allocation.
 let f=fixture(2,2*65536,true).await;
 inject(&f.incoming,negotiation());until(||f.sender.stats().oversize==1).await;
 assert_eq!((f.sender.stats().items,f.sender.stats().bytes,f.sender.stats().allocations),(0,0,0));
 assert_eq!(f.server.open_connections(),0);f.server.close(0u32.into(),b"oversize");
 timeout(Duration::from_secs(5),f.sender.join()).await.unwrap();
 // Dropping the endpoint cancels the independent sender, with a send still blocked.
 let f=fixture(2,2*65536,false).await;
 f.outgoing.write_blocked.store(true,Ordering::SeqCst);inject(&f.incoming,negotiation());
 until(||f.sender.ownership().1==1).await;
 let sender=f.sender.clone();drop(f.server);
 timeout(Duration::from_secs(5),sender.join()).await.unwrap();
 assert_eq!(sender.ownership(),(0,0,0));assert_eq!(sender.stats().bytes,0);
 // A full protocol arena still uses the independent response pool for refusal.
 let f=fixture(2,2*65536,false).await;
 let mut peers=Vec::new();for _ in 0..4 { peers.push(healthy(&f).await); }
 f.outgoing.write_blocked.store(true,Ordering::SeqCst);
 let mut attempts=Vec::new();
 for _ in 0..9 {
  attempts.push(f.client.connect(f.server.local_addr().unwrap(),"localhost").unwrap());
  let incoming=timeout(Duration::from_secs(5),f.server.accept()).await.unwrap().unwrap();
  assert!(matches!(incoming.accept(),Err(ConnectionError::ApplicationClosed(_))));
 }
 until(||f.sender.stats().full==7 && f.sender.ownership().1==1).await;
 assert_eq!(f.server.open_connections(),4);assert_eq!(f.sender.stats().allocations,2);
 assert_eq!(f.runtime.spawned.load(Ordering::SeqCst),6);
 assert!(peers.iter().all(|(c,s)|c.close_reason().is_none() && s.close_reason().is_none()),"response suppression cannot close the admitted peer");
 f.sender.cancel();timeout(Duration::from_secs(5),f.sender.join()).await.unwrap();
 assert_eq!(f.sender.ownership(),(0,0,0));assert_eq!(f.sender.stats().items,0);
 drop((attempts,peers));
}

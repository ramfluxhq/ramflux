// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A group command queued during receive survives a failing background projection.
use super::*;

struct PublicationFault {
    inner: Gateway,
    root: PathBuf,
    entered: Option<oneshot::Sender<()>>,
    release: Arc<tokio::sync::Notify>,
}
fn fault_client(root: &Path) -> Result<RamfluxClient, SdkError> {
    let mut client = RamfluxClient::new();
    let root_seed = ramflux_crypto::blake3_256("ramflux.test.account.root.v1", b"alice");
    client.create_identity_root("alice", root_seed);
    client.create_device_branch("alice", "device-alice", 1, [0x62; 32]);
    client.open_account_index(root)?;
    client.unlock_account("alice", b"actor-test-secret")?;
    Ok(client)
}
impl GatewaySessionFrameSink for PublicationFault {
    fn send_frame<'a>(&'a mut self, frame: &'a [u8]) -> GatewaySessionFrameFuture<'a, ()> {
        self.inner.send_frame(frame)
    }
    fn finish(&mut self) -> Result<(), TransportError> {
        self.inner.finish()
    }
}
impl GatewaySessionFrameSource for PublicationFault {
    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async move {
            if matches!(self.inner.last, Some(GatewayClientFrame::Resume { .. }))
                && let Some(entered) = self.entered.take()
            {
                let _ = entered.send(());
                self.release.notified().await;
                // A durable group-message projection failure must not end the account thread.
                let client = fault_client(&self.root)
                    .map_err(|error| TransportError::Quic(error.to_string()))?;
                client
                    .account_db()
                    .and_then(|db| {
                        db.persist_actor_state(
                            "routed/message-metadata/corrupt-group-msg",
                            &serde_json::json!({"kind":"invalid_group_route"}),
                        )?;
                        client.send_direct_message(
                            "group-thread",
                            "corrupt-group-msg",
                            "device-alice",
                            b"opaque",
                        )?;
                        Ok(())
                    })
                    .map_err(|error| TransportError::Quic(error.to_string()))?;
            }
            self.inner.recv_frame().await
        })
    }
}
#[tokio::test(flavor = "current_thread")]
async fn group_command_queued_during_receive_gets_a_typed_error_without_stopping_the_actor()
-> Result<(), SdkError> {
    LocalSet::new().run_until(async {
        let root = root("group-actor-error");
        let (entered, receiving) = oneshot::channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let fixture_root = root.clone();
        let fixture_release = release.clone();
        let initialize: AccountInitializer = Box::new(move |index| {
            let mut account = account_with_counter(&fixture_root,"alice",None,
                Arc::new(AtomicBool::new(false)),Arc::new(AtomicUsize::new(0)),Some(index))?;
            let config = account.gateway_config.clone();
            account.put_engine(GatewaySessionEngine::with_test_transport(config,
                Box::new(PublicationFault {
                    inner:Gateway {last:None,pending_cursor:None,blocked:None,
                        cancelled:Arc::new(AtomicBool::new(false)),submits:Arc::new(AtomicUsize::new(0)),
                        cancelled_notice:None},
                    root:fixture_root,entered:Some(entered),release:fixture_release,
                })));
            Ok(account)
        });
        let supervisor = supervisor(&root,BTreeMap::from([("alice".into(),initialize)]))?;
        let (bus,server) = client(Rc::clone(&supervisor),1).await?;
        bus.request_frame(request("create","alice","group.create",serde_json::json!({
            "group_id":"group","conversation_id":"group-thread","creator_id":"device-alice","name":"Checklist"
        }))).await?;
        tokio::time::timeout(Duration::from_secs(5),receiving).await
            .map_err(|_|failure("background group receive did not start"))?
            .map_err(|_|failure("receive fixture stopped"))?;
        let queued = tokio::task::spawn_local(async move {
            let response=bus.request_frame_structured(request("add","alice","group.member.add",
                serde_json::json!({"group_id":"group","member_id":"unknown","role":"member"}))).await;
            (bus,response)
        });
        tokio::task::yield_now().await;
        release.notify_one();
        let (bus,result)=tokio::time::timeout(Duration::from_secs(10),queued).await
            .map_err(|_|failure("queued group operation hung"))?
            .map_err(|_|failure("queued group operation panicked"))?;
        let error=result.err().ok_or_else(||failure("invalid group add succeeded"))?;
        assert!(matches!(&error,SdkError::LocalBusRefused {code,..} if code=="ValidationFailed"),"{error}");
        assert!(!error.to_string().contains("account actor stopped"),"{error}");
        assert!(supervisor.account_actor("alice").is_some_and(|actor|!actor.has_stopped()));
        fault_client(&root)?.account_db()?.remove_actor_state("routed/message-metadata/corrupt-group-msg")?;
        let renamed=bus.request_frame(request("rename","alice","group.name.set",
            serde_json::json!({"group_id":"group","name":"Still alive"}))).await?;
        assert_eq!(renamed["name"],"Still alive");
        drop(bus);
        server.await.map_err(|_|failure("connection panicked"))??;
        supervisor.shutdown().await?;
        drop(supervisor);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }).await
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A group command queued during receive survives a failing background projection.
use super::*;

struct PublicationFault {
    inner: Gateway,
    entered: Option<oneshot::Sender<()>>,
    injected: Option<oneshot::Sender<()>>,
    release: Arc<tokio::sync::Notify>,
    root: PathBuf,
    alice: native_actor::Side,
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
    fn recv_idle_frame(&mut self) -> ramflux_transport::GatewaySessionFrameFuture<'_, Vec<u8>> {
        ramflux_transport::GatewaySessionFrameSource::recv_idle_frame(&mut self.inner)
    }

    fn recv_frame(&mut self) -> GatewaySessionFrameFuture<'_, Vec<u8>> {
        Box::pin(async move {
            if matches!(self.inner.last, Some(GatewayClientFrame::Resume { .. }))
                && let Some(entered) = self.entered.take()
            {
                let _ = entered.send(());
                self.release.notified().await;
                // A durable group-message projection failure must not end the account thread.
                let client = native_actor::second_client(&self.root, &self.alice)
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
                if let Some(injected) = self.injected.take() {
                    let _ = injected.send(());
                }
            }
            self.inner.recv_frame().await
        })
    }
}
#[tokio::test(flavor = "current_thread")]
async fn group_command_queued_during_receive_gets_a_typed_error_without_stopping_the_actor()
-> Result<(), SdkError> {
    Box::pin(LocalSet::new().run_until(Box::pin(async {
        let pair = native_actor::pair().await.map_err(|error| failure(&format!("native pair: {error}")))?;
        let root = pair.data_root.clone();
        let (entered, receiving) = oneshot::channel();
        let (injected, faulted) = oneshot::channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let initialize = pair.alice.initializer(&root, &pair.bob.manifest, PublicationFault {
            inner: native_actor::gateway(None, Arc::new(AtomicBool::new(false)), Arc::default(), None),
            entered: Some(entered), injected: Some(injected), release: Arc::clone(&release),
            root: root.clone(), alice: pair.alice.clone(),
        });
        let supervisor = supervisor(&root,BTreeMap::from([("alice".into(),initialize)]))?;
        let (bus,server) = client(Rc::clone(&supervisor),1).await?;
        bus.request_frame(request("create","alice","group.create",serde_json::json!({
            "group_id":"group","conversation_id":"group-thread","creator_id":"device-alice","name":"Checklist"
        }))).await.map_err(|error|failure(&format!("initial group create: {error}")))?;
        tokio::time::timeout(HANG,receiving).await
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
        tokio::time::timeout(HANG,faulted).await
            .map_err(|_|failure("receive fault was not inserted"))?
            .map_err(|_|failure("receive fault injection stopped"))?;
        // The queued invalid command may finish before receive is released. This valid
        // mutation proves the injected publication error has actually been observed.
        let publication=bus.request_frame_structured(request("fault-observed","alice","group.name.set",
            serde_json::json!({"group_id":"group","name":"Publication fault"}))).await;
        let error=publication.err().ok_or_else(||failure("injected publication unexpectedly succeeded"))?;
        assert!(matches!(&error,SdkError::LocalBusRefused {code,..} if code=="ValidationFailed"),"{error}");
        assert!(!error.to_string().contains("account actor stopped"),"{error}");
        assert!(supervisor.account_actor("alice").is_some_and(|actor|!actor.has_stopped()));
        native_actor::second_client(&root, &pair.alice)?.account_db()?.remove_actor_state("routed/message-metadata/corrupt-group-msg")
            .map_err(|error|failure(&format!("remove injected metadata: {error}")))?;
        let renamed=bus.request_frame(request("rename","alice","group.name.set",
            serde_json::json!({"group_id":"group","name":"Still alive"}))).await
            .map_err(|error|failure(&format!("rename after clearing injection: {error}")))?;
        assert_eq!(renamed["name"],"Still alive");
        drop(bus);
        server.await.map_err(|_|failure("connection panicked"))??;
        supervisor.shutdown().await?;
        drop(supervisor);
        Ok(())
    }))).await
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real relay and recipient staging: a delayed Offer cannot outlive its private bus call.
#[cfg(test)]
mod tests {
    use super::super::*;
    use ramflux_protocol::custody::pairing::relay::*;
    type Reply<T> = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<T, SdkError>> + std::marker::Send>,
    >;
    struct Registered(std::path::PathBuf, String);
    impl Drop for Registered {
        fn drop(&mut self) {
            let _ = remove_actor(&self.0, &self.1);
        }
    }
    struct ObservedPoll {
        inner: Arc<dyn PairingTransport>,
        first: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    }
    impl PairingTransport for ObservedPoll {
        fn claim(&self, origin: String, request: Claim) -> Reply<Claimed> {
            self.inner.claim(origin, request)
        }
        fn send(&self, origin: String, request: Send) -> Reply<Sent> {
            self.inner.send(origin, request)
        }
        fn close(&self, origin: String, request: Close) -> Reply<Closed> {
            self.inner.close(origin, request)
        }
        fn poll(&self, origin: String, request: Poll) -> Reply<Polled> {
            let pending = self.inner.poll(origin, request);
            let first = self.first.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
            Box::pin(async move {
                let response = pending.await?;
                if let Some(first) = first {
                    assert!(response.frames.is_empty(), "test: source Offer was not delayed");
                    let _ = first.send(());
                }
                Ok(response)
            })
        }
    }
    #[tokio::test(start_paused = true)]
    async fn pairing_attended_join_waits_for_actual_staging_after_delayed_offer() -> TestResult {
        let hold = ClockHold::new();
        let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
        hold.finish().await?;
        result
    }
    async fn run() -> TestResult {
        let mut rig = Box::pin(Rig::open()).await?;
        let begun = rig
            .primary
            .begin(Begin {
                schema: "ramflux.pairing.Begin.v2".into(),
                version: 2,
                capabilities: vec!["message".into(), "register".into(), "sync".into()],
                lease_not_before: rig.now,
                lease_expires_at: rig.now + 86_400,
                display_name: "Phone".into(),
            })
            .await?;
        let Outcome::Begin { value } = begun.outcome else {
            return Err("test: delayed-Offer source invitation missing".into());
        };
        let (first, polled) = tokio::sync::oneshot::channel();
        rig.secondary.wrap_transport_for_test(|inner| {
            Arc::new(ObservedPoll { inner, first: Mutex::new(Some(first)) })
        });
        let root = rig.participant_b.root.clone();
        let id = rig.participant_b.account_id.clone();
        install_actor(&root, id.clone(), rig.secondary)?;
        let _registered = Registered(root.clone(), id.clone());
        let join = handle_bus(
            &root,
            &id,
            "device.pair.join",
            serde_json::to_value(Join {
                schema: "ramflux.pairing.Join.v2".into(),
                version: 2,
                token: value.invite_token,
                display_name: "Web secondary".into(),
            })?,
        );
        tokio::pin!(join);
        tokio::select! {
            result = &mut join => return Err(format!("test: private join returned before Offer/staging: {result:?}").into()),
            result = polled => result.map_err(|_| "test: first empty relay poll not observed")?,
        }
        assert!(
            rig.participant_b.db.lock().map_err(|_| "test: B owner")?.is_none(),
            "test: recipient staged without an Offer"
        );
        rig.clock.advance_ms(1001);
        rig.primary.sync_relay().await?;
        rig.clock.advance_ms(1001);
        tokio::time::advance(std::time::Duration::from_millis(500)).await;
        let result = join.await;
        let stage_exists =
            rig.participant_b.db.lock().map_err(|_| "test: staged B owner")?.is_some();
        remove_actor_and_drain(&root, &id).await?;
        result?;
        assert!(stage_exists, "test: attended bus join returned before actual credential staging");
        rig.primary.lock().await?;
        Ok(())
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Runtime expiry failures preserve command replies, sync work and event attribution.
use super::*;
use crate::client::native_test_support::{Fixture, TestResult};
use serde_json::json;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use tokio::sync::oneshot;

type Reply = oneshot::Receiver<Result<super::super::actor::ActorResponse, SdkError>>;

struct Harness {
    runtime: AccountRuntime,
    commands: mpsc::Sender<AccountCommand>,
    stop: watch::Sender<bool>,
    observed: Rc<RefCell<Vec<LocalBusFrame>>>,
    reject: Rc<Cell<usize>>,
    failures: Rc<Cell<usize>>,
    delay: Rc<Cell<Duration>>,
    _root: crate::custody::tests::Root,
}

fn networking(frame: &LocalBusFrame) -> bool {
    frame.body["table_name"] == "runtime_actor_state"
        && frame.body["keys"]["state_kind"] == "account/networking"
}

// Hold admission outside the expiry window so only expiry publication changes the cause.
struct HeldAdmission;
impl super::super::connection_manager::SessionConnector for HeldAdmission {
    fn connect(
        &self,
        _config: GatewaySessionConfig,
        _deadline: tokio::time::Instant,
    ) -> super::super::connection_manager::SessionFuture<'_, GatewaySessionEngine> {
        Box::pin(std::future::pending())
    }
}

impl Harness {
    async fn new() -> TestResult<Self> {
        let fixture = Fixture::new("expiry-runtime").await?;
        let mut account = LocalBusAccountState::disconnected(
            fixture.client,
            fixture.config,
            fixture.manifest.principal_commitment,
        );
        super::super::native_account::record_networking_at(
            &mut account,
            Some(&SdkError::CustodyNetwork(ramflux_protocol::custody::CustodyRefusal::Capacity)),
            crate::custody::network_now()?,
        )?;
        account.connection = Some(super::super::connection_manager::ConnectionHandle::start_with(
            account.gateway_config.clone(),
            None,
            super::super::runtime_limits::RuntimeTimeouts::held_for_test(),
            Arc::new(HeldAdmission),
            None,
        ));
        let (commands, receiver) = mpsc::channel(8);
        let (stop, shutdown) = watch::channel(false);
        let (events, mut batches) = mpsc::channel::<EventBatch>(8);
        let observed = Rc::new(RefCell::new(Vec::new()));
        let reject = Rc::new(Cell::new(0_usize));
        let failures = Rc::new(Cell::new(0_usize));
        let delay = Rc::new(Cell::new(Duration::ZERO));
        let publish_delay = delay.clone();
        let (frames, remaining, failed) = (observed.clone(), reject.clone(), failures.clone());
        tokio::task::spawn_local(async move {
            while let Some(batch) = batches.recv().await {
                // Drop the real router acknowledgement, leaving its channel open for retries.
                let is_networking = batch.events.iter().any(networking);
                frames.borrow_mut().extend(batch.events);
                if remaining.get() > 0 && is_networking {
                    remaining.set(remaining.get() - 1);
                    failed.set(failed.get() + 1);
                    continue;
                }
                tokio::time::sleep(publish_delay.get()).await;
                let _ = batch.accepted.send(());
            }
        });
        let (connection_sender, connection_work) = mpsc::channel(2);
        let (lifecycle_sender, lifecycle) = mpsc::channel(4);
        let (preempt_sender, preempt) = watch::channel(0);
        let mut control_shutdown = shutdown.clone();
        tokio::task::spawn_local(async move {
            let _signals = (lifecycle_sender, preempt_sender);
            let _ = control_shutdown.changed().await;
        });
        let runtime = AccountRuntime {
            timeouts: super::super::runtime_limits::RuntimeTimeouts::default(),
            lifecycle,
            preempt,
            connection_sender,
            connection_work,
            transfers: super::uploads::Transfers::start(),
            id: "expiry-runtime".into(),
            state: LocalBusDaemonState {
                account_index: None,
                config: LocalBusConfig::new(fixture.root.0.join("bus.sock"), &fixture.root.0),
                nodes: crate::node::NodeStore::default(),
                accounts: BTreeMap::from([("expiry-runtime".into(), account)]),
                active_account_id: None,
                attended_accounts: BTreeSet::new(),
                subscribers: BTreeMap::new(),
            },
            receiver,
            readers: Arc::new(RoutingMutex::new(None)),
            events,
            shutdown,
            courier: None,
            networking_expiry_pending: None,
            networking_expiry_warned: false,
            networking_observation_warned: false,
            courier_events: None,
        };
        runtime.publish(&runtime.networking_expiry_request()).await?;
        observed.borrow_mut().clear();
        Ok(Self { runtime, commands, stop, observed, reject, failures, delay, _root: fixture.root })
    }

    fn account(&self) -> TestResult<&LocalBusAccountState> {
        self.runtime.state.accounts.get("expiry-runtime").ok_or_else(|| "account missing".into())
    }
}

async fn queue(commands: &mpsc::Sender<AccountCommand>, id: &str) -> TestResult<Reply> {
    let (reply, response) = oneshot::channel();
    let (outbound, _) = mpsc::channel(1);
    commands
        .send(AccountCommand {
            admission: None,
            private: None,
            request: LocalBusFrame::request(
                id,
                Some("expiry-runtime".into()),
                "account",
                "account.status",
                json!({}),
            ),
            connection_id: 1,
            topics: BTreeSet::new(),
            attended: true,
            nodes: None,
            outbound,
            reply: Some(reply),
        })
        .await?;
    Ok(response)
}

#[tokio::test(start_paused = true)]
async fn custody_expiry_publish_failure_replies_and_keeps_actor_open() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut h = Harness::new().await?;
            h.reject.set(1);
            tokio::time::advance(Duration::from_secs(300)).await;
            let first = queue(&h.commands, "unrelated-first").await?;
            let commands = h.commands.clone();
            let stop = h.stop.clone();
            let failures = h.failures.clone();
            let observed = h.observed.clone();
            let (ready, _) = std::sync::mpsc::sync_channel(1);
            let actor = tokio::task::spawn_local(async move {
                let result = h.runtime.serve(ready).await;
                h.runtime.stop_courier().await;
                h.runtime.stop_connection().await;
                h.runtime.close_readers().await;
                result
            });
            let response = first.await??;
            assert!(response.body["networking_reason"].is_null());
            assert_eq!(failures.get(), 1, "the expiry publication must actually fail");
            let second = queue(&commands, "unrelated-second").await?;
            assert!(second.await??.body["networking_reason"].is_null());
            let frames: Vec<_> =
                observed.borrow().iter().filter(|f| networking(f)).cloned().collect();
            assert_eq!(frames.len(), 1, "the expiry must be journaled exactly once");
            assert_eq!(frames[0].request_id, "networking-expiry", "even a retry is runtime work");
            stop.send(true)?;
            actor.await??;
            Ok(())
        }))
        .await
}

#[tokio::test(start_paused = true)]
async fn custody_expiry_publish_failure_does_not_skip_sync() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut h = Harness::new().await?;
            h.reject.set(1);
            tokio::time::advance(Duration::from_secs(300)).await;
            let _ = h.runtime.sync().await?;
            assert_eq!(h.failures.get(), 1, "the expiry publication must actually fail");
            assert_eq!(
                h.account()?.client.account_db()?.load_actor_state::<u64>("sync/tick")?,
                Some(1),
                "the sync driver must complete its pass after an expiry publication error"
            );
            assert!(
                h.observed
                    .borrow()
                    .iter()
                    .filter(|f| networking(f))
                    .all(|f| f.request_id == "networking-expiry")
            );
            h.runtime.stop_courier().await;
            h.runtime.stop_connection().await;
            Ok(())
        }))
        .await
}

#[tokio::test(start_paused = true)]
async fn custody_background_tick_publishes_expiry_without_a_command() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut h = Harness::new().await?;
            let reader = h.account()?.client.account_db()?.open_reader()?;
            let since = reader.journal_bounds()?.head_seq;
            let observed = h.observed.clone();
            let stop = h.stop.clone();
            let (ready, started) = std::sync::mpsc::sync_channel(1);
            let actor = tokio::task::spawn_local(async move {
                let result = h.runtime.serve(ready).await;
                h.runtime.stop_courier().await;
                h.runtime.stop_connection().await;
                h.runtime.close_readers().await;
                result
            });
            tokio::task::yield_now().await;
            started.try_recv()?;
            tokio::time::advance(Duration::from_secs(300)).await;
            for _ in 0..1000 {
                if observed
                    .borrow()
                    .iter()
                    .any(|f| networking(f) && f.request_id == "networking-expiry")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
            let frames: Vec<_> = observed
                .borrow()
                .iter()
                .filter(|f| networking(f) && f.request_id == "networking-expiry")
                .cloned()
                .collect();
            assert_eq!(
                frames.len(),
                1,
                "a background tick must publish the expired view without commands"
            );
            assert_eq!(frames[0].request_id, "networking-expiry");
            let clears = || -> TestResult<usize> {
                Ok(reader
                    .journal_after(since, 1024)?
                    .iter()
                    .filter(|event| {
                        event.topic == "account.networking.changed"
                            && event.body["networking_reason"].is_null()
                    })
                    .count())
            };
            assert_eq!(clears()?, 1, "the background tick must journal the end of the block");
            tokio::time::advance(Duration::from_secs(10)).await;
            for _ in 0..100 {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                observed
                    .borrow()
                    .iter()
                    .filter(|f| networking(f) && f.request_id == "networking-expiry")
                    .count(),
                1
            );
            assert_eq!(clears()?, 1, "subsequent ticks must not duplicate the expiry");
            stop.send(true)?;
            actor.await??;
            Ok(())
        }))
        .await
}

#[derive(Clone, Default)]
struct ExpiryWarnings(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl tracing::Subscriber for ExpiryWarnings {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Message(bool);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 =
                        format!("{value:?}").contains("networking expiry publication deferred");
                }
            }
        }
        let mut message = Message(false);
        event.record(&mut message);
        if *event.metadata().level() == tracing::Level::WARN && message.0 {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test(start_paused = true)]
async fn custody_expiry_publication_failure_warning_episode_resets_after_recovery() -> TestResult {
    // Isolate tracing callsite caches from the other SDK tests.
    if std::env::var_os("RAMFLUX_EXPIRY_PUBLICATION_LOG_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "bus::account_runtime::expiry_tests::custody_expiry_publication_failure_warning_episode_resets_after_recovery", "--nocapture"])
            .env("RAMFLUX_EXPIRY_PUBLICATION_LOG_CHILD", "1")
            .output()?;
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    let warnings = ExpiryWarnings::default();
    tracing::subscriber::set_global_default(warnings.clone())?;
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut h = Harness::new().await?;
            let blocked = h
                .account()?
                .client
                .account_db()?
                .load_actor_state::<serde_json::Value>("account/networking")?
                .ok_or("blocked view")?;
            h.reject.set(2);
            tokio::time::advance(Duration::from_secs(300)).await;
            h.runtime.refresh_networking_expiry().await;
            assert!(h.runtime.networking_expiry_warned);
            // Force another publication failure in the same warning episode.
            h.account()?
                .client
                .account_db()?
                .persist_actor_state("account/networking", &blocked)?;
            h.runtime.refresh_networking_expiry().await;
            assert!(h.runtime.networking_expiry_warned);
            assert_eq!(h.failures.get(), 2);
            assert_eq!(
                warnings.0.load(std::sync::atomic::Ordering::Relaxed),
                1,
                "consecutive publication failures must warn only once"
            );
            h.runtime.refresh_networking_expiry().await;
            assert!(!h.runtime.networking_expiry_warned);
            assert!(h.runtime.networking_expiry_pending.is_none());
            h.reject.set(1);
            h.account()?
                .client
                .account_db()?
                .persist_actor_state("account/networking", &blocked)?;
            h.runtime.refresh_networking_expiry().await;
            assert_eq!(
                warnings.0.load(std::sync::atomic::Ordering::Relaxed),
                2,
                "a new failure episode may warn after recovery"
            );
            Ok(())
        }))
        .await
}

#[tokio::test(start_paused = true)]
async fn custody_expiry_retry_attributes_only_the_expiry_entry() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            for retry_drain in [false, true] {
                let mut h = Harness::new().await?;
                h.reject.set(1);
                tokio::time::advance(Duration::from_secs(300)).await;
                h.runtime.refresh_networking_expiry().await;
                assert_eq!(h.failures.get(), 1);
                let expiry_sequence = h.runtime.networking_expiry_pending.ok_or("expiry")?;
                let account =
                    h.runtime.state.accounts.get_mut("expiry-runtime").ok_or("account")?;
                super::super::native_account::record_networking_at(
                    account,
                    Some(&SdkError::CustodyNetwork(
                        ramflux_protocol::custody::CustodyRefusal::Busy,
                    )),
                    crate::custody::network_now()?,
                )?;
                let busy_sequence = account
                    .client
                    .account_db()?
                    .pending_actor_state_sequence("account/networking")?
                    .ok_or("busy")?;
                assert_ne!(expiry_sequence, busy_sequence);
                let request = LocalBusFrame::request(
                    "new-attempt",
                    Some("expiry-runtime".into()),
                    "account",
                    "account.status",
                    json!({}),
                );
                // The failed expiry publication retains its marker while the
                // later Busy row awaits its first drain.
                if retry_drain {
                    assert!(h.runtime.publish_networking_expiry().await?);
                } else {
                    h.runtime.publish(&request).await?;
                }
                let frames = h.observed.borrow();
                assert_eq!(
                    frames
                        .iter()
                        .find(|f| f.frame_id == format!("outbox_{expiry_sequence}"))
                        .ok_or("expiry frame")?
                        .request_id,
                    "networking-expiry"
                );
                assert_eq!(
                    frames
                        .iter()
                        .find(|f| f.frame_id == format!("outbox_{busy_sequence}"))
                        .ok_or("busy frame")?
                        .request_id,
                    if retry_drain { "sync" } else { "new-attempt" }
                );
            }
            Ok(())
        }))
        .await
}

#[tokio::test(start_paused = true)]
async fn custody_expiry_successful_noop_resets_warning_latch() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut h = Harness::new().await?;
            h.reject.set(1);
            tokio::time::advance(Duration::from_secs(300)).await;
            h.runtime.refresh_networking_expiry().await;
            assert_eq!(h.failures.get(), 1);
            assert!(h.runtime.networking_expiry_warned);
            // Complete publication first, then let a no-op refresh observe recovery.
            assert!(h.runtime.publish_networking_expiry().await?);
            assert!(h.runtime.networking_expiry_warned);
            assert!(!h.runtime.publish_networking_expiry().await?);
            h.runtime.refresh_networking_expiry().await;
            assert!(!h.runtime.networking_expiry_warned);
            Ok(())
        }))
        .await
}

#[tokio::test(start_paused = true)]
async fn custody_expiry_tick_stays_within_sync_deadline() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut h = Harness::new().await?;
            tokio::time::advance(Duration::from_secs(300)).await;
            h.delay.set(Duration::from_secs(30));
            let start = tokio::time::Instant::now();
            let result = h.runtime.sync().await;
            assert!(matches!(result, Err(SdkError::LocalBus(ref message))
            if message == "background sync deadline exceeded"));
            assert!(
                tokio::time::Instant::now() - start
                    <= Duration::from_secs(20) + Duration::from_millis(1),
                "expiry publication escaped the sync deadline"
            );
            assert!(
                h.runtime.networking_expiry_pending.is_some(),
                "cancelled publish must remain retryable"
            );
            assert!(h.observed.borrow().iter().any(networking), "expiry publish must be reached");
            h.delay.set(Duration::ZERO);
            h.runtime.refresh_networking_expiry().await;
            assert!(h.runtime.networking_expiry_pending.is_none());
            Ok(())
        }))
        .await
}

#[tokio::test]
async fn observation_persistence_failure_keeps_actor_open_and_allows_retry() -> TestResult {
    LocalSet::new()
        .run_until(Box::pin(async {
            let mut h = Harness::new().await?;
            let db = h
                .runtime
                .state
                .accounts
                .get_mut("expiry-runtime")
                .ok_or("account")?
                .client
                .active_account_db
                .take()
                .ok_or("db")?;
            for _ in 0..2 {
                h.runtime
                    .apply_connection_work(
                        super::super::connection_manager::AccountWork::Observation {
                            event:
                                super::super::connection_manager::ConnectionEvent::Disconnected {
                                    reason:
                                        super::super::connection_manager::DisconnectReason::Stop,
                                    generation: 0,
                                },
                        },
                    )
                    .await?;
                assert!(h.runtime.networking_observation_warned);
            }
            h.runtime
                .state
                .accounts
                .get_mut("expiry-runtime")
                .ok_or("account")?
                .client
                .active_account_db = Some(db);
            h.runtime
                .apply_connection_work(super::super::connection_manager::AccountWork::Observation {
                    event: super::super::connection_manager::ConnectionEvent::Disconnected {
                        reason: super::super::connection_manager::DisconnectReason::Stop,
                        generation: 0,
                    },
                })
                .await?;
            let saved = h
                .account()?
                .client
                .account_db()?
                .load_actor_state::<serde_json::Value>("account/networking")?
                .ok_or("snapshot")?;
            assert!(saved.get("session").is_some());
            assert!(!h.runtime.networking_observation_warned, "recovery re-arms warning");
            h.runtime
                .state
                .accounts
                .get_mut("expiry-runtime")
                .ok_or("account")?
                .client
                .active_account_db = None;
            h.runtime
                .apply_connection_work(super::super::connection_manager::AccountWork::Observation {
                    event: super::super::connection_manager::ConnectionEvent::Disconnected {
                        reason: super::super::connection_manager::DisconnectReason::Stop,
                        generation: 0,
                    },
                })
                .await?;
            assert!(h.runtime.networking_observation_warned, "a new outage warns again");
            h.runtime.stop_connection().await;
            Ok(())
        }))
        .await
}

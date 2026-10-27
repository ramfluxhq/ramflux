// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One supervised retry worker resumes durable seals and stops before runtime teardown returns.
use std::{
    sync::{Arc, Condvar, Mutex, Weak},
    thread::JoinHandle,
    time::Duration,
};
pub(crate) struct MigrationCourier {
    stopped: Arc<(Mutex<bool>, Condvar)>,
    worker: Option<JoinHandle<()>>,
}
impl Drop for MigrationCourier {
    fn drop(&mut self) {
        let (stopped, changed) = &*self.stopped;
        *stopped.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        changed.notify_all();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl MigrationCourier {
    pub(crate) fn start(
        service: Weak<ramflux_node_core::CustodyService>,
        store: Weak<ramflux_node_core::RouterRedbStore>,
    ) -> std::io::Result<Self> {
        let stopped = Arc::new((Mutex::new(false), Condvar::new()));
        let control = stopped.clone();
        let worker =
            std::thread::Builder::new().name("home-migration-courier".into()).spawn(move || {
                loop {
                    let (stopped, changed) = &*control;
                    if *stopped.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
                        break;
                    }
                    let (Some(service), Some(store)) = (service.upgrade(), store.upgrade()) else {
                        break;
                    };
                    if let Err(error) = service.home_migration_tick(
                        &store,
                        ramflux_node_core::now_unix_seconds(),
                        16,
                    ) {
                        tracing::warn!(error = %error, "home migration retry work unavailable");
                    }
                    drop((service, store));
                    let guard = stopped.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    if *guard {
                        break;
                    }
                    drop(
                        changed
                            .wait_timeout(guard, Duration::from_millis(250))
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                    );
                }
            })?;
        Ok(Self { stopped, worker: Some(worker) })
    }
}

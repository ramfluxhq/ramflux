// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Typed synchronous checkpoints on the account writer; no task owns database state.

use crate::SdkError;
use crate::bus::connection_manager::AccountWork;
use crate::prelude::LocalBusAccountState;
use tokio::sync::{mpsc, oneshot};

type LocalStep = Box<dyn FnOnce(&mut LocalBusAccountState) + Send>;
pub(crate) struct Checkpoint {
    pub generation: u64,
    step: LocalStep,
}
impl Checkpoint {
    pub(crate) fn apply(self, account: &mut LocalBusAccountState) {
        (self.step)(account);
    }
}
#[derive(Clone)]
pub(crate) struct Writer {
    sender: mpsc::Sender<AccountWork>,
    generation: u64,
    #[cfg(test)]
    source_reads: bool,
}
impl Writer {
    pub(crate) fn new(sender: mpsc::Sender<AccountWork>, generation: u64) -> Self {
        Self {
            sender,
            generation,
            #[cfg(test)]
            source_reads: false,
        }
    }
    #[cfg(test)]
    pub(crate) fn source_reads(&self) -> Self {
        Self { source_reads: true, ..self.clone() }
    }

    pub(crate) async fn fatal(&self, error: SdkError) {
        let _ = self.sender.send(AccountWork::Fatal { generation: self.generation, error }).await;
    }
    pub(crate) async fn apply<T: Send + 'static>(
        &self,
        step: impl FnOnce(&mut LocalBusAccountState) -> Result<T, SdkError> + Send + 'static,
    ) -> Result<T, SdkError> {
        if super::super::connection_manager::session_host::priority_exchange_active() {
            return Err(SdkError::PriorityWriterAccess);
        }
        let (reply, response) = oneshot::channel();
        #[cfg(test)]
        let source_reads = self.source_reads;
        let step = Box::new(move |account: &mut LocalBusAccountState| {
            #[cfg(test)]
            let _source_scope = source_reads
                .then(|| {
                    account
                        .client
                        .account_db()
                        .ok()
                        .and_then(ramflux_storage::AccountDb::observe_source_reads)
                })
                .flatten();
            if !reply.is_closed() {
                let _ = reply.send(step(account));
            }
        });
        self.sender
            .send(AccountWork::Courier(Checkpoint { generation: self.generation, step }))
            .await
            .map_err(|_| stopped())?;
        response.await.map_err(|_| stopped())?
    }
}
fn stopped() -> SdkError {
    ramflux_transport::TransportError::ShutdownDraining.into()
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One bounded username flight per account. The writer owns journals and verified observations;
//! the network task owns only its captured connection inputs and signed public documents.
use super::AccountRuntime;
use crate::{
    SdkError,
    bus::{
        actor::{AccountCommand, ActorResponse},
        username_directory as adapter,
    },
};
use tokio::{
    sync::oneshot,
    task::JoinHandle,
    time::{Duration, Instant},
};
type Reply = oneshot::Sender<Result<ActorResponse, SdkError>>;
pub(super) struct Completion {
    prepared: adapter::Prepared,
    result: Result<crate::username_directory::UsernameNetworkReply, SdkError>,
    caller: Option<(AccountCommand, Reply)>,
}
pub(super) struct Calls {
    transport: crate::username_directory::UsernameConnection,
    task: Option<JoinHandle<Completion>>,
    background: bool,
    next: Instant,
    backoff: Duration,
}
impl Default for Calls {
    fn default() -> Self {
        Self {
            transport: crate::username_directory::UsernameConnection::default(),
            task: None,
            background: false,
            next: Instant::now() + Duration::from_secs(1),
            backoff: Duration::from_secs(1),
        }
    }
}
impl Drop for Calls {
    fn drop(&mut self) {
        self.transport.clear();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Calls {
    pub(super) async fn receive(&mut self) -> Option<Completion> {
        let outcome = match self.task.as_mut() {
            Some(task) => task.await,
            None => return std::future::pending().await,
        };
        self.task.take();
        outcome.ok()
    }
    pub(super) fn deadline(&self) -> Option<Instant> {
        self.task.is_none().then_some(self.next)
    }
    pub(super) async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        self.transport.clear();
    }
    fn spawn(
        &mut self,
        mut prepared: adapter::Prepared,
        caller: Option<(AccountCommand, Reply)>,
        deadline: Instant,
    ) {
        self.background = caller.is_none();
        prepared.transport = self.transport.clone();
        self.task = Some(tokio::spawn(async move {
            // Leave the writer a bounded reply margin before the caller's absolute fence.
            let exchange_deadline =
                deadline.checked_sub(Duration::from_secs(1)).unwrap_or(deadline);
            let result =
                tokio::time::timeout_at(exchange_deadline, prepared.exchange(exchange_deadline))
                    .await
                    .map_err(|_| SdkError::NetworkingPending)
                    .and_then(std::convert::identity);
            Completion { prepared, result, caller }
        }));
    }
}
impl AccountRuntime {
    pub(super) async fn start_username(&mut self, command: AccountCommand, reply: Reply) {
        if self.username.background && self.username.task.is_some() {
            self.username.stop().await;
        }
        if self.username.task.is_some() {
            let _ = reply.send(Err(
                ramflux_protocol::username_directory::DirectoryCode::OperationPending.into(),
            ));
            return;
        }
        match adapter::prepare(&command.request, &self.state) {
            Ok(prepared) => {
                let deadline = command.admission.as_ref().map_or_else(
                    || Instant::now() + self.timeouts.command,
                    |admission| admission.command_deadline,
                );
                self.username.spawn(prepared, Some((command, reply)), deadline);
            }
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
    }
    pub(super) fn start_username_delivery(&mut self) {
        self.username.next = Instant::now() + self.username.backoff;
        if self.username.task.is_some() {
            return;
        }
        match adapter::delivery_status(&self.state, &self.id) {
            Ok(Some(prepared)) => {
                self.username.spawn(prepared, None, Instant::now() + self.timeouts.command);
            }
            Ok(None) => self.username.next = Instant::now() + Duration::from_secs(60),
            Err(error) => {
                tracing::debug!(
                    error_code = crate::prelude::local_bus_error_code(&error),
                    "username delivery deferred"
                );
                self.username.backoff = (self.username.backoff * 2).min(Duration::from_secs(60));
            }
        }
    }
    pub(super) async fn finish_username(
        &mut self,
        completion: Completion,
    ) -> Result<bool, SdkError> {
        let Completion { prepared, result, caller } = completion;
        let result = match result {
            Ok(result) => {
                let deadline = caller
                    .as_ref()
                    .and_then(|(command, _)| command.admission.as_ref())
                    .map_or_else(
                        || Instant::now() + self.timeouts.command,
                        |admission| admission.command_deadline,
                    );
                let mut shutdown = self.shutdown.clone();
                let mut preempt = self.preempt.clone();
                let apply = super::super::command_admission::COMMAND_CONTEXT.scope(
                    deadline,
                    tokio::time::timeout_at(
                        deadline,
                        adapter::apply(&mut self.state, &self.id, prepared, result),
                    ),
                );
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => return Ok(true),
                    _ = preempt.changed() => {
                        if let Some((_, reply)) = caller { let _ = reply.send(Err(SdkError::NetworkingPending)); }
                        return Ok(false);
                    },
                    result = apply => result.map_err(|_| super::super::command_admission::unavailable("username apply deadline expired")).and_then(std::convert::identity),
                }
            }
            Err(error) => Err(error),
        };
        self.username.backoff = if result.is_ok() {
            Duration::from_secs(1)
        } else {
            (self.username.backoff * 2).min(Duration::from_secs(60))
        };
        self.username.next = Instant::now() + self.username.backoff;
        if let Some((command, reply)) = caller {
            let result = result.and_then(|result| {
                if let Some(account) = self.state.accounts.get(&self.id) {
                    super::super::read_model::capture(
                        account,
                        &command.request,
                        &result.response_body,
                    )?;
                }
                Ok(ActorResponse { body: result.response_body, events: Vec::new(), nodes: None })
            });
            self.complete_command(&command, result, reply).await
        } else {
            if let Ok(result) = result {
                match adapter::delivery_retry(&self.state, &self.id, &result.response_body) {
                    Ok(Some(prepared)) => {
                        self.username.spawn(prepared, None, Instant::now() + self.timeouts.command);
                    }
                    Ok(None) => self.username.next = Instant::now() + Duration::from_secs(60),
                    Err(error) => tracing::debug!(
                        error_code = crate::prelude::local_bus_error_code(&error),
                        "username retry refused"
                    ),
                }
            }
            Ok(false)
        }
    }
}

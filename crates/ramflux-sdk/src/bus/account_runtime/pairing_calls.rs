// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One attended pairing courier. Preparation/input never occupy the account command loop.
use super::{AccountRuntime, stopped};
use crate::{
    SdkError,
    bus::actor::{AccountCommand, ActorResponse},
};
use tokio::{sync::oneshot, task::JoinHandle};
type Reply = oneshot::Sender<Result<ActorResponse, SdkError>>;
pub(super) struct Completion {
    command: AccountCommand,
    reply: Reply,
    result: Result<ActorResponse, SdkError>,
}
#[derive(Default)]
pub(super) struct Calls {
    task: Option<JoinHandle<Completion>>,
    stop: Option<oneshot::Sender<()>>,
}
impl Drop for Calls {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Calls {
    pub(super) fn busy(&self, method: &str) -> bool {
        self.task.is_some()
            && (method.starts_with("device.transfer.") || method.starts_with("device.pair."))
    }
    pub(super) async fn receive(&mut self) -> Option<Completion> {
        let outcome = match self.task.as_mut() {
            Some(task) => task.await,
            None => return std::future::pending().await,
        };
        self.task.take();
        self.stop.take();
        outcome.ok()
    }
    pub(super) async fn stop(&mut self) {
        // Await private worker drain before dropping the actual ordinary data owner,
        // including an account-loop error that did not originate from lifecycle work.
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if self.task.is_some()
            && let Some(completion) = self.receive().await
        {
            let _ = completion.reply.send(Err(stopped()));
        }
    }
}
impl AccountRuntime {
    pub(super) async fn start_pairing_begin(&mut self, command: AccountCommand, reply: Reply) {
        if self.pairing.task.is_some() {
            let _ = reply.send(Err(SdkError::PairingCode("Busy")));
            return;
        }
        let staged = match self.prepare_pairing_owner(&command).await {
            Ok(staged) => staged,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        let root = self.state.config.data_root.clone();
        let account = self.id.clone();
        let mut shutdown = self.shutdown.clone();
        let mut preempt = self.preempt.clone();
        let (stop, mut stopped_call) = oneshot::channel();
        self.pairing.stop = Some(stop);
        self.pairing.task = Some(tokio::spawn(async move {
            let mut reply = reply;
            let mut cancelled = false;
            let result = {
                let work = async {
                    if let Some(staged) = &staged {
                        staged.install().await?;
                    }
                    crate::custody::pairing::handle_bus(
                        &root,
                        &account,
                        &command.request.method,
                        command.request.body.clone(),
                    )
                    .await
                };
                tokio::pin!(work);
                tokio::select! {
                    biased;
                    _=&mut stopped_call=>{cancelled=true;Err(stopped())},
                    _=shutdown.changed()=>{cancelled=true;Err(stopped())},
                    _=preempt.changed()=>{cancelled=true;Err(stopped())},
                    ()=reply.closed()=>{cancelled=true;Err(stopped())},
                    result=&mut work=>result.and_then(|result|Ok(ActorResponse {body:serde_json::to_value(result)?,events:Vec::new(),nodes:None})),
                }
            };
            if let Some(staged) = &staged {
                staged.drain(cancelled || result.is_err()).await;
            }
            if cancelled {
                let _ = crate::custody::pairing::remove_actor_and_drain(&root, &account).await;
            }
            Completion { command, reply, result }
        }));
    }
    async fn prepare_pairing_owner(
        &self,
        command: &AccountCommand,
    ) -> Result<Option<crate::bus::pairing::StagedResume>, SdkError> {
        let staged =
            crate::bus::pairing::capture_staged_resume(&self.state, &self.id, &command.request)?;
        if staged.is_none() {
            crate::bus::pairing::ensure_actor(&self.state, &self.id, &command.request).await?;
        }
        Ok(staged)
    }
    pub(super) async fn finish_pairing_begin(
        &mut self,
        completion: Completion,
    ) -> Result<bool, SdkError> {
        let Completion { command, reply, result } = completion;
        if let Some(account) = self.state.accounts.get_mut(&self.id) {
            super::super::pairing::refresh_source_role(account)?;
            if let Ok(response) = &result {
                super::super::read_model::capture(account, &command.request, &response.body)?;
            }
        }
        self.complete_command(&command, result, reply).await
    }
}

#[cfg(test)]
mod tests;

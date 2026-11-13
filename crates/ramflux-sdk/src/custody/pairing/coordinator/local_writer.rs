// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded synchronous local work serviced by the frontend's actual account writer.
use super::{PairingActor, SdkError, full::cancel::FullRuntimeCancel};
use ramflux_storage::{AccountDb, AccountIndex, FullLocalUnlockGuard};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
fn retired() -> SdkError {
    SdkError::PairingCode("Retired")
}
trait Request: Send {
    fn reject(self: Box<Self>, error: SdkError);
    fn apply(self: Box<Self>, db: &AccountDb);
}
struct Work<F, R> {
    action: F,
    reply: oneshot::Sender<Result<R, SdkError>>,
}
impl<F, R> Request for Work<F, R>
where
    F: FnOnce(&AccountDb) -> Result<R, SdkError> + Send + 'static,
    R: Send + 'static,
{
    fn reject(self: Box<Self>, error: SdkError) {
        let _ = self.reply.send(Err(error));
    }
    fn apply(self: Box<Self>, db: &AccountDb) {
        if !self.reply.is_closed() {
            let _ = self.reply.send((self.action)(db));
        }
    }
}
struct Envelope {
    request: Box<dyn Request>,
    _permit: OwnedSemaphorePermit,
}
struct Scope {
    root: PathBuf,
    account: String,
    anchor: String,
    path: PathBuf,
    unlock: FullLocalUnlockGuard,
    runtime: Arc<FullRuntimeCancel>,
    work: Arc<tokio::sync::Notify>,
}
impl Scope {
    fn live(&self) -> Result<(), SdkError> {
        self.runtime.require_live()?;
        self.unlock.require_unlocked()?;
        Ok(())
    }
    fn require_db(&self, db: &AccountDb) -> Result<(), SdkError> {
        self.live()?;
        let selected = AccountIndex::open(&self.root)?.account(&self.account)?;
        if db.local_account_id != self.account
            || std::fs::canonicalize(db.account_index_root())? != self.root
            || selected.principal_commitment != self.anchor
            || std::fs::canonicalize(&db.path)? != self.path
            || self.path != std::fs::canonicalize(self.root.join(selected.db_relative_path))?
            || selected.account_state == "removed"
        {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(super) struct LocalWriterPort {
    scope: Arc<Scope>,
    sender: mpsc::Sender<Envelope>,
    admission: Arc<Semaphore>,
}
/// No account database or key is retained. Keep this service with the ordinary
/// account owner and call it between async operations using its actual selected writer.
/// Dropping it closes pending replies; abandoned requests cannot execute local work.
pub struct PairingLocalWriterService {
    scope: Arc<Scope>,
    receiver: mpsc::Receiver<Envelope>,
}
impl PairingLocalWriterService {
    pub(super) fn require_actor(
        &self,
        root: &std::path::Path,
        actor: &PairingActor,
    ) -> Result<(), SdkError> {
        self.scope.live()?;
        if std::fs::canonicalize(root)? != self.scope.root
            || actor.identity.account_id != self.scope.account
            || !Arc::ptr_eq(&actor.full_runtime, &self.scope.runtime)
            || actor.local_writer.as_ref().is_none_or(|port| !Arc::ptr_eq(&port.scope, &self.scope))
        {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        Ok(())
    }
    /// Wake the ordinary account loop without borrowing its writer or polling a timer.
    #[must_use]
    pub fn work_signal(&self) -> Arc<tokio::sync::Notify> {
        self.scope.work.clone()
    }
    /// Execute at most one synchronous local action and release its writer borrow.
    /// Local actions must never perform relay/native I/O or retain the borrowed writer.
    /// # Errors
    /// Refuses lock/removal, a foreign/replaced writer or a retired account generation.
    pub fn try_apply(&mut self, db: &AccountDb) -> Result<bool, SdkError> {
        let Ok(envelope) = self.receiver.try_recv() else {
            return Ok(false);
        };
        if let Err(error) = self.scope.require_db(db) {
            envelope.request.reject(error);
            return Ok(true);
        }
        let _local = self.scope.runtime.local_work()?;
        envelope.request.apply(db);
        Ok(true)
    }
}
impl LocalWriterPort {
    fn require_participant(
        &self,
        participant: &crate::custody::pairing::LocalPairingParticipant,
    ) -> Result<(), SdkError> {
        self.scope.live()?;
        if participant.account_id != self.scope.account
            || std::fs::canonicalize(&participant.root)? != self.scope.root
        {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        Ok(())
    }
    pub(super) fn sign_manifest(
        &self,
        participant: &crate::custody::pairing::LocalPairingParticipant,
        request: &crate::custody::pairing::FullSourceManifestSigningRequest<'_>,
    ) -> Result<String, SdkError> {
        self.require_participant(participant)?;
        let _local = self.scope.runtime.local_work()?;
        let signed = participant.sign_full_source_manifest_off_loan(request, &self.scope.unlock)?;
        self.scope.live()?;
        Ok(signed)
    }
    pub(super) fn sign_grant(
        &self,
        participant: &crate::custody::pairing::LocalPairingParticipant,
        request: &crate::custody::pairing::FullGrantSigningRequest<'_>,
    ) -> Result<String, SdkError> {
        self.require_participant(participant)?;
        let _local = self.scope.runtime.local_work()?;
        let signed = participant.sign_full_grant_off_loan(request, &self.scope.unlock)?;
        self.scope.live()?;
        Ok(signed)
    }
    pub(super) async fn request<R: Send + 'static>(
        &self,
        action: impl FnOnce(&AccountDb) -> Result<R, SdkError> + Send + 'static,
    ) -> Result<R, SdkError> {
        self.scope.live()?;
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| SdkError::PairingCode("Busy"))?;
        let (reply, receive) = oneshot::channel();
        let envelope = Envelope { request: Box::new(Work { action, reply }), _permit: permit };
        self.sender.try_send(envelope).map_err(|_| retired())?;
        self.scope.work.notify_one();
        let result = tokio::select! {
            biased;
            ()=self.scope.runtime.cancelled()=>return Err(retired()),
            result=tokio::time::timeout(std::time::Duration::from_secs(10),receive)=>{
                result.map_err(|_|SdkError::PairingCode("Busy"))?.map_err(|_|retired())?
            }
        };
        self.scope.live()?;
        result
    }
}
impl PairingActor {
    /// Bind short local requests to this frontend's actual selected writer. This
    /// retains weak unlock liveness only; the service contains no database or key.
    /// Attach before installing/starting the actor and service it in the account owner.
    /// # Errors
    /// Refuses an existing binding/ceremony or a foreign/locked account writer.
    pub fn bind_frontend_writer(
        &mut self,
        db: &AccountDb,
    ) -> Result<PairingLocalWriterService, SdkError> {
        self.require_open()?;
        if self.local_writer.is_some() || self.ceremony.is_some() {
            return Err(SdkError::PairingCode("Busy"));
        }
        self.bind_selected_writer(db, Arc::new(tokio::sync::Notify::new()))
    }
    pub(super) fn bind_installed_frontend_writer(
        &mut self,
        db: &AccountDb,
        signal: Arc<tokio::sync::Notify>,
    ) -> Result<PairingLocalWriterService, SdkError> {
        self.require_open()?;
        if self.local_writer.is_some() || !self.full_new_recipient_installed() {
            return Err(SdkError::PairingCode("WrongContext"));
        }
        self.bind_selected_writer(db, signal)
    }
    fn bind_selected_writer(
        &mut self,
        db: &AccountDb,
        signal: Arc<tokio::sync::Notify>,
    ) -> Result<PairingLocalWriterService, SdkError> {
        let participant = self.participant.as_ref().ok_or(SdkError::PairingCode("WrongContext"))?;
        let scope = Arc::new(Scope {
            root: std::fs::canonicalize(&participant.root)?,
            account: self.identity.account_id.clone(),
            anchor: self.identity.local_ref.account_anchor.clone(),
            path: std::fs::canonicalize(&db.path)?,
            unlock: db.full_local_unlock_guard()?,
            runtime: self.full_runtime.clone(),
            work: signal,
        });
        scope.require_db(db)?;
        let (sender, receiver) = mpsc::channel(1);
        self.local_writer = Some(LocalWriterPort {
            scope: scope.clone(),
            sender,
            admission: Arc::new(Semaphore::new(1)),
        });
        Ok(PairingLocalWriterService { scope, receiver })
    }
}

#[cfg(test)]
mod tests;

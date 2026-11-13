// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Root-scoped frontend ownership. Account names alone cannot select another store's actor.
use super::{PairingActor, PairingNative, SdkError};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

type Key = (PathBuf, String);
fn key(root: &Path, account: &str) -> Result<Key, SdkError> {
    Ok((std::fs::canonicalize(root)?, account.into()))
}
pub(super) struct Entry {
    pub(super) actor: tokio::sync::Mutex<PairingActor>,
    cancelled: AtomicBool,
    native: Option<Arc<dyn PairingNative>>,
    credential_provider: Option<Arc<dyn crate::custody::pairing::LocalCredentialProvider>>,
    full_runtime: Arc<super::full::cancel::FullRuntimeCancel>,
    work: Arc<tokio::sync::Notify>,
    writer: Option<Mutex<super::PairingLocalWriterService>>,
    pump: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl Entry {
    pub(super) fn require_live(&self) -> Result<(), SdkError> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(SdkError::PairingCode("Retired"))
        } else {
            Ok(())
        }
    }
}
fn actors() -> &'static Mutex<HashMap<Key, Arc<Entry>>> {
    static ACTORS: OnceLock<Mutex<HashMap<Key, Arc<Entry>>>> = OnceLock::new();
    ACTORS.get_or_init(|| Mutex::new(HashMap::new()))
}
/// Install one owner without replacing a live frontend. Root aliases resolve to the same slot.
/// # Errors
/// Refuses a foreign account/root, an existing owner or an unavailable root.
pub fn install_actor(root: &Path, account_id: String, actor: PairingActor) -> Result<(), SdkError> {
    install_actor_with_writer(root, account_id, actor, None)
}

/// Install a short local service without transferring the actual account writer.
pub(crate) fn install_actor_with_writer(
    root: &Path,
    account_id: String,
    actor: PairingActor,
    writer: Option<super::PairingLocalWriterService>,
) -> Result<(), SdkError> {
    actor.require_open()?;
    if let Some(writer) = &writer {
        writer.require_actor(root, &actor)?;
    }
    let key = (std::fs::canonicalize(root)?, account_id);
    if actor.identity.account_id != key.1
        || actor.participant.as_ref().is_some_and(|participant| {
            std::fs::canonicalize(&participant.root).ok().as_ref() != Some(&key.0)
        })
    {
        return Err(SdkError::PairingCode("WrongContext"));
    }
    let mut owners = actors().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if owners.contains_key(&key) {
        return Err(SdkError::PairingCode("Busy"));
    }
    let native = actor.native.clone();
    let credential_provider =
        actor.participant.as_ref().map(|participant| participant.provider.clone());
    let full_runtime = actor.full_runtime.clone();
    let entry = Arc::new(Entry {
        actor: tokio::sync::Mutex::new(actor),
        native,
        credential_provider,
        full_runtime,
        cancelled: AtomicBool::new(false),
        work: writer
            .as_ref()
            .map(super::PairingLocalWriterService::work_signal)
            .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new())),
        writer: writer.map(Mutex::new),
        pump: Mutex::new(None),
    });
    owners.insert(key, entry.clone());
    drop(owners);
    // Pure synchronous SDK callers may drive their actor explicitly. The bus installs
    // within its account runtime and always owns this separate relay-only pump.
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        let owner = Arc::downgrade(&entry);
        let task = runtime.spawn(async move {
            while let Some(entry) = owner.upgrade() {
                if entry.require_live().is_err() {
                    break;
                }
                {
                    let mut actor = entry.actor.lock().await;
                    if entry.require_live().is_err() {
                        break;
                    }
                    let progress =
                        actor.sync_relay().await.and_then(|_| actor.service_staged_full_target());
                    if let Err(error) = progress {
                        actor.note_background_error(&error);
                    }
                    if actor.candidate_control_ready()
                        && let Err(error) = actor.poll_full_management_control().await
                    {
                        actor.note_background_error(&error);
                    }
                }
                entry.work.notify_one();
                drop(entry);
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });
        *entry.pump.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
    }
    Ok(())
}
/// Fence callbacks and close the proof connection immediately on owner lock/disconnect.
/// An already submitted head remains journaled for reconciliation.
/// # Errors
/// Returns root lookup errors. Missing owners are already removed.
pub fn remove_actor(root: &Path, account_id: &str) -> Result<(), SdkError> {
    drop(remove_entry(root, account_id)?);
    Ok(())
}
/// Fence first, then erase the actor and join even detached blocking/epoch work before
/// ordinary account lock completes. Saved data-only/uncertain-publication rows remain.
/// # Errors
/// Returns root lookup errors. Missing owners are already retired.
pub async fn remove_actor_and_drain(root: &Path, account_id: &str) -> Result<(), SdkError> {
    if let Some(entry) = remove_entry(root, account_id)? {
        let pump = entry.pump.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(pump) = pump {
            pump.abort();
            let _ = pump.await;
        }
        entry.actor.lock().await.retire_owned_runtime().await;
    }
    Ok(())
}
fn remove_entry(root: &Path, account_id: &str) -> Result<Option<Arc<Entry>>, SdkError> {
    let key = match key(root, account_id) {
        Ok(key) => key,
        Err(SdkError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let entry = actors().lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&key);
    if let Some(entry) = &entry {
        crate::custody::pairing::cancel_credential(&key.0, account_id);
        if let Some(provider) = &entry.credential_provider {
            provider.cancel();
        }
        entry.cancelled.store(true, Ordering::Release);
        entry.full_runtime.stop();
        if let Some(pump) =
            entry.pump.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_ref()
        {
            pump.abort();
        }
        if let Some(native) = &entry.native {
            native.close();
        }
    }
    Ok(entry)
}

pub(crate) fn work_signal(root: &Path, account: &str) -> Option<Arc<tokio::sync::Notify>> {
    find(root, account).ok().map(|entry| entry.work.clone())
}
pub(crate) fn service_full_transfer(
    root: &Path,
    account: &str,
    db: &ramflux_storage::AccountDb,
) -> Result<bool, SdkError> {
    let entry = match find(root, account) {
        Ok(entry) => entry,
        Err(SdkError::PairingCode("NotFound")) => return Ok(false),
        Err(error) => return Err(error),
    };
    entry.require_live()?;
    let applied = match &entry.writer {
        Some(writer) => {
            writer.lock().map_err(|_| SdkError::PairingCode("Retired"))?.try_apply(db)?
        }
        None => false,
    };
    let Ok(mut actor) = entry.actor.try_lock() else { return Ok(applied) };
    actor.service_full_transfer(db).map(|progress| progress || applied)
}
#[cfg(test)]
pub(crate) async fn settle_actor_data_for_test(
    root: &Path,
    account: &str,
) -> Result<(bool, String), SdkError> {
    let entry = find(root, account)?;
    let actor = entry.actor.lock().await;
    actor.settle_full_local_jobs_for_test().await;
    let complete = actor.full_base_disk_complete_for_test();
    let ceremony = actor.ceremony.as_ref().ok_or(SdkError::PairingCode("NotFound"))?;
    Ok((
        complete,
        format!(
            "phase={} result={:?} a3={} packet={} stream={} disk={complete}",
            ceremony.phase,
            ceremony.result,
            actor.full_epoch_in_flight_for_test(),
            actor.full_epoch_ready_for_test(),
            actor.full_base_stream_started_for_test()
        ),
    ))
}
pub(super) fn find(root: &Path, account_id: &str) -> Result<Arc<Entry>, SdkError> {
    let key = key(root, account_id)?;
    actors()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
        .cloned()
        .ok_or(SdkError::PairingCode("NotFound"))
}

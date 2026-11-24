// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account access epochs shared by routing, transport delivery and native result polls.
use crate::SdkError;
use crate::platform::app_lock_clock::Deadline;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex, Weak},
};
use tokio::sync::RwLock;

static ROOTS: LazyLock<Mutex<BTreeMap<PathBuf, Weak<Fences>>>> = LazyLock::new(Mutex::default);

pub(crate) trait Observer: Send + Sync {
    fn locked(&self, account: &str);
}
#[derive(Clone, Default)]
pub(crate) struct Epoch {
    pub generation: u64,
    pub locked: bool,
    pub reason: &'static str,
    pub deadline: Option<Deadline>,
}
impl Epoch {
    pub(crate) fn blocks_access(&self) -> bool {
        self.locked || self.expired()
    }
    pub(crate) fn expired(&self) -> bool {
        self.deadline.as_ref().is_some_and(|deadline| deadline.remaining().is_zero())
    }
    pub(crate) fn remaining_ms(&self) -> u64 {
        self.deadline.as_ref().map_or(0, Deadline::remaining_ms)
    }
    pub(crate) fn state(&self) -> &'static str {
        if self.locked || self.expired() {
            "locked"
        } else if self.deadline.is_some() {
            "armed"
        } else {
            "unlocked"
        }
    }
}
#[derive(Default)]
struct State {
    accounts: BTreeMap<String, Epoch>,
    observers: Vec<Weak<dyn Observer>>,
}
#[derive(Default)]
pub(crate) struct Fences {
    state: Mutex<State>,
    pub delivery: Arc<RwLock<()>>,
}
#[derive(Clone)]
pub(crate) struct Token {
    owner: Arc<Fences>,
    account: Option<String>,
    epochs: BTreeMap<String, (u64, bool)>,
    redacted_view: bool,
}
impl Token {
    pub(crate) fn affects(&self, account: &str) -> bool {
        self.account.as_deref().is_none_or(|id| id == account)
    }
    pub(crate) fn check(&self) -> Result<(), SdkError> {
        self.with_current(|| ())
    }
    pub(crate) fn with_current<T>(&self, deliver: impl FnOnce() -> T) -> Result<T, SdkError> {
        let state = self.owner.state.lock().map_err(|_| locked())?;
        for (id, epoch) in &state.accounts {
            let (generation, was_locked) = self.epochs.get(id).copied().unwrap_or((0, false));
            if self.affects(id)
                && ((epoch.blocks_access() && (!self.redacted_view || !was_locked))
                    || generation != epoch.generation)
            {
                return Err(locked());
            }
        }
        Ok(deliver())
    }
}

impl Fences {
    pub(crate) fn for_root(root: &Path) -> Result<Arc<Self>, SdkError> {
        let root = std::fs::canonicalize(root)?;
        let mut roots = ROOTS.lock().map_err(|_| locked())?;
        roots.retain(|_, owner| owner.strong_count() != 0);
        if let Some(owner) = roots.get(&root).and_then(Weak::upgrade) {
            return Ok(owner);
        }
        let owner = Arc::new(Self::default());
        roots.insert(root, Arc::downgrade(&owner));
        Ok(owner)
    }
    #[cfg(feature = "c-abi")]
    pub(crate) fn serialize<T>(&self, deliver: impl FnOnce() -> T) -> Result<T, SdkError> {
        let state = self.state.lock().map_err(|_| locked())?;
        // Native polls can run before the timer task is scheduled. Erase retained results
        // and queued plaintext at the deadline, under the same delivery serialization.
        for (account, epoch) in &state.accounts {
            if epoch.expired() {
                for observer in state.observers.iter().filter_map(Weak::upgrade) {
                    observer.locked(account);
                }
            }
        }
        Ok(deliver())
    }
    #[cfg(feature = "c-abi")]
    pub(crate) fn observe(&self, observer: Weak<dyn Observer>) -> Result<(), SdkError> {
        self.state.lock().map_err(|_| locked())?.observers.push(observer);
        Ok(())
    }
    pub(crate) fn token(self: &Arc<Self>, account: Option<&str>) -> Result<Token, SdkError> {
        let state = self.state.lock().map_err(|_| locked())?;
        Ok(Token {
            owner: Arc::clone(self),
            account: account.map(str::to_owned),
            redacted_view: false,
            epochs: state
                .accounts
                .iter()
                .filter(|(id, _)| account.is_none_or(|account| account == id.as_str()))
                .map(|(id, epoch)| (id.clone(), (epoch.generation, epoch.blocks_access())))
                .collect(),
        })
    }
    pub(crate) fn for_method(
        self: &Arc<Self>,
        method: &str,
        account: Option<&str>,
    ) -> Result<Token, SdkError> {
        let mut token = self.token(scope(method, account))?;
        token.redacted_view = redacted_view(method);
        Ok(token)
    }
    pub(crate) fn any_locked(&self) -> Result<bool, SdkError> {
        Ok(self.state.lock().map_err(|_| locked())?.accounts.values().any(Epoch::blocks_access))
    }
    pub(crate) fn epoch(&self, account: &str) -> Result<Epoch, SdkError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| locked())?
            .accounts
            .get(account)
            .cloned()
            .unwrap_or_default())
    }
    pub(crate) fn initialize(
        &self,
        account: &str,
        policy: &ramflux_storage::AppLockPolicy,
    ) -> Result<(), SdkError> {
        let mut state = self.state.lock().map_err(|_| locked())?;
        let generation = match state.accounts.get(account) {
            Some(previous) => previous.generation.checked_add(1).ok_or_else(locked)?,
            None => policy.generation,
        };
        state.accounts.insert(
            account.into(),
            Epoch {
                generation,
                locked: policy.enabled,
                reason: if policy.enabled { "cold_start" } else { "authenticated" },
                deadline: None,
            },
        );
        if policy.enabled {
            for observer in state.observers.iter().filter_map(Weak::upgrade) {
                observer.locked(account);
            }
        }
        Ok(())
    }
    pub(crate) fn transition(
        &self,
        account: &str,
        enabled: bool,
        is_locked: bool,
        reason: &'static str,
    ) -> Result<Epoch, SdkError> {
        let mut state = self.state.lock().map_err(|_| locked())?;
        let epoch = state.accounts.entry(account.into()).or_default();
        epoch.generation = epoch.generation.checked_add(1).ok_or_else(locked)?;
        epoch.locked = is_locked && enabled;
        epoch.reason = reason;
        epoch.deadline = None;
        let result = epoch.clone();
        if is_locked {
            state.observers.retain(|observer| {
                if let Some(observer) = observer.upgrade() {
                    observer.locked(account);
                    true
                } else {
                    false
                }
            });
        }
        Ok(result)
    }
    pub(crate) fn deadline(
        &self,
        account: &str,
        deadline: Option<Deadline>,
    ) -> Result<(), SdkError> {
        let mut state = self.state.lock().map_err(|_| locked())?;
        if let Some(epoch) = state.accounts.get_mut(account)
            && !epoch.locked
        {
            if deadline.is_none() && epoch.expired() {
                return Err(locked());
            }
            epoch.deadline = deadline;
        }
        Ok(())
    }
    pub(crate) fn armed(&self) -> Result<Vec<(String, Epoch)>, SdkError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| locked())?
            .accounts
            .iter()
            .filter(|(_, epoch)| epoch.deadline.is_some())
            .map(|(id, epoch)| (id.clone(), epoch.clone()))
            .collect())
    }
}
pub(crate) fn redacted_view(method: &str) -> bool {
    matches!(method, "account.list" | "account.backup.jobs")
}
/// Global views do not become account-scoped when a caller adds an unused account identifier.
pub(crate) fn scope<'a>(method: &str, account: Option<&'a str>) -> Option<&'a str> {
    if matches!(
        method,
        "account.list"
            | "account.backup.jobs"
            | "account.backup.cancel"
            | "account.restore.verify"
            | "account.restore.install"
    ) {
        None
    } else {
        account
    }
}
pub(crate) fn control(method: &str) -> bool {
    matches!(
        method,
        "account.app_lock.configure"
            | "account.app_lock.lifecycle"
            | "account.app_lock.state"
            | "account.app_lock.lock"
            | "account.app_lock.unlock"
            | "account.unlock"
            | "account.lock"
            | "account.sign_out"
            | "device.credential.request"
            | "daemon.status"
            | "daemon.stop"
            | "subscription.close"
            | "account.app_lock.changed"
    )
}
pub(crate) fn locked() -> SdkError {
    SdkError::LocalBusRefused {
        code: "app_locked".into(),
        message: "account app lock is closed".into(),
        body: Box::new(serde_json::json!({"reason_code":"app_locked"})),
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process routing owns handles, never account business state or an I/O-spanning lock.

use super::actor::{AccountActor, AccountCommand, ActorResponse};
use super::events::EventBatch;
use crate::prelude::*;
use std::cell::RefCell;
use tokio::sync::oneshot;

pub(super) struct Supervisor {
    pub(super) config: LocalBusConfig,
    owner: RefCell<std::rc::Weak<Supervisor>>,
    pub(super) index: AccountIndex,
    nodes: RefCell<crate::node::NodeStore>,
    node_actor: AccountActor,
    pub(super) backup_jobs: super::backup_jobs::BackupJobs,
    pub(super) daemon_attended: RefCell<BTreeSet<u64>>,
    pub(super) installing: RefCell<BTreeSet<String>>,
    backup_expiry: RefCell<Option<tokio::task::JoinHandle<()>>>,
    accounts: RefCell<BTreeMap<String, AccountActor>>,
    subscribers: Rc<RefCell<BTreeMap<u64, LocalBusSubscriber>>>,
    events: mpsc::Sender<EventBatch>,
    event_receiver: RefCell<Option<mpsc::Receiver<EventBatch>>>,
    event_task: RefCell<Option<tokio::task::JoinHandle<()>>>,
    streams: RefCell<BTreeMap<u64, tokio::task::JoinHandle<()>>>,
    attended: RefCell<BTreeMap<u64, String>>,
    stop_requested: watch::Sender<bool>,
    stop_response: watch::Sender<bool>,
    stop_owner: RefCell<Option<(u64, String)>>,
}

impl Supervisor {
    pub(super) fn new(config: LocalBusConfig) -> Result<Rc<Self>, SdkError> {
        let nodes = crate::node::NodeStore::load(&config.data_root, &config.builtin_nodes)?;
        let (stop_requested, _) = watch::channel(false);
        let (stop_response, _) = watch::channel(false);
        let (events, event_receiver) = mpsc::channel::<EventBatch>(64);
        let index = AccountIndex::open(&config.data_root)?;
        let node_actor = AccountActor::start(
            String::new(),
            config.clone(),
            nodes.clone(),
            index.clone(),
            events.clone(),
        )?;
        let supervisor = Rc::new(Self {
            owner: RefCell::new(std::rc::Weak::new()),
            backup_jobs: super::backup_jobs::BackupJobs::new(&config.data_root, index.clone())?,
            daemon_attended: RefCell::new(BTreeSet::default()),
            installing: RefCell::new(BTreeSet::default()),
            backup_expiry: RefCell::new(None),
            config,
            index,
            stop_requested,
            stop_response,
            stop_owner: RefCell::new(None),
            events,
            event_receiver: RefCell::new(Some(event_receiver)),
            event_task: RefCell::new(None),
            nodes: RefCell::new(nodes),
            node_actor,
            accounts: RefCell::new(BTreeMap::new()),
            subscribers: Rc::new(RefCell::new(BTreeMap::new())),
            streams: RefCell::new(BTreeMap::new()),
            attended: RefCell::new(BTreeMap::new()),
        });
        *supervisor.owner.borrow_mut() = Rc::downgrade(&supervisor);
        Ok(supervisor)
    }

    #[cfg(test)]
    pub(super) fn from_initializers(
        config: &LocalBusConfig,
        accounts: Vec<(String, super::actor::AccountInitializer)>,
        active: Option<String>,
    ) -> Result<Rc<Self>, SdkError> {
        let supervisor = Self::new(config.clone())?;
        for (id, initialize) in accounts {
            let actor = AccountActor::start_loaded(
                id.clone(),
                config.clone(),
                supervisor.nodes.borrow().clone(),
                supervisor.index.clone(),
                supervisor.events.clone(),
                Some(initialize),
            )?;
            supervisor.accounts.borrow_mut().insert(id, actor);
        }
        if let Some(active) = active {
            supervisor.index.set_active_account(&active)?;
        }
        Ok(supervisor)
    }

    pub(super) fn hydrate(
        self: &Rc<Self>,
        tasks: &mut tokio::task::JoinSet<()>,
    ) -> Result<(), SdkError> {
        let directory = self.config.data_root.join("local_bus_accounts");
        let mut paths = self
            .index
            .known_account_ids()?
            .into_iter()
            .map(|id| local_bus_account_manifest_path(&self.config.data_root, &id))
            .collect::<BTreeSet<_>>();
        if directory.exists() {
            for entry in std::fs::read_dir(directory)? {
                let path = entry?.path();
                if path.extension().and_then(std::ffi::OsStr::to_str) == Some("json") {
                    paths.insert(path);
                }
            }
        }
        for path in paths {
            if let Some(id) = path.file_stem().and_then(std::ffi::OsStr::to_str)
                && crate::custody::account_exists(&self.config.data_root, id)?
            {
                continue;
            }
            let manifest = match read_local_bus_account_manifest(&path) {
                Ok(manifest) => manifest,
                Err(error) => {
                    tracing::warn!(%error, "skipping unreadable account manifest");
                    continue;
                }
            };
            if self
                .index
                .account(&manifest.local_account_id)
                .is_ok_and(|account| account.account_state == "locked")
            {
                continue;
            }
            let supervisor = Rc::clone(self);
            tasks.spawn_local(async move {
                let (outbound, _receiver) = mpsc::channel(1);
                let connection = LocalBusConnectionState::new(0, outbound);
                let request = LocalBusFrame::request(
                    "restore",
                    Some(manifest.local_account_id.clone()),
                    "account",
                    "account.unlock",
                    serde_json::json!({"passphrase":manifest.account_secret}),
                );
                let body = match supervisor.request(request.clone(), &connection).await {
                    Ok(_) => serde_json::json!({"state":"unlocked"}),
                    Err(error) => {
                        tracing::warn!(%error, "account restore failed");
                        serde_json::json!({"state":"failed", "error":local_bus_error(&request, &error).error})
                    }
                };
                supervisor.broadcast(&[local_bus_event(
                    &request,
                    &manifest.local_account_id,
                    "account",
                    "account.restore.finished",
                    body,
                )]);
            });
        }
        Ok(())
    }

    pub(super) async fn request(
        &self,
        mut request: LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<ActorResponse, SdkError> {
        if !super::lifecycle::handles(&request.method) {
            return self.route(request, connection).await;
        }
        if request.method == "account.backup.import" {
            request.account_id = Some(super::lifecycle::import_account_id(&request).await?);
        }
        if let Some(body) = super::custody_setup::guard_account(&self.config.data_root, &request)? {
            return Ok(reply(body));
        }
        let receipt =
            super::lifecycle::reserve(self.index.clone(), self.config.data_root.clone(), &request)
                .await?;
        if let Some(body) = receipt.as_ref().and_then(|receipt| receipt.cached.clone()) {
            return Ok(reply(body));
        }
        if receipt.is_some() {
            request.operation_id = None;
            if let Some(body) = request.body.as_object_mut() {
                body.remove("idempotency_key");
            }
        }
        let result = self.route(request, connection).await;
        if let (Some(receipt), Ok(response)) = (receipt, &result) {
            super::lifecycle::complete(self.index.clone(), receipt, response.body.clone()).await?;
        }
        result
    }

    fn ensure_request_allowed(&self, request: &LocalBusFrame) -> Result<(), SdkError> {
        if *self.stop_requested.borrow() && request.method != "daemon.stop" {
            return Err(SdkError::LocalBus("daemon is stopping".to_owned()));
        }
        if request.kind != LocalBusFrameKind::Request {
            return Err(SdkError::LocalBus("expected request frame".to_owned()));
        }
        Ok(())
    }
    async fn route(
        &self,
        mut request: LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<ActorResponse, SdkError> {
        self.start_event_router();
        self.ensure_request_allowed(&request)?;
        if let Some(body) = super::custody_setup::guard_account(&self.config.data_root, &request)? {
            return Ok(reply(body));
        }
        if crate::backup::BACKUP_JOB_METHODS.contains(&request.method.as_str()) {
            return self.backup_request(request, connection).await;
        }
        match request.method.as_str() {
            "account.list" => {
                return self.account_list().await;
            }
            "account.switch" => {
                let id = request_account_id(&request)?.to_owned();
                if !self.accounts.borrow().contains_key(&id) {
                    return Err(not_open(&id));
                }
                self.set_active(&id).await?;
                return Ok(reply(serde_json::json!({"active_account_id": id})));
            }
            "daemon.status" => {
                return Ok(reply(
                    serde_json::json!({"accounts": self.accounts.borrow().values().filter(|actor| actor.is_open()).count(), "socket_path": self.config.socket_path, "born_v3_creation":self.config.enable_born_v3_creation}),
                ));
            }
            "daemon.stop" => {
                if self.stop_owner.borrow().is_none() {
                    *self.stop_owner.borrow_mut() =
                        Some((connection.connection_id, request.request_id.clone()));
                    self.stop_requested.send_replace(true);
                }
                self.shutdown().await?;
                return Ok(reply(serde_json::json!({"stopping":true})));
            }
            _ => {}
        }
        if request.method.starts_with("node.")
            && (request.method != "node.probe" || request.account_id.is_none())
        {
            let mut response = self.node_actor.request(command(request, connection)).await?;
            if let Some(nodes) = response.nodes.take() {
                *self.nodes.borrow_mut() = nodes;
            }
            return Ok(response);
        }
        self.prepare_import(&mut request, connection).await?;
        let id = if request.method == "account.create" {
            request
                .body
                .get("local_account_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    SdkError::LocalBus("account.create requires local_account_id".to_owned())
                })?
                .to_owned()
        } else {
            request_account_id(&request)?.to_owned()
        };
        if self.installing.borrow().contains(&id) {
            return Err(super::backup_jobs::refusal("restore_install_in_progress"));
        }
        let actor = self.accounts.borrow().get(&id).cloned();
        let creating = matches!(
            request.method.as_str(),
            "account.create" | "account.unlock" | "account.backup.import"
        );
        let actor = if let Some(actor) = actor {
            actor
        } else if creating {
            let actor = AccountActor::start(
                id.clone(),
                self.config.clone(),
                self.nodes.borrow().clone(),
                self.index.clone(),
                self.events.clone(),
            )?;
            self.accounts.borrow_mut().insert(id.clone(), actor.clone());
            actor
        } else {
            return Err(not_open(&id));
        };
        let locking = request.method == "account.lock";
        let mut request = command(request, connection);
        request.attended = self.attended.borrow().values().any(|account| account == &id);
        request.nodes = Some(self.nodes.borrow().clone());
        let response = actor.request(request).await;
        if creating && response.is_ok() {
            self.set_active(&id).await?;
            self.set_unlocked(&id, true).await?;
        }
        if locking && response.is_ok() {
            actor.stop().await?;
            self.set_unlocked(&id, false).await?;
            self.accounts.borrow_mut().remove(&id);
            self.subscribers.borrow_mut().retain(|_, subscriber| subscriber.account_id != id);
            self.attended.borrow_mut().retain(|_, account| account != &id);
        }
        response
    }

    pub(super) async fn activate_native(
        &self,
        id: &str,
        passphrase: zeroize::Zeroizing<String>,
    ) -> Result<crate::LocalBusCreatedAccount, SdkError> {
        self.start_event_router();
        let existing = self.accounts.borrow().get(id).cloned();
        let actor = if let Some(actor) = existing {
            actor
        } else {
            let actor = AccountActor::start(
                id.into(),
                self.config.clone(),
                self.nodes.borrow().clone(),
                self.index.clone(),
                self.events.clone(),
            )?;
            self.accounts.borrow_mut().insert(id.into(), actor.clone());
            actor
        };
        let result = actor.unlock_native(passphrase).await?;
        self.set_active(id).await?;
        self.set_unlocked(id, true).await?;
        Ok(result)
    }

    async fn account_list(&self) -> Result<ActorResponse, SdkError> {
        let index = self.index.clone();
        let root = self.config.data_root.clone();
        let (active,known) = tokio::task::spawn_blocking(move || -> Result<_,SdkError> {
            let mut known=Vec::new();
            for id in index.known_account_ids()? {
                if crate::custody::account_exists(&root,&id)? { continue; }
                let path=local_bus_account_manifest_path(&root,&id);
                let manifest=super::daemon::account_manifest_available(&path).then(||read_local_bus_account_manifest(&path)).transpose()?;
                known.push(serde_json::json!({"id":id,"label":manifest.as_ref().and_then(|m|m.label.as_ref()),"kind":manifest.as_ref().and_then(|m|m.kind.as_ref()),"principal_id":manifest.as_ref().map(|m|&m.principal_id)}));
            }
            for mut account in crate::custody::list_accounts(&root,super::custody_setup::now()?)? {
                account["id"]=account["local_account_id"].clone();
                known.push(account);
            }
            Ok((index.active_account()?,known))
        })
            .await
            .map_err(|error| SdkError::LocalBus(format!("index reader failed: {error}")))??;
        let accounts = self
            .accounts
            .borrow()
            .iter()
            .filter(|(_, actor)| actor.is_open())
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        let active = active.filter(|id| accounts.contains(id));
        let mut known = known;
        for row in &mut known {
            if row["custody_v3_observed"].as_bool() == Some(true) {
                row["networking"] = row["state"].clone();
            }
            row["state"] = serde_json::json!(if row
                .get("id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|id| accounts.iter().any(|account| account == id))
            {
                "unlocked"
            } else {
                "locked"
            });
        }
        Ok(reply(
            serde_json::json!({"accounts":accounts, "account_details":known, "active_account_id":active}),
        ))
    }

    async fn prepare_import(
        &self,
        request: &mut LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<(), SdkError> {
        if request.method == "account.backup.import" {
            let id = request_account_id(request)?.to_owned();
            let old = self.accounts.borrow().get(&id).cloned();
            if let Some(actor) = old {
                let lock = LocalBusFrame::request(
                    "import-lock",
                    Some(id.clone()),
                    "account",
                    "account.lock",
                    serde_json::json!({}),
                );
                actor.request(command(lock, connection)).await?;
                actor.stop().await?;
                self.attended.borrow_mut().retain(|_, account| account != &id);
                self.subscribers.borrow_mut().retain(|_, subscriber| subscriber.account_id != id);
                self.accounts.borrow_mut().remove(&id);
            }
            request.account_id = Some(id);
        }
        Ok(())
    }

    async fn set_unlocked(&self, id: &str, unlocked: bool) -> Result<(), SdkError> {
        let index = self.index.clone();
        let id = id.to_owned();
        tokio::task::spawn_blocking(move || index.set_account_unlocked(&id, unlocked))
            .await
            .map_err(|error| SdkError::LocalBus(format!("index writer failed: {error}")))??;
        Ok(())
    }

    async fn set_active(&self, id: &str) -> Result<(), SdkError> {
        let index = self.index.clone();
        let id = id.to_owned();
        tokio::task::spawn_blocking(move || index.set_active_account(&id))
            .await
            .map_err(|error| SdkError::LocalBus(format!("index writer failed: {error}")))??;
        Ok(())
    }

    pub(super) fn owned_backup_handle(&self) -> Result<Rc<Self>, SdkError> {
        self.owner.borrow().upgrade().ok_or_else(|| SdkError::LocalBus("daemon stopped".into()))
    }
    pub(super) fn replace_backup_stream(&self, id: u64, task: tokio::task::JoinHandle<()>) {
        if let Some(previous) = self.streams.borrow_mut().insert(id, task) {
            previous.abort();
        }
    }
    pub(super) fn remove_backup_actor(&self, id: &str) {
        self.accounts.borrow_mut().remove(id);
    }
    pub(super) fn new_backup_actor(&self, id: &str) -> Result<AccountActor, SdkError> {
        let actor = AccountActor::start(
            id.into(),
            self.config.clone(),
            self.nodes.borrow().clone(),
            self.index.clone(),
            self.events.clone(),
        )?;
        self.accounts.borrow_mut().insert(id.into(), actor.clone());
        Ok(actor)
    }
    pub(super) fn account_actor(&self, id: &str) -> Option<AccountActor> {
        self.accounts.borrow().get(id).cloned()
    }

    pub(super) fn stop_requested(&self) -> watch::Receiver<bool> {
        self.stop_requested.subscribe()
    }
    pub(super) fn stop_response(&self) -> watch::Receiver<bool> {
        self.stop_response.subscribe()
    }
    pub(super) fn finish_stop_response(&self, connection: u64, request: &str) {
        if self
            .stop_owner
            .borrow()
            .as_ref()
            .is_some_and(|(owner, id)| *owner == connection && id == request)
        {
            self.stop_response.send_replace(true);
        }
    }

    pub(super) fn finish_stop_connection(&self, connection: u64) {
        if self.stop_owner.borrow().as_ref().is_some_and(|(owner, _)| *owner == connection) {
            self.stop_response.send_replace(true);
        }
    }

    pub(super) async fn shutdown(&self) -> Result<(), SdkError> {
        self.backup_jobs.stop().await;
        self.start_event_router();
        // A retained stopped handle must not reclaim a replacement daemon's staging.
        let expiry = self.backup_expiry.borrow_mut().take();
        if let Some(task) = expiry {
            task.abort();
            let _ = task.await;
        }
        let actors = self.accounts.borrow().values().cloned().collect::<Vec<_>>();
        let mut result = Ok(());
        for actor in actors {
            if let Err(error) = actor.stop().await {
                result = Err(error);
            }
        }
        if let Err(error) = self.node_actor.stop().await {
            result = Err(error);
        }
        result
    }

    pub(super) async fn subscribe_stream(
        &self,
        request: LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<(), SdkError> {
        self.start_event_router();
        if let Some(id) = &connection.attended_account_id {
            self.attended.borrow_mut().insert(connection.connection_id, id.clone());
        }
        if request.account_id.is_none() {
            return self.subscribe_backup_stream(request, connection).await;
        }
        let id = request_account_id(&request)?;
        let actor = self.accounts.borrow().get(id).cloned().ok_or_else(|| not_open(id))?;
        if let Some(task) = self.streams.borrow_mut().remove(&connection.connection_id) {
            task.abort();
        }
        if let Some(task) =
            super::subscription::start(actor.reader_pool()?, request, connection.outbound.clone())
                .await?
        {
            self.streams.borrow_mut().insert(connection.connection_id, task);
        }
        Ok(())
    }

    pub(super) fn subscribe(&self, connection: &LocalBusConnectionState, account_id: String) {
        if let Some(id) = &connection.attended_account_id {
            self.attended.borrow_mut().insert(connection.connection_id, id.clone());
        }
        self.subscribers.borrow_mut().insert(
            connection.connection_id,
            LocalBusSubscriber {
                account_id,
                topics: connection.topics.clone(),
                outbound: connection.outbound.clone(),
            },
        );
    }

    pub(super) fn disconnect(&self, id: u64) {
        if let Some(task) = self.streams.borrow_mut().remove(&id) {
            task.abort();
        }
        self.subscribers.borrow_mut().remove(&id);
        self.attended.borrow_mut().remove(&id);
        self.daemon_attended.borrow_mut().remove(&id);
    }

    pub(super) fn broadcast(&self, events: &[LocalBusFrame]) {
        super::events::broadcast(&mut self.subscribers.borrow_mut(), events);
    }

    #[cfg(test)]
    pub(super) fn start_test_event_router(&self) {
        self.start_event_router();
    }

    fn start_event_router(&self) {
        if self.backup_expiry.borrow().is_none() {
            let jobs = self.backup_jobs.clone();
            *self.backup_expiry.borrow_mut() = Some(tokio::task::spawn_local(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    jobs.expire();
                }
            }));
        }
        if let Some(mut receiver) = self.event_receiver.borrow_mut().take() {
            let subscribers = Rc::clone(&self.subscribers);
            *self.event_task.borrow_mut() = Some(tokio::task::spawn_local(async move {
                while let Some(batch) = receiver.recv().await {
                    super::events::broadcast(&mut subscribers.borrow_mut(), &batch.events);
                    let _ = batch.accepted.send(());
                }
            }));
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        if let Some(task) = self.backup_expiry.get_mut().take() {
            task.abort();
        }
        for (_, task) in std::mem::take(self.streams.get_mut()) {
            task.abort();
        }
        if let Some(task) = self.event_task.get_mut().take() {
            task.abort();
        }
    }
}

fn command(request: LocalBusFrame, connection: &LocalBusConnectionState) -> AccountCommand {
    let (reply, _) = oneshot::channel();
    AccountCommand {
        private: None,
        request,
        connection_id: connection.connection_id,
        topics: connection.topics.clone(),
        attended: connection.attended_account_id.is_some(),
        nodes: None,
        outbound: connection.outbound.clone(),
        reply: Some(reply),
    }
}

fn not_open(id: &str) -> SdkError {
    SdkError::AccountNotOpen(id.to_owned())
}
fn reply(body: serde_json::Value) -> ActorResponse {
    ActorResponse { body, events: Vec::new(), nodes: None }
}

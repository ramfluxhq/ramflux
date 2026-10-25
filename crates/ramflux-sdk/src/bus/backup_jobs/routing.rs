// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Human-only daemon job requests; installation quiesces only the affected account.
use super::service::refused;
use crate::bus::{
    actor::{AccountCommand, ActorResponse},
    supervisor::Supervisor,
};
use crate::prelude::*;
impl Supervisor {
    pub(crate) async fn backup_request(
        &self,
        mut request: LocalBusFrame,
        connection: &LocalBusConnectionState,
    ) -> Result<ActorResponse, SdkError> {
        if request.method == "account.backup.jobs" {
            return Ok(ActorResponse {
                body: self.backup_jobs.jobs()?,
                events: Vec::new(),
                nodes: None,
            });
        }
        let attended = connection.attended_account_id.is_some()
            || self.daemon_attended.borrow().contains(&connection.connection_id);
        if !attended {
            return Err(SdkError::CapabilityDenied(
                "backup jobs require an attended human frontend".into(),
            ));
        }
        if let Some(id) = request.account_id.as_deref() {
            let manifest = read_local_bus_account_manifest(&local_bus_account_manifest_path(
                &self.config.data_root,
                id,
            ))?;
            if manifest.kind.as_deref().unwrap_or("human") != "human"
                || manifest.client_mode == LocalBusClientMode::HeadlessAi
            {
                return Err(SdkError::CapabilityDenied(
                    "backup jobs require a human account".into(),
                ));
            }
        }
        let method = request.method.clone();
        let row = match method.as_str() {
            "account.backup.create" => {
                let id = request_account_id(&request)?;
                let actor = self.account_actor(id).ok_or_else(|| refused("account_locked"))?;
                let path = request
                    .body
                    .get("output_path")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| refused("not_writable"))?
                    .to_owned();
                let secret = take_secret(&mut request)?;
                self.backup_jobs.create(path, secret, actor)?
            }
            "account.restore.verify" => {
                let path = request
                    .body
                    .get("input_path")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| refused("unreadable"))?
                    .to_owned();
                let secret = take_secret(&mut request)?;
                self.backup_jobs.verify(path, secret)?
            }
            "account.backup.cancel" => {
                let id = request.body["job_id"].as_str().ok_or_else(|| refused("unknown_job"))?;
                self.backup_jobs.cancel(id).await?
            }
            "account.restore.install" => {
                let id = request.body["job_id"].as_str().ok_or_else(|| refused("unknown_job"))?;
                let (row, stage) = self.backup_jobs.begin_install(id)?;
                let account = row
                    .archive
                    .as_ref()
                    .ok_or_else(|| refused("invalid_job_phase"))?
                    .local_account_id
                    .clone();
                self.installing.borrow_mut().insert(account.clone());
                let supervisor = self.owned_backup_handle()?;
                let job = row.clone();
                let context = LocalBusConnectionState::new(
                    connection.connection_id,
                    connection.outbound.clone(),
                );
                self.backup_jobs.task(tokio::task::spawn_local(async move {
                    let result=async {
                        if let Some(actor)=supervisor.account_actor(&account){actor.stop().await?;}
                        supervisor.remove_backup_actor(&account);
                        let service=supervisor.backup_jobs.clone();let work=job.clone();
                        tokio::task::spawn_blocking(move||service.install_generation(&work,stage)).await.map_err(|_|refused("interrupted"))?
                    }.await;
                    supervisor.installing.borrow_mut().remove(&account);
                    let reopened=if supervisor.index.account(&account).is_ok(){supervisor.restart_backup_actor(&account,&context).await}else{Ok(())};
                    match result {
                        Err(error)=>supervisor.backup_jobs.fail_install(&job.job_id,&error),
                        Ok((_,restored,kept_newer))=>{
                            if let Err(error)=reopened {tracing::warn!(%error,"restored account will reopen on next unlock");}
                            let _=supervisor.backup_jobs.change(|registry|registry.installed(&job.job_id,restored,kept_newer,super::service::now()));
                        }
                    }
                }))?;
                row
            }
            _ => return Err(refused("unsupported_version")),
        };
        Ok(ActorResponse { body: serde_json::json!({"job":row}), events: Vec::new(), nodes: None })
    }
    async fn restart_backup_actor(
        &self,
        id: &str,
        connection: &LocalBusConnectionState,
    ) -> Result<(), SdkError> {
        let manifest = read_local_bus_account_manifest(&local_bus_account_manifest_path(
            &self.config.data_root,
            id,
        ))?;
        let actor = self.new_backup_actor(id)?;
        let request = LocalBusFrame::request(
            "restore-open",
            Some(id.into()),
            "account",
            "account.unlock",
            serde_json::json!({"passphrase":manifest.account_secret}),
        );
        let (reply, _) = tokio::sync::oneshot::channel();
        actor
            .request(AccountCommand {
                backup: None,
                request,
                connection_id: connection.connection_id,
                topics: BTreeSet::default(),
                attended: true,
                nodes: None,
                outbound: connection.outbound.clone(),
                reply: Some(reply),
            })
            .await?;
        Ok(())
    }
}
fn take_secret(request: &mut LocalBusFrame) -> Result<zeroize::Zeroizing<String>, SdkError> {
    let mut value =
        request.body.get_mut("passphrase").ok_or_else(|| refused("wrong_passphrase"))?.take();
    let secret = value.as_str().ok_or_else(|| refused("wrong_passphrase"))?.to_owned();
    crate::bus::secrets::wipe(&mut value);
    Ok(zeroize::Zeroizing::new(secret))
}

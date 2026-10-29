// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Attended full-data archive jobs; authority credentials never enter an archive.
use crate::{
    RfError,
    cli::{AccountBackupAction, AccountBackupCommand},
    utils::print_json,
};
use ramflux_sdk::{
    LocalBusClient,
    backup::{BackupJob, BackupJobState},
};
use serde_json::json;
use zeroize::Zeroizing;

pub(crate) async fn handle(
    bus: &mut LocalBusClient,
    command: AccountBackupCommand,
) -> Result<(), RfError> {
    bus.request(
        None,
        "stream",
        "subscription.open",
        json!({
            "topics":["account.backup.job.changed"], "since_seq":0, "attended_frontend":true
        }),
    )
    .await?;
    let response = match command.action {
        AccountBackupAction::Export(export) => {
            let passphrase = super::account::rf_required_env(
                export.passphrase_env.as_deref(),
                "RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE",
            )?;
            let started = bus
                .request(
                    Some(export.account),
                    "account",
                    "account.backup.create",
                    json!({"output_path":export.out, "passphrase":passphrase}),
                )
                .await?;
            wait(bus, job(started)?, BackupJobState::Done).await?
        }
        AccountBackupAction::Import(import) => {
            let passphrase = super::account::rf_required_env(
                import.passphrase_env.as_deref(),
                "RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE",
            )?;
            let new_passphrase = import
                .new_passphrase_env
                .as_deref()
                .map(|name| super::account::rf_required_env(Some(name), name).map(Zeroizing::new))
                .transpose()?;
            let started = bus
                .request(
                    None,
                    "account",
                    "account.restore.verify",
                    json!({"input_path":import.input, "passphrase":passphrase}),
                )
                .await?;
            let verified = wait(bus, job(started)?, BackupJobState::Verified).await?;
            let mut body = json!({"job_id":verified.job_id});
            if let Some(mut secret) = new_passphrase {
                body["passphrase"] = std::mem::take(&mut *secret).into();
            }
            let started = bus.request(None, "account", "account.restore.install", body).await?;
            wait(bus, job(started)?, BackupJobState::Done).await?
        }
    };
    print_json(&serde_json::to_value(response)?)
}

fn job(mut response: serde_json::Value) -> Result<BackupJob, RfError> {
    Ok(serde_json::from_value(response["job"].take())?)
}

async fn wait(
    bus: &mut LocalBusClient,
    mut row: BackupJob,
    expected: BackupJobState,
) -> Result<BackupJob, RfError> {
    loop {
        if row.state == expected {
            return Ok(row);
        }
        if row.state.terminal() {
            return Err(RfError::Message(format!(
                "Backup job {}: {}",
                row.job_id,
                serde_json::to_string(&row)?
            )));
        }
        // Drain the subscribed events while polling authoritative job rows after loss/lag.
        tokio::select! {
            event = bus.next_event() => { event?; }
            () = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
        }
        let rows = bus.request(None, "account", "account.backup.jobs", json!({})).await?;
        let jobs: Vec<BackupJob> = serde_json::from_value(rows["jobs"].clone())?;
        row = jobs
            .into_iter()
            .find(|next| next.job_id == row.job_id)
            .ok_or_else(|| RfError::Message("Backup job is no longer available.".into()))?;
    }
}

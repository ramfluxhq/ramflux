// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Select the credential export's attended custodian from durable custody, never the active account.
use crate::{RfError, cli::AccountExportAgentCredentials};
use ramflux_sdk::LocalBusClient;
use serde_json::{Value, json};

pub(super) async fn export(
    bus: &mut LocalBusClient,
    input: AccountExportAgentCredentials,
) -> Result<(), RfError> {
    let listed = bus.request(None, "account", "account.list", json!({})).await?;
    let owner = custodian(&listed, &input.account, input.custodian.as_deref())?;
    bus.request(
        Some(owner.clone()),
        "stream",
        "subscription.open",
        json!({"topics":[],"attended_frontend":true}),
    )
    .await?;
    let result = bus
        .request(
            Some(owner.clone()),
            "account",
            "account.export_agent_credentials",
            json!({"account":input.account,"path":input.out}),
        )
        .await
        .map_err(|error| {
            RfError::Message(format!(
                "custodian `{owner}` cannot export credentials for agent `{}`: {error}",
                input.account
            ))
        })?;
    super::print_json(&result)
}

fn custodian(listed: &Value, agent: &str, explicit: Option<&str>) -> Result<String, RfError> {
    let recorded = listed["account_details"]
        .as_array()
        .and_then(|accounts| accounts.iter().find(|row| row["id"].as_str() == Some(agent)))
        .and_then(|row| row["custodian_account_id"].as_str());
    match (explicit, recorded) {
        (Some(selected), Some(recorded)) if selected != recorded => Err(RfError::Message(format!(
            "custodian `{selected}` is not agent `{agent}`'s recorded custodian `{recorded}`"
        ))),
        (Some(selected), _) | (None, Some(selected)) => Ok(selected.to_owned()),
        (None, None) => Err(RfError::Message(format!(
            "agent `{agent}` has no custodian record; pass `--custodian <owner id>`"
        ))),
    }
}

#[cfg(test)]
mod tests;

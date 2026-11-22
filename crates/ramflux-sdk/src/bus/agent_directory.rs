// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Agents hosted for this owner, read from the public device manifest.
//! The fence store already scans `agent_hosts_of`. This is that scan on the owner's
//! manifest, so a phone whose backup has no agent files can list and retire them.
//! No new bus method.

use super::actor::AccountActor;
use crate::SdkError;
use ramflux_protocol::message as g;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub(super) struct HostedAgent {
    pub(super) agent_anchor: String,
    #[serde(default)]
    pub(super) retired: bool,
}

#[derive(Deserialize)]
struct DirectoryAgents {
    #[serde(default)]
    hosted_agents: Vec<HostedAgent>,
}

/// Host rows of this account's anchor. `Ok(None)` when the account has no gateway yet.
/// # Errors
/// A directory fetch that fails, or an anchor that cannot be placed in the path.
pub(super) async fn hosted_agents(
    actor: &AccountActor,
) -> Result<Option<(String, Vec<HostedAgent>)>, SdkError> {
    let Some(config) = actor.agent_gateway().await? else {
        return Ok(None);
    };
    let root = config
        .custody
        .as_ref()
        .map(|custody| custody.account_root.clone())
        .ok_or(SdkError::NetworkingPending)?;
    let account_id = config
        .custody
        .as_ref()
        .map(|custody| custody.account_id.clone())
        .ok_or(SdkError::NetworkingPending)?;
    let now = super::custody_setup::now()?;
    let native = crate::custody::load_data_account(&root, &account_id, now)?;
    let anchor = native.record().body.account_anchor.clone();
    if !anchor_path_ok(&anchor) {
        return Err(SdkError::CustodySetupInvalid);
    }
    let path = format!("/mvp1/device-manifest/{anchor}");
    let manifest =
        crate::prekey::sdk_gateway_get_json::<Option<serde_json::Value>>(&config, &path).await?;
    let Some(manifest) = manifest else {
        return Ok(Some((anchor, Vec::new())));
    };
    let body: DirectoryAgents =
        serde_json::from_value(manifest).map_err(|_| SdkError::CustodySetupInvalid)?;
    Ok(Some((anchor, body.hosted_agents)))
}

/// Append node-hosted agents that this page does not already contain.
/// A full local page is left as it is. An empty local page reports a fetch failure.
/// # Errors
/// The directory fetch, when the local page has no records to return instead.
pub(super) async fn attach_hosted(
    actor: &AccountActor,
    limit: Option<u32>,
    mut result: g::AgentConfigResult,
) -> Result<g::AgentConfigResult, SdkError> {
    let Some(limit) = limit else {
        return Ok(result);
    };
    let (has_next, empty, room) = match result.value.as_ref() {
        Some(g::agent_config_result::Value::Page(page)) => (
            page.next.is_some(),
            page.records.is_empty(),
            usize::try_from(limit).unwrap_or(0).saturating_sub(page.records.len()),
        ),
        _ => return Ok(result),
    };
    if has_next || room == 0 {
        return Ok(result);
    }
    let hosted = match hosted_agents(actor).await {
        Ok(Some(hosted)) => hosted,
        Ok(None) if empty => return Err(SdkError::NetworkingPending),
        Err(error) if empty => return Err(error),
        Ok(None) | Err(_) => return Ok(result),
    };
    let Some(g::agent_config_result::Value::Page(page)) = result.value.as_mut() else {
        return Ok(result);
    };
    push_missing(page, &hosted.0, hosted.1, room);
    Ok(result)
}

/// Whether the node lists this anchor for the account. Missing gateway is not a list.
/// # Errors
/// The directory fetch.
pub(super) async fn anchor_is_hosted(actor: &AccountActor, agent: &str) -> Result<bool, SdkError> {
    let Some((_, rows)) = hosted_agents(actor).await? else {
        return Err(SdkError::NetworkingPending);
    };
    Ok(rows.iter().any(|row| row.agent_anchor == agent))
}

fn push_missing(page: &mut g::AgentPage, custodian: &str, rows: Vec<HostedAgent>, room: usize) {
    let mut added = 0_usize;
    for row in rows {
        if added >= room {
            break;
        }
        if page.records.iter().any(|record| record.agent_anchor == row.agent_anchor) {
            continue;
        }
        page.records.push(wire_hosted(custodian, &row));
        added += 1;
    }
}

fn wire_hosted(custodian: &str, row: &HostedAgent) -> g::AgentRecord {
    g::AgentRecord {
        agent_anchor: row.agent_anchor.clone(),
        custodian_anchor: custodian.to_owned(),
        persona: None,
        host: None,
        config: None,
        revision: None,
        lifecycle: if row.retired {
            crate::agent_record::LIFECYCLE_RETIRED
        } else {
            crate::agent_record::LIFECYCLE_ACTIVE
        }
        .to_owned(),
        observation: String::new(),
        cleanup: String::new(),
        access: None,
        role: String::new(),
    }
}

fn anchor_path_ok(anchor: &str) -> bool {
    !anchor.is_empty()
        && anchor.len() <= 128
        && anchor.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

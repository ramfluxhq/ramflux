// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! PRX follow-up for the desktop daemon. The account writer does not call PRX.
//! Limits are published after `agent.create` returns a plan anchor. Purge runs
//! after local `agent.delete`. History erase uses the conversation id as the
//! session id, which matches PRX only when that session was created with the
//! same key. The agent host's server-assigned session is a separate path.

use ramflux_protocol::decode_base64url;
use ramflux_protocol::message as g;
use ramflux_prx_client::{AgentLimits, AgentName, ApiCode, PrxClient, PrxError};
use std::path::Path;

use crate::SdkError;

/// Limits copied off an `agent.create` body before the account writer takes it.
pub(crate) struct LimitPublish {
    pub(crate) provider: String,
    pub(crate) model: String,
    pub(crate) tools: Vec<String>,
    pub(crate) turns: Option<u32>,
    pub(crate) cost: Option<u64>,
}

/// Publishes limits and purges after the account writer has finished.
/// No client means the local result stands and nothing is sent.
///
/// # Errors
/// `agent_not_retired` when purge is refused because PRX has not retired the agent.
/// Other PRX failures use a static `prx_*` code. The local retire is not rolled back.
pub(crate) async fn after_agent(
    client: Option<&PrxClient>,
    data_root: &Path,
    publish: Option<&LimitPublish>,
    purge_anchor: Option<&str>,
    result: &g::AgentConfigResult,
) -> Result<(), SdkError> {
    let Some(client) = client else {
        return Ok(());
    };
    if let Some(publish) = publish {
        let anchor = custody_anchor(result).ok_or(SdkError::PrxCall("prx_rejected"))?;
        publish_limits(client, anchor, publish).await?;
    }
    if let Some(anchor) = purge_anchor {
        purge_agent(client, data_root, anchor).await?;
    }
    Ok(())
}

/// Best-effort session erase after an everyone-delete has already committed locally.
pub(crate) async fn erase_if_configured(
    client: Option<&PrxClient>,
    data_root: &Path,
    conversation_id: &str,
) {
    let Some(client) = client else {
        return;
    };
    if let Ok(erased) = erase_session(client, conversation_id).await {
        let _ = write_json(data_root, "history", conversation_id, &erased);
    }
}

async fn publish_limits(
    client: &PrxClient,
    anchor: &str,
    publish: &LimitPublish,
) -> Result<(), SdkError> {
    let name = name_from_anchor(anchor)?;
    let caps = client.capabilities().await.map_err(|error| map_prx(&error))?;
    let limits =
        AgentLimits { max_concurrent_turns: publish.turns, max_cost_per_day_cents: publish.cost };
    let spec = ramflux_prx_client::NamedLimits {
        provider: &publish.provider,
        model: &publish.model,
        tool_names: &publish.tools,
        limits: &limits,
    };
    ramflux_prx_client::publish_named_limits(client, &caps, &name, &spec)
        .await
        .map_err(|error| map_prx(&error))?;
    Ok(())
}

async fn purge_agent(client: &PrxClient, data_root: &Path, anchor: &str) -> Result<(), SdkError> {
    let name = name_from_anchor(anchor)?;
    let caps = client.capabilities().await.map_err(|error| map_prx(&error))?;
    let current = client.get(&caps, &name).await.map_err(|error| map_prx(&error))?;
    let key = stable_key("rf-purge-", anchor);
    let receipt = client
        .purge(&caps, &name, &current.revision, &key)
        .await
        .map_err(|error| map_prx(&error))?;
    let body = serde_json::json!({
        "name": receipt.name.as_str(),
        "incarnations": receipt.incarnations,
        "counts": receipt.counts,
        "completed_at": receipt.completed_at,
    });
    write_json(data_root, "purge", name.as_str(), &body)
}

async fn erase_session(
    client: &PrxClient,
    conversation_id: &str,
) -> Result<serde_json::Value, SdkError> {
    let caps = client.capabilities().await.map_err(|error| map_prx(&error))?;
    let prefix = stable_key("rf-hist-", conversation_id);
    let erased = client
        .erase_session_history(&caps, conversation_id, &prefix)
        .await
        .map_err(|error| map_prx(&error))?;
    let rows: Vec<serde_json::Value> = erased
        .iter()
        .map(|row| {
            serde_json::json!({
                "erase_id": row.erase_id,
                "generation": row.generation,
                "remaining": row.remaining,
                "incarnation": row.incarnation,
                "session": row.scope.session,
                "agent": row.scope.agent,
                "scope_incarnation": row.scope.incarnation,
            })
        })
        .collect();
    Ok(serde_json::Value::Array(rows))
}

fn custody_anchor(result: &g::AgentConfigResult) -> Option<&str> {
    match &result.value {
        Some(g::agent_config_result::Value::Custody(status)) => status.agent_anchor.as_deref(),
        Some(g::agent_config_result::Value::Record(record)) => Some(record.agent_anchor.as_str()),
        _ => None,
    }
}

fn name_from_anchor(anchor: &str) -> Result<AgentName, SdkError> {
    let bytes = decode_base64url(anchor).map_err(|_| SdkError::PrxCall("prx_rejected"))?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| SdkError::PrxCall("prx_rejected"))?;
    Ok(AgentName::from_anchor(&array))
}

fn map_prx(error: &PrxError) -> SdkError {
    match error {
        PrxError::Api { code: ApiCode::AgentNotRetired, .. } => SdkError::AgentNotRetired,
        PrxError::Api { code: ApiCode::ModelCapabilitiesUnknown, .. } => {
            SdkError::PrxCall("model_capabilities_unknown")
        }
        PrxError::Unsupported { .. } => SdkError::PrxCall("prx_unsupported"),
        PrxError::Unavailable | PrxError::Timeout => SdkError::PrxCall("prx_unavailable"),
        _ => SdkError::PrxCall("prx_rejected"),
    }
}

fn stable_key(prefix: &str, material: &str) -> String {
    let mut acc: u128 = 0xcbf2_9ce4_8422_2325;
    for byte in material.bytes() {
        acc ^= u128::from(byte);
        acc = acc.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{prefix}{acc:032x}")
}

fn write_json(
    root: &Path,
    kind: &str,
    material: &str,
    body: &serde_json::Value,
) -> Result<(), SdkError> {
    let dir = root.join("prx_receipts");
    std::fs::create_dir_all(&dir).map_err(|_| SdkError::PrxCall("prx_rejected"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| SdkError::PrxCall("prx_rejected"))?;
    }
    let path = dir.join(format!("{kind}-{}.json", stable_key("", material)));
    let bytes = serde_json::to_vec(body).map_err(|_| SdkError::PrxCall("prx_rejected"))?;
    let mut file = std::fs::File::create(&path).map_err(|_| SdkError::PrxCall("prx_rejected"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| SdkError::PrxCall("prx_rejected"))?;
    }
    std::io::Write::write_all(&mut file, &bytes).map_err(|_| SdkError::PrxCall("prx_rejected"))?;
    file.sync_all().map_err(|_| SdkError::PrxCall("prx_rejected"))
}

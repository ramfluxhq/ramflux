// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! PRX follow-up for the desktop daemon. The account writer does not call PRX.
//! The full config of an agent is published after `agent.create` returns a plan anchor (AGENT-MGMT-01A:
//! provider, model, autonomy, prompt, tools, enabled and limits, with or without limits). Purge runs
//! after local `agent.delete`. History erase uses the conversation id as the
//! session id, which matches PRX only when that session was created with the
//! same key. The agent host's server-assigned session is a separate path.

use ramflux_protocol::decode_base64url;
use ramflux_protocol::message as g;
use ramflux_prx_client::{
    AgentConfig, AgentLimits, AgentName, ApiCode, ApplyOutcome, PrxClient, PrxError,
};
use std::path::Path;

use crate::SdkError;

/// The config of an `agent.create` body, copied off before the account writer takes it.
pub(crate) struct ConfigPublish {
    config: AgentConfig,
    /// The create carried `confirmed: true`, so a PRX high-risk confirmation is answered once.
    confirmed: bool,
}

impl ConfigPublish {
    /// The config of a create body. `None` when the body has no config or the config is not one
    /// PRX accepts; the account writer refuses such a create before any effect.
    pub(crate) fn of(body: &g::AgentCreate) -> Option<Self> {
        use crate::agent_record::config as fields;
        let config = body.config.as_ref()?;
        let limits = config.limits.as_ref().map(|limits| AgentLimits {
            max_concurrent_turns: limits.max_concurrent_turns,
            max_cost_per_day_cents: limits.max_cost_per_day_cents,
        });
        Some(Self {
            config: AgentConfig {
                provider: config.provider.clone(),
                model: config.model.clone(),
                prompt: config.prompt.clone(),
                autonomy: if config.autonomy.is_empty() {
                    ramflux_prx_client::Autonomy::Full
                } else {
                    fields::autonomy_of(&config.autonomy)?
                },
                tools: fields::tools_of(&config.tools),
                enabled: config.enabled.unwrap_or(true),
                limits,
                approval_wait_secs: ramflux_prx_client::DEFAULT_APPROVAL_WAIT_SECS,
            },
            confirmed: body.confirmed == Some(true),
        })
    }
}

/// Publishes the config and purges after the account writer has finished.
/// No client means the local result stands and nothing is sent.
///
/// # Errors
/// `agent_not_retired` when purge is refused because PRX has not retired the agent.
/// Other PRX failures use a static `prx_*` code. The local retire is not rolled back.
pub(crate) async fn after_agent(
    client: Option<&PrxClient>,
    data_root: &Path,
    publish: Option<&ConfigPublish>,
    purge_anchor: Option<&str>,
    result: &g::AgentConfigResult,
) -> Result<(), SdkError> {
    let Some(client) = client else {
        return Ok(());
    };
    if let Some(publish) = publish {
        let anchor = custody_anchor(result).ok_or(SdkError::PrxCall("prx_rejected"))?;
        publish_config(client, anchor, publish).await?;
    }
    if let Some(anchor) = purge_anchor {
        purge_agent(client, data_root, anchor).await?;
    }
    Ok(())
}

/// An `agent.get` of an agent that was created but not yet updated has no mirrored revision.
/// When PRX is reachable and holds the config the mirror shows, its revision is added to the
/// reply, so a client can pass it to `agent.update`. A PRX that is absent, down, or changed
/// leaves the reply as the mirror has it.
pub(crate) async fn fill_revision(
    client: Option<&PrxClient>,
    mut result: g::AgentConfigResult,
) -> g::AgentConfigResult {
    let (Some(client), Some(g::agent_config_result::Value::Record(record))) =
        (client, result.value.as_mut())
    else {
        return result;
    };
    if record.revision.is_some() || record.lifecycle != crate::agent_record::LIFECYCLE_ACTIVE {
        return result;
    }
    let Some(mirror) = record.config.as_ref().and_then(crate::agent_record::config::config_of_wire)
    else {
        return result;
    };
    let Ok(name) = name_from_anchor(&record.agent_anchor) else {
        return result;
    };
    let Ok(caps) = client.capabilities().await else {
        return result;
    };
    if let Ok(current) = client.get(&caps, &name).await
        && crate::agent_record::config::configs_match(&mirror, &current.config)
    {
        record.revision = Some(current.revision.as_str().to_owned());
    }
    result
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

async fn publish_config(
    client: &PrxClient,
    anchor: &str,
    publish: &ConfigPublish,
) -> Result<(), SdkError> {
    let name = name_from_anchor(anchor)?;
    let caps = client.capabilities().await.map_err(|error| map_prx(&error))?;
    let outcome = client
        .apply_agent(&caps, &name, &publish.config, None)
        .await
        .map_err(|error| map_prx(&error))?;
    match outcome {
        ApplyOutcome::Applied(_) | ApplyOutcome::AlreadyApplied(_) => Ok(()),
        ApplyOutcome::NeedsConfirmation { revision } if publish.confirmed => client
            .put(&caps, &name, &publish.config, &revision, true)
            .await
            .map(|_| ())
            .map_err(|error| map_prx(&error)),
        ApplyOutcome::NeedsConfirmation { .. } => {
            Err(SdkError::AgentCreationRefused("confirmation_required"))
        }
        ApplyOutcome::NeedsReview { .. } => Err(SdkError::PrxCall("revision_conflict")),
    }
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

pub(crate) fn name_from_anchor(anchor: &str) -> Result<AgentName, SdkError> {
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
        PrxError::Api { code: ApiCode::FieldInvalid | ApiCode::AgentToolsInvalid, .. } => {
            SdkError::PrxCall("field_invalid")
        }
        PrxError::Api { code: ApiCode::RevisionConflict, .. } => {
            SdkError::PrxCall("revision_conflict")
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

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One read-modify-write that installs admission limits on a named agent.
//! Callers that have no bound set do not call this.

use crate::agent::{AgentConfig, AgentLimits, DEFAULT_APPROVAL_WAIT_SECS, PutOutcome, Tools};
use crate::autonomy::Autonomy;
use crate::capabilities::Capabilities;
use crate::client::PrxClient;
use crate::error::{ApiCode, PrxError, local_refusal};
use crate::name::AgentName;

/// What to write when installing admission limits. An existing agent keeps its config and
/// only `limits` changes. A missing agent is created from `provider`, `model` and `tool_names`.
pub struct NamedLimits<'a> {
    pub provider: &'a str,
    pub model: &'a str,
    pub tool_names: &'a [String],
    pub limits: &'a AgentLimits,
}

/// Writes `limits` onto `name`. An existing agent keeps its config; a missing one is created
/// with full autonomy and the tools in `spec`. `confirm_high_risk` is not sent.
///
/// # Errors
/// Returns a local `field_invalid` when no bound is set (nothing is sent), `Unsupported` when
/// the route or `agent_limits_v1` is missing, or the error of the list or the `PUT`.
pub async fn publish_named_limits(
    client: &PrxClient,
    caps: &Capabilities,
    name: &AgentName,
    spec: &NamedLimits<'_>,
) -> Result<PutOutcome, PrxError> {
    if spec.limits.max_concurrent_turns.is_none() && spec.limits.max_cost_per_day_cents.is_none() {
        return Err(local_refusal(ApiCode::FieldInvalid));
    }
    let listed = client.list(caps).await?;
    let config = match listed.agents.iter().find(|agent| &agent.name == name) {
        Some(found) => {
            let mut config = found.config.clone();
            config.limits = Some(spec.limits.clone());
            config
        }
        None => AgentConfig {
            provider: spec.provider.to_owned(),
            model: spec.model.to_owned(),
            prompt: None,
            autonomy: Autonomy::Full,
            tools: tools_of(spec.tool_names),
            enabled: true,
            limits: Some(spec.limits.clone()),
            approval_wait_secs: DEFAULT_APPROVAL_WAIT_SECS,
        },
    };
    client.put(caps, name, &config, &listed.revision, false).await
}

fn tools_of(names: &[String]) -> Tools {
    if names.is_empty() || (names.len() == 1 && names.first().is_some_and(|name| name == "*")) {
        Tools::All
    } else {
        Tools::List(names.to_vec())
    }
}

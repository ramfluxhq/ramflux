// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The config mirror of an agent record (AGENT-MGMT-01A) and the checks `agent.create`,
//! `agent.update` and the record store share. PRX owns the real config; the desktop keeps this
//! mirror so `agent.get` can show it. Every check here is closed: a value outside it is refused
//! before any effect.
use super::StoredAgentRecord;
use ramflux_prx_client::{
    AgentConfig, AgentLimits, Autonomy, DEFAULT_APPROVAL_WAIT_SECS, PROMPT_MAX_BYTES, Tools,
};
use std::collections::BTreeSet;

/// Longest `provider` or `model`, in bytes.
const TEXT_MAX_BYTES: usize = 128;
/// Most tool names of one agent.
const TOOLS_MAX: usize = 256;
/// Longest tool name, in bytes.
const TOOL_NAME_MAX_BYTES: usize = 128;
/// The prompt and the tool names together stay far below the 64 KiB record file cap.
const CONFIG_TEXT_MAX_BYTES: usize = 40 * 1024;
const WILDCARD: &str = "*";

/// A non-empty provider or model name within bounds.
pub(crate) fn text_ok(text: &str) -> bool {
    !text.is_empty() && text.len() <= TEXT_MAX_BYTES
}

/// One of the three autonomy levels PRX accepts.
pub(crate) fn autonomy_ok(text: &str) -> bool {
    autonomy_of(text).is_some()
}

/// A prompt PRX stores. The empty prompt is allowed.
pub(crate) fn prompt_ok(text: &str) -> bool {
    text.len() <= PROMPT_MAX_BYTES
}

/// A tool list PRX accepts: bounded, distinct, and `*` only alone.
pub(crate) fn tools_ok(names: &[String]) -> bool {
    if names.len() > TOOLS_MAX {
        return false;
    }
    let distinct: BTreeSet<&str> = names.iter().map(String::as_str).collect();
    if distinct.len() != names.len() || (names.len() > 1 && distinct.contains(WILDCARD)) {
        return false;
    }
    names.iter().all(|name| {
        !name.is_empty() && name.len() <= TOOL_NAME_MAX_BYTES && !name.chars().any(char::is_control)
    })
}

/// The admission limit bounds of PRX.
pub(crate) fn limits_ok(turns: Option<u32>, cost: Option<u64>) -> bool {
    turns.is_none_or(|value| (1..=1024).contains(&value))
        && cost.is_none_or(|value| (1..=1_000_000_000).contains(&value))
}

/// Every given field is valid, and the prompt and tools fit the record together.
pub(crate) fn fields_ok(
    provider: Option<&str>,
    model: Option<&str>,
    autonomy: Option<&str>,
    prompt: Option<&str>,
    tools: Option<&[String]>,
) -> bool {
    let text: usize = prompt.map_or(0, str::len)
        + tools.map_or(0, |names| names.iter().map(String::len).sum::<usize>());
    provider.is_none_or(text_ok)
        && model.is_none_or(text_ok)
        && autonomy.is_none_or(autonomy_ok)
        && prompt.is_none_or(prompt_ok)
        && tools.is_none_or(tools_ok)
        && text <= CONFIG_TEXT_MAX_BYTES
}

/// The config fields of a stored record are inside the closed shapes.
pub(crate) fn record_config_ok(record: &StoredAgentRecord) -> bool {
    fields_ok(
        record.provider.as_deref(),
        record.model.as_deref(),
        record.autonomy.as_deref(),
        record.prompt.as_deref(),
        record.tools.as_deref(),
    ) && limits_ok(record.max_concurrent_turns, record.max_cost_per_day_cents)
        && record.revision.as_deref().is_none_or(revision_ok)
}

fn revision_ok(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// The autonomy level of its wire spelling.
pub(crate) fn autonomy_of(text: &str) -> Option<Autonomy> {
    match text {
        "full" => Some(Autonomy::Full),
        "supervised" => Some(Autonomy::Supervised),
        "readonly" => Some(Autonomy::Readonly),
        _ => None,
    }
}

/// The wire spelling of an autonomy level.
pub(crate) fn autonomy_text(level: Autonomy) -> &'static str {
    match level {
        Autonomy::Full => "full",
        Autonomy::Supervised => "supervised",
        Autonomy::Readonly => "readonly",
    }
}

/// The PRX tools of a wire list: empty and `["*"]` both mean all of Main's tools.
pub(crate) fn tools_of(names: &[String]) -> Tools {
    if names.is_empty() || (names.len() == 1 && names.first().is_some_and(|name| name == WILDCARD))
    {
        Tools::All
    } else {
        Tools::List(names.to_vec())
    }
}

/// The wire list of PRX tools.
pub(crate) fn tools_names(tools: &Tools) -> Vec<String> {
    match tools {
        Tools::All => vec![WILDCARD.to_owned()],
        Tools::List(names) => names.clone(),
    }
}

/// The config the mirror holds, with PRX's defaults for what the mirror does not know. `None`
/// when the mirror has no provider and model.
pub(crate) fn config_of_record(record: &StoredAgentRecord) -> Option<AgentConfig> {
    build(
        record.provider.as_deref()?,
        record.model.as_deref()?,
        record.autonomy.as_deref(),
        record.prompt.as_deref(),
        record.tools.as_deref(),
        record.enabled,
        limits_of(record.max_concurrent_turns, record.max_cost_per_day_cents),
    )
}

fn build(
    provider: &str,
    model: &str,
    autonomy: Option<&str>,
    prompt: Option<&str>,
    tools: Option<&[String]>,
    enabled: Option<bool>,
    limits: Option<AgentLimits>,
) -> Option<AgentConfig> {
    Some(AgentConfig {
        provider: provider.to_owned(),
        model: model.to_owned(),
        prompt: prompt.map(str::to_owned),
        autonomy: autonomy
            .filter(|text| !text.is_empty())
            .map_or(Some(Autonomy::Full), autonomy_of)?,
        tools: tools_of(tools.unwrap_or_default()),
        enabled: enabled.unwrap_or(true),
        limits,
        approval_wait_secs: DEFAULT_APPROVAL_WAIT_SECS,
    })
}

fn limits_of(turns: Option<u32>, cost: Option<u64>) -> Option<AgentLimits> {
    (turns.is_some() || cost.is_some())
        .then_some(AgentLimits { max_concurrent_turns: turns, max_cost_per_day_cents: cost })
}

/// Whether PRX's config is the one the mirror shows. A mirror without a prompt accepts PRX's
/// composed one; the approval wait is not mirrored.
pub(crate) fn mirror_matches(record: &StoredAgentRecord, current: &AgentConfig) -> bool {
    config_of_record(record).is_some_and(|mirror| configs_match(&mirror, current))
}

/// `mirror_matches` for two configs: everything equal, the prompt only when `mirror` has one.
pub(crate) fn configs_match(mirror: &AgentConfig, current: &AgentConfig) -> bool {
    mirror.provider == current.provider
        && mirror.model == current.model
        && mirror.autonomy == current.autonomy
        && mirror.tools == current.tools
        && mirror.enabled == current.enabled
        && mirror.limits == current.limits
        && (mirror.prompt.is_none() || mirror.prompt == current.prompt)
}

/// The config of a wire `AgentConfigData` (a record read). `None` without provider and model.
pub(crate) fn config_of_wire(
    wire: &ramflux_protocol::message::AgentConfigData,
) -> Option<AgentConfig> {
    let (turns, cost) = wire.limits.as_ref().map_or((None, None), |limits| {
        (limits.max_concurrent_turns, limits.max_cost_per_day_cents)
    });
    build(
        Some(wire.provider.as_str()).filter(|text| !text.is_empty())?,
        Some(wire.model.as_str()).filter(|text| !text.is_empty())?,
        Some(wire.autonomy.as_str()),
        wire.prompt.as_deref(),
        Some(wire.tools.as_slice()),
        wire.enabled,
        limits_of(turns, cost),
    )
}

/// Writes what PRX stored into the mirror of `record`.
pub(crate) fn set_mirror(record: &mut StoredAgentRecord, config: &AgentConfig, revision: &str) {
    record.provider = Some(config.provider.clone());
    record.model = Some(config.model.clone());
    record.autonomy = Some(autonomy_text(config.autonomy).to_owned());
    record.prompt.clone_from(&config.prompt);
    record.tools = Some(tools_names(&config.tools));
    record.enabled = Some(config.enabled);
    record.revision = Some(revision.to_owned());
    let limits = config.limits.clone().unwrap_or_default();
    record.max_concurrent_turns = limits.max_concurrent_turns;
    record.max_cost_per_day_cents = limits.max_cost_per_day_cents;
}

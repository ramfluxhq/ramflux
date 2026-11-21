// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed validation of the agent persona and access policy (AGENT-IDENTITY-01 D11). Refusals use
//! the typed tokens of `SdkError::AgentCreationRefused`; no text of the user is echoed.
use crate::SdkError;
use ramflux_protocol::message::{AgentAccessPolicy, AgentPersona};
use std::collections::BTreeSet;

/// Upper bounds on persona text (bytes). The name is also a display name, so it stays short.
const MAX_NAME_BYTES: usize = 256;
const MAX_AVATAR_BYTES: usize = 2048;
const MAX_RESPONSIBILITY_BYTES: usize = 4096;

/// Validates the access policy: `dm` and `group_inviters` are closed tokens; `allowed_humans` is a
/// unique list of canonical anchors and must be empty unless one field is `allowlist`.
pub(crate) fn check_access(access: &AgentAccessPolicy) -> Result<(), SdkError> {
    let closed = |token: &str| matches!(token, "owner" | "contacts" | "allowlist" | "open");
    if !closed(&access.dm) || !closed(&access.group_inviters) {
        return Err(SdkError::AgentCreationRefused("access_policy_invalid"));
    }
    let allowlist = access.dm == "allowlist" || access.group_inviters == "allowlist";
    if !allowlist && !access.allowed_humans.is_empty() {
        return Err(SdkError::AgentCreationRefused("access_policy_invalid"));
    }
    let mut seen = BTreeSet::new();
    for anchor in &access.allowed_humans {
        crate::custody::valid_id(anchor)
            .map_err(|_| SdkError::AgentCreationRefused("access_policy_invalid"))?;
        if !seen.insert(anchor.as_str()) {
            return Err(SdkError::AgentCreationRefused("access_policy_invalid"));
        }
    }
    Ok(())
}

/// Validates the persona: name and responsibility are required and bounded; the avatar is bounded.
pub(crate) fn check_persona(persona: &AgentPersona) -> Result<(), SdkError> {
    let refused = || SdkError::AgentCreationRefused("persona_invalid");
    if persona.name.trim().is_empty()
        || persona.responsibility.trim().is_empty()
        || persona.name.len() > MAX_NAME_BYTES
        || persona.avatar.len() > MAX_AVATAR_BYTES
        || persona.responsibility.len() > MAX_RESPONSIBILITY_BYTES
    {
        return Err(refused());
    }
    Ok(())
}

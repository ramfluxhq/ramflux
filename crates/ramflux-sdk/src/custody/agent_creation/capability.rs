// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The D7 capability check. The home node advertises `agent_custody_authorization_v1` in its
//! signed client discovery record. Agent creation refuses with a typed unsupported error,
//! before any agent key, reservation or account write, when the selected node does not.

use crate::SdkError;

/// Refuses with [`SdkError::AgentCustodyUnsupported`] unless `client_capabilities` (the
/// capability list of the selected node profile) contains the agent custody capability.
///
/// # Errors
/// Returns `AgentCustodyUnsupported` when the capability is absent.
pub fn require_agent_custody_authorization(client_capabilities: &[String]) -> Result<(), SdkError> {
    if client_capabilities
        .iter()
        .any(|capability| capability == ramflux_protocol::AGENT_CUSTODY_AUTHORIZATION_CAPABILITY)
    {
        Ok(())
    } else {
        Err(SdkError::AgentCustodyUnsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPABILITY: &str = ramflux_protocol::AGENT_CUSTODY_AUTHORIZATION_CAPABILITY;

    #[test]
    fn advertised_capability_passes_the_check() {
        let advertised = vec!["prekey".to_owned(), CAPABILITY.to_owned()];
        assert!(
            require_agent_custody_authorization(&advertised).is_ok(),
            "an advertised agent custody capability must pass"
        );
    }

    #[test]
    fn absent_capability_is_typed_unsupported_and_names_no_secret() {
        let absent = vec!["prekey".to_owned(), "object_relay".to_owned()];
        let refusal = require_agent_custody_authorization(&absent);
        assert!(
            matches!(refusal, Err(SdkError::AgentCustodyUnsupported)),
            "a node without the capability must give the typed unsupported error, got {refusal:?}"
        );
        assert!(
            require_agent_custody_authorization(&[]).is_err(),
            "an empty capability list must not pass the check"
        );
    }

    #[test]
    fn a_similar_name_does_not_satisfy_the_check() {
        let near = vec![format!("{CAPABILITY}.bak"), CAPABILITY.to_uppercase()];
        assert!(
            require_agent_custody_authorization(&near).is_err(),
            "only the exact capability name passes"
        );
    }
}

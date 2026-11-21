// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Gateway client capabilities shared by federation discovery and the router echo.
//! Federation does not observe the router's live capability probe. An explicit list
//! is the shared input. Ephemeral is served only together with session push.

const CONFIGURED_NAME_LIMIT: usize = 64;

/// Capabilities named by `configured`.
/// Unknown names are ignored. Only the first 64 names are read.
/// Ephemeral is included only when session push is named too.
#[must_use]
pub fn select_gateway_client_capabilities(configured: &[String]) -> Vec<String> {
    let mut session_push = false;
    let mut ephemeral = false;
    for name in configured.iter().take(CONFIGURED_NAME_LIMIT) {
        let name = name.trim();
        if name == ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY {
            session_push = true;
        } else if name == ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY {
            ephemeral = true;
        }
    }
    let mut names = Vec::new();
    if session_push {
        names.push(ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.to_owned());
        if ephemeral {
            names.push(ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY.to_owned());
        }
    }
    names
}

/// Federation publication. `None` publishes nothing, because the router echo is not visible here.
#[must_use]
pub fn published_gateway_client_capabilities(configured: Option<&[String]>) -> Vec<String> {
    configured.map_or_else(Vec::new, select_gateway_client_capabilities)
}

/// Router `GET /mvp1/session-push-capabilities` body.
/// `None` keeps the historical echo of both features. `Some` echoes the selected list.
#[must_use]
pub fn router_echo_gateway_client_capabilities(configured: Option<&[String]>) -> Vec<String> {
    let Some(names) = configured else {
        return vec![
            ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.to_owned(),
            ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY.to_owned(),
        ];
    };
    select_gateway_client_capabilities(names)
}

#[cfg(test)]
mod tests {
    use super::{
        CONFIGURED_NAME_LIMIT, published_gateway_client_capabilities,
        router_echo_gateway_client_capabilities, select_gateway_client_capabilities,
    };

    fn push() -> String {
        ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY.to_owned()
    }

    fn ephemeral() -> String {
        ramflux_protocol::ephemeral::GATEWAY_EPHEMERAL_CAPABILITY.to_owned()
    }

    #[test]
    fn selection_requires_session_push_and_ignores_unknown_names() {
        assert!(
            select_gateway_client_capabilities(&[]).is_empty(),
            "an empty list serves neither feature"
        );
        assert!(
            select_gateway_client_capabilities(&[ephemeral()]).is_empty(),
            "ephemeral requires session push"
        );
        assert_eq!(
            select_gateway_client_capabilities(&[push(), "other".to_owned(), push()]),
            vec![push()],
            "unknown names are ignored and session push is not repeated"
        );
        assert_eq!(
            select_gateway_client_capabilities(&[
                ephemeral(),
                "  ".to_owned(),
                format!(" {} ", push()),
            ]),
            vec![push(), ephemeral()],
            "ephemeral follows session push"
        );
        let mut overflow = vec!["nope".to_owned(); CONFIGURED_NAME_LIMIT];
        overflow.push(push());
        assert!(
            select_gateway_client_capabilities(&overflow).is_empty(),
            "names past the first 64 are ignored"
        );
    }

    #[test]
    fn federation_omits_an_unset_list_and_the_router_keeps_its_echo() {
        assert!(
            published_gateway_client_capabilities(None).is_empty(),
            "federation does not invent capabilities it cannot observe"
        );
        assert_eq!(
            router_echo_gateway_client_capabilities(None),
            vec![push(), ephemeral()],
            "an unset router list keeps the historical echo"
        );
        let configured = [push(), ephemeral()];
        assert_eq!(
            published_gateway_client_capabilities(Some(&configured)),
            router_echo_gateway_client_capabilities(Some(&configured)),
            "federation and the router publish the same explicit list"
        );
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generated transport commits C to exact Inner bytes; routing is derived from authenticated I.
use super::{Kind, Plaintext, Routing, invalid};
use crate::SdkError;
use prost::Message as _;
use ramflux_protocol::message as g;

pub(super) fn identified_inner(bytes: &[u8]) -> Option<g::Inner> {
    g::Inner::decode(bytes).ok().filter(|inner| inner.identity.is_some())
}

pub(super) fn generated_plaintext(bytes: &[u8]) -> Result<Plaintext, SdkError> {
    let scanned = g::validation::scan_inner(bytes)
        .map_err(|_| invalid("generated transport Inner malformed"))?;
    let inner =
        identified_inner(bytes).ok_or_else(|| invalid("generated transport identity missing"))?;
    let identity = inner.identity.ok_or_else(|| invalid("generated transport identity missing"))?;
    g::identity::verify(&identity).map_err(|_| invalid("generated transport identity invalid"))?;
    let group = identity.group_id.clone();
    let kind = match scanned.kind {
        8 if group.is_some() => Kind::GroupControl,
        8 | 11 | 12 => Kind::Control,
        6 => Kind::Receipt,
        _ if group.is_some() => Kind::GroupMessage,
        _ => Kind::Direct,
    };
    let message_id = ramflux_protocol::encode_base64url(identity.id);
    let group_message_id = (kind == Kind::GroupMessage).then(|| message_id.clone());
    Ok(Plaintext {
        routing: Routing {
            kind,
            conversation_id: identity.conversation_id,
            group_id: group,
            message_id,
            group_message_id,
            attachments: false,
        },
        body_base64: zeroize::Zeroizing::new(ramflux_protocol::encode_base64url(bytes)),
    })
}

pub(super) fn seal_plaintext(
    body: &[u8],
    route: &Routing,
) -> Result<zeroize::Zeroizing<Vec<u8>>, SdkError> {
    if crate::client::target_selection::schema_v1_selected() && identified_inner(body).is_some() {
        #[cfg(test)]
        if super::report::allows_invalid_header_fixture() {
            return Ok(zeroize::Zeroizing::new(body.to_vec()));
        }
        generated_plaintext(body)?;
        Ok(zeroize::Zeroizing::new(body.to_vec()))
    } else {
        Ok(zeroize::Zeroizing::new(serde_json::to_vec(&Plaintext {
            routing: route.clone(),
            body_base64: zeroize::Zeroizing::new(ramflux_protocol::encode_base64url(body)),
        })?))
    }
}

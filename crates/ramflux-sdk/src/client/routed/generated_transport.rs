// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generated transport commits C to exact Inner bytes; routing is derived from authenticated I.
use super::{Kind, Plaintext, Routing, invalid};
use crate::SdkError;
use prost::Message as _;
use ramflux_protocol::message as g;
use zeroize::Zeroize as _;

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
    if crate::client::target_selection::schema_v1_selected()
        && let Some(mut inner) = identified_inner(body)
    {
        #[cfg(test)]
        if super::report::allows_invalid_header_fixture() {
            return Ok(zeroize::Zeroizing::new(body.to_vec()));
        }
        let closed_a2i = inner.kind == 8
            && g::Control::decode(inner.body.as_slice())
                .is_ok_and(|control| control.operation == 11);
        inner.body.zeroize();
        if inner.kind == 12 {
            crate::RamfluxClient::require_self_sync_floor_bootstrap()?;
        }
        if closed_a2i {
            crate::RamfluxClient::require_a2i_binding_authority()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::native_test_support::{Fixture, TestResult};

    fn signed_a2i(source: &Fixture) -> TestResult<g::A2iControlEvent> {
        let branch = source.client.device_branch.as_ref().ok_or("branch")?;
        let mut native = ramflux_protocol::A2iControlEvent {
            schema: ramflux_protocol::domain::A2I_CONTROL.into(),
            version: 1,
            domain: ramflux_protocol::domain::A2I_CONTROL.into(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: branch.device_id.clone(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: String::new(),
            },
            event_type: serde_json::from_value(serde_json::json!("a2i.control"))?,
            control_domain: ramflux_protocol::ControlDomain::McpTool,
            action: "approve".into(),
            subject: serde_json::json!({"tool":"search"}),
            correlation_id: "closed-sealer".into(),
            source_device_id: branch.device_id.clone(),
            target_device_id: "another-device".into(),
            grant_id: Some("uninstalled-grant".into()),
            expires_at: None,
        };
        native.signed.signature =
            ramflux_crypto::sign_protocol_object_with_device_branch(branch, &native)?;
        Ok(crate::client::routed::native_control::a2i::to_generated(&native)?)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shared_generated_sealer_refuses_closed_a2i_and_floorless_self_sync_before_framing()
    -> TestResult {
        let source = Fixture::new("native-closed-sealer").await?;
        let _live = ramflux_protocol::schema_profile::SchemaV1LiveGuard::enter();
        let identity = source.client.allocate_generated_identity("closed-control", 1, false)?;
        let route = Routing {
            kind: Kind::Control,
            conversation_id: "closed-control".into(),
            message_id: "closed".into(),
            group_id: None,
            group_message_id: None,
            attachments: false,
        };
        // The known discriminator is enough to refuse authority; no payload shape may
        // turn either closed kind into a usable generic plaintext producer.
        let control = g::Control {
            operation: 11,
            payload: Some(g::control::Payload::A2i(signed_a2i(&source)?)),
        };
        let mut inner = g::Inner {
            layer: g::registry::COMPILED_LAYER,
            kind: 8,
            identity: Some(identity),
            body: control.encode_to_vec(),
        };
        assert_eq!(
            g::validation::scan_inner(&inner.encode_to_vec())?.outcome,
            g::validation::ScanOutcome::Supported,
            "the refused input is a structurally valid signed control"
        );
        assert!(matches!(
            seal_plaintext(&inner.encode_to_vec(), &route),
            Err(SdkError::GeneratedRefused {
                code: crate::error::GeneratedRefusalCode::Authority,
                ..
            })
        ));
        inner.kind = 12;
        inner.body.clear();
        assert!(matches!(
            seal_plaintext(&inner.encode_to_vec(), &route),
            Err(SdkError::InboundPending(_))
        ));
        Ok(())
    }
}

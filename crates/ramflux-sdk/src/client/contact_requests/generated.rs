// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One fixed native contact-consent leaf; primary consent and encrypted transport stay separate.
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::{
    custody::{ContactConsentV2, Envelope},
    message as g,
};
use zeroize::Zeroizing;

pub(super) fn decode(bytes: &[u8]) -> Result<Option<Envelope<ContactConsentV2>>, SdkError> {
    if !crate::client::target_selection::schema_v1_selected() {
        return Ok(None);
    }
    let Ok(inner) = g::Inner::decode(bytes) else {
        return Ok(None);
    };
    if inner.kind != 8 {
        return Ok(None);
    }
    let control = g::Control::decode(inner.body.as_slice())
        .map_err(|_| super::invalid("contact Control malformed"))?;
    if control.operation != 3 {
        return Ok(None);
    }
    crate::client::generated_control::validate_control_operation(&control)?;
    g::validation::scan_inner(bytes).map_err(|error| SdkError::GeneratedRefused {
        code: crate::GeneratedRefusalCode::Content,
        reason: error.to_string(),
    })?;
    let Some(g::control::Payload::ContactControl(contact)) = control.payload else {
        return Err(super::invalid("contact Control missing"));
    };
    let leaf = contact.consent.ok_or_else(|| super::invalid("native contact consent missing"))?;
    let consent: Envelope<ContactConsentV2> =
        ramflux_protocol::custody::decode(&leaf.canonical, 8192)?;
    if ramflux_protocol::canonical_json_bytes(&consent)? != leaf.canonical {
        return Err(super::invalid("native contact consent must be canonical"));
    }
    Ok(Some(consent))
}

impl RamfluxClient {
    pub(super) fn generated_contact_inner(
        &self,
        consent: &Envelope<ContactConsentV2>,
        cached: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        let conversation =
            super::conversation(&consent.body.requester_root, &consent.body.target_root)?;
        let source = &consent.body.sending_device_ref;
        let own = self.owned_device_identity()?;
        let epoch = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.device_epoch;
        if source.account_anchor != own.root_commitment()
            || source.device_id != own.device_id()
            || source.device_epoch != epoch
        {
            return Err(super::invalid("native consent source changed"));
        }
        let control = crate::client::generated_control::control_from_payload(
            g::control::Payload::ContactControl(g::ContactControl {
                consent: Some(g::NativeContactConsent {
                    canonical: ramflux_protocol::canonical_json_bytes(consent)?,
                }),
            }),
        )?;
        if let Some(bytes) = cached {
            if g::validation::scan_inner(bytes).map_err(|_| SdkError::ReplayMismatch)?.outcome
                != g::validation::ScanOutcome::Supported
            {
                return Err(SdkError::ReplayMismatch);
            }
            let inner = g::Inner::decode(bytes).map_err(|_| SdkError::ReplayMismatch)?;
            let identity = inner.identity.as_ref().ok_or(SdkError::ReplayMismatch)?;
            if inner.kind != 8
                || inner.layer != g::registry::COMPILED_LAYER
                || inner.body != control.encode_to_vec()
                || identity.conversation_id != conversation
                || identity.group_id.is_some()
                || identity.group_epoch.is_some()
                || identity.device_sequence & (1 << 63) != 0
                || g::identity::verify(identity).is_err()
                || identity.author.as_ref().is_none_or(|author| {
                    author.account_anchor != source.account_anchor
                        || author.device_id != source.device_id
                        || author.device_epoch != source.device_epoch
                })
            {
                return Err(SdkError::ReplayMismatch);
            }
            return Ok(Zeroizing::new(bytes.to_vec()));
        }
        let identity = self.allocate_generated_identity(
            &conversation,
            crate::client::generated_identity::now_ms(),
            false,
        )?;
        Ok(Zeroizing::new(Self::encode_generated_inner(
            identity,
            &g::Content { value: Some(g::content::Value::Control(control)) },
        )?))
    }

    pub(crate) fn receive_generated_contact_control(
        &self,
        entry: &GatewayInboxEntry,
        route: &crate::client::routed::Routing,
        bytes: &[u8],
    ) -> Result<(), SdkError> {
        if decode(bytes)?.is_none() {
            return Err(super::invalid("generated native contact consent missing"));
        }
        let verified = self.verify_contact_control(entry, route, bytes)?;
        self.apply_contact_control(&verified)
    }
}

pub(in crate::client) fn message_id(body: &[u8], fallback: &str) -> Result<String, SdkError> {
    if decode(body)?.is_some() {
        let inner = g::Inner::decode(body).map_err(|_| super::invalid("contact Inner missing"))?;
        return Ok(ramflux_protocol::encode_base64url(
            inner.identity.ok_or_else(|| super::invalid("contact identity missing"))?.id,
        ));
    }
    Ok(fallback.into())
}

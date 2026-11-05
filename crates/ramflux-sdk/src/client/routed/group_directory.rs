// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Legacy group directory inputs cross the network boundary without an account or ratchet.

use super::{Kind, Opened, Routing, invalid};
use crate::prelude::*;

pub(crate) enum ReceiveGroupDirectory {
    Shared(Box<crate::client::shared_group::GroupDirectoryEvidence>),
    Legacy(Box<LegacyGroupDirectory>),
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Lookup {
    root: String,
    device: String,
    url: Option<String>,
}
pub(crate) struct LegacyGroupDirectory {
    lookup: Option<Lookup>,
    manifest: Option<SdkDeviceManifestResponse>,
}
pub(crate) enum LegacyGroupRequest {
    Other,
    Control { lookup: Option<Lookup> },
}
impl LegacyGroupRequest {
    pub(crate) fn directory_root(&self) -> Option<&str> {
        match self { Self::Control { lookup: Some(lookup) } => Some(&lookup.root), _ => None }
    }

    pub(crate) async fn resolve(
        self,
        gateway: &GatewaySessionConfig,
    ) -> Result<Option<ReceiveGroupDirectory>, SdkError> {
        let Self::Control { lookup } = self else { return Ok(None) };
        let manifest = if let Some(lookup) = &lookup {
            Some(if let Some(url) = &lookup.url {
                let manifest = crate::prekey::http_async::get::<Option<SdkDeviceManifestResponse>>(
                    url,
                    &format!("/mvp1/device-manifest/{}", lookup.root),
                    gateway.timeout,
                )
                .await?
                .ok_or_else(|| SdkError::InboundPending("group manifest unavailable".into()))?;
                crate::client::contact::verify_device_manifest(&manifest, &lookup.root)?;
                crate::client::identity_authority::ready_manifest(manifest, now_unix_timestamp())
            } else {
                crate::client::contact::fetch_verified_device_manifest(gateway, &lookup.root)
                    .await?
            })
        } else {
            None
        };
        Ok(Some(ReceiveGroupDirectory::Legacy(Box::new(LegacyGroupDirectory { lookup, manifest }))))
    }
}
impl RamfluxClient {
    pub(crate) fn legacy_group_directory_request(
        &self,
        entry: &GatewayInboxEntry,
        route: &Routing,
        body: &[u8],
        local: &str,
    ) -> Result<LegacyGroupRequest, SdkError> {
        if route.kind != Kind::GroupControl {
            return Ok(LegacyGroupRequest::Other);
        }
        self.contact_route_gate(entry, route, body)?;
        self.confirm_routed_context(route, entry)?;
        if let Some(group) = route.group_id.as_deref()
            && self.group_state(group).is_ok()
        {
            self.require_routed_group_member(group, entry)?;
        }
        let lookup = if let Ok(control) =
            serde_json::from_slice::<crate::group::SdkGroupControlEnvelope>(body)
        {
            if serde_json::to_value(&control.event.body)?
                .get("group_id")
                .and_then(serde_json::Value::as_str)
                != route.group_id.as_deref()
            {
                return Err(invalid("group control routing mismatch"));
            }
            self.group_join_identity_request(&control.event)?.map(|(root, device)| Lookup {
                root,
                device,
                url: None,
            })
        } else {
            let wrapper: SdkGroupSenderKeyDistributionEnvelope = serde_json::from_slice(body)?;
            let bytes = ramflux_protocol::decode_base64url(&wrapper.distribution_base64)
                .map_err(|_| invalid("invalid group distribution"))?;
            let distribution: SdkGroupSenderKeyDistribution = serde_json::from_slice(&bytes)?;
            if Some(distribution.group_id.as_str()) != route.group_id.as_deref() {
                return Err(invalid("group distribution routing mismatch"));
            }
            Self::sender_key_membership_event(local, &wrapper)?
                .map(|event| {
                    let ramflux_protocol::GroupEventBody::MemberJoined {
                        actor_principal_commitment,
                        ..
                    } = &event.body
                    else {
                        return Err(invalid("group membership requires member_joined"));
                    };
                    Ok(Lookup {
                        root: actor_principal_commitment.clone(),
                        device: event.actor_device_id,
                        url: wrapper.actor_manifest_url.filter(|url| !url.is_empty()),
                    })
                })
                .transpose()?
        };
        Ok(LegacyGroupRequest::Control { lookup })
    }

    pub(super) fn prepare_legacy_group_with_directory(
        &self,
        config: &GatewaySessionConfig,
        opened: &Opened,
        entry: &GatewayInboxEntry,
        evidence: &LegacyGroupDirectory,
    ) -> Result<Option<(ramflux_protocol::GroupEvent, String)>, SdkError> {
        // Recompute permission, route, recipient and the selected directory on fresh state.
        let current = self.legacy_group_directory_request(
            entry,
            &opened.routing,
            &opened.body,
            &config.device_id,
        )?;
        let LegacyGroupRequest::Control { lookup } = current else {
            return Err(invalid("prepared group control route changed"));
        };
        if lookup != evidence.lookup {
            return Err(SdkError::InboundPending("group directory changed before commit".into()));
        }
        if let Some(lookup) = &lookup {
            let manifest = evidence.manifest.as_ref().ok_or_else(|| {
                SdkError::InboundPending("group directory must be prepared".into())
            })?;
            let manifest = self.accept_fetched_device_manifest(
                manifest.clone(),
                &lookup.root,
                "group.receive",
            )?;
            let actor = manifest
                .devices
                .iter()
                .find(|device| device.device_id == lookup.device)
                .ok_or_else(|| invalid("group device absent from verified manifest"))?;
            if let Ok(wrapper) =
                serde_json::from_slice::<SdkGroupSenderKeyDistributionEnvelope>(&opened.body)
                && let Some(event) = Self::sender_key_membership_event(&config.device_id, &wrapper)?
            {
                let result = Self::verify_sender_key_membership_actor(event, actor)?;
                if serde_json::to_value(&result.0.body)?
                    .get("group_id")
                    .and_then(serde_json::Value::as_str)
                    != opened.routing.group_id.as_deref()
                {
                    return Err(invalid("group membership routing mismatch"));
                }
                return Ok(Some(result));
            }
        }
        Ok(None)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Atomic signed group bootstrap and issuer-only current sender-key material.
use super::invalid;
use crate::prelude::*;
use ramflux_crypto::{VerifiedGroupState, verify_group_state_snapshot};
use ramflux_protocol::group_state::GroupStateSnapshot;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub(crate) const PACKET_SCHEMA: &str = "ramflux.sdk.group_state.v1";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SharedGroupPacket {
    schema: String,
    snapshot_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    distribution_base64: Option<Zeroizing<String>>,
}
pub(crate) struct PreparedSharedGroup {
    state: VerifiedGroupState,
    distribution: Option<Zeroizing<Vec<u8>>>,
}
fn packet(state: &VerifiedGroupState) -> Result<SharedGroupPacket, SdkError> {
    Ok(SharedGroupPacket {
        schema: PACKET_SCHEMA.into(),
        snapshot_base64: ramflux_protocol::encode_base64url(
            ramflux_protocol::canonical_json_bytes(state.snapshot())?,
        ),
        distribution_base64: None,
    })
}
pub(crate) fn packet_bytes(state: &VerifiedGroupState) -> Result<Vec<u8>, SdkError> {
    Ok(serde_json::to_vec(&packet(state)?)?)
}
pub(crate) fn decode_packet(bytes: &[u8]) -> Result<Option<VerifiedGroupState>, SdkError> {
    if bytes.len() > ramflux_protocol::group_state::MAX_GROUP_STATE_BYTES * 2 {
        return Err(invalid("group state packet exceeds its byte budget"));
    }
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Ok(None);
    };
    if header["schema"] != PACKET_SCHEMA {
        return Ok(None);
    }
    let packet: SharedGroupPacket = ramflux_protocol::parse_i_json(bytes)?;
    let bytes = ramflux_protocol::decode_base64url(&packet.snapshot_base64)
        .map_err(|_| invalid("invalid group state encoding"))?;
    Ok(Some(verify_group_state_snapshot(GroupStateSnapshot::from_wire_bytes(&bytes)?)?))
}
impl RamfluxClient {
    pub(crate) fn shared_group_packet(
        &self,
        state: &VerifiedGroupState,
        recipient_is_member: bool,
    ) -> Result<Vec<u8>, SdkError> {
        let own = self.owned_device_identity()?;
        if !recipient_is_member
            || state.view().effective_role(own.root_commitment(), own.device_id()).is_none()
        {
            return packet_bytes(state);
        }
        if self.group_state(&state.view().group_id)?.group_epoch != state.view().epoch {
            return Err(SdkError::InboundPending(
                "group bootstrap state advanced before sealing".into(),
            ));
        }
        let mut packet = packet(state)?;
        packet.distribution_base64 =
            Some(Zeroizing::new(ramflux_protocol::encode_base64url(Zeroizing::new(
                self.export_group_sender_key_distribution(&state.view().group_id, own.device_id())?,
            ))));
        Ok(serde_json::to_vec(&packet)?)
    }
    pub(crate) async fn prepare_shared_group_receive(
        &self,
        engine: &GatewaySessionEngine,
        opened: &crate::client::routed::Opened,
        entry: &GatewayInboxEntry,
        body: &[u8],
    ) -> Result<Option<PreparedSharedGroup>, SdkError> {
        if opened.routing.kind != crate::client::routed::Kind::GroupControl {
            return Ok(None);
        }
        let Some(state) = decode_packet(body)? else { return Ok(None) };
        if opened.routing.group_id.as_deref() != Some(state.view().group_id.as_str())
            || opened.routing.conversation_id != state.view().conversation_id
        {
            return Err(invalid("group state routing mismatch"));
        }
        self.verify_shared_group_source(&engine.config, &state, entry).await?;
        self.authenticated_envelope_sender(entry)?;
        self.prepare_shared_group_payload(state, body).map(Some)
    }
    pub(super) fn prepare_shared_group_payload(
        &self,
        state: VerifiedGroupState,
        body: &[u8],
    ) -> Result<PreparedSharedGroup, SdkError> {
        let packet: SharedGroupPacket = ramflux_protocol::parse_i_json(body)?;
        let distribution = packet
            .distribution_base64
            .map(|encoded| {
                if encoded.len() > 4096 {
                    return Err(invalid("group bootstrap key exceeds byte budget"));
                }
                let bytes = Zeroizing::new(
                    ramflux_protocol::decode_base64url(&encoded)
                        .map_err(|_| invalid("invalid group bootstrap key encoding"))?,
                );
                let parsed: SdkGroupSenderKeyDistribution = ramflux_protocol::parse_i_json(&bytes)?;
                let issuer = &state.snapshot().issuer.identity;
                let source =
                    self.device_identity_for_root(&issuer.root_commitment, &issuer.device_id)?;
                let trusted = self.trusted_device(&source)?;
                if parsed.schema != "ramflux.sdk.group_sender_key.distribution.v2"
                    || parsed.version != 2
                    || parsed.group_id != state.view().group_id
                    || parsed.group_key_epoch != state.view().epoch
                    || parsed.sender_id != issuer.device_id
                    || parsed.sender_device_signing_public_key.as_deref()
                        != Some(issuer.signing_public_key.as_str())
                    || trusted["principal_id"] != issuer.principal_id
                    || trusted["signing_public_key"] != issuer.signing_public_key
                {
                    return Err(invalid(
                        "group bootstrap key is not from the authenticated issuer",
                    ));
                }
                Ok(bytes)
            })
            .transpose()?;
        Ok(PreparedSharedGroup { state, distribution })
    }
    pub(crate) fn apply_prepared_shared_group(
        &self,
        prepared: &PreparedSharedGroup,
        local_target: &str,
    ) -> Result<bool, SdkError> {
        let state = &prepared.state;
        if self
            .account_db()?
            .group_snapshot_epoch(&state.view().group_id)?
            .is_some_and(|epoch| epoch > state.view().epoch)
        {
            return Ok(false);
        }
        self.account_db()?.write_transaction(|| {
            let changed = self.accept_shared_group_state(state, local_target)?;
            let local = self.owned_device_identity()?;
            if let Some(bytes) = &prepared.distribution
                && state.view().effective_role(local.root_commitment(), local.device_id()).is_some()
            {
                let distribution: SdkGroupSenderKeyDistribution =
                    ramflux_protocol::parse_i_json(bytes)?;
                let issuer = &state.snapshot().issuer.identity;
                let source =
                    self.device_identity_for_root(&issuer.root_commitment, &issuer.device_id)?;
                let checkpoint = group_sender_key_checkpoint_name(
                    &distribution.group_id,
                    &source,
                    distribution.group_key_epoch,
                    "recv",
                )?;
                if self.projection_checkpoint(&checkpoint)?.is_some() {
                    let existing = self.load_group_sender_key_state(
                        &distribution.group_id,
                        &source,
                        distribution.group_key_epoch,
                        "recv",
                    )?;
                    if existing.session_snapshot.root_key_bytes() != distribution.sender_key_seed {
                        return Err(invalid("group bootstrap key changed within the same epoch"));
                    }
                } else {
                    self.import_group_key_for_identity(bytes, &source, false)?;
                }
            }
            Ok(changed)
        })
    }
}

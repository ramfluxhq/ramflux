// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed content discriminator and untouched protocol payload bytes inside ordinary E2EE.
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{RpcKind, SurfaceAction, SurfaceEvent, SurfaceRpc};
use serde::{Deserialize, Serialize};
pub(crate) const MAX_CARRIER_BYTES: usize = 1024 * 1024;
pub(crate) const PREFIX: &[u8] = b"ramflux.surface.v2\n";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PayloadKind {
    Event,
    Action,
    ActionReceipt,
    FunctionCall,
    FunctionResponse,
    Error,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Carrier {
    pub schema: String,
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posted_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    pub payload_kind: PayloadKind,
    pub conversation_id: String,
    pub surface_id: String,
    pub message_id: String,
    pub sender_principal_id: String,
    pub sender_device_id: String,
    pub author_principal_id: String,
    pub wire_base64: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<super::SnapshotProof>,
}
#[derive(Serialize)]
struct Signing {
    domain: &'static str,
    body: serde_json::Value,
}
impl PayloadKind {
    pub(crate) const fn rpc_kind(&self) -> Option<RpcKind> {
        match self {
            Self::FunctionCall => Some(RpcKind::FunctionCall),
            Self::FunctionResponse => Some(RpcKind::FunctionResponse),
            Self::Error => Some(RpcKind::Error),
            _ => None,
        }
    }
}
pub(crate) enum Payload {
    Event(SurfaceEvent),
    Action(SurfaceAction),
    Rpc(RpcKind, SurfaceRpc),
    ActionReceipt { original: Box<Carrier>, action: SurfaceAction },
}
impl Carrier {
    fn signing(&self) -> Result<Signing, SdkError> {
        let mut value = serde_json::to_value(self)?;
        if let Some(object) = value.as_object_mut() {
            object.remove("signature");
        }
        Ok(Signing { domain: ramflux_protocol::domain::SURFACE_CARRIER, body: value })
    }
    pub fn payload(&self) -> Result<Payload, SdkError> {
        let bytes = ramflux_protocol::decode_base64url(&self.wire_base64)
            .map_err(|_| invalid("invalid surface wire encoding"))?;
        let payload = match self.payload_kind {
            PayloadKind::Event => Payload::Event(SurfaceEvent::from_wire_bytes(&bytes)?),
            PayloadKind::Action => Payload::Action(SurfaceAction::from_wire_bytes(&bytes)?),
            PayloadKind::FunctionCall | PayloadKind::FunctionResponse | PayloadKind::Error => {
                let kind =
                    self.payload_kind.rpc_kind().ok_or_else(|| invalid("RPC kind missing"))?;
                Payload::Rpc(kind, SurfaceRpc::from_wire_bytes(&bytes, kind)?)
            }
            PayloadKind::ActionReceipt => {
                let original = Self::decode(&bytes)?
                    .ok_or_else(|| invalid("action receipt lacks original carrier"))?;
                if original.payload_kind != PayloadKind::Action
                    || original.author_principal_id != self.author_principal_id
                {
                    return Err(invalid("action receipt binding mismatch"));
                }
                let Payload::Action(action) = original.payload()? else {
                    return Err(invalid("action receipt payload mismatch"));
                };
                Payload::ActionReceipt { original: Box::new(original), action }
            }
        };
        if (self.payload_kind == PayloadKind::Action || self.payload_kind.rpc_kind().is_some())
            && self.snapshot.is_some()
        {
            return Err(invalid("actions cannot carry state attestations"));
        }
        if let Payload::Event(event) = &payload {
            if self.snapshot.is_some() {
                return Err(invalid("event proofs belong in the v3 resync frame"));
            }
            if event.is_resync() {
                ramflux_protocol::SurfaceState::validate_proof(event)?;
            }
        }
        let (conversation, surface) = match &payload {
            Payload::Event(event) => (event.conversation_id(), event.surface_id()),
            Payload::Rpc(_, rpc) => (&rpc.frame().conversation_id, &rpc.frame().surface_id),
            Payload::Action(action) | Payload::ActionReceipt { action, .. } => {
                (action.conversation_id(), action.surface_id())
            }
        };
        if let (Some(proof), Payload::ActionReceipt { action, .. }) = (&self.snapshot, &payload) {
            proof.restore(self, &ramflux_protocol::SurfaceState::default(), action.version())?;
        }
        if self.schema != ramflux_protocol::domain::SURFACE_CARRIER
            || self.content_type != "surface"
            || conversation != self.conversation_id
            || surface != self.surface_id
            || self.message_id.is_empty()
            || self.message_id.len() > 256
        {
            return Err(invalid("invalid surface carrier binding"));
        }
        Ok(payload)
    }
    pub fn bytes(&self) -> Result<Vec<u8>, SdkError> {
        let mut bytes = PREFIX.to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        Ok(bytes)
    }
    fn validate_identifiers(&self) -> Result<(), SdkError> {
        if [self.posted_at, self.updated_at]
            .into_iter()
            .flatten()
            .any(|at| !(0..=253_402_300_799).contains(&at))
            || self.posted_at.zip(self.updated_at).is_some_and(|(posted, updated)| posted > updated)
        {
            return Err(invalid("surface display timestamp is outside the supported range"));
        }

        for id in [
            &self.conversation_id,
            &self.surface_id,
            &self.message_id,
            &self.sender_principal_id,
            &self.sender_device_id,
            &self.author_principal_id,
        ] {
            if id.is_empty() || id.len() > 256 {
                return Err(invalid("surface carrier identifier exceeds budget"));
            }
        }
        Ok(())
    }
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, SdkError> {
        let Some(json) = bytes.strip_prefix(PREFIX) else {
            return Ok(None);
        };
        if bytes.len() > MAX_CARRIER_BYTES {
            return Err(invalid("surface carrier exceeds byte budget"));
        }
        let carrier: Self = ramflux_protocol::parse_i_json(json)?;
        if (carrier.payload_kind == PayloadKind::Action && bytes.len() > 256 * 1024)
            || (carrier.payload_kind == PayloadKind::Event && bytes.len() > 512 * 1024)
        {
            return Err(invalid("surface action carrier exceeds byte budget"));
        }
        carrier.validate_identifiers()?;
        Ok(Some(carrier))
    }
}
pub(crate) fn invalid(message: &str) -> SdkError {
    SdkError::LocalBus(message.into())
}
impl RamfluxClient {
    pub(crate) fn sign_surface_carrier(&self, mut carrier: Carrier) -> Result<Carrier, SdkError> {
        carrier.payload()?;
        let device = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if carrier.sender_principal_id != device.principal_id
            || carrier.sender_device_id != device.device_id
        {
            return Err(invalid("surface carrier source mismatch"));
        }
        let prior = self.account_db()?.client_record("surface", &carrier.surface_reference()?)?;
        if carrier.posted_at.is_none() {
            carrier.posted_at = prior.as_ref().and_then(|v| v["created_at"].as_i64());
            if carrier.posted_at.is_none()
                && matches!(carrier.payload()?, Payload::Event(event) if event.version()==1 && event.is_create())
            {
                carrier.posted_at = Some(crate::prelude::now_unix_timestamp());
            }
        }
        carrier.updated_at = Some(
            carrier
                .updated_at
                .unwrap_or_else(crate::prelude::now_unix_timestamp)
                .max(carrier.posted_at.unwrap_or(0))
                .max(prior.as_ref().and_then(|v| v["updated_at"].as_i64()).unwrap_or(0)),
        );
        carrier.signature = ramflux_crypto::sign_with_device_branch(device, &carrier.signing()?)?;
        // Apply the same transport budget before sending as on receive.
        if carrier.bytes()?.len()
            > match carrier.payload_kind {
                PayloadKind::Action => 256 * 1024,
                PayloadKind::Event => 512 * 1024,
                PayloadKind::ActionReceipt
                | PayloadKind::FunctionCall
                | PayloadKind::FunctionResponse
                | PayloadKind::Error => MAX_CARRIER_BYTES,
            }
        {
            return Err(invalid("surface carrier exceeds byte budget"));
        }
        carrier.validate_identifiers()?;
        Ok(carrier)
    }
    pub(crate) fn verify_surface_carrier(
        &self,
        carrier: &Carrier,
        principal: &str,
        device: &str,
    ) -> Result<Payload, SdkError> {
        if carrier.sender_principal_id != principal || carrier.sender_device_id != device {
            return Err(invalid("surface carrier differs from authenticated sender"));
        }
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let public = if device == local.device_id && principal == local.principal_id {
            ramflux_protocol::encode_base64url(local.signing_key.verifying_key().to_bytes())
        } else {
            let record = self.surface_signer_record(principal, device)?;
            if record["principal_id"] != principal {
                return Err(invalid("surface signer principal mismatch"));
            }
            record["signing_public_key"]
                .as_str()
                .ok_or_else(|| invalid("surface signer key missing"))?
                .to_owned()
        };
        ramflux_crypto::verify_device_branch_signature(
            &public,
            &carrier.signing()?,
            &carrier.signature,
        )?;
        let payload = carrier.payload()?;
        Ok(payload)
    }
}

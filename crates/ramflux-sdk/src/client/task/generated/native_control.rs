// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Lossless native control fields; callers retain membership, signer and decision admission.
use super::{g, invalid};
use crate::SdkError;
use crate::client::task::{
    carrier::Carrier,
    control::{Ack, Control},
};

impl Ack {
    pub(crate) fn to_generated(&self) -> Result<g::TaskAck, SdkError> {
        Ok(g::TaskAck {
            carrier: Some(self.original()?.to_generated()?),
            certificate: Some(g::TaskCertificate::try_from(&self.certificate)?),
            manifests: self
                .manifests
                .iter()
                .map(g::NativeDeviceManifest::try_from)
                .collect::<Result<_, _>>()?,
            signer_principal: self.signer_principal.clone(),
            signer_device: self.signer_device.clone(),
            signature: self.signature.clone(),
        })
    }
    pub(crate) fn from_generated(value: &g::TaskAck) -> Result<Self, SdkError> {
        let carrier = Carrier::from_generated(
            value.carrier.as_ref().ok_or_else(|| invalid("task ack carrier missing"))?,
        )?;
        Ok(Self {
            carrier_base64: ramflux_protocol::encode_base64url(carrier.bytes()?),
            certificate: super::certificate::native_certificate(
                value
                    .certificate
                    .as_ref()
                    .ok_or_else(|| invalid("task ack certificate missing"))?,
            )?,
            manifests: value
                .manifests
                .iter()
                .map(super::manifest::generated_manifest_fields)
                .collect::<Result<_, _>>()?,
            signer_principal: value.signer_principal.clone(),
            signer_device: value.signer_device.clone(),
            signature: value.signature.clone(),
        })
    }
}

impl Control {
    pub(crate) fn to_generated(&self) -> Result<g::TaskControl, SdkError> {
        let value = match self {
            Self::Intent { carrier_base64 } => {
                let bytes = ramflux_protocol::decode_base64url(carrier_base64)
                    .map_err(|_| invalid("task intent encoding"))?;
                let carrier = Carrier::decode(&bytes)?
                    .ok_or_else(|| invalid("task intent carrier missing"))?;
                g::task_control::Value::Intent(g::TaskControlIntent {
                    carrier: Some(carrier.to_generated()?),
                })
            }
            Self::Ack(value) => g::task_control::Value::Ack(g::TaskControlAck {
                value: Some(value.to_generated()?),
            }),
        };
        Ok(g::TaskControl { value: Some(value) })
    }
    pub(crate) fn from_generated(value: &g::TaskControl) -> Result<Self, SdkError> {
        match value.value.as_ref().ok_or_else(|| invalid("task control choice missing"))? {
            g::task_control::Value::Intent(value) => {
                let carrier = Carrier::from_generated(
                    value.carrier.as_ref().ok_or_else(|| invalid("task intent carrier missing"))?,
                )?;
                Ok(Self::Intent {
                    carrier_base64: ramflux_protocol::encode_base64url(carrier.bytes()?),
                })
            }
            g::task_control::Value::Ack(value) => Ok(Self::Ack(Box::new(Ack::from_generated(
                value.value.as_ref().ok_or_else(|| invalid("task ack missing"))?,
            )?))),
        }
    }
}

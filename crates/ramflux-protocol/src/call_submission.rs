// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Calls carry a complete nullable submission body; ordinary submits keep their existing shape.

use crate::{CallSubmitContext, Envelope, SignedCallIntentV1, SignedRequest};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeMap};

pub struct CallSubmitCarrier {
    pub signed_request: SignedRequest,
    pub envelope: Envelope,
    pub call_intent: Option<Box<SignedCallIntentV1>>,
    pub wake_id: Option<String>,
    pub call_ref: Option<String>,
    pub call_terminal: Option<String>,
    pub call_context: Option<CallSubmitContext>,
}

pub struct CallSubmitCarrierRef<'a> {
    pub signed_request: &'a SignedRequest,
    pub envelope: &'a Envelope,
    pub call_intent: Option<&'a SignedCallIntentV1>,
    pub wake_id: Option<&'a str>,
    pub call_ref: Option<&'a str>,
    pub call_terminal: Option<&'a str>,
    pub call_context: Option<&'a CallSubmitContext>,
}
impl Serialize for CallSubmitCarrierRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let call = self.call_intent.is_some()
            || self.wake_id.is_some()
            || self.call_ref.is_some()
            || self.call_terminal.is_some()
            || self.call_context.is_some();
        let mut map = serializer.serialize_map(Some(if call { 7 } else { 2 }))?;
        map.serialize_entry("signed_request", self.signed_request)?;
        map.serialize_entry("envelope", self.envelope)?;
        if call {
            map.serialize_entry("call_intent", &self.call_intent)?;
            map.serialize_entry("wake_id", &self.wake_id)?;
            map.serialize_entry("call_ref", &self.call_ref)?;
            map.serialize_entry("call_terminal", &self.call_terminal)?;
            map.serialize_entry("call_context", &self.call_context)?;
        }
        map.end()
    }
}

#[derive(Default)]
enum Nullable<T> {
    #[default]
    Missing,
    Present(Option<T>),
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Nullable<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::Present(Option::<T>::deserialize(deserializer)?))
    }
}
impl<T> Nullable<T> {
    fn nonnull(&self) -> bool {
        matches!(self, Self::Present(Some(_)))
    }
    fn present(&self) -> bool {
        matches!(self, Self::Present(_))
    }
    fn value(self) -> Option<T> {
        match self {
            Self::Missing => None,
            Self::Present(value) => value,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCarrier {
    signed_request: SignedRequest,
    envelope: Envelope,
    #[serde(default)]
    call_intent: Nullable<Box<SignedCallIntentV1>>,
    #[serde(default)]
    wake_id: Nullable<String>,
    #[serde(default)]
    call_ref: Nullable<String>,
    #[serde(default)]
    call_terminal: Nullable<String>,
    #[serde(default)]
    call_context: Nullable<CallSubmitContext>,
}
impl<'de> Deserialize<'de> for CallSubmitCarrier {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawCarrier::deserialize(deserializer)?;
        let call = raw.call_intent.nonnull()
            || raw.wake_id.nonnull()
            || raw.call_ref.nonnull()
            || raw.call_terminal.nonnull()
            || raw.call_context.nonnull();
        if call
            && !(raw.call_intent.present()
                && raw.wake_id.present()
                && raw.call_ref.present()
                && raw.call_terminal.present()
                && raw.call_context.nonnull())
        {
            return Err(serde::de::Error::custom("complete call submission members required"));
        }
        let value = Self {
            signed_request: raw.signed_request,
            envelope: raw.envelope,
            call_intent: raw.call_intent.value(),
            wake_id: raw.wake_id.value(),
            call_ref: raw.call_ref.value(),
            call_terminal: raw.call_terminal.value(),
            call_context: raw.call_context.value(),
        };
        if call {
            let context = value
                .call_context
                .as_ref()
                .ok_or_else(|| serde::de::Error::custom("call context required"))?;
            context.validate().map_err(serde::de::Error::custom)?;
            if value.call_ref.as_ref() != Some(&context.call_ref)
                || value.signed_request.request_id != context.request_id
                || value.envelope.envelope_id != context.envelope_id
            {
                return Err(serde::de::Error::custom("call submission context mismatch"));
            }
        }
        Ok(value)
    }
}

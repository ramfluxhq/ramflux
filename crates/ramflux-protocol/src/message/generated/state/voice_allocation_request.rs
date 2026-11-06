// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct VoiceAllocationRequest {
    #[prost(string, tag = "1")]
    pub call_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub caller: ::core::option::Option<CallEndpoint>,
    #[prost(message, optional, tag = "3")]
    pub callee: ::core::option::Option<CallEndpoint>,
}
impl serde::Serialize for VoiceAllocationRequest {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.call_id.is_empty() {
            len += 1;
        }
        if self.caller.is_some() {
            len += 1;
        }
        if self.callee.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.VoiceAllocationRequest", len)?;
        if !self.call_id.is_empty() {
            struct_ser.serialize_field("callId", &self.call_id)?;
        }
        if let Some(v) = self.caller.as_ref() {
            struct_ser.serialize_field("caller", v)?;
        }
        if let Some(v) = self.callee.as_ref() {
            struct_ser.serialize_field("callee", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for VoiceAllocationRequest {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["call_id", "callId", "caller", "callee"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            CallId,
            Caller,
            Callee,
        }
        impl<'de> serde::Deserialize<'de> for GeneratedField {
            fn deserialize<D>(deserializer: D) -> std::result::Result<GeneratedField, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct GeneratedVisitor;
                impl serde::de::Visitor<'_> for GeneratedVisitor {
                    type Value = GeneratedField;
                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        write!(formatter, "expected one of: {:?}", &FIELDS)
                    }
                    #[allow(unused_variables)]
                    fn visit_str<E>(self, value: &str) -> std::result::Result<GeneratedField, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "callId" | "call_id" => Ok(GeneratedField::CallId),
                            "caller" => Ok(GeneratedField::Caller),
                            "callee" => Ok(GeneratedField::Callee),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = VoiceAllocationRequest;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.VoiceAllocationRequest")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<VoiceAllocationRequest, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut call_id__ = None;
                let mut caller__ = None;
                let mut callee__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::CallId => {
                            if call_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("callId"));
                            }
                            call_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Caller => {
                            if caller__.is_some() {
                                return Err(serde::de::Error::duplicate_field("caller"));
                            }
                            caller__ = map_.next_value()?;
                        }
                        GeneratedField::Callee => {
                            if callee__.is_some() {
                                return Err(serde::de::Error::duplicate_field("callee"));
                            }
                            callee__ = map_.next_value()?;
                        }
                    }
                }
                Ok(VoiceAllocationRequest {
                    call_id: call_id__.unwrap_or_default(),
                    caller: caller__,
                    callee: callee__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.VoiceAllocationRequest",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

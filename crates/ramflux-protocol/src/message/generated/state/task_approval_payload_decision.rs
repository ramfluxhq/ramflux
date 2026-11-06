// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaskApprovalPayloadDecision {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<TaskApprovalRequest>,
    #[prost(bool, tag = "2")]
    pub approved: bool,
    #[prost(string, optional, tag = "3")]
    pub grant_signature: ::core::option::Option<::prost::alloc::string::String>,
}
impl serde::Serialize for TaskApprovalPayloadDecision {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.request.is_some() {
            len += 1;
        }
        if self.approved {
            len += 1;
        }
        if self.grant_signature.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.TaskApprovalPayloadDecision", len)?;
        if let Some(v) = self.request.as_ref() {
            struct_ser.serialize_field("request", v)?;
        }
        if self.approved {
            struct_ser.serialize_field("approved", &self.approved)?;
        }
        if let Some(v) = self.grant_signature.as_ref() {
            struct_ser.serialize_field("grantSignature", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TaskApprovalPayloadDecision {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["request", "approved", "grant_signature", "grantSignature"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Request,
            Approved,
            GrantSignature,
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
                            "request" => Ok(GeneratedField::Request),
                            "approved" => Ok(GeneratedField::Approved),
                            "grantSignature" | "grant_signature" => {
                                Ok(GeneratedField::GrantSignature)
                            }
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TaskApprovalPayloadDecision;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.TaskApprovalPayloadDecision")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<TaskApprovalPayloadDecision, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut request__ = None;
                let mut approved__ = None;
                let mut grant_signature__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Request => {
                            if request__.is_some() {
                                return Err(serde::de::Error::duplicate_field("request"));
                            }
                            request__ = map_.next_value()?;
                        }
                        GeneratedField::Approved => {
                            if approved__.is_some() {
                                return Err(serde::de::Error::duplicate_field("approved"));
                            }
                            approved__ = Some(map_.next_value()?);
                        }
                        GeneratedField::GrantSignature => {
                            if grant_signature__.is_some() {
                                return Err(serde::de::Error::duplicate_field("grantSignature"));
                            }
                            grant_signature__ = map_.next_value()?;
                        }
                    }
                }
                Ok(TaskApprovalPayloadDecision {
                    request: request__,
                    approved: approved__.unwrap_or_default(),
                    grant_signature: grant_signature__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.TaskApprovalPayloadDecision",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

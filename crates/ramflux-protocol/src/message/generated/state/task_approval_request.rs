// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaskApprovalRequest {
    #[prost(message, optional, tag = "1")]
    pub binding: ::core::option::Option<TaskApprovalBinding>,
    #[prost(message, optional, tag = "2")]
    pub approval: ::core::option::Option<LocalMcpApprovalRecord>,
    #[prost(message, optional, tag = "3")]
    pub grant_body: ::core::option::Option<LocalMcpGrantSigningBody>,
}
impl serde::Serialize for TaskApprovalRequest {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.binding.is_some() {
            len += 1;
        }
        if self.approval.is_some() {
            len += 1;
        }
        if self.grant_body.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.TaskApprovalRequest", len)?;
        if let Some(v) = self.binding.as_ref() {
            struct_ser.serialize_field("binding", v)?;
        }
        if let Some(v) = self.approval.as_ref() {
            struct_ser.serialize_field("approval", v)?;
        }
        if let Some(v) = self.grant_body.as_ref() {
            struct_ser.serialize_field("grantBody", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TaskApprovalRequest {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["binding", "approval", "grant_body", "grantBody"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Binding,
            Approval,
            GrantBody,
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
                            "binding" => Ok(GeneratedField::Binding),
                            "approval" => Ok(GeneratedField::Approval),
                            "grantBody" | "grant_body" => Ok(GeneratedField::GrantBody),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TaskApprovalRequest;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.TaskApprovalRequest")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TaskApprovalRequest, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut binding__ = None;
                let mut approval__ = None;
                let mut grant_body__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Binding => {
                            if binding__.is_some() {
                                return Err(serde::de::Error::duplicate_field("binding"));
                            }
                            binding__ = map_.next_value()?;
                        }
                        GeneratedField::Approval => {
                            if approval__.is_some() {
                                return Err(serde::de::Error::duplicate_field("approval"));
                            }
                            approval__ = map_.next_value()?;
                        }
                        GeneratedField::GrantBody => {
                            if grant_body__.is_some() {
                                return Err(serde::de::Error::duplicate_field("grantBody"));
                            }
                            grant_body__ = map_.next_value()?;
                        }
                    }
                }
                Ok(TaskApprovalRequest {
                    binding: binding__,
                    approval: approval__,
                    grant_body: grant_body__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.TaskApprovalRequest",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

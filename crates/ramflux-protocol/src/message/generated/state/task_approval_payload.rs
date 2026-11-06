// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaskApprovalPayload {
    #[prost(oneof = "task_approval_payload::Value", tags = "1, 2")]
    pub value: ::core::option::Option<task_approval_payload::Value>,
}
/// Nested message and enum types in `TaskApprovalPayload`.
pub mod task_approval_payload {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Value {
        #[prost(message, tag = "1")]
        Request(super::TaskApprovalPayloadRequest),
        #[prost(message, tag = "2")]
        Decision(super::TaskApprovalPayloadDecision),
    }
}
impl serde::Serialize for TaskApprovalPayload {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.value.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.TaskApprovalPayload", len)?;
        if let Some(v) = self.value.as_ref() {
            match v {
                task_approval_payload::Value::Request(v) => {
                    struct_ser.serialize_field("request", v)?;
                }
                task_approval_payload::Value::Decision(v) => {
                    struct_ser.serialize_field("decision", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TaskApprovalPayload {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["request", "decision"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Request,
            Decision,
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
                            "decision" => Ok(GeneratedField::Decision),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TaskApprovalPayload;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.TaskApprovalPayload")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TaskApprovalPayload, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut value__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Request => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("request"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task_approval_payload::Value::Request);
                        }
                        GeneratedField::Decision => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("decision"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task_approval_payload::Value::Decision);
                        }
                    }
                }
                Ok(TaskApprovalPayload { value: value__ })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.TaskApprovalPayload",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaskEventBody {
    #[prost(oneof = "task_event_body::Value", tags = "1, 2, 3, 4, 5, 6, 7")]
    pub value: ::core::option::Option<task_event_body::Value>,
}
/// Nested message and enum types in `TaskEventBody`.
pub mod task_event_body {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Value {
        #[prost(message, tag = "1")]
        Start(super::TaskEventBodyStart),
        #[prost(message, tag = "2")]
        Proposal(super::TaskEventBodyProposal),
        #[prost(message, tag = "3")]
        Accept(super::TaskEventBodyAccept),
        #[prost(message, tag = "4")]
        Decline(super::TaskEventBodyDecline),
        #[prost(message, tag = "5")]
        Update(super::TaskEventBodyUpdate),
        #[prost(message, tag = "6")]
        Cancel(super::TaskEventBodyCancel),
        #[prost(message, tag = "7")]
        Resolve(super::TaskEventBodyResolve),
    }
}
impl serde::Serialize for TaskEventBody {
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
            serializer.serialize_struct("ramflux.message.v1.TaskEventBody", len)?;
        if let Some(v) = self.value.as_ref() {
            match v {
                task_event_body::Value::Start(v) => {
                    struct_ser.serialize_field("start", v)?;
                }
                task_event_body::Value::Proposal(v) => {
                    struct_ser.serialize_field("proposal", v)?;
                }
                task_event_body::Value::Accept(v) => {
                    struct_ser.serialize_field("accept", v)?;
                }
                task_event_body::Value::Decline(v) => {
                    struct_ser.serialize_field("decline", v)?;
                }
                task_event_body::Value::Update(v) => {
                    struct_ser.serialize_field("update", v)?;
                }
                task_event_body::Value::Cancel(v) => {
                    struct_ser.serialize_field("cancel", v)?;
                }
                task_event_body::Value::Resolve(v) => {
                    struct_ser.serialize_field("resolve", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TaskEventBody {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] =
            &["start", "proposal", "accept", "decline", "update", "cancel", "resolve"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Start,
            Proposal,
            Accept,
            Decline,
            Update,
            Cancel,
            Resolve,
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
                            "start" => Ok(GeneratedField::Start),
                            "proposal" => Ok(GeneratedField::Proposal),
                            "accept" => Ok(GeneratedField::Accept),
                            "decline" => Ok(GeneratedField::Decline),
                            "update" => Ok(GeneratedField::Update),
                            "cancel" => Ok(GeneratedField::Cancel),
                            "resolve" => Ok(GeneratedField::Resolve),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TaskEventBody;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.TaskEventBody")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TaskEventBody, V::Error>
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
                        GeneratedField::Start => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("start"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task_event_body::Value::Start);
                        }
                        GeneratedField::Proposal => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("proposal"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task_event_body::Value::Proposal);
                        }
                        GeneratedField::Accept => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("accept"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task_event_body::Value::Accept);
                        }
                        GeneratedField::Decline => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("decline"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task_event_body::Value::Decline);
                        }
                        GeneratedField::Update => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("update"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task_event_body::Value::Update);
                        }
                        GeneratedField::Cancel => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("cancel"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task_event_body::Value::Cancel);
                        }
                        GeneratedField::Resolve => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("resolve"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task_event_body::Value::Resolve);
                        }
                    }
                }
                Ok(TaskEventBody { value: value__ })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.TaskEventBody",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

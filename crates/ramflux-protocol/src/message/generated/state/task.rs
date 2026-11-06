// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Task {
    #[prost(oneof = "task::Payload", tags = "16, 17, 18, 19")]
    pub payload: ::core::option::Option<task::Payload>,
}
/// Nested message and enum types in `Task`.
pub mod task {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Payload {
        #[prost(message, tag = "16")]
        Carrier(super::TaskCarrier),
        #[prost(message, tag = "17")]
        Approval(super::TaskApprovalPacket),
        #[prost(message, tag = "18")]
        Control(super::TaskControl),
        #[prost(message, tag = "19")]
        OwnHistory(super::TaskHistoryExport),
    }
}
impl serde::Serialize for Task {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.payload.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.Task", len)?;
        if let Some(v) = self.payload.as_ref() {
            match v {
                task::Payload::Carrier(v) => {
                    struct_ser.serialize_field("carrier", v)?;
                }
                task::Payload::Approval(v) => {
                    struct_ser.serialize_field("approval", v)?;
                }
                task::Payload::Control(v) => {
                    struct_ser.serialize_field("control", v)?;
                }
                task::Payload::OwnHistory(v) => {
                    struct_ser.serialize_field("ownHistory", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Task {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["carrier", "approval", "control", "own_history", "ownHistory"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Carrier,
            Approval,
            Control,
            OwnHistory,
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
                            "carrier" => Ok(GeneratedField::Carrier),
                            "approval" => Ok(GeneratedField::Approval),
                            "control" => Ok(GeneratedField::Control),
                            "ownHistory" | "own_history" => Ok(GeneratedField::OwnHistory),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Task;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.Task")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Task, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut payload__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Carrier => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("carrier"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task::Payload::Carrier);
                        }
                        GeneratedField::Approval => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("approval"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task::Payload::Approval);
                        }
                        GeneratedField::Control => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("control"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task::Payload::Control);
                        }
                        GeneratedField::OwnHistory => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ownHistory"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task::Payload::OwnHistory);
                        }
                    }
                }
                Ok(Task { payload: payload__ })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.Task", FIELDS, GeneratedVisitor)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaskControl {
    #[prost(oneof = "task_control::Value", tags = "1, 2")]
    pub value: ::core::option::Option<task_control::Value>,
}
/// Nested message and enum types in `TaskControl`.
pub mod task_control {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Value {
        #[prost(message, tag = "1")]
        Intent(super::TaskControlIntent),
        #[prost(message, tag = "2")]
        Ack(super::TaskControlAck),
    }
}
impl serde::Serialize for TaskControl {
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
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.TaskControl", len)?;
        if let Some(v) = self.value.as_ref() {
            match v {
                task_control::Value::Intent(v) => {
                    struct_ser.serialize_field("intent", v)?;
                }
                task_control::Value::Ack(v) => {
                    struct_ser.serialize_field("ack", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TaskControl {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["intent", "ack"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Intent,
            Ack,
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
                            "intent" => Ok(GeneratedField::Intent),
                            "ack" => Ok(GeneratedField::Ack),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TaskControl;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.TaskControl")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TaskControl, V::Error>
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
                        GeneratedField::Intent => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("intent"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task_control::Value::Intent);
                        }
                        GeneratedField::Ack => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ack"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(task_control::Value::Ack);
                        }
                    }
                }
                Ok(TaskControl { value: value__ })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.TaskControl", FIELDS, GeneratedVisitor)
    }
}

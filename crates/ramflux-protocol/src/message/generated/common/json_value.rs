// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JsonValue {
    #[prost(oneof = "json_value::Value", tags = "1, 2, 3, 4, 5, 6")]
    pub value: ::core::option::Option<json_value::Value>,
}
/// Nested message and enum types in `JsonValue`.
pub mod json_value {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Value {
        #[prost(message, tag = "1")]
        Null(super::JsonNull),
        #[prost(bool, tag = "2")]
        Boolean(bool),
        #[prost(string, tag = "3")]
        Number(::prost::alloc::string::String),
        #[prost(string, tag = "4")]
        Text(::prost::alloc::string::String),
        #[prost(message, tag = "5")]
        Array(super::JsonArray),
        #[prost(message, tag = "6")]
        Object(super::JsonObject),
    }
}
impl serde::Serialize for JsonValue {
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
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.JsonValue", len)?;
        if let Some(v) = self.value.as_ref() {
            match v {
                json_value::Value::Null(v) => {
                    struct_ser.serialize_field("null", v)?;
                }
                json_value::Value::Boolean(v) => {
                    struct_ser.serialize_field("boolean", v)?;
                }
                json_value::Value::Number(v) => {
                    struct_ser.serialize_field("number", v)?;
                }
                json_value::Value::Text(v) => {
                    struct_ser.serialize_field("text", v)?;
                }
                json_value::Value::Array(v) => {
                    struct_ser.serialize_field("array", v)?;
                }
                json_value::Value::Object(v) => {
                    struct_ser.serialize_field("object", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for JsonValue {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["null", "boolean", "number", "text", "array", "object"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Null,
            Boolean,
            Number,
            Text,
            Array,
            Object,
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
                            "null" => Ok(GeneratedField::Null),
                            "boolean" => Ok(GeneratedField::Boolean),
                            "number" => Ok(GeneratedField::Number),
                            "text" => Ok(GeneratedField::Text),
                            "array" => Ok(GeneratedField::Array),
                            "object" => Ok(GeneratedField::Object),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = JsonValue;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.JsonValue")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<JsonValue, V::Error>
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
                        GeneratedField::Null => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("null"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(json_value::Value::Null);
                        }
                        GeneratedField::Boolean => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("boolean"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(json_value::Value::Boolean);
                        }
                        GeneratedField::Number => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("number"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(json_value::Value::Number);
                        }
                        GeneratedField::Text => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("text"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(json_value::Value::Text);
                        }
                        GeneratedField::Array => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("array"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(json_value::Value::Array);
                        }
                        GeneratedField::Object => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("object"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(json_value::Value::Object);
                        }
                    }
                }
                Ok(JsonValue { value: value__ })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.JsonValue", FIELDS, GeneratedVisitor)
    }
}

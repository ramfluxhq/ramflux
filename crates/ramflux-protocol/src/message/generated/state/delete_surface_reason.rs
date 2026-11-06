// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, Copy, PartialEq, Eq, Hash, ::prost::Message)]
pub struct DeleteSurfaceReason {
    #[prost(oneof = "delete_surface_reason::Value", tags = "1, 2, 3, 4, 5")]
    pub value: ::core::option::Option<delete_surface_reason::Value>,
}
/// Nested message and enum types in `DeleteSurfaceReason`.
pub mod delete_surface_reason {
    #[derive(Clone, Copy, PartialEq, Eq, Hash, ::prost::Oneof)]
    pub enum Value {
        #[prost(message, tag = "1")]
        Completed(super::DeleteSurfaceReasonCompleted),
        #[prost(message, tag = "2")]
        Cancelled(super::DeleteSurfaceReasonCancelled),
        #[prost(message, tag = "3")]
        Replaced(super::DeleteSurfaceReasonReplaced),
        #[prost(message, tag = "4")]
        Expired(super::DeleteSurfaceReasonExpired),
        #[prost(message, tag = "5")]
        Error(super::DeleteSurfaceReasonError),
    }
}
impl serde::Serialize for DeleteSurfaceReason {
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
            serializer.serialize_struct("ramflux.message.v1.DeleteSurfaceReason", len)?;
        if let Some(v) = self.value.as_ref() {
            match v {
                delete_surface_reason::Value::Completed(v) => {
                    struct_ser.serialize_field("completed", v)?;
                }
                delete_surface_reason::Value::Cancelled(v) => {
                    struct_ser.serialize_field("cancelled", v)?;
                }
                delete_surface_reason::Value::Replaced(v) => {
                    struct_ser.serialize_field("replaced", v)?;
                }
                delete_surface_reason::Value::Expired(v) => {
                    struct_ser.serialize_field("expired", v)?;
                }
                delete_surface_reason::Value::Error(v) => {
                    struct_ser.serialize_field("error", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for DeleteSurfaceReason {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["completed", "cancelled", "replaced", "expired", "error"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Completed,
            Cancelled,
            Replaced,
            Expired,
            Error,
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
                            "completed" => Ok(GeneratedField::Completed),
                            "cancelled" => Ok(GeneratedField::Cancelled),
                            "replaced" => Ok(GeneratedField::Replaced),
                            "expired" => Ok(GeneratedField::Expired),
                            "error" => Ok(GeneratedField::Error),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = DeleteSurfaceReason;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.DeleteSurfaceReason")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<DeleteSurfaceReason, V::Error>
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
                        GeneratedField::Completed => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("completed"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(delete_surface_reason::Value::Completed);
                        }
                        GeneratedField::Cancelled => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("cancelled"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(delete_surface_reason::Value::Cancelled);
                        }
                        GeneratedField::Replaced => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("replaced"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(delete_surface_reason::Value::Replaced);
                        }
                        GeneratedField::Expired => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("expired"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(delete_surface_reason::Value::Expired);
                        }
                        GeneratedField::Error => {
                            if value__.is_some() {
                                return Err(serde::de::Error::duplicate_field("error"));
                            }
                            value__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(delete_surface_reason::Value::Error);
                        }
                    }
                }
                Ok(DeleteSurfaceReason { value: value__ })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.DeleteSurfaceReason",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

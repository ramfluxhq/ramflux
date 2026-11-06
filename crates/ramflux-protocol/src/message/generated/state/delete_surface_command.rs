// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct DeleteSurfaceCommand {
    #[prost(string, tag = "1")]
    pub surface_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub reason: ::core::option::Option<DeleteSurfaceReason>,
}
impl serde::Serialize for DeleteSurfaceCommand {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.surface_id.is_empty() {
            len += 1;
        }
        if self.reason.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.DeleteSurfaceCommand", len)?;
        if !self.surface_id.is_empty() {
            struct_ser.serialize_field("surfaceId", &self.surface_id)?;
        }
        if let Some(v) = self.reason.as_ref() {
            struct_ser.serialize_field("reason", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for DeleteSurfaceCommand {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["surface_id", "surfaceId", "reason"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            SurfaceId,
            Reason,
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
                            "surfaceId" | "surface_id" => Ok(GeneratedField::SurfaceId),
                            "reason" => Ok(GeneratedField::Reason),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = DeleteSurfaceCommand;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.DeleteSurfaceCommand")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<DeleteSurfaceCommand, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut surface_id__ = None;
                let mut reason__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::SurfaceId => {
                            if surface_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("surfaceId"));
                            }
                            surface_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Reason => {
                            if reason__.is_some() {
                                return Err(serde::de::Error::duplicate_field("reason"));
                            }
                            reason__ = map_.next_value()?;
                        }
                    }
                }
                Ok(DeleteSurfaceCommand {
                    surface_id: surface_id__.unwrap_or_default(),
                    reason: reason__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.DeleteSurfaceCommand",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

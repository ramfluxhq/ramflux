// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateSurfaceCommand {
    #[prost(string, tag = "1")]
    pub surface_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub surface_type: ::core::option::Option<SurfaceType>,
    #[prost(string, tag = "3")]
    pub catalog: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub catalog_version: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub fallback_text: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "6")]
    pub fallback_markdown: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag = "7")]
    pub components: ::prost::alloc::vec::Vec<JsonValue>,
    #[prost(message, optional, tag = "8")]
    pub data_model: ::core::option::Option<JsonObject>,
    #[prost(message, repeated, tag = "9")]
    pub allowed_actions: ::prost::alloc::vec::Vec<JsonValue>,
}
impl serde::Serialize for CreateSurfaceCommand {
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
        if self.surface_type.is_some() {
            len += 1;
        }
        if !self.catalog.is_empty() {
            len += 1;
        }
        if !self.catalog_version.is_empty() {
            len += 1;
        }
        if !self.fallback_text.is_empty() {
            len += 1;
        }
        if self.fallback_markdown.is_some() {
            len += 1;
        }
        if !self.components.is_empty() {
            len += 1;
        }
        if self.data_model.is_some() {
            len += 1;
        }
        if !self.allowed_actions.is_empty() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.CreateSurfaceCommand", len)?;
        if !self.surface_id.is_empty() {
            struct_ser.serialize_field("surfaceId", &self.surface_id)?;
        }
        if let Some(v) = self.surface_type.as_ref() {
            struct_ser.serialize_field("surfaceType", v)?;
        }
        if !self.catalog.is_empty() {
            struct_ser.serialize_field("catalog", &self.catalog)?;
        }
        if !self.catalog_version.is_empty() {
            struct_ser.serialize_field("catalogVersion", &self.catalog_version)?;
        }
        if !self.fallback_text.is_empty() {
            struct_ser.serialize_field("fallbackText", &self.fallback_text)?;
        }
        if let Some(v) = self.fallback_markdown.as_ref() {
            struct_ser.serialize_field("fallbackMarkdown", v)?;
        }
        if !self.components.is_empty() {
            struct_ser.serialize_field("components", &self.components)?;
        }
        if let Some(v) = self.data_model.as_ref() {
            struct_ser.serialize_field("dataModel", v)?;
        }
        if !self.allowed_actions.is_empty() {
            struct_ser.serialize_field("allowedActions", &self.allowed_actions)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for CreateSurfaceCommand {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "surface_id",
            "surfaceId",
            "surface_type",
            "surfaceType",
            "catalog",
            "catalog_version",
            "catalogVersion",
            "fallback_text",
            "fallbackText",
            "fallback_markdown",
            "fallbackMarkdown",
            "components",
            "data_model",
            "dataModel",
            "allowed_actions",
            "allowedActions",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            SurfaceId,
            SurfaceType,
            Catalog,
            CatalogVersion,
            FallbackText,
            FallbackMarkdown,
            Components,
            DataModel,
            AllowedActions,
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
                            "surfaceType" | "surface_type" => Ok(GeneratedField::SurfaceType),
                            "catalog" => Ok(GeneratedField::Catalog),
                            "catalogVersion" | "catalog_version" => {
                                Ok(GeneratedField::CatalogVersion)
                            }
                            "fallbackText" | "fallback_text" => Ok(GeneratedField::FallbackText),
                            "fallbackMarkdown" | "fallback_markdown" => {
                                Ok(GeneratedField::FallbackMarkdown)
                            }
                            "components" => Ok(GeneratedField::Components),
                            "dataModel" | "data_model" => Ok(GeneratedField::DataModel),
                            "allowedActions" | "allowed_actions" => {
                                Ok(GeneratedField::AllowedActions)
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
            type Value = CreateSurfaceCommand;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.CreateSurfaceCommand")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<CreateSurfaceCommand, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut surface_id__ = None;
                let mut surface_type__ = None;
                let mut catalog__ = None;
                let mut catalog_version__ = None;
                let mut fallback_text__ = None;
                let mut fallback_markdown__ = None;
                let mut components__ = None;
                let mut data_model__ = None;
                let mut allowed_actions__ = None;
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
                        GeneratedField::SurfaceType => {
                            if surface_type__.is_some() {
                                return Err(serde::de::Error::duplicate_field("surfaceType"));
                            }
                            surface_type__ = map_.next_value()?;
                        }
                        GeneratedField::Catalog => {
                            if catalog__.is_some() {
                                return Err(serde::de::Error::duplicate_field("catalog"));
                            }
                            catalog__ = Some(map_.next_value()?);
                        }
                        GeneratedField::CatalogVersion => {
                            if catalog_version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("catalogVersion"));
                            }
                            catalog_version__ = Some(map_.next_value()?);
                        }
                        GeneratedField::FallbackText => {
                            if fallback_text__.is_some() {
                                return Err(serde::de::Error::duplicate_field("fallbackText"));
                            }
                            fallback_text__ = Some(map_.next_value()?);
                        }
                        GeneratedField::FallbackMarkdown => {
                            if fallback_markdown__.is_some() {
                                return Err(serde::de::Error::duplicate_field("fallbackMarkdown"));
                            }
                            fallback_markdown__ = map_.next_value()?;
                        }
                        GeneratedField::Components => {
                            if components__.is_some() {
                                return Err(serde::de::Error::duplicate_field("components"));
                            }
                            components__ = Some(map_.next_value()?);
                        }
                        GeneratedField::DataModel => {
                            if data_model__.is_some() {
                                return Err(serde::de::Error::duplicate_field("dataModel"));
                            }
                            data_model__ = map_.next_value()?;
                        }
                        GeneratedField::AllowedActions => {
                            if allowed_actions__.is_some() {
                                return Err(serde::de::Error::duplicate_field("allowedActions"));
                            }
                            allowed_actions__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(CreateSurfaceCommand {
                    surface_id: surface_id__.unwrap_or_default(),
                    surface_type: surface_type__,
                    catalog: catalog__.unwrap_or_default(),
                    catalog_version: catalog_version__.unwrap_or_default(),
                    fallback_text: fallback_text__.unwrap_or_default(),
                    fallback_markdown: fallback_markdown__,
                    components: components__.unwrap_or_default(),
                    data_model: data_model__,
                    allowed_actions: allowed_actions__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.CreateSurfaceCommand",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

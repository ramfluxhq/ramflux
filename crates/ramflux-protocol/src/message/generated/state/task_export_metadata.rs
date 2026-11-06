// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct TaskExportMetadata {
    #[prost(bool, tag = "1")]
    pub truncated: bool,
    #[prost(uint32, tag = "2")]
    pub skipped_items: u32,
    #[prost(string, optional, tag = "3")]
    pub next_cursor: ::core::option::Option<::prost::alloc::string::String>,
}
impl serde::Serialize for TaskExportMetadata {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.truncated {
            len += 1;
        }
        if self.skipped_items != 0 {
            len += 1;
        }
        if self.next_cursor.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.TaskExportMetadata", len)?;
        if self.truncated {
            struct_ser.serialize_field("truncated", &self.truncated)?;
        }
        if self.skipped_items != 0 {
            struct_ser.serialize_field("skippedItems", &self.skipped_items)?;
        }
        if let Some(v) = self.next_cursor.as_ref() {
            struct_ser.serialize_field("nextCursor", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for TaskExportMetadata {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] =
            &["truncated", "skipped_items", "skippedItems", "next_cursor", "nextCursor"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Truncated,
            SkippedItems,
            NextCursor,
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
                            "truncated" => Ok(GeneratedField::Truncated),
                            "skippedItems" | "skipped_items" => Ok(GeneratedField::SkippedItems),
                            "nextCursor" | "next_cursor" => Ok(GeneratedField::NextCursor),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = TaskExportMetadata;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.TaskExportMetadata")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<TaskExportMetadata, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut truncated__ = None;
                let mut skipped_items__ = None;
                let mut next_cursor__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Truncated => {
                            if truncated__.is_some() {
                                return Err(serde::de::Error::duplicate_field("truncated"));
                            }
                            truncated__ = Some(map_.next_value()?);
                        }
                        GeneratedField::SkippedItems => {
                            if skipped_items__.is_some() {
                                return Err(serde::de::Error::duplicate_field("skippedItems"));
                            }
                            skipped_items__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::NextCursor => {
                            if next_cursor__.is_some() {
                                return Err(serde::de::Error::duplicate_field("nextCursor"));
                            }
                            next_cursor__ = map_.next_value()?;
                        }
                    }
                }
                Ok(TaskExportMetadata {
                    truncated: truncated__.unwrap_or_default(),
                    skipped_items: skipped_items__.unwrap_or_default(),
                    next_cursor: next_cursor__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.TaskExportMetadata",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

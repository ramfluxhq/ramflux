// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OwnContactSync {
    #[prost(message, optional, tag = "1")]
    pub manifest: ::core::option::Option<NativeDeviceManifest>,
    #[prost(message, optional, tag = "2")]
    pub link: ::core::option::Option<FriendLinkRecord>,
}
impl serde::Serialize for OwnContactSync {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.manifest.is_some() {
            len += 1;
        }
        if self.link.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.OwnContactSync", len)?;
        if let Some(v) = self.manifest.as_ref() {
            struct_ser.serialize_field("manifest", v)?;
        }
        if let Some(v) = self.link.as_ref() {
            struct_ser.serialize_field("link", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for OwnContactSync {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["manifest", "link"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Manifest,
            Link,
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
                            "manifest" => Ok(GeneratedField::Manifest),
                            "link" => Ok(GeneratedField::Link),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = OwnContactSync;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.OwnContactSync")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<OwnContactSync, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut manifest__ = None;
                let mut link__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Manifest => {
                            if manifest__.is_some() {
                                return Err(serde::de::Error::duplicate_field("manifest"));
                            }
                            manifest__ = map_.next_value()?;
                        }
                        GeneratedField::Link => {
                            if link__.is_some() {
                                return Err(serde::de::Error::duplicate_field("link"));
                            }
                            link__ = map_.next_value()?;
                        }
                    }
                }
                Ok(OwnContactSync { manifest: manifest__, link: link__ })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.OwnContactSync",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

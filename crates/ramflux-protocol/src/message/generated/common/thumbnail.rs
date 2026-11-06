// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct Thumbnail {
    #[prost(string, tag = "1")]
    pub mime_type: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub width: u32,
    #[prost(uint32, tag = "3")]
    pub height: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub encoded_image: ::prost::alloc::vec::Vec<u8>,
}
impl serde::Serialize for Thumbnail {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.mime_type.is_empty() {
            len += 1;
        }
        if self.width != 0 {
            len += 1;
        }
        if self.height != 0 {
            len += 1;
        }
        if !self.encoded_image.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.Thumbnail", len)?;
        if !self.mime_type.is_empty() {
            struct_ser.serialize_field("mimeType", &self.mime_type)?;
        }
        if self.width != 0 {
            struct_ser.serialize_field("width", &self.width)?;
        }
        if self.height != 0 {
            struct_ser.serialize_field("height", &self.height)?;
        }
        if !self.encoded_image.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "encodedImage",
                pbjson::private::base64::encode(&self.encoded_image).as_str(),
            )?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Thumbnail {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] =
            &["mime_type", "mimeType", "width", "height", "encoded_image", "encodedImage"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            MimeType,
            Width,
            Height,
            EncodedImage,
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
                            "mimeType" | "mime_type" => Ok(GeneratedField::MimeType),
                            "width" => Ok(GeneratedField::Width),
                            "height" => Ok(GeneratedField::Height),
                            "encodedImage" | "encoded_image" => Ok(GeneratedField::EncodedImage),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Thumbnail;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.Thumbnail")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Thumbnail, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut mime_type__ = None;
                let mut width__ = None;
                let mut height__ = None;
                let mut encoded_image__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::MimeType => {
                            if mime_type__.is_some() {
                                return Err(serde::de::Error::duplicate_field("mimeType"));
                            }
                            mime_type__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Width => {
                            if width__.is_some() {
                                return Err(serde::de::Error::duplicate_field("width"));
                            }
                            width__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Height => {
                            if height__.is_some() {
                                return Err(serde::de::Error::duplicate_field("height"));
                            }
                            height__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::EncodedImage => {
                            if encoded_image__.is_some() {
                                return Err(serde::de::Error::duplicate_field("encodedImage"));
                            }
                            encoded_image__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                    }
                }
                Ok(Thumbnail {
                    mime_type: mime_type__.unwrap_or_default(),
                    width: width__.unwrap_or_default(),
                    height: height__.unwrap_or_default(),
                    encoded_image: encoded_image__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.Thumbnail", FIELDS, GeneratedVisitor)
    }
}

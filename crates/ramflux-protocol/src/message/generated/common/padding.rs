// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct Padding {
    #[prost(uint32, tag = "1")]
    pub unpadded_frame_length: u32,
    #[prost(uint32, tag = "2")]
    pub padded_frame_length: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub zeroes: ::prost::alloc::vec::Vec<u8>,
}
impl serde::Serialize for Padding {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.unpadded_frame_length != 0 {
            len += 1;
        }
        if self.padded_frame_length != 0 {
            len += 1;
        }
        if !self.zeroes.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.Padding", len)?;
        if self.unpadded_frame_length != 0 {
            struct_ser.serialize_field("unpaddedFrameLength", &self.unpadded_frame_length)?;
        }
        if self.padded_frame_length != 0 {
            struct_ser.serialize_field("paddedFrameLength", &self.padded_frame_length)?;
        }
        if !self.zeroes.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "zeroes",
                pbjson::private::base64::encode(&self.zeroes).as_str(),
            )?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Padding {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "unpadded_frame_length",
            "unpaddedFrameLength",
            "padded_frame_length",
            "paddedFrameLength",
            "zeroes",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            UnpaddedFrameLength,
            PaddedFrameLength,
            Zeroes,
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
                            "unpaddedFrameLength" | "unpadded_frame_length" => {
                                Ok(GeneratedField::UnpaddedFrameLength)
                            }
                            "paddedFrameLength" | "padded_frame_length" => {
                                Ok(GeneratedField::PaddedFrameLength)
                            }
                            "zeroes" => Ok(GeneratedField::Zeroes),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Padding;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.Padding")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Padding, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut unpadded_frame_length__ = None;
                let mut padded_frame_length__ = None;
                let mut zeroes__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::UnpaddedFrameLength => {
                            if unpadded_frame_length__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "unpaddedFrameLength",
                                ));
                            }
                            unpadded_frame_length__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::PaddedFrameLength => {
                            if padded_frame_length__.is_some() {
                                return Err(serde::de::Error::duplicate_field("paddedFrameLength"));
                            }
                            padded_frame_length__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Zeroes => {
                            if zeroes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("zeroes"));
                            }
                            zeroes__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                    }
                }
                Ok(Padding {
                    unpadded_frame_length: unpadded_frame_length__.unwrap_or_default(),
                    padded_frame_length: padded_frame_length__.unwrap_or_default(),
                    zeroes: zeroes__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.Padding", FIELDS, GeneratedVisitor)
    }
}

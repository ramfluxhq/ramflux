// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct Unsupported {
    #[prost(uint32, tag = "1")]
    pub layer: u32,
    #[prost(uint32, tag = "2")]
    pub kind: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub raw_inner: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub raw_digest: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag = "5")]
    pub reason: ::prost::alloc::string::String,
}
impl serde::Serialize for Unsupported {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.layer != 0 {
            len += 1;
        }
        if self.kind != 0 {
            len += 1;
        }
        if !self.raw_inner.is_empty() {
            len += 1;
        }
        if !self.raw_digest.is_empty() {
            len += 1;
        }
        if !self.reason.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.Unsupported", len)?;
        if self.layer != 0 {
            struct_ser.serialize_field("layer", &self.layer)?;
        }
        if self.kind != 0 {
            struct_ser.serialize_field("kind", &self.kind)?;
        }
        if !self.raw_inner.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "rawInner",
                pbjson::private::base64::encode(&self.raw_inner).as_str(),
            )?;
        }
        if !self.raw_digest.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "rawDigest",
                pbjson::private::base64::encode(&self.raw_digest).as_str(),
            )?;
        }
        if !self.reason.is_empty() {
            struct_ser.serialize_field("reason", &self.reason)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Unsupported {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] =
            &["layer", "kind", "raw_inner", "rawInner", "raw_digest", "rawDigest", "reason"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Layer,
            Kind,
            RawInner,
            RawDigest,
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
                            "layer" => Ok(GeneratedField::Layer),
                            "kind" => Ok(GeneratedField::Kind),
                            "rawInner" | "raw_inner" => Ok(GeneratedField::RawInner),
                            "rawDigest" | "raw_digest" => Ok(GeneratedField::RawDigest),
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
            type Value = Unsupported;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.Unsupported")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Unsupported, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut layer__ = None;
                let mut kind__ = None;
                let mut raw_inner__ = None;
                let mut raw_digest__ = None;
                let mut reason__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Layer => {
                            if layer__.is_some() {
                                return Err(serde::de::Error::duplicate_field("layer"));
                            }
                            layer__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Kind => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("kind"));
                            }
                            kind__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::RawInner => {
                            if raw_inner__.is_some() {
                                return Err(serde::de::Error::duplicate_field("rawInner"));
                            }
                            raw_inner__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::RawDigest => {
                            if raw_digest__.is_some() {
                                return Err(serde::de::Error::duplicate_field("rawDigest"));
                            }
                            raw_digest__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Reason => {
                            if reason__.is_some() {
                                return Err(serde::de::Error::duplicate_field("reason"));
                            }
                            reason__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(Unsupported {
                    layer: layer__.unwrap_or_default(),
                    kind: kind__.unwrap_or_default(),
                    raw_inner: raw_inner__.unwrap_or_default(),
                    raw_digest: raw_digest__.unwrap_or_default(),
                    reason: reason__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.Unsupported", FIELDS, GeneratedVisitor)
    }
}

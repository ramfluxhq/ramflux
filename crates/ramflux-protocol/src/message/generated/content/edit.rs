// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Edit {
    #[prost(message, optional, tag = "1")]
    pub target: ::core::option::Option<MessageRef>,
    #[prost(uint64, tag = "2")]
    pub revision: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub previous_content_digest: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub replacement: ::core::option::Option<Message>,
}
impl serde::Serialize for Edit {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.target.is_some() {
            len += 1;
        }
        if self.revision != 0 {
            len += 1;
        }
        if !self.previous_content_digest.is_empty() {
            len += 1;
        }
        if self.replacement.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.Edit", len)?;
        if let Some(v) = self.target.as_ref() {
            struct_ser.serialize_field("target", v)?;
        }
        if self.revision != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("revision", ToString::to_string(&self.revision).as_str())?;
        }
        if !self.previous_content_digest.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "previousContentDigest",
                pbjson::private::base64::encode(&self.previous_content_digest).as_str(),
            )?;
        }
        if let Some(v) = self.replacement.as_ref() {
            struct_ser.serialize_field("replacement", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Edit {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "target",
            "revision",
            "previous_content_digest",
            "previousContentDigest",
            "replacement",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Target,
            Revision,
            PreviousContentDigest,
            Replacement,
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
                            "target" => Ok(GeneratedField::Target),
                            "revision" => Ok(GeneratedField::Revision),
                            "previousContentDigest" | "previous_content_digest" => {
                                Ok(GeneratedField::PreviousContentDigest)
                            }
                            "replacement" => Ok(GeneratedField::Replacement),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Edit;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.Edit")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Edit, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut target__ = None;
                let mut revision__ = None;
                let mut previous_content_digest__ = None;
                let mut replacement__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Target => {
                            if target__.is_some() {
                                return Err(serde::de::Error::duplicate_field("target"));
                            }
                            target__ = map_.next_value()?;
                        }
                        GeneratedField::Revision => {
                            if revision__.is_some() {
                                return Err(serde::de::Error::duplicate_field("revision"));
                            }
                            revision__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::PreviousContentDigest => {
                            if previous_content_digest__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "previousContentDigest",
                                ));
                            }
                            previous_content_digest__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Replacement => {
                            if replacement__.is_some() {
                                return Err(serde::de::Error::duplicate_field("replacement"));
                            }
                            replacement__ = map_.next_value()?;
                        }
                    }
                }
                Ok(Edit {
                    target: target__,
                    revision: revision__.unwrap_or_default(),
                    previous_content_digest: previous_content_digest__.unwrap_or_default(),
                    replacement: replacement__,
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.Edit", FIELDS, GeneratedVisitor)
    }
}

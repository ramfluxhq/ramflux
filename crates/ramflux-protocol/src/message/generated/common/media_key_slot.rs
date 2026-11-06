// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct MediaKeySlot {
    #[prost(message, optional, tag = "1")]
    pub recipient: ::core::option::Option<QualifiedDevice>,
    #[prost(bytes = "vec", tag = "2")]
    pub encrypted_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub format: u32,
}
impl serde::Serialize for MediaKeySlot {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.recipient.is_some() {
            len += 1;
        }
        if !self.encrypted_key.is_empty() {
            len += 1;
        }
        if self.format != 0 {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.MediaKeySlot", len)?;
        if let Some(v) = self.recipient.as_ref() {
            struct_ser.serialize_field("recipient", v)?;
        }
        if !self.encrypted_key.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "encryptedKey",
                pbjson::private::base64::encode(&self.encrypted_key).as_str(),
            )?;
        }
        if self.format != 0 {
            struct_ser.serialize_field("format", &self.format)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for MediaKeySlot {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["recipient", "encrypted_key", "encryptedKey", "format"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Recipient,
            EncryptedKey,
            Format,
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
                            "recipient" => Ok(GeneratedField::Recipient),
                            "encryptedKey" | "encrypted_key" => Ok(GeneratedField::EncryptedKey),
                            "format" => Ok(GeneratedField::Format),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = MediaKeySlot;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.MediaKeySlot")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<MediaKeySlot, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut recipient__ = None;
                let mut encrypted_key__ = None;
                let mut format__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Recipient => {
                            if recipient__.is_some() {
                                return Err(serde::de::Error::duplicate_field("recipient"));
                            }
                            recipient__ = map_.next_value()?;
                        }
                        GeneratedField::EncryptedKey => {
                            if encrypted_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("encryptedKey"));
                            }
                            encrypted_key__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Format => {
                            if format__.is_some() {
                                return Err(serde::de::Error::duplicate_field("format"));
                            }
                            format__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                    }
                }
                Ok(MediaKeySlot {
                    recipient: recipient__,
                    encrypted_key: encrypted_key__.unwrap_or_default(),
                    format: format__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.MediaKeySlot", FIELDS, GeneratedVisitor)
    }
}

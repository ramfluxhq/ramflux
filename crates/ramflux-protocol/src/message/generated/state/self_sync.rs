// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SelfSync {
    #[prost(uint32, tag = "1")]
    pub operation: u32,
    #[prost(message, optional, tag = "2")]
    pub read_through: ::core::option::Option<MessageRef>,
    #[prost(message, optional, tag = "3")]
    pub draft: ::core::option::Option<Message>,
    #[prost(message, optional, tag = "4")]
    pub pin: ::core::option::Option<MessageRef>,
    #[prost(bool, tag = "5")]
    pub mute: bool,
    #[prost(uint64, tag = "6")]
    pub revision: u64,
}
impl serde::Serialize for SelfSync {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.operation != 0 {
            len += 1;
        }
        if self.read_through.is_some() {
            len += 1;
        }
        if self.draft.is_some() {
            len += 1;
        }
        if self.pin.is_some() {
            len += 1;
        }
        if self.mute {
            len += 1;
        }
        if self.revision != 0 {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.SelfSync", len)?;
        if self.operation != 0 {
            struct_ser.serialize_field("operation", &self.operation)?;
        }
        if let Some(v) = self.read_through.as_ref() {
            struct_ser.serialize_field("readThrough", v)?;
        }
        if let Some(v) = self.draft.as_ref() {
            struct_ser.serialize_field("draft", v)?;
        }
        if let Some(v) = self.pin.as_ref() {
            struct_ser.serialize_field("pin", v)?;
        }
        if self.mute {
            struct_ser.serialize_field("mute", &self.mute)?;
        }
        if self.revision != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("revision", ToString::to_string(&self.revision).as_str())?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SelfSync {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] =
            &["operation", "read_through", "readThrough", "draft", "pin", "mute", "revision"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Operation,
            ReadThrough,
            Draft,
            Pin,
            Mute,
            Revision,
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
                            "operation" => Ok(GeneratedField::Operation),
                            "readThrough" | "read_through" => Ok(GeneratedField::ReadThrough),
                            "draft" => Ok(GeneratedField::Draft),
                            "pin" => Ok(GeneratedField::Pin),
                            "mute" => Ok(GeneratedField::Mute),
                            "revision" => Ok(GeneratedField::Revision),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SelfSync;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.SelfSync")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<SelfSync, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut operation__ = None;
                let mut read_through__ = None;
                let mut draft__ = None;
                let mut pin__ = None;
                let mut mute__ = None;
                let mut revision__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Operation => {
                            if operation__.is_some() {
                                return Err(serde::de::Error::duplicate_field("operation"));
                            }
                            operation__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::ReadThrough => {
                            if read_through__.is_some() {
                                return Err(serde::de::Error::duplicate_field("readThrough"));
                            }
                            read_through__ = map_.next_value()?;
                        }
                        GeneratedField::Draft => {
                            if draft__.is_some() {
                                return Err(serde::de::Error::duplicate_field("draft"));
                            }
                            draft__ = map_.next_value()?;
                        }
                        GeneratedField::Pin => {
                            if pin__.is_some() {
                                return Err(serde::de::Error::duplicate_field("pin"));
                            }
                            pin__ = map_.next_value()?;
                        }
                        GeneratedField::Mute => {
                            if mute__.is_some() {
                                return Err(serde::de::Error::duplicate_field("mute"));
                            }
                            mute__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Revision => {
                            if revision__.is_some() {
                                return Err(serde::de::Error::duplicate_field("revision"));
                            }
                            revision__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                    }
                }
                Ok(SelfSync {
                    operation: operation__.unwrap_or_default(),
                    read_through: read_through__,
                    draft: draft__,
                    pin: pin__,
                    mute: mute__.unwrap_or_default(),
                    revision: revision__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.SelfSync", FIELDS, GeneratedVisitor)
    }
}

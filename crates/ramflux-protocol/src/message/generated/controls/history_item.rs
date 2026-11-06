// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HistoryItem {
    #[prost(bytes = "vec", tag = "1")]
    pub exact_inner: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "16")]
    pub source_evidence: ::core::option::Option<HistoryOriginEvidence>,
    #[prost(message, optional, tag = "3")]
    pub tombstone: ::core::option::Option<Delete>,
}
impl serde::Serialize for HistoryItem {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.exact_inner.is_empty() {
            len += 1;
        }
        if self.source_evidence.is_some() {
            len += 1;
        }
        if self.tombstone.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.HistoryItem", len)?;
        if !self.exact_inner.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "exactInner",
                pbjson::private::base64::encode(&self.exact_inner).as_str(),
            )?;
        }
        if let Some(v) = self.source_evidence.as_ref() {
            struct_ser.serialize_field("sourceEvidence", v)?;
        }
        if let Some(v) = self.tombstone.as_ref() {
            struct_ser.serialize_field("tombstone", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for HistoryItem {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] =
            &["exact_inner", "exactInner", "source_evidence", "sourceEvidence", "tombstone"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            ExactInner,
            SourceEvidence,
            Tombstone,
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
                            "exactInner" | "exact_inner" => Ok(GeneratedField::ExactInner),
                            "sourceEvidence" | "source_evidence" => {
                                Ok(GeneratedField::SourceEvidence)
                            }
                            "tombstone" => Ok(GeneratedField::Tombstone),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = HistoryItem;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.HistoryItem")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<HistoryItem, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut exact_inner__ = None;
                let mut source_evidence__ = None;
                let mut tombstone__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::ExactInner => {
                            if exact_inner__.is_some() {
                                return Err(serde::de::Error::duplicate_field("exactInner"));
                            }
                            exact_inner__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::SourceEvidence => {
                            if source_evidence__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sourceEvidence"));
                            }
                            source_evidence__ = map_.next_value()?;
                        }
                        GeneratedField::Tombstone => {
                            if tombstone__.is_some() {
                                return Err(serde::de::Error::duplicate_field("tombstone"));
                            }
                            tombstone__ = map_.next_value()?;
                        }
                    }
                }
                Ok(HistoryItem {
                    exact_inner: exact_inner__.unwrap_or_default(),
                    source_evidence: source_evidence__,
                    tombstone: tombstone__,
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.HistoryItem", FIELDS, GeneratedVisitor)
    }
}

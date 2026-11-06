// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct HistoryOriginEvidence {
    #[prost(bytes = "vec", tag = "1")]
    pub canonical_sender_envelope: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub source_authority: ::core::option::Option<NativeCustodyManifest>,
    #[prost(message, optional, tag = "3")]
    pub group_membership: ::core::option::Option<NativeGroupSnapshot>,
}
impl serde::Serialize for HistoryOriginEvidence {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.canonical_sender_envelope.is_empty() {
            len += 1;
        }
        if self.source_authority.is_some() {
            len += 1;
        }
        if self.group_membership.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.HistoryOriginEvidence", len)?;
        if !self.canonical_sender_envelope.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "canonicalSenderEnvelope",
                pbjson::private::base64::encode(&self.canonical_sender_envelope).as_str(),
            )?;
        }
        if let Some(v) = self.source_authority.as_ref() {
            struct_ser.serialize_field("sourceAuthority", v)?;
        }
        if let Some(v) = self.group_membership.as_ref() {
            struct_ser.serialize_field("groupMembership", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for HistoryOriginEvidence {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "canonical_sender_envelope",
            "canonicalSenderEnvelope",
            "source_authority",
            "sourceAuthority",
            "group_membership",
            "groupMembership",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            CanonicalSenderEnvelope,
            SourceAuthority,
            GroupMembership,
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
                            "canonicalSenderEnvelope" | "canonical_sender_envelope" => {
                                Ok(GeneratedField::CanonicalSenderEnvelope)
                            }
                            "sourceAuthority" | "source_authority" => {
                                Ok(GeneratedField::SourceAuthority)
                            }
                            "groupMembership" | "group_membership" => {
                                Ok(GeneratedField::GroupMembership)
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
            type Value = HistoryOriginEvidence;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.HistoryOriginEvidence")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<HistoryOriginEvidence, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut canonical_sender_envelope__ = None;
                let mut source_authority__ = None;
                let mut group_membership__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::CanonicalSenderEnvelope => {
                            if canonical_sender_envelope__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "canonicalSenderEnvelope",
                                ));
                            }
                            canonical_sender_envelope__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::SourceAuthority => {
                            if source_authority__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sourceAuthority"));
                            }
                            source_authority__ = map_.next_value()?;
                        }
                        GeneratedField::GroupMembership => {
                            if group_membership__.is_some() {
                                return Err(serde::de::Error::duplicate_field("groupMembership"));
                            }
                            group_membership__ = map_.next_value()?;
                        }
                    }
                }
                Ok(HistoryOriginEvidence {
                    canonical_sender_envelope: canonical_sender_envelope__.unwrap_or_default(),
                    source_authority: source_authority__,
                    group_membership: group_membership__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.HistoryOriginEvidence",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

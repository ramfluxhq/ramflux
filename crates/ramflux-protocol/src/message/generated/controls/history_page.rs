// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HistoryPage {
    #[prost(bytes = "vec", tag = "1")]
    pub transfer_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub page: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub previous_page_digest: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag = "4")]
    pub items: ::prost::alloc::vec::Vec<HistoryItem>,
    #[prost(bytes = "vec", tag = "5")]
    pub page_digest: ::prost::alloc::vec::Vec<u8>,
}
impl serde::Serialize for HistoryPage {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.transfer_id.is_empty() {
            len += 1;
        }
        if self.page != 0 {
            len += 1;
        }
        if !self.previous_page_digest.is_empty() {
            len += 1;
        }
        if !self.items.is_empty() {
            len += 1;
        }
        if !self.page_digest.is_empty() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.HistoryPage", len)?;
        if !self.transfer_id.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "transferId",
                pbjson::private::base64::encode(&self.transfer_id).as_str(),
            )?;
        }
        if self.page != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("page", ToString::to_string(&self.page).as_str())?;
        }
        if !self.previous_page_digest.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "previousPageDigest",
                pbjson::private::base64::encode(&self.previous_page_digest).as_str(),
            )?;
        }
        if !self.items.is_empty() {
            struct_ser.serialize_field("items", &self.items)?;
        }
        if !self.page_digest.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "pageDigest",
                pbjson::private::base64::encode(&self.page_digest).as_str(),
            )?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for HistoryPage {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "transfer_id",
            "transferId",
            "page",
            "previous_page_digest",
            "previousPageDigest",
            "items",
            "page_digest",
            "pageDigest",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            TransferId,
            Page,
            PreviousPageDigest,
            Items,
            PageDigest,
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
                            "transferId" | "transfer_id" => Ok(GeneratedField::TransferId),
                            "page" => Ok(GeneratedField::Page),
                            "previousPageDigest" | "previous_page_digest" => {
                                Ok(GeneratedField::PreviousPageDigest)
                            }
                            "items" => Ok(GeneratedField::Items),
                            "pageDigest" | "page_digest" => Ok(GeneratedField::PageDigest),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = HistoryPage;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.HistoryPage")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<HistoryPage, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut transfer_id__ = None;
                let mut page__ = None;
                let mut previous_page_digest__ = None;
                let mut items__ = None;
                let mut page_digest__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::TransferId => {
                            if transfer_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("transferId"));
                            }
                            transfer_id__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Page => {
                            if page__.is_some() {
                                return Err(serde::de::Error::duplicate_field("page"));
                            }
                            page__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::PreviousPageDigest => {
                            if previous_page_digest__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "previousPageDigest",
                                ));
                            }
                            previous_page_digest__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Items => {
                            if items__.is_some() {
                                return Err(serde::de::Error::duplicate_field("items"));
                            }
                            items__ = Some(map_.next_value()?);
                        }
                        GeneratedField::PageDigest => {
                            if page_digest__.is_some() {
                                return Err(serde::de::Error::duplicate_field("pageDigest"));
                            }
                            page_digest__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                    }
                }
                Ok(HistoryPage {
                    transfer_id: transfer_id__.unwrap_or_default(),
                    page: page__.unwrap_or_default(),
                    previous_page_digest: previous_page_digest__.unwrap_or_default(),
                    items: items__.unwrap_or_default(),
                    page_digest: page_digest__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.HistoryPage", FIELDS, GeneratedVisitor)
    }
}

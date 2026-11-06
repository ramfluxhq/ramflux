// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Surface {
    #[prost(oneof = "surface::Payload", tags = "16, 17, 18")]
    pub payload: ::core::option::Option<surface::Payload>,
}
/// Nested message and enum types in `Surface`.
pub mod surface {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Payload {
        #[prost(message, tag = "16")]
        Delivery(super::SurfaceDelivery),
        #[prost(message, tag = "17")]
        ResyncRequest(super::SurfaceResyncRequest),
        #[prost(message, tag = "18")]
        OwnHistory(super::SurfaceHistoryExport),
    }
}
impl serde::Serialize for Surface {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.payload.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.Surface", len)?;
        if let Some(v) = self.payload.as_ref() {
            match v {
                surface::Payload::Delivery(v) => {
                    struct_ser.serialize_field("delivery", v)?;
                }
                surface::Payload::ResyncRequest(v) => {
                    struct_ser.serialize_field("resyncRequest", v)?;
                }
                surface::Payload::OwnHistory(v) => {
                    struct_ser.serialize_field("ownHistory", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Surface {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] =
            &["delivery", "resync_request", "resyncRequest", "own_history", "ownHistory"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Delivery,
            ResyncRequest,
            OwnHistory,
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
                            "delivery" => Ok(GeneratedField::Delivery),
                            "resyncRequest" | "resync_request" => Ok(GeneratedField::ResyncRequest),
                            "ownHistory" | "own_history" => Ok(GeneratedField::OwnHistory),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Surface;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.Surface")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Surface, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut payload__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Delivery => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("delivery"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(surface::Payload::Delivery);
                        }
                        GeneratedField::ResyncRequest => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("resyncRequest"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(surface::Payload::ResyncRequest);
                        }
                        GeneratedField::OwnHistory => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ownHistory"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(surface::Payload::OwnHistory);
                        }
                    }
                }
                Ok(Surface { payload: payload__ })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.Surface", FIELDS, GeneratedVisitor)
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct GroupControlBodyRequest {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<NativeGroupChangeRequest>,
    #[prost(message, optional, tag = "2")]
    pub federation: ::core::option::Option<LocalBusFederationRoute>,
}
impl serde::Serialize for GroupControlBodyRequest {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.request.is_some() {
            len += 1;
        }
        if self.federation.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.GroupControlBodyRequest", len)?;
        if let Some(v) = self.request.as_ref() {
            struct_ser.serialize_field("request", v)?;
        }
        if let Some(v) = self.federation.as_ref() {
            struct_ser.serialize_field("federation", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for GroupControlBodyRequest {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["request", "federation"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Request,
            Federation,
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
                            "request" => Ok(GeneratedField::Request),
                            "federation" => Ok(GeneratedField::Federation),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = GroupControlBodyRequest;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.GroupControlBodyRequest")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<GroupControlBodyRequest, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut request__ = None;
                let mut federation__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Request => {
                            if request__.is_some() {
                                return Err(serde::de::Error::duplicate_field("request"));
                            }
                            request__ = map_.next_value()?;
                        }
                        GeneratedField::Federation => {
                            if federation__.is_some() {
                                return Err(serde::de::Error::duplicate_field("federation"));
                            }
                            federation__ = map_.next_value()?;
                        }
                    }
                }
                Ok(GroupControlBodyRequest { request: request__, federation: federation__ })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.GroupControlBodyRequest",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

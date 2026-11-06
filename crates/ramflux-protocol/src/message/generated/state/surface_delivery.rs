// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SurfaceDelivery {
    #[prost(message, optional, tag = "1")]
    pub kind: ::core::option::Option<SurfaceControlKind>,
    #[prost(message, optional, tag = "2")]
    pub carrier: ::core::option::Option<SurfaceCarrier>,
    #[prost(uint64, optional, tag = "3")]
    pub group_epoch: ::core::option::Option<u64>,
    #[prost(message, optional, tag = "4")]
    pub context: ::core::option::Option<OwnContext>,
    #[prost(message, repeated, tag = "5")]
    pub manifests: ::prost::alloc::vec::Vec<NativeDeviceManifest>,
}
impl serde::Serialize for SurfaceDelivery {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.kind.is_some() {
            len += 1;
        }
        if self.carrier.is_some() {
            len += 1;
        }
        if self.group_epoch.is_some() {
            len += 1;
        }
        if self.context.is_some() {
            len += 1;
        }
        if !self.manifests.is_empty() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.SurfaceDelivery", len)?;
        if let Some(v) = self.kind.as_ref() {
            struct_ser.serialize_field("kind", v)?;
        }
        if let Some(v) = self.carrier.as_ref() {
            struct_ser.serialize_field("carrier", v)?;
        }
        if let Some(v) = self.group_epoch.as_ref() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("groupEpoch", ToString::to_string(&v).as_str())?;
        }
        if let Some(v) = self.context.as_ref() {
            struct_ser.serialize_field("context", v)?;
        }
        if !self.manifests.is_empty() {
            struct_ser.serialize_field("manifests", &self.manifests)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SurfaceDelivery {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] =
            &["kind", "carrier", "group_epoch", "groupEpoch", "context", "manifests"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Kind,
            Carrier,
            GroupEpoch,
            Context,
            Manifests,
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
                            "kind" => Ok(GeneratedField::Kind),
                            "carrier" => Ok(GeneratedField::Carrier),
                            "groupEpoch" | "group_epoch" => Ok(GeneratedField::GroupEpoch),
                            "context" => Ok(GeneratedField::Context),
                            "manifests" => Ok(GeneratedField::Manifests),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SurfaceDelivery;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.SurfaceDelivery")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<SurfaceDelivery, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut kind__ = None;
                let mut carrier__ = None;
                let mut group_epoch__ = None;
                let mut context__ = None;
                let mut manifests__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Kind => {
                            if kind__.is_some() {
                                return Err(serde::de::Error::duplicate_field("kind"));
                            }
                            kind__ = map_.next_value()?;
                        }
                        GeneratedField::Carrier => {
                            if carrier__.is_some() {
                                return Err(serde::de::Error::duplicate_field("carrier"));
                            }
                            carrier__ = map_.next_value()?;
                        }
                        GeneratedField::GroupEpoch => {
                            if group_epoch__.is_some() {
                                return Err(serde::de::Error::duplicate_field("groupEpoch"));
                            }
                            group_epoch__ = map_
                                .next_value::<
                                    ::std::option::Option<
                                        ::pbjson::private::NumberDeserialize<_>,
                                    >,
                                >()?
                                .map(|x| x.0);
                        }
                        GeneratedField::Context => {
                            if context__.is_some() {
                                return Err(serde::de::Error::duplicate_field("context"));
                            }
                            context__ = map_.next_value()?;
                        }
                        GeneratedField::Manifests => {
                            if manifests__.is_some() {
                                return Err(serde::de::Error::duplicate_field("manifests"));
                            }
                            manifests__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(SurfaceDelivery {
                    kind: kind__,
                    carrier: carrier__,
                    group_epoch: group_epoch__,
                    context: context__,
                    manifests: manifests__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.SurfaceDelivery",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

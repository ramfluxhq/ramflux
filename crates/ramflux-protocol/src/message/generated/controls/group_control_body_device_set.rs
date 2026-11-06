// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct GroupControlBodyDeviceSet {
    #[prost(string, tag = "1")]
    pub group_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub actor: ::core::option::Option<NativeGroupActor>,
    #[prost(uint64, tag = "3")]
    pub device_set_epoch: u64,
}
impl serde::Serialize for GroupControlBodyDeviceSet {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.group_id.is_empty() {
            len += 1;
        }
        if self.actor.is_some() {
            len += 1;
        }
        if self.device_set_epoch != 0 {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.GroupControlBodyDeviceSet", len)?;
        if !self.group_id.is_empty() {
            struct_ser.serialize_field("groupId", &self.group_id)?;
        }
        if let Some(v) = self.actor.as_ref() {
            struct_ser.serialize_field("actor", v)?;
        }
        if self.device_set_epoch != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "deviceSetEpoch",
                ToString::to_string(&self.device_set_epoch).as_str(),
            )?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for GroupControlBodyDeviceSet {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] =
            &["group_id", "groupId", "actor", "device_set_epoch", "deviceSetEpoch"];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            GroupId,
            Actor,
            DeviceSetEpoch,
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
                            "groupId" | "group_id" => Ok(GeneratedField::GroupId),
                            "actor" => Ok(GeneratedField::Actor),
                            "deviceSetEpoch" | "device_set_epoch" => {
                                Ok(GeneratedField::DeviceSetEpoch)
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
            type Value = GroupControlBodyDeviceSet;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.GroupControlBodyDeviceSet")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<GroupControlBodyDeviceSet, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut group_id__ = None;
                let mut actor__ = None;
                let mut device_set_epoch__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::GroupId => {
                            if group_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("groupId"));
                            }
                            group_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Actor => {
                            if actor__.is_some() {
                                return Err(serde::de::Error::duplicate_field("actor"));
                            }
                            actor__ = map_.next_value()?;
                        }
                        GeneratedField::DeviceSetEpoch => {
                            if device_set_epoch__.is_some() {
                                return Err(serde::de::Error::duplicate_field("deviceSetEpoch"));
                            }
                            device_set_epoch__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                    }
                }
                Ok(GroupControlBodyDeviceSet {
                    group_id: group_id__.unwrap_or_default(),
                    actor: actor__,
                    device_set_epoch: device_set_epoch__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.GroupControlBodyDeviceSet",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

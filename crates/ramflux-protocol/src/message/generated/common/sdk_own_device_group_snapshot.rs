// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SdkOwnDeviceGroupSnapshot {
    #[prost(message, optional, tag = "1")]
    pub shared_state: ::core::option::Option<NativeGroupSnapshot>,
    #[prost(string, tag = "2")]
    pub group_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "3")]
    pub group_epoch: u64,
    #[prost(uint32, tag = "4")]
    pub max_members: u32,
    #[prost(string, tag = "5")]
    pub new_member_history: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub local_role: ::prost::alloc::string::String,
    #[prost(uint64, tag = "7")]
    pub local_joined_epoch: u64,
    #[prost(message, repeated, tag = "8")]
    pub members: ::prost::alloc::vec::Vec<SdkOwnDeviceGroupMemberSnapshot>,
    #[prost(message, repeated, tag = "9")]
    pub routes: ::prost::alloc::vec::Vec<LocalBusGroupMemberRoute>,
}
impl serde::Serialize for SdkOwnDeviceGroupSnapshot {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if self.shared_state.is_some() {
            len += 1;
        }
        if !self.group_id.is_empty() {
            len += 1;
        }
        if self.group_epoch != 0 {
            len += 1;
        }
        if self.max_members != 0 {
            len += 1;
        }
        if !self.new_member_history.is_empty() {
            len += 1;
        }
        if !self.local_role.is_empty() {
            len += 1;
        }
        if self.local_joined_epoch != 0 {
            len += 1;
        }
        if !self.members.is_empty() {
            len += 1;
        }
        if !self.routes.is_empty() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.SdkOwnDeviceGroupSnapshot", len)?;
        if let Some(v) = self.shared_state.as_ref() {
            struct_ser.serialize_field("sharedState", v)?;
        }
        if !self.group_id.is_empty() {
            struct_ser.serialize_field("groupId", &self.group_id)?;
        }
        if self.group_epoch != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser
                .serialize_field("groupEpoch", ToString::to_string(&self.group_epoch).as_str())?;
        }
        if self.max_members != 0 {
            struct_ser.serialize_field("maxMembers", &self.max_members)?;
        }
        if !self.new_member_history.is_empty() {
            struct_ser.serialize_field("newMemberHistory", &self.new_member_history)?;
        }
        if !self.local_role.is_empty() {
            struct_ser.serialize_field("localRole", &self.local_role)?;
        }
        if self.local_joined_epoch != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "localJoinedEpoch",
                ToString::to_string(&self.local_joined_epoch).as_str(),
            )?;
        }
        if !self.members.is_empty() {
            struct_ser.serialize_field("members", &self.members)?;
        }
        if !self.routes.is_empty() {
            struct_ser.serialize_field("routes", &self.routes)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for SdkOwnDeviceGroupSnapshot {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "shared_state",
            "sharedState",
            "group_id",
            "groupId",
            "group_epoch",
            "groupEpoch",
            "max_members",
            "maxMembers",
            "new_member_history",
            "newMemberHistory",
            "local_role",
            "localRole",
            "local_joined_epoch",
            "localJoinedEpoch",
            "members",
            "routes",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            SharedState,
            GroupId,
            GroupEpoch,
            MaxMembers,
            NewMemberHistory,
            LocalRole,
            LocalJoinedEpoch,
            Members,
            Routes,
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
                            "sharedState" | "shared_state" => Ok(GeneratedField::SharedState),
                            "groupId" | "group_id" => Ok(GeneratedField::GroupId),
                            "groupEpoch" | "group_epoch" => Ok(GeneratedField::GroupEpoch),
                            "maxMembers" | "max_members" => Ok(GeneratedField::MaxMembers),
                            "newMemberHistory" | "new_member_history" => {
                                Ok(GeneratedField::NewMemberHistory)
                            }
                            "localRole" | "local_role" => Ok(GeneratedField::LocalRole),
                            "localJoinedEpoch" | "local_joined_epoch" => {
                                Ok(GeneratedField::LocalJoinedEpoch)
                            }
                            "members" => Ok(GeneratedField::Members),
                            "routes" => Ok(GeneratedField::Routes),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = SdkOwnDeviceGroupSnapshot;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.SdkOwnDeviceGroupSnapshot")
            }
            fn visit_map<V>(
                self,
                mut map_: V,
            ) -> std::result::Result<SdkOwnDeviceGroupSnapshot, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut shared_state__ = None;
                let mut group_id__ = None;
                let mut group_epoch__ = None;
                let mut max_members__ = None;
                let mut new_member_history__ = None;
                let mut local_role__ = None;
                let mut local_joined_epoch__ = None;
                let mut members__ = None;
                let mut routes__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::SharedState => {
                            if shared_state__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sharedState"));
                            }
                            shared_state__ = map_.next_value()?;
                        }
                        GeneratedField::GroupId => {
                            if group_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("groupId"));
                            }
                            group_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::GroupEpoch => {
                            if group_epoch__.is_some() {
                                return Err(serde::de::Error::duplicate_field("groupEpoch"));
                            }
                            group_epoch__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::MaxMembers => {
                            if max_members__.is_some() {
                                return Err(serde::de::Error::duplicate_field("maxMembers"));
                            }
                            max_members__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::NewMemberHistory => {
                            if new_member_history__.is_some() {
                                return Err(serde::de::Error::duplicate_field("newMemberHistory"));
                            }
                            new_member_history__ = Some(map_.next_value()?);
                        }
                        GeneratedField::LocalRole => {
                            if local_role__.is_some() {
                                return Err(serde::de::Error::duplicate_field("localRole"));
                            }
                            local_role__ = Some(map_.next_value()?);
                        }
                        GeneratedField::LocalJoinedEpoch => {
                            if local_joined_epoch__.is_some() {
                                return Err(serde::de::Error::duplicate_field("localJoinedEpoch"));
                            }
                            local_joined_epoch__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Members => {
                            if members__.is_some() {
                                return Err(serde::de::Error::duplicate_field("members"));
                            }
                            members__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Routes => {
                            if routes__.is_some() {
                                return Err(serde::de::Error::duplicate_field("routes"));
                            }
                            routes__ = Some(map_.next_value()?);
                        }
                    }
                }
                Ok(SdkOwnDeviceGroupSnapshot {
                    shared_state: shared_state__,
                    group_id: group_id__.unwrap_or_default(),
                    group_epoch: group_epoch__.unwrap_or_default(),
                    max_members: max_members__.unwrap_or_default(),
                    new_member_history: new_member_history__.unwrap_or_default(),
                    local_role: local_role__.unwrap_or_default(),
                    local_joined_epoch: local_joined_epoch__.unwrap_or_default(),
                    members: members__.unwrap_or_default(),
                    routes: routes__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.SdkOwnDeviceGroupSnapshot",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

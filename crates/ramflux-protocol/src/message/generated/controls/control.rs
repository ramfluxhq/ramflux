// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Control {
    #[prost(enumeration = "ControlOperation", tag = "1")]
    pub operation: i32,
    #[prost(
        oneof = "control::Payload",
        tags = "16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31"
    )]
    pub payload: ::core::option::Option<control::Payload>,
}
/// Nested message and enum types in `Control`.
pub mod control {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Payload {
        #[prost(message, tag = "16")]
        Reset(super::PairReset),
        #[prost(message, tag = "17")]
        ResetAck(super::PairResetAck),
        #[prost(message, tag = "18")]
        ContactControl(super::ContactControl),
        #[prost(message, tag = "19")]
        GroupState(super::GroupStateControl),
        #[prost(message, tag = "20")]
        GroupKeyControl(super::GroupKeyControl),
        #[prost(message, tag = "21")]
        OwnContactSync(super::OwnContactSync),
        #[prost(message, tag = "22")]
        OwnHistory(super::HistoryPage),
        #[prost(message, tag = "23")]
        HomeMigration(super::HomeMigrationControl),
        #[prost(message, tag = "24")]
        RecoveryControl(super::RecoveryControl),
        #[prost(message, tag = "25")]
        LivePresence(super::LivePresence),
        #[prost(message, tag = "26")]
        A2i(super::A2iControlEvent),
        #[prost(message, tag = "27")]
        ObjectRevoke(super::ObjectRevokeAccess),
        #[prost(message, tag = "28")]
        OwnContactTombstone(super::OwnContactTombstone),
        #[prost(message, tag = "29")]
        OwnGroupConsent(super::OwnGroupConsent),
        #[prost(message, tag = "30")]
        OwnMessageCopy(super::OwnMessageCopy),
        #[prost(message, tag = "31")]
        Friend(super::FriendControl),
    }
}
impl serde::Serialize for Control {
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
        if self.payload.is_some() {
            len += 1;
        }
        let mut struct_ser = serializer.serialize_struct("ramflux.message.v1.Control", len)?;
        if self.operation != 0 {
            let v = crate::message::protojson::EnumValue::<ControlOperation>::new(self.operation);
            struct_ser.serialize_field("operation", &v)?;
        }
        if let Some(v) = self.payload.as_ref() {
            match v {
                control::Payload::Reset(v) => {
                    struct_ser.serialize_field("reset", v)?;
                }
                control::Payload::ResetAck(v) => {
                    struct_ser.serialize_field("resetAck", v)?;
                }
                control::Payload::ContactControl(v) => {
                    struct_ser.serialize_field("contactControl", v)?;
                }
                control::Payload::GroupState(v) => {
                    struct_ser.serialize_field("groupState", v)?;
                }
                control::Payload::GroupKeyControl(v) => {
                    struct_ser.serialize_field("groupKeyControl", v)?;
                }
                control::Payload::OwnContactSync(v) => {
                    struct_ser.serialize_field("ownContactSync", v)?;
                }
                control::Payload::OwnHistory(v) => {
                    struct_ser.serialize_field("ownHistory", v)?;
                }
                control::Payload::HomeMigration(v) => {
                    struct_ser.serialize_field("homeMigration", v)?;
                }
                control::Payload::RecoveryControl(v) => {
                    struct_ser.serialize_field("recoveryControl", v)?;
                }
                control::Payload::LivePresence(v) => {
                    struct_ser.serialize_field("livePresence", v)?;
                }
                control::Payload::A2i(v) => {
                    struct_ser.serialize_field("a2i", v)?;
                }
                control::Payload::ObjectRevoke(v) => {
                    struct_ser.serialize_field("objectRevoke", v)?;
                }
                control::Payload::OwnContactTombstone(v) => {
                    struct_ser.serialize_field("ownContactTombstone", v)?;
                }
                control::Payload::OwnGroupConsent(v) => {
                    struct_ser.serialize_field("ownGroupConsent", v)?;
                }
                control::Payload::OwnMessageCopy(v) => {
                    struct_ser.serialize_field("ownMessageCopy", v)?;
                }
                control::Payload::Friend(v) => {
                    struct_ser.serialize_field("friend", v)?;
                }
            }
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for Control {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "operation",
            "reset",
            "reset_ack",
            "resetAck",
            "contact_control",
            "contactControl",
            "group_state",
            "groupState",
            "group_key_control",
            "groupKeyControl",
            "own_contact_sync",
            "ownContactSync",
            "own_history",
            "ownHistory",
            "home_migration",
            "homeMigration",
            "recovery_control",
            "recoveryControl",
            "live_presence",
            "livePresence",
            "a2i",
            "object_revoke",
            "objectRevoke",
            "own_contact_tombstone",
            "ownContactTombstone",
            "own_group_consent",
            "ownGroupConsent",
            "own_message_copy",
            "ownMessageCopy",
            "friend",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Operation,
            Reset,
            ResetAck,
            ContactControl,
            GroupState,
            GroupKeyControl,
            OwnContactSync,
            OwnHistory,
            HomeMigration,
            RecoveryControl,
            LivePresence,
            A2i,
            ObjectRevoke,
            OwnContactTombstone,
            OwnGroupConsent,
            OwnMessageCopy,
            Friend,
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
                            "reset" => Ok(GeneratedField::Reset),
                            "resetAck" | "reset_ack" => Ok(GeneratedField::ResetAck),
                            "contactControl" | "contact_control" => {
                                Ok(GeneratedField::ContactControl)
                            }
                            "groupState" | "group_state" => Ok(GeneratedField::GroupState),
                            "groupKeyControl" | "group_key_control" => {
                                Ok(GeneratedField::GroupKeyControl)
                            }
                            "ownContactSync" | "own_contact_sync" => {
                                Ok(GeneratedField::OwnContactSync)
                            }
                            "ownHistory" | "own_history" => Ok(GeneratedField::OwnHistory),
                            "homeMigration" | "home_migration" => Ok(GeneratedField::HomeMigration),
                            "recoveryControl" | "recovery_control" => {
                                Ok(GeneratedField::RecoveryControl)
                            }
                            "livePresence" | "live_presence" => Ok(GeneratedField::LivePresence),
                            "a2i" => Ok(GeneratedField::A2i),
                            "objectRevoke" | "object_revoke" => Ok(GeneratedField::ObjectRevoke),
                            "ownContactTombstone" | "own_contact_tombstone" => {
                                Ok(GeneratedField::OwnContactTombstone)
                            }
                            "ownGroupConsent" | "own_group_consent" => {
                                Ok(GeneratedField::OwnGroupConsent)
                            }
                            "ownMessageCopy" | "own_message_copy" => {
                                Ok(GeneratedField::OwnMessageCopy)
                            }
                            "friend" => Ok(GeneratedField::Friend),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = Control;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.Control")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<Control, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut operation__ = None;
                let mut payload__ = None;
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
                                map_
                                    .next_value::<
                                        crate::message::protojson::EnumValue<ControlOperation>,
                                    >()?
                                    .value,
                            );
                        }
                        GeneratedField::Reset => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("reset"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::Reset);
                        }
                        GeneratedField::ResetAck => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("resetAck"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::ResetAck);
                        }
                        GeneratedField::ContactControl => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("contactControl"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::ContactControl);
                        }
                        GeneratedField::GroupState => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("groupState"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::GroupState);
                        }
                        GeneratedField::GroupKeyControl => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("groupKeyControl"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::GroupKeyControl);
                        }
                        GeneratedField::OwnContactSync => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ownContactSync"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::OwnContactSync);
                        }
                        GeneratedField::OwnHistory => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ownHistory"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::OwnHistory);
                        }
                        GeneratedField::HomeMigration => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("homeMigration"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::HomeMigration);
                        }
                        GeneratedField::RecoveryControl => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("recoveryControl"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::RecoveryControl);
                        }
                        GeneratedField::LivePresence => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("livePresence"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::LivePresence);
                        }
                        GeneratedField::A2i => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("a2i"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::A2i);
                        }
                        GeneratedField::ObjectRevoke => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("objectRevoke"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::ObjectRevoke);
                        }
                        GeneratedField::OwnContactTombstone => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "ownContactTombstone",
                                ));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::OwnContactTombstone);
                        }
                        GeneratedField::OwnGroupConsent => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ownGroupConsent"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::OwnGroupConsent);
                        }
                        GeneratedField::OwnMessageCopy => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ownMessageCopy"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::OwnMessageCopy);
                        }
                        GeneratedField::Friend => {
                            if payload__.is_some() {
                                return Err(serde::de::Error::duplicate_field("friend"));
                            }
                            payload__ = map_
                                .next_value::<::std::option::Option<_>>()?
                                .map(control::Payload::Friend);
                        }
                    }
                }
                Ok(Control { operation: operation__.unwrap_or_default(), payload: payload__ })
            }
        }
        deserializer.deserialize_struct("ramflux.message.v1.Control", FIELDS, GeneratedVisitor)
    }
}

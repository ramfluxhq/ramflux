// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ControlOperation {
    ControlUnspecified = 0,
    ControlPairReset = 1,
    ControlPairResetAck = 2,
    ControlContact = 3,
    ControlGroupState = 4,
    ControlGroupKey = 5,
    ControlOwnContact = 6,
    ControlOwnHistory = 7,
    ControlHomeMigration = 8,
    ControlRecovery = 9,
    ControlLivePresence = 10,
    ControlA2i = 11,
    ControlObjectRevoke = 12,
    ControlOwnContactTombstone = 13,
    ControlOwnGroupConsent = 14,
    ControlOwnMessageCopy = 15,
    ControlFriend = 16,
}
impl ControlOperation {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::ControlUnspecified => "CONTROL_UNSPECIFIED",
            Self::ControlPairReset => "CONTROL_PAIR_RESET",
            Self::ControlPairResetAck => "CONTROL_PAIR_RESET_ACK",
            Self::ControlContact => "CONTROL_CONTACT",
            Self::ControlGroupState => "CONTROL_GROUP_STATE",
            Self::ControlGroupKey => "CONTROL_GROUP_KEY",
            Self::ControlOwnContact => "CONTROL_OWN_CONTACT",
            Self::ControlOwnHistory => "CONTROL_OWN_HISTORY",
            Self::ControlHomeMigration => "CONTROL_HOME_MIGRATION",
            Self::ControlRecovery => "CONTROL_RECOVERY",
            Self::ControlLivePresence => "CONTROL_LIVE_PRESENCE",
            Self::ControlA2i => "CONTROL_A2I",
            Self::ControlObjectRevoke => "CONTROL_OBJECT_REVOKE",
            Self::ControlOwnContactTombstone => "CONTROL_OWN_CONTACT_TOMBSTONE",
            Self::ControlOwnGroupConsent => "CONTROL_OWN_GROUP_CONSENT",
            Self::ControlOwnMessageCopy => "CONTROL_OWN_MESSAGE_COPY",
            Self::ControlFriend => "CONTROL_FRIEND",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CONTROL_UNSPECIFIED" => Some(Self::ControlUnspecified),
            "CONTROL_PAIR_RESET" => Some(Self::ControlPairReset),
            "CONTROL_PAIR_RESET_ACK" => Some(Self::ControlPairResetAck),
            "CONTROL_CONTACT" => Some(Self::ControlContact),
            "CONTROL_GROUP_STATE" => Some(Self::ControlGroupState),
            "CONTROL_GROUP_KEY" => Some(Self::ControlGroupKey),
            "CONTROL_OWN_CONTACT" => Some(Self::ControlOwnContact),
            "CONTROL_OWN_HISTORY" => Some(Self::ControlOwnHistory),
            "CONTROL_HOME_MIGRATION" => Some(Self::ControlHomeMigration),
            "CONTROL_RECOVERY" => Some(Self::ControlRecovery),
            "CONTROL_LIVE_PRESENCE" => Some(Self::ControlLivePresence),
            "CONTROL_A2I" => Some(Self::ControlA2i),
            "CONTROL_OBJECT_REVOKE" => Some(Self::ControlObjectRevoke),
            "CONTROL_OWN_CONTACT_TOMBSTONE" => Some(Self::ControlOwnContactTombstone),
            "CONTROL_OWN_GROUP_CONSENT" => Some(Self::ControlOwnGroupConsent),
            "CONTROL_OWN_MESSAGE_COPY" => Some(Self::ControlOwnMessageCopy),
            "CONTROL_FRIEND" => Some(Self::ControlFriend),
            _ => None,
        }
    }
}
impl serde::Serialize for ControlOperation {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::ControlUnspecified => "CONTROL_UNSPECIFIED",
            Self::ControlPairReset => "CONTROL_PAIR_RESET",
            Self::ControlPairResetAck => "CONTROL_PAIR_RESET_ACK",
            Self::ControlContact => "CONTROL_CONTACT",
            Self::ControlGroupState => "CONTROL_GROUP_STATE",
            Self::ControlGroupKey => "CONTROL_GROUP_KEY",
            Self::ControlOwnContact => "CONTROL_OWN_CONTACT",
            Self::ControlOwnHistory => "CONTROL_OWN_HISTORY",
            Self::ControlHomeMigration => "CONTROL_HOME_MIGRATION",
            Self::ControlRecovery => "CONTROL_RECOVERY",
            Self::ControlLivePresence => "CONTROL_LIVE_PRESENCE",
            Self::ControlA2i => "CONTROL_A2I",
            Self::ControlObjectRevoke => "CONTROL_OBJECT_REVOKE",
            Self::ControlOwnContactTombstone => "CONTROL_OWN_CONTACT_TOMBSTONE",
            Self::ControlOwnGroupConsent => "CONTROL_OWN_GROUP_CONSENT",
            Self::ControlOwnMessageCopy => "CONTROL_OWN_MESSAGE_COPY",
            Self::ControlFriend => "CONTROL_FRIEND",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for ControlOperation {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "CONTROL_UNSPECIFIED",
            "CONTROL_PAIR_RESET",
            "CONTROL_PAIR_RESET_ACK",
            "CONTROL_CONTACT",
            "CONTROL_GROUP_STATE",
            "CONTROL_GROUP_KEY",
            "CONTROL_OWN_CONTACT",
            "CONTROL_OWN_HISTORY",
            "CONTROL_HOME_MIGRATION",
            "CONTROL_RECOVERY",
            "CONTROL_LIVE_PRESENCE",
            "CONTROL_A2I",
            "CONTROL_OBJECT_REVOKE",
            "CONTROL_OWN_CONTACT_TOMBSTONE",
            "CONTROL_OWN_GROUP_CONSENT",
            "CONTROL_OWN_MESSAGE_COPY",
            "CONTROL_FRIEND",
        ];
        struct GeneratedVisitor;
        impl serde::de::Visitor<'_> for GeneratedVisitor {
            type Value = ControlOperation;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "expected one of: {:?}", &FIELDS)
            }
            fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v).ok().and_then(|x| x.try_into().ok()).ok_or_else(|| {
                    serde::de::Error::invalid_value(serde::de::Unexpected::Signed(v), &self)
                })
            }
            fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i32::try_from(v).ok().and_then(|x| x.try_into().ok()).ok_or_else(|| {
                    serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(v), &self)
                })
            }
            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match value {
                    "CONTROL_UNSPECIFIED" => Ok(ControlOperation::ControlUnspecified),
                    "CONTROL_PAIR_RESET" => Ok(ControlOperation::ControlPairReset),
                    "CONTROL_PAIR_RESET_ACK" => Ok(ControlOperation::ControlPairResetAck),
                    "CONTROL_CONTACT" => Ok(ControlOperation::ControlContact),
                    "CONTROL_GROUP_STATE" => Ok(ControlOperation::ControlGroupState),
                    "CONTROL_GROUP_KEY" => Ok(ControlOperation::ControlGroupKey),
                    "CONTROL_OWN_CONTACT" => Ok(ControlOperation::ControlOwnContact),
                    "CONTROL_OWN_HISTORY" => Ok(ControlOperation::ControlOwnHistory),
                    "CONTROL_HOME_MIGRATION" => Ok(ControlOperation::ControlHomeMigration),
                    "CONTROL_RECOVERY" => Ok(ControlOperation::ControlRecovery),
                    "CONTROL_LIVE_PRESENCE" => Ok(ControlOperation::ControlLivePresence),
                    "CONTROL_A2I" => Ok(ControlOperation::ControlA2i),
                    "CONTROL_OBJECT_REVOKE" => Ok(ControlOperation::ControlObjectRevoke),
                    "CONTROL_OWN_CONTACT_TOMBSTONE" => {
                        Ok(ControlOperation::ControlOwnContactTombstone)
                    }
                    "CONTROL_OWN_GROUP_CONSENT" => Ok(ControlOperation::ControlOwnGroupConsent),
                    "CONTROL_OWN_MESSAGE_COPY" => Ok(ControlOperation::ControlOwnMessageCopy),
                    "CONTROL_FRIEND" => Ok(ControlOperation::ControlFriend),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}

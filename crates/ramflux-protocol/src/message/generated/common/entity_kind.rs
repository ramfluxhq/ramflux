// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum EntityKind {
    EntityUnspecified = 0,
    EntityBold = 1,
    EntityItalic = 2,
    EntityCode = 3,
    EntityLink = 4,
    EntityMention = 5,
    EntitySpoiler = 6,
}
impl EntityKind {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::EntityUnspecified => "ENTITY_UNSPECIFIED",
            Self::EntityBold => "ENTITY_BOLD",
            Self::EntityItalic => "ENTITY_ITALIC",
            Self::EntityCode => "ENTITY_CODE",
            Self::EntityLink => "ENTITY_LINK",
            Self::EntityMention => "ENTITY_MENTION",
            Self::EntitySpoiler => "ENTITY_SPOILER",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ENTITY_UNSPECIFIED" => Some(Self::EntityUnspecified),
            "ENTITY_BOLD" => Some(Self::EntityBold),
            "ENTITY_ITALIC" => Some(Self::EntityItalic),
            "ENTITY_CODE" => Some(Self::EntityCode),
            "ENTITY_LINK" => Some(Self::EntityLink),
            "ENTITY_MENTION" => Some(Self::EntityMention),
            "ENTITY_SPOILER" => Some(Self::EntitySpoiler),
            _ => None,
        }
    }
}
impl serde::Serialize for EntityKind {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let variant = match self {
            Self::EntityUnspecified => "ENTITY_UNSPECIFIED",
            Self::EntityBold => "ENTITY_BOLD",
            Self::EntityItalic => "ENTITY_ITALIC",
            Self::EntityCode => "ENTITY_CODE",
            Self::EntityLink => "ENTITY_LINK",
            Self::EntityMention => "ENTITY_MENTION",
            Self::EntitySpoiler => "ENTITY_SPOILER",
        };
        serializer.serialize_str(variant)
    }
}
impl<'de> serde::Deserialize<'de> for EntityKind {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "ENTITY_UNSPECIFIED",
            "ENTITY_BOLD",
            "ENTITY_ITALIC",
            "ENTITY_CODE",
            "ENTITY_LINK",
            "ENTITY_MENTION",
            "ENTITY_SPOILER",
        ];
        struct GeneratedVisitor;
        impl serde::de::Visitor<'_> for GeneratedVisitor {
            type Value = EntityKind;
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
                    "ENTITY_UNSPECIFIED" => Ok(EntityKind::EntityUnspecified),
                    "ENTITY_BOLD" => Ok(EntityKind::EntityBold),
                    "ENTITY_ITALIC" => Ok(EntityKind::EntityItalic),
                    "ENTITY_CODE" => Ok(EntityKind::EntityCode),
                    "ENTITY_LINK" => Ok(EntityKind::EntityLink),
                    "ENTITY_MENTION" => Ok(EntityKind::EntityMention),
                    "ENTITY_SPOILER" => Ok(EntityKind::EntitySpoiler),
                    _ => Err(serde::de::Error::unknown_variant(value, FIELDS)),
                }
            }
        }
        deserializer.deserialize_any(GeneratedVisitor)
    }
}

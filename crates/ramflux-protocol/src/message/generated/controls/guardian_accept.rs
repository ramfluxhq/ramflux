// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct GuardianAccept {
    #[prost(string, tag = "1")]
    pub schema: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub version: u32,
    #[prost(string, tag = "3")]
    pub accept_id: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub invite_id: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub owner_principal_id: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub guardian_principal_id: ::prost::alloc::string::String,
    #[prost(string, tag = "7")]
    pub guardian_device_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "8")]
    pub guardian_device_epoch: u64,
    #[prost(string, tag = "9")]
    pub guardian_device_public_key_base64url: ::prost::alloc::string::String,
    #[prost(string, tag = "10")]
    pub recovery_quorum_id: ::prost::alloc::string::String,
    #[prost(int64, tag = "11")]
    pub accepted_at: i64,
    #[prost(message, optional, tag = "12")]
    pub signed: ::core::option::Option<SignedFields>,
}
impl serde::Serialize for GuardianAccept {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.schema.is_empty() {
            len += 1;
        }
        if self.version != 0 {
            len += 1;
        }
        if !self.accept_id.is_empty() {
            len += 1;
        }
        if !self.invite_id.is_empty() {
            len += 1;
        }
        if !self.owner_principal_id.is_empty() {
            len += 1;
        }
        if !self.guardian_principal_id.is_empty() {
            len += 1;
        }
        if !self.guardian_device_id.is_empty() {
            len += 1;
        }
        if self.guardian_device_epoch != 0 {
            len += 1;
        }
        if !self.guardian_device_public_key_base64url.is_empty() {
            len += 1;
        }
        if !self.recovery_quorum_id.is_empty() {
            len += 1;
        }
        if self.accepted_at != 0 {
            len += 1;
        }
        if self.signed.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.GuardianAccept", len)?;
        if !self.schema.is_empty() {
            struct_ser.serialize_field("schema", &self.schema)?;
        }
        if self.version != 0 {
            struct_ser.serialize_field("version", &self.version)?;
        }
        if !self.accept_id.is_empty() {
            struct_ser.serialize_field("acceptId", &self.accept_id)?;
        }
        if !self.invite_id.is_empty() {
            struct_ser.serialize_field("inviteId", &self.invite_id)?;
        }
        if !self.owner_principal_id.is_empty() {
            struct_ser.serialize_field("ownerPrincipalId", &self.owner_principal_id)?;
        }
        if !self.guardian_principal_id.is_empty() {
            struct_ser.serialize_field("guardianPrincipalId", &self.guardian_principal_id)?;
        }
        if !self.guardian_device_id.is_empty() {
            struct_ser.serialize_field("guardianDeviceId", &self.guardian_device_id)?;
        }
        if self.guardian_device_epoch != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "guardianDeviceEpoch",
                ToString::to_string(&self.guardian_device_epoch).as_str(),
            )?;
        }
        if !self.guardian_device_public_key_base64url.is_empty() {
            struct_ser.serialize_field(
                "guardianDevicePublicKeyBase64url",
                &self.guardian_device_public_key_base64url,
            )?;
        }
        if !self.recovery_quorum_id.is_empty() {
            struct_ser.serialize_field("recoveryQuorumId", &self.recovery_quorum_id)?;
        }
        if self.accepted_at != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser
                .serialize_field("acceptedAt", ToString::to_string(&self.accepted_at).as_str())?;
        }
        if let Some(v) = self.signed.as_ref() {
            struct_ser.serialize_field("signed", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for GuardianAccept {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "schema",
            "version",
            "accept_id",
            "acceptId",
            "invite_id",
            "inviteId",
            "owner_principal_id",
            "ownerPrincipalId",
            "guardian_principal_id",
            "guardianPrincipalId",
            "guardian_device_id",
            "guardianDeviceId",
            "guardian_device_epoch",
            "guardianDeviceEpoch",
            "guardian_device_public_key_base64url",
            "guardianDevicePublicKeyBase64url",
            "recovery_quorum_id",
            "recoveryQuorumId",
            "accepted_at",
            "acceptedAt",
            "signed",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Schema,
            Version,
            AcceptId,
            InviteId,
            OwnerPrincipalId,
            GuardianPrincipalId,
            GuardianDeviceId,
            GuardianDeviceEpoch,
            GuardianDevicePublicKeyBase64url,
            RecoveryQuorumId,
            AcceptedAt,
            Signed,
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
                            "schema" => Ok(GeneratedField::Schema),
                            "version" => Ok(GeneratedField::Version),
                            "acceptId" | "accept_id" => Ok(GeneratedField::AcceptId),
                            "inviteId" | "invite_id" => Ok(GeneratedField::InviteId),
                            "ownerPrincipalId" | "owner_principal_id" => {
                                Ok(GeneratedField::OwnerPrincipalId)
                            }
                            "guardianPrincipalId" | "guardian_principal_id" => {
                                Ok(GeneratedField::GuardianPrincipalId)
                            }
                            "guardianDeviceId" | "guardian_device_id" => {
                                Ok(GeneratedField::GuardianDeviceId)
                            }
                            "guardianDeviceEpoch" | "guardian_device_epoch" => {
                                Ok(GeneratedField::GuardianDeviceEpoch)
                            }
                            "guardianDevicePublicKeyBase64url"
                            | "guardian_device_public_key_base64url" => {
                                Ok(GeneratedField::GuardianDevicePublicKeyBase64url)
                            }
                            "recoveryQuorumId" | "recovery_quorum_id" => {
                                Ok(GeneratedField::RecoveryQuorumId)
                            }
                            "acceptedAt" | "accepted_at" => Ok(GeneratedField::AcceptedAt),
                            "signed" => Ok(GeneratedField::Signed),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = GuardianAccept;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.GuardianAccept")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<GuardianAccept, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut schema__ = None;
                let mut version__ = None;
                let mut accept_id__ = None;
                let mut invite_id__ = None;
                let mut owner_principal_id__ = None;
                let mut guardian_principal_id__ = None;
                let mut guardian_device_id__ = None;
                let mut guardian_device_epoch__ = None;
                let mut guardian_device_public_key_base64url__ = None;
                let mut recovery_quorum_id__ = None;
                let mut accepted_at__ = None;
                let mut signed__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::Schema => {
                            if schema__.is_some() {
                                return Err(serde::de::Error::duplicate_field("schema"));
                            }
                            schema__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Version => {
                            if version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("version"));
                            }
                            version__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::AcceptId => {
                            if accept_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("acceptId"));
                            }
                            accept_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::InviteId => {
                            if invite_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("inviteId"));
                            }
                            invite_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::OwnerPrincipalId => {
                            if owner_principal_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ownerPrincipalId"));
                            }
                            owner_principal_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::GuardianPrincipalId => {
                            if guardian_principal_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "guardianPrincipalId",
                                ));
                            }
                            guardian_principal_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::GuardianDeviceId => {
                            if guardian_device_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("guardianDeviceId"));
                            }
                            guardian_device_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::GuardianDeviceEpoch => {
                            if guardian_device_epoch__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "guardianDeviceEpoch",
                                ));
                            }
                            guardian_device_epoch__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::GuardianDevicePublicKeyBase64url => {
                            if guardian_device_public_key_base64url__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "guardianDevicePublicKeyBase64url",
                                ));
                            }
                            guardian_device_public_key_base64url__ = Some(map_.next_value()?);
                        }
                        GeneratedField::RecoveryQuorumId => {
                            if recovery_quorum_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("recoveryQuorumId"));
                            }
                            recovery_quorum_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::AcceptedAt => {
                            if accepted_at__.is_some() {
                                return Err(serde::de::Error::duplicate_field("acceptedAt"));
                            }
                            accepted_at__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Signed => {
                            if signed__.is_some() {
                                return Err(serde::de::Error::duplicate_field("signed"));
                            }
                            signed__ = map_.next_value()?;
                        }
                    }
                }
                Ok(GuardianAccept {
                    schema: schema__.unwrap_or_default(),
                    version: version__.unwrap_or_default(),
                    accept_id: accept_id__.unwrap_or_default(),
                    invite_id: invite_id__.unwrap_or_default(),
                    owner_principal_id: owner_principal_id__.unwrap_or_default(),
                    guardian_principal_id: guardian_principal_id__.unwrap_or_default(),
                    guardian_device_id: guardian_device_id__.unwrap_or_default(),
                    guardian_device_epoch: guardian_device_epoch__.unwrap_or_default(),
                    guardian_device_public_key_base64url: guardian_device_public_key_base64url__
                        .unwrap_or_default(),
                    recovery_quorum_id: recovery_quorum_id__.unwrap_or_default(),
                    accepted_at: accepted_at__.unwrap_or_default(),
                    signed: signed__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.GuardianAccept",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

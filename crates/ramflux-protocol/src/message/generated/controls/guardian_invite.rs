// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct GuardianInvite {
    #[prost(string, tag = "1")]
    pub schema: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub version: u32,
    #[prost(string, tag = "3")]
    pub invite_id: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub inviter_principal_id: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub inviter_device_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "6")]
    pub inviter_device_epoch: u64,
    #[prost(string, tag = "7")]
    pub inviter_device_public_key_base64url: ::prost::alloc::string::String,
    #[prost(string, tag = "8")]
    pub guardian_principal_id: ::prost::alloc::string::String,
    #[prost(string, tag = "9")]
    pub recovery_quorum_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "10")]
    pub share: ::core::option::Option<GuardianRecoveryShare>,
    #[prost(int64, tag = "11")]
    pub issued_at: i64,
    #[prost(int64, tag = "12")]
    pub expires_at: i64,
    #[prost(message, optional, tag = "13")]
    pub signed: ::core::option::Option<SignedFields>,
}
impl serde::Serialize for GuardianInvite {
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
        if !self.invite_id.is_empty() {
            len += 1;
        }
        if !self.inviter_principal_id.is_empty() {
            len += 1;
        }
        if !self.inviter_device_id.is_empty() {
            len += 1;
        }
        if self.inviter_device_epoch != 0 {
            len += 1;
        }
        if !self.inviter_device_public_key_base64url.is_empty() {
            len += 1;
        }
        if !self.guardian_principal_id.is_empty() {
            len += 1;
        }
        if !self.recovery_quorum_id.is_empty() {
            len += 1;
        }
        if self.share.is_some() {
            len += 1;
        }
        if self.issued_at != 0 {
            len += 1;
        }
        if self.expires_at != 0 {
            len += 1;
        }
        if self.signed.is_some() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.GuardianInvite", len)?;
        if !self.schema.is_empty() {
            struct_ser.serialize_field("schema", &self.schema)?;
        }
        if self.version != 0 {
            struct_ser.serialize_field("version", &self.version)?;
        }
        if !self.invite_id.is_empty() {
            struct_ser.serialize_field("inviteId", &self.invite_id)?;
        }
        if !self.inviter_principal_id.is_empty() {
            struct_ser.serialize_field("inviterPrincipalId", &self.inviter_principal_id)?;
        }
        if !self.inviter_device_id.is_empty() {
            struct_ser.serialize_field("inviterDeviceId", &self.inviter_device_id)?;
        }
        if self.inviter_device_epoch != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "inviterDeviceEpoch",
                ToString::to_string(&self.inviter_device_epoch).as_str(),
            )?;
        }
        if !self.inviter_device_public_key_base64url.is_empty() {
            struct_ser.serialize_field(
                "inviterDevicePublicKeyBase64url",
                &self.inviter_device_public_key_base64url,
            )?;
        }
        if !self.guardian_principal_id.is_empty() {
            struct_ser.serialize_field("guardianPrincipalId", &self.guardian_principal_id)?;
        }
        if !self.recovery_quorum_id.is_empty() {
            struct_ser.serialize_field("recoveryQuorumId", &self.recovery_quorum_id)?;
        }
        if let Some(v) = self.share.as_ref() {
            struct_ser.serialize_field("share", v)?;
        }
        if self.issued_at != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser
                .serialize_field("issuedAt", ToString::to_string(&self.issued_at).as_str())?;
        }
        if self.expires_at != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser
                .serialize_field("expiresAt", ToString::to_string(&self.expires_at).as_str())?;
        }
        if let Some(v) = self.signed.as_ref() {
            struct_ser.serialize_field("signed", v)?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for GuardianInvite {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "schema",
            "version",
            "invite_id",
            "inviteId",
            "inviter_principal_id",
            "inviterPrincipalId",
            "inviter_device_id",
            "inviterDeviceId",
            "inviter_device_epoch",
            "inviterDeviceEpoch",
            "inviter_device_public_key_base64url",
            "inviterDevicePublicKeyBase64url",
            "guardian_principal_id",
            "guardianPrincipalId",
            "recovery_quorum_id",
            "recoveryQuorumId",
            "share",
            "issued_at",
            "issuedAt",
            "expires_at",
            "expiresAt",
            "signed",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            Schema,
            Version,
            InviteId,
            InviterPrincipalId,
            InviterDeviceId,
            InviterDeviceEpoch,
            InviterDevicePublicKeyBase64url,
            GuardianPrincipalId,
            RecoveryQuorumId,
            Share,
            IssuedAt,
            ExpiresAt,
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
                            "inviteId" | "invite_id" => Ok(GeneratedField::InviteId),
                            "inviterPrincipalId" | "inviter_principal_id" => {
                                Ok(GeneratedField::InviterPrincipalId)
                            }
                            "inviterDeviceId" | "inviter_device_id" => {
                                Ok(GeneratedField::InviterDeviceId)
                            }
                            "inviterDeviceEpoch" | "inviter_device_epoch" => {
                                Ok(GeneratedField::InviterDeviceEpoch)
                            }
                            "inviterDevicePublicKeyBase64url"
                            | "inviter_device_public_key_base64url" => {
                                Ok(GeneratedField::InviterDevicePublicKeyBase64url)
                            }
                            "guardianPrincipalId" | "guardian_principal_id" => {
                                Ok(GeneratedField::GuardianPrincipalId)
                            }
                            "recoveryQuorumId" | "recovery_quorum_id" => {
                                Ok(GeneratedField::RecoveryQuorumId)
                            }
                            "share" => Ok(GeneratedField::Share),
                            "issuedAt" | "issued_at" => Ok(GeneratedField::IssuedAt),
                            "expiresAt" | "expires_at" => Ok(GeneratedField::ExpiresAt),
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
            type Value = GuardianInvite;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.GuardianInvite")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<GuardianInvite, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut schema__ = None;
                let mut version__ = None;
                let mut invite_id__ = None;
                let mut inviter_principal_id__ = None;
                let mut inviter_device_id__ = None;
                let mut inviter_device_epoch__ = None;
                let mut inviter_device_public_key_base64url__ = None;
                let mut guardian_principal_id__ = None;
                let mut recovery_quorum_id__ = None;
                let mut share__ = None;
                let mut issued_at__ = None;
                let mut expires_at__ = None;
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
                        GeneratedField::InviteId => {
                            if invite_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("inviteId"));
                            }
                            invite_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::InviterPrincipalId => {
                            if inviter_principal_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "inviterPrincipalId",
                                ));
                            }
                            inviter_principal_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::InviterDeviceId => {
                            if inviter_device_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("inviterDeviceId"));
                            }
                            inviter_device_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::InviterDeviceEpoch => {
                            if inviter_device_epoch__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "inviterDeviceEpoch",
                                ));
                            }
                            inviter_device_epoch__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::InviterDevicePublicKeyBase64url => {
                            if inviter_device_public_key_base64url__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "inviterDevicePublicKeyBase64url",
                                ));
                            }
                            inviter_device_public_key_base64url__ = Some(map_.next_value()?);
                        }
                        GeneratedField::GuardianPrincipalId => {
                            if guardian_principal_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "guardianPrincipalId",
                                ));
                            }
                            guardian_principal_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::RecoveryQuorumId => {
                            if recovery_quorum_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("recoveryQuorumId"));
                            }
                            recovery_quorum_id__ = Some(map_.next_value()?);
                        }
                        GeneratedField::Share => {
                            if share__.is_some() {
                                return Err(serde::de::Error::duplicate_field("share"));
                            }
                            share__ = map_.next_value()?;
                        }
                        GeneratedField::IssuedAt => {
                            if issued_at__.is_some() {
                                return Err(serde::de::Error::duplicate_field("issuedAt"));
                            }
                            issued_at__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::ExpiresAt => {
                            if expires_at__.is_some() {
                                return Err(serde::de::Error::duplicate_field("expiresAt"));
                            }
                            expires_at__ = Some(
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
                Ok(GuardianInvite {
                    schema: schema__.unwrap_or_default(),
                    version: version__.unwrap_or_default(),
                    invite_id: invite_id__.unwrap_or_default(),
                    inviter_principal_id: inviter_principal_id__.unwrap_or_default(),
                    inviter_device_id: inviter_device_id__.unwrap_or_default(),
                    inviter_device_epoch: inviter_device_epoch__.unwrap_or_default(),
                    inviter_device_public_key_base64url: inviter_device_public_key_base64url__
                        .unwrap_or_default(),
                    guardian_principal_id: guardian_principal_id__.unwrap_or_default(),
                    recovery_quorum_id: recovery_quorum_id__.unwrap_or_default(),
                    share: share__,
                    issued_at: issued_at__.unwrap_or_default(),
                    expires_at: expires_at__.unwrap_or_default(),
                    signed: signed__,
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.GuardianInvite",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

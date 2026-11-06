// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#[allow(unused_imports)]
use super::super::*;

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub struct RatchetHeader {
    #[prost(bytes = "vec", tag = "1")]
    pub session_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub counter: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub ratchet_public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub previous_chain_length: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub sender_device_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub recipient_device_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "7")]
    pub device_epoch: u64,
    #[prost(bytes = "vec", tag = "8")]
    pub event_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub key_commitment: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    pub body_commitment: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "11")]
    pub authority_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "12")]
    pub bootstrap_transcript_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "13")]
    pub bundle_hash: ::prost::alloc::vec::Vec<u8>,
}
impl serde::Serialize for RatchetHeader {
    #[allow(deprecated)]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut len = 0;
        if !self.session_id.is_empty() {
            len += 1;
        }
        if self.counter != 0 {
            len += 1;
        }
        if !self.ratchet_public_key.is_empty() {
            len += 1;
        }
        if self.previous_chain_length != 0 {
            len += 1;
        }
        if !self.sender_device_hash.is_empty() {
            len += 1;
        }
        if !self.recipient_device_hash.is_empty() {
            len += 1;
        }
        if self.device_epoch != 0 {
            len += 1;
        }
        if !self.event_id.is_empty() {
            len += 1;
        }
        if !self.key_commitment.is_empty() {
            len += 1;
        }
        if !self.body_commitment.is_empty() {
            len += 1;
        }
        if !self.authority_hash.is_empty() {
            len += 1;
        }
        if !self.bootstrap_transcript_hash.is_empty() {
            len += 1;
        }
        if !self.bundle_hash.is_empty() {
            len += 1;
        }
        let mut struct_ser =
            serializer.serialize_struct("ramflux.message.v1.RatchetHeader", len)?;
        if !self.session_id.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "sessionId",
                pbjson::private::base64::encode(&self.session_id).as_str(),
            )?;
        }
        if self.counter != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field("counter", ToString::to_string(&self.counter).as_str())?;
        }
        if !self.ratchet_public_key.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "ratchetPublicKey",
                pbjson::private::base64::encode(&self.ratchet_public_key).as_str(),
            )?;
        }
        if self.previous_chain_length != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "previousChainLength",
                ToString::to_string(&self.previous_chain_length).as_str(),
            )?;
        }
        if !self.sender_device_hash.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "senderDeviceHash",
                pbjson::private::base64::encode(&self.sender_device_hash).as_str(),
            )?;
        }
        if !self.recipient_device_hash.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "recipientDeviceHash",
                pbjson::private::base64::encode(&self.recipient_device_hash).as_str(),
            )?;
        }
        if self.device_epoch != 0 {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser
                .serialize_field("deviceEpoch", ToString::to_string(&self.device_epoch).as_str())?;
        }
        if !self.event_id.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "eventId",
                pbjson::private::base64::encode(&self.event_id).as_str(),
            )?;
        }
        if !self.key_commitment.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "keyCommitment",
                pbjson::private::base64::encode(&self.key_commitment).as_str(),
            )?;
        }
        if !self.body_commitment.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "bodyCommitment",
                pbjson::private::base64::encode(&self.body_commitment).as_str(),
            )?;
        }
        if !self.authority_hash.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "authorityHash",
                pbjson::private::base64::encode(&self.authority_hash).as_str(),
            )?;
        }
        if !self.bootstrap_transcript_hash.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "bootstrapTranscriptHash",
                pbjson::private::base64::encode(&self.bootstrap_transcript_hash).as_str(),
            )?;
        }
        if !self.bundle_hash.is_empty() {
            #[allow(clippy::needless_borrow)]
            #[allow(clippy::needless_borrows_for_generic_args)]
            struct_ser.serialize_field(
                "bundleHash",
                pbjson::private::base64::encode(&self.bundle_hash).as_str(),
            )?;
        }
        struct_ser.end()
    }
}
impl<'de> serde::Deserialize<'de> for RatchetHeader {
    #[allow(deprecated)]
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "session_id",
            "sessionId",
            "counter",
            "ratchet_public_key",
            "ratchetPublicKey",
            "previous_chain_length",
            "previousChainLength",
            "sender_device_hash",
            "senderDeviceHash",
            "recipient_device_hash",
            "recipientDeviceHash",
            "device_epoch",
            "deviceEpoch",
            "event_id",
            "eventId",
            "key_commitment",
            "keyCommitment",
            "body_commitment",
            "bodyCommitment",
            "authority_hash",
            "authorityHash",
            "bootstrap_transcript_hash",
            "bootstrapTranscriptHash",
            "bundle_hash",
            "bundleHash",
        ];
        #[allow(clippy::enum_variant_names)]
        enum GeneratedField {
            SessionId,
            Counter,
            RatchetPublicKey,
            PreviousChainLength,
            SenderDeviceHash,
            RecipientDeviceHash,
            DeviceEpoch,
            EventId,
            KeyCommitment,
            BodyCommitment,
            AuthorityHash,
            BootstrapTranscriptHash,
            BundleHash,
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
                            "sessionId" | "session_id" => Ok(GeneratedField::SessionId),
                            "counter" => Ok(GeneratedField::Counter),
                            "ratchetPublicKey" | "ratchet_public_key" => {
                                Ok(GeneratedField::RatchetPublicKey)
                            }
                            "previousChainLength" | "previous_chain_length" => {
                                Ok(GeneratedField::PreviousChainLength)
                            }
                            "senderDeviceHash" | "sender_device_hash" => {
                                Ok(GeneratedField::SenderDeviceHash)
                            }
                            "recipientDeviceHash" | "recipient_device_hash" => {
                                Ok(GeneratedField::RecipientDeviceHash)
                            }
                            "deviceEpoch" | "device_epoch" => Ok(GeneratedField::DeviceEpoch),
                            "eventId" | "event_id" => Ok(GeneratedField::EventId),
                            "keyCommitment" | "key_commitment" => Ok(GeneratedField::KeyCommitment),
                            "bodyCommitment" | "body_commitment" => {
                                Ok(GeneratedField::BodyCommitment)
                            }
                            "authorityHash" | "authority_hash" => Ok(GeneratedField::AuthorityHash),
                            "bootstrapTranscriptHash" | "bootstrap_transcript_hash" => {
                                Ok(GeneratedField::BootstrapTranscriptHash)
                            }
                            "bundleHash" | "bundle_hash" => Ok(GeneratedField::BundleHash),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }
                deserializer.deserialize_identifier(GeneratedVisitor)
            }
        }
        struct GeneratedVisitor;
        impl<'de> serde::de::Visitor<'de> for GeneratedVisitor {
            type Value = RatchetHeader;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("struct ramflux.message.v1.RatchetHeader")
            }
            fn visit_map<V>(self, mut map_: V) -> std::result::Result<RatchetHeader, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut session_id__ = None;
                let mut counter__ = None;
                let mut ratchet_public_key__ = None;
                let mut previous_chain_length__ = None;
                let mut sender_device_hash__ = None;
                let mut recipient_device_hash__ = None;
                let mut device_epoch__ = None;
                let mut event_id__ = None;
                let mut key_commitment__ = None;
                let mut body_commitment__ = None;
                let mut authority_hash__ = None;
                let mut bootstrap_transcript_hash__ = None;
                let mut bundle_hash__ = None;
                let mut seen_fields__ = std::collections::HashSet::new();
                while let Some(k) = map_.next_key()? {
                    if !seen_fields__.insert(std::mem::discriminant(&k)) {
                        return Err(serde::de::Error::custom("duplicate ProtoJSON field or alias"));
                    }
                    match k {
                        GeneratedField::SessionId => {
                            if session_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("sessionId"));
                            }
                            session_id__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::Counter => {
                            if counter__.is_some() {
                                return Err(serde::de::Error::duplicate_field("counter"));
                            }
                            counter__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::RatchetPublicKey => {
                            if ratchet_public_key__.is_some() {
                                return Err(serde::de::Error::duplicate_field("ratchetPublicKey"));
                            }
                            ratchet_public_key__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::PreviousChainLength => {
                            if previous_chain_length__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "previousChainLength",
                                ));
                            }
                            previous_chain_length__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::SenderDeviceHash => {
                            if sender_device_hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field("senderDeviceHash"));
                            }
                            sender_device_hash__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::RecipientDeviceHash => {
                            if recipient_device_hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "recipientDeviceHash",
                                ));
                            }
                            recipient_device_hash__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::DeviceEpoch => {
                            if device_epoch__.is_some() {
                                return Err(serde::de::Error::duplicate_field("deviceEpoch"));
                            }
                            device_epoch__ = Some(
                                map_.next_value::<::pbjson::private::NumberDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::EventId => {
                            if event_id__.is_some() {
                                return Err(serde::de::Error::duplicate_field("eventId"));
                            }
                            event_id__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::KeyCommitment => {
                            if key_commitment__.is_some() {
                                return Err(serde::de::Error::duplicate_field("keyCommitment"));
                            }
                            key_commitment__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::BodyCommitment => {
                            if body_commitment__.is_some() {
                                return Err(serde::de::Error::duplicate_field("bodyCommitment"));
                            }
                            body_commitment__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::AuthorityHash => {
                            if authority_hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field("authorityHash"));
                            }
                            authority_hash__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::BootstrapTranscriptHash => {
                            if bootstrap_transcript_hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "bootstrapTranscriptHash",
                                ));
                            }
                            bootstrap_transcript_hash__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                        GeneratedField::BundleHash => {
                            if bundle_hash__.is_some() {
                                return Err(serde::de::Error::duplicate_field("bundleHash"));
                            }
                            bundle_hash__ = Some(
                                map_.next_value::<::pbjson::private::BytesDeserialize<_>>()?.0,
                            );
                        }
                    }
                }
                Ok(RatchetHeader {
                    session_id: session_id__.unwrap_or_default(),
                    counter: counter__.unwrap_or_default(),
                    ratchet_public_key: ratchet_public_key__.unwrap_or_default(),
                    previous_chain_length: previous_chain_length__.unwrap_or_default(),
                    sender_device_hash: sender_device_hash__.unwrap_or_default(),
                    recipient_device_hash: recipient_device_hash__.unwrap_or_default(),
                    device_epoch: device_epoch__.unwrap_or_default(),
                    event_id: event_id__.unwrap_or_default(),
                    key_commitment: key_commitment__.unwrap_or_default(),
                    body_commitment: body_commitment__.unwrap_or_default(),
                    authority_hash: authority_hash__.unwrap_or_default(),
                    bootstrap_transcript_hash: bootstrap_transcript_hash__.unwrap_or_default(),
                    bundle_hash: bundle_hash__.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_struct(
            "ramflux.message.v1.RatchetHeader",
            FIELDS,
            GeneratedVisitor,
        )
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Addendum A1: one bounded, role-authenticated Auth-HPKE confirmation per epoch.
use super::super::{PROFILE, PairingWire, Result, SecretBase64, WireError, b32, require};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HpkeConfirmFull {
    pub confirmation: String,
    pub enc: String,
    pub epoch: String,
    pub kind: String,
    pub lease_id: String,
    pub role: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendFullControl {
    pub control: HpkeConfirmFull,
    pub kind: String,
    pub profile: String,
    pub token: SecretBase64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollFullControl {
    pub epoch: String,
    pub kind: String,
    pub lease_id: String,
    pub profile: String,
    pub role: String,
    pub token: SecretBase64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolledFullControl {
    #[serde(deserialize_with = "super::super::super::required_nullable")]
    pub control: Option<HpkeConfirmFull>,
    pub kind: String,
    pub profile: String,
}
/// Exact H1 token reply; the other role's token is never included.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeTokenFull {
    pub epoch: String,
    pub kind: String,
    pub lease_id: String,
    #[serde(serialize_with = "canonical_peer_proof")]
    pub peer_proof: crate::custody::Envelope<super::super::lease::ResumeProof>,
    pub profile: String,
    pub role: String,
    pub token: SecretBase64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProveFull {
    pub kind: String,
    pub profile: String,
    #[serde(serialize_with = "canonical_peer_proof")]
    pub proof: crate::custody::Envelope<super::super::lease::ResumeProof>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumePendingFull {
    pub epoch: String,
    pub kind: String,
    pub lease_id: String,
    pub profile: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollFull {
    #[serde(deserialize_with = "super::super::super::required_nullable")]
    pub acknowledged: Option<super::super::U64>,
    pub epoch: String,
    pub kind: String,
    pub lease_id: String,
    pub profile: String,
    pub role: String,
    pub token: SecretBase64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SentFull {
    pub counter: super::super::U64,
    pub kind: String,
    pub profile: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseFull {
    pub epoch: String,
    pub kind: String,
    pub lease_id: String,
    pub profile: String,
    pub role: String,
    pub token: SecretBase64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosedFull {
    pub kind: String,
    pub profile: String,
}
pub(super) fn canonical_peer_proof<S: serde::Serializer>(
    proof: &crate::custody::Envelope<super::super::lease::ResumeProof>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Keys<'a> {
        destination: &'a str,
        source: &'a str,
    }
    #[derive(Serialize)]
    struct Body<'a> {
        boot_id: &'a str,
        epoch: &'a str,
        hpke_keys: Keys<'a>,
        lease_id: &'a str,
        nonce: &'a str,
        role: &'a str,
        schema: &'a str,
        version: u32,
    }
    #[derive(Serialize)]
    struct Envelope<'a> {
        body: Body<'a>,
        signature: &'a str,
    }
    let body = &proof.body;
    Envelope {
        body: Body {
            boot_id: &body.boot_id,
            epoch: &body.epoch,
            hpke_keys: Keys {
                destination: &body.hpke_keys.destination,
                source: &body.hpke_keys.source,
            },
            lease_id: &body.lease_id,
            nonce: &body.nonce,
            role: &body.role,
            schema: &body.schema,
            version: body.version,
        },
        signature: &proof.signature,
    }
    .serialize(serializer)
}
fn decode_control<T: PairingWire + serde::de::DeserializeOwned>(input: &[u8]) -> Result<T> {
    require(input.len() <= T::LIMIT, "control_size")?;
    let value: T = crate::parse_i_json_secret(input).map_err(|_| WireError::Shape)?;
    require(Zeroizing::new(value.to_wire_bytes()?).as_slice() == input, "canonical_control")?;
    Ok(value)
}
// Struct declarations have exact JCS field order. Secret tokens never enter a Value tree.
macro_rules! canonical_control {
    ($ty:ty, $value:ident, $validation:block) => {
        impl $ty {
            /// Direct bounded canonical encoding, wiping bearer tokens on release.
            /// # Errors
            /// Refuses invalid fields or a complete carrier above 8192 bytes.
            pub fn encode_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
                self.validate()?;
                let mut bytes = Zeroizing::new(Vec::with_capacity(Self::LIMIT));
                serde_json::to_writer(&mut *bytes, self).map_err(|_| WireError::Json)?;
                require(bytes.len() <= Self::LIMIT, "control_size")?;
                Ok(bytes)
            }
        }
        impl PairingWire for $ty {
            const LIMIT: usize = 8192;
            fn validate(&self) -> Result<()> {
                let $value = self;
                $validation
            }
            fn to_wire_bytes(&self) -> Result<Vec<u8>> {
                Ok(std::mem::take(&mut *self.encode_secret()?))
            }
            fn from_wire_bytes(input: &[u8]) -> Result<Self> {
                decode_control(input)
            }
        }
    };
}
canonical_control!(HpkeConfirmFull, value, {
    require(value.kind == "hpke_confirm" && value.role == "initiator", "role")?;
    for item in [&value.enc, &value.epoch, &value.lease_id] {
        b32(item, "full_context")?;
    }
    require(value.confirmation.len() <= Self::LIMIT, "confirmation")?;
    let raw = crate::decode_base64url(&value.confirmation)
        .map_err(|_| WireError::Field("confirmation"))?;
    require(raw.len() >= 16 && crate::encode_base64url(raw) == value.confirmation, "confirmation")
});
canonical_control!(SendFullControl, value, {
    require(value.kind == "send_full_control" && value.profile == PROFILE, "profile")?;
    require(value.token.decode(32)?.len() == 32, "token")?;
    value.control.validate()
});
canonical_control!(PollFullControl, value, {
    require(value.kind == "poll_full_control" && value.profile == PROFILE, "profile")?;
    require(value.role == "responder", "role")?;
    b32(&value.epoch, "epoch")?;
    b32(&value.lease_id, "lease_id")?;
    require(value.token.decode(32)?.len() == 32, "token")
});
canonical_control!(PolledFullControl, value, {
    require(value.kind == "polled_full_control" && value.profile == PROFILE, "profile")?;
    if let Some(control) = &value.control {
        control.validate()?;
    }
    Ok(())
});

canonical_control!(ResumeTokenFull, value, {
    require(
        value.kind == "resume_token_full" && value.profile == super::super::PROFILE,
        "profile",
    )?;
    b32(&value.epoch, "epoch")?;
    b32(&value.lease_id, "lease_id")?;
    require(matches!(value.role.as_str(), "initiator" | "responder"), "role")?;
    require(value.token.decode(32)?.len() == 32, "token")?;
    value.peer_proof.body.validate()?;
    require(
        value.peer_proof.body.role != value.role
            && value.peer_proof.body.epoch == value.epoch
            && value.peer_proof.body.lease_id == value.lease_id,
        "resume_context",
    )?;
    let signature = crate::decode_base64url(&value.peer_proof.signature)
        .map_err(|_| WireError::Field("signature"))?;
    require(
        signature.len() == 64 && crate::encode_base64url(signature) == value.peer_proof.signature,
        "signature",
    )
});

canonical_control!(ProveFull, value, {
    require(value.kind == "prove_full" && value.profile == super::super::PROFILE, "profile")?;
    value.proof.body.validate()?;
    let signature = crate::decode_base64url(&value.proof.signature)
        .map_err(|_| WireError::Field("signature"))?;
    require(
        signature.len() == 64 && crate::encode_base64url(signature) == value.proof.signature,
        "signature",
    )
});
canonical_control!(ResumePendingFull, value, {
    require(
        value.kind == "resume_pending_full" && value.profile == super::super::PROFILE,
        "profile",
    )?;
    b32(&value.epoch, "epoch")?;
    b32(&value.lease_id, "lease_id")
});
canonical_control!(PollFull, value, {
    require(value.kind == "poll_full" && value.profile == super::super::PROFILE, "profile")?;
    b32(&value.epoch, "epoch")?;
    b32(&value.lease_id, "lease_id")?;
    require(matches!(value.role.as_str(), "initiator" | "responder"), "role")?;
    require(value.token.decode(32)?.len() == 32, "token")?;
    require(
        value.acknowledged.is_none_or(|counter| counter.0 < super::super::PACKETS_PER_KEY),
        "ResumeRequired",
    )
});
canonical_control!(SentFull, value, {
    require(value.kind == "sent_full" && value.profile == super::super::PROFILE, "profile")?;
    require(value.counter.0 < super::super::PACKETS_PER_KEY, "ResumeRequired")
});
canonical_control!(CloseFull, value, {
    require(value.kind == "close_full" && value.profile == super::super::PROFILE, "profile")?;
    b32(&value.epoch, "epoch")?;
    b32(&value.lease_id, "lease_id")?;
    require(matches!(value.role.as_str(), "initiator" | "responder"), "role")?;
    require(value.token.decode(32)?.len() == 32, "token")
});
canonical_control!(ClosedFull, value, {
    require(value.kind == "closed_full" && value.profile == super::super::PROFILE, "profile")
});

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    fn request() -> SendFullControl {
        SendFullControl {
            control: HpkeConfirmFull {
                confirmation: crate::encode_base64url([5; 64]),
                enc: crate::encode_base64url([1; 32]),
                epoch: crate::encode_base64url([2; 32]),
                kind: "hpke_confirm".into(),
                lease_id: crate::encode_base64url([3; 32]),
                role: "initiator".into(),
            },
            kind: "send_full_control".into(),
            profile: PROFILE.into(),
            token: SecretBase64::from_bytes(&[4; 32]),
        }
    }
    #[test]
    fn full_control_a1_exact_canonical_bytes_and_closed_arms() -> TestResult {
        let request = request();
        let expected = format!(
            "{{\"control\":{{\"confirmation\":\"{}\",\"enc\":\"{}\",\"epoch\":\"{}\",\"kind\":\"hpke_confirm\",\"lease_id\":\"{}\",\"role\":\"initiator\"}},\"kind\":\"send_full_control\",\"profile\":\"primary_transfer_full_v1\",\"token\":\"{}\"}}",
            crate::encode_base64url([5; 64]),
            crate::encode_base64url([1; 32]),
            crate::encode_base64url([2; 32]),
            crate::encode_base64url([3; 32]),
            crate::encode_base64url([4; 32]),
        );
        assert_eq!(request.encode_secret()?.as_slice(), expected.as_bytes());
        SendFullControl::from_wire_bytes(expected.as_bytes())?;
        for invalid in [
            expected.replacen(':', ": ", 1),
            expected.replacen("hpke_confirm", "other_control", 1),
            expected.replacen("initiator", "responder", 1),
            expected.replacen(
                "\"kind\":\"send_full_control\"",
                "\"kind\":\"send_full_control\",\"extra\":0",
                1,
            ),
            expected.replacen("\"token\":", "\"token\":\"duplicate\",\"token\":", 1),
        ] {
            assert!(SendFullControl::from_wire_bytes(invalid.as_bytes()).is_err());
        }
        let empty = b"{\"control\":null,\"kind\":\"polled_full_control\",\"profile\":\"primary_transfer_full_v1\"}";
        assert!(PolledFullControl::from_wire_bytes(empty)?.control.is_none());
        assert!(
            PolledFullControl::from_wire_bytes(
                b"{\"kind\":\"polled_full_control\",\"profile\":\"primary_transfer_full_v1\"}"
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn full_control_a1_whole_carrier_limit_includes_token_and_routing() -> TestResult {
        let mut request = request();
        // Independent serializer determines actual size; no assumed framing allowance.
        let mut largest = None;
        let mut first_excess = None;
        for length in 5600..6100 {
            request.control.confirmation = crate::encode_base64url(vec![0; length]);
            let raw = serde_json::to_vec(&request)?;
            if raw.len() <= 8192 {
                largest = Some(raw);
            } else {
                first_excess = Some(raw);
                break;
            }
        }
        SendFullControl::from_wire_bytes(&largest.ok_or("no fitting control")?)?;
        let excess = first_excess.ok_or("no oversized control")?;
        assert!(SendFullControl::from_wire_bytes(&excess).is_err());
        assert!(request.encode_secret().is_err());
        Ok(())
    }
}

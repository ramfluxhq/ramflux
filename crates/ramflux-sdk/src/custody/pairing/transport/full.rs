// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A1/A2 full relay transport: sensitive erasing credentials and one body allocation.
use super::{
    ErasingBody, HttpRelay, REQUEST_DEADLINE, SdkError, failure_error, http_error,
    require_https_origin, status_error, wire,
};
use ramflux_protocol::custody::pairing::{
    PairingWire,
    full_transfer::{
        PACKET_BYTES, SecretBase64,
        relay::{PollFullControl, SendFull, SendFullControl},
    },
};
use reqwest::header::HeaderValue;
use zeroize::Zeroizing;

mod sealed {
    pub trait Sealed {}
}
/// Only compiled full-role request codecs can create this authenticated transport request.
pub trait FullRelayRequest: sealed::Sealed + Sync {
    fn route(&self) -> &'static str;
    fn scope(&self) -> (&str, &str, &str, &SecretBase64);
    /// # Errors
    /// Refuses a malformed or oversized complete full-profile body.
    fn encode_full(&self) -> Result<Zeroizing<Vec<u8>>, SdkError>;
}
impl sealed::Sealed for SendFull {}
impl FullRelayRequest for SendFull {
    fn route(&self) -> &'static str {
        "send"
    }
    fn scope(&self) -> (&str, &str, &str, &SecretBase64) {
        (&self.packet.lease_id, &self.packet.epoch, &self.packet.role, &self.token)
    }
    fn encode_full(&self) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        self.encode_secret().map_err(|error| wire(&error))
    }
}
impl sealed::Sealed for SendFullControl {}
impl FullRelayRequest for SendFullControl {
    fn route(&self) -> &'static str {
        "send"
    }
    fn scope(&self) -> (&str, &str, &str, &SecretBase64) {
        (&self.control.lease_id, &self.control.epoch, &self.control.role, &self.token)
    }
    fn encode_full(&self) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        self.encode_secret().map_err(|error| wire(&error))
    }
}
impl sealed::Sealed for PollFullControl {}
impl FullRelayRequest for PollFullControl {
    fn route(&self) -> &'static str {
        "poll"
    }
    fn scope(&self) -> (&str, &str, &str, &SecretBase64) {
        (&self.lease_id, &self.epoch, &self.role, &self.token)
    }
    fn encode_full(&self) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        self.encode_secret().map_err(|error| wire(&error))
    }
}
fn prepare(value: &impl FullRelayRequest) -> Result<(HeaderValue, Zeroizing<Vec<u8>>), SdkError> {
    use std::io::Write;
    let body = value.encode_full()?;
    let (lease, epoch, role, token) = value.scope();
    let token = token.decode(32).map_err(|error| wire(&error))?;
    let encoded_token = Zeroizing::new(ramflux_protocol::encode_base64url(token.as_slice()));
    let mut bytes = Zeroizing::new(Vec::with_capacity(160));
    write!(&mut *bytes, "PairingFull {lease}.{epoch}.{role}.{}", encoded_token.as_str())
        .map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    // HeaderValue retains the Bytes owner: its final drop wipes the complete header value.
    let mut authorization =
        HeaderValue::from_maybe_shared(bytes::Bytes::from_owner(ErasingBody(bytes)))
            .map_err(|_| SdkError::PairingCode("InvalidInput"))?;
    authorization.set_sensitive(true);
    Ok((authorization, body))
}
impl HttpRelay {
    /// Full-role HTTP exchange. Closed request codecs bind A2 to the exact serialized body.
    /// Existing add-device relay limits and decoding remain unchanged.
    /// # Errors
    /// Refuses non-HTTPS origins, malformed scope, a deadline/size violation or typed refusal.
    pub async fn full_round<R: PairingWire>(
        &self,
        origin: &str,
        request: &impl FullRelayRequest,
    ) -> Result<R, SdkError> {
        require_https_origin(origin)?;
        let (authorization, body) = prepare(request)?;
        let reply = tokio::time::timeout(REQUEST_DEADLINE, async {
            let url =
                format!("{}/client/pairing/v1/{}", origin.trim_end_matches('/'), request.route());
            let mut response = self
                .client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(reqwest::header::CONNECTION, "close")
                .header(reqwest::header::AUTHORIZATION, authorization)
                .body(bytes::Bytes::from_owner(ErasingBody(body)))
                .send()
                .await
                .map_err(http_error)?;
            let status = response.status();
            if response.content_length().is_some_and(|length| length > PACKET_BYTES as u64) {
                return Err(SdkError::PairingCode("InvalidInput"));
            }
            let mut bytes = Zeroizing::new(Vec::with_capacity(PACKET_BYTES));
            while let Some(chunk) = response.chunk().await.map_err(http_error)? {
                if bytes.len().checked_add(chunk.len()).is_none_or(|length| length > PACKET_BYTES) {
                    return Err(SdkError::PairingCode("InvalidInput"));
                }
                bytes.extend_from_slice(&chunk);
            }
            if status != reqwest::StatusCode::OK {
                return Err(status_error(status, &bytes));
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| SdkError::PairingCode("ResumeRequired"))??;
        R::from_wire_bytes(&reply).map_err(|_| {
            super::Failure::from_wire_bytes(&reply)
                .map_or(SdkError::PairingCode("InvalidInput"), |failure| failure_error(&failure))
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn full_http_a2_sensitive_header_exactly_matches_the_closed_control_body() -> TestResult {
        let value = PollFullControl {
            epoch: ramflux_protocol::encode_base64url([2; 32]),
            kind: "poll_full_control".into(),
            lease_id: ramflux_protocol::encode_base64url([1; 32]),
            profile: ramflux_protocol::custody::pairing::full_transfer::PROFILE.into(),
            role: "responder".into(),
            token: SecretBase64::from_bytes(&[3; 32]),
        };
        let (header, body) = prepare(&value)?;
        assert!(header.is_sensitive());
        let token = ramflux_protocol::encode_base64url([3; 32]);
        assert_eq!(
            header.to_str()?,
            format!("PairingFull {}.{}.responder.{token}", value.lease_id, value.epoch)
        );
        assert!(!format!("{header:?}").contains(&token));
        assert!(!format!("{header:?}").contains("PairingFull"));
        assert_eq!(PollFullControl::from_wire_bytes(&body)?.token.decode(32)?.as_slice(), &[3; 32]);
        Ok(())
    }
}

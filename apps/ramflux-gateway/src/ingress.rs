// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One bounded, strict and authenticated-admission entry for every gateway framed runtime.
pub(crate) enum Ingress {
    Session(Box<ramflux_node_core::GatewayClientFrame>),
    Rejected(serde_json::Value),
    Request(ramflux_transport::GatewayQuicRequest),
}
pub(crate) fn parse(bytes: &[u8], source: std::net::IpAddr) -> anyhow::Result<Ingress> {
    match parse_inner(bytes, source) {
        Ok(ingress) => Ok(ingress),
        Err(error) => registration_rejection(bytes)
            .map_or(Err(error), |response| Ok(Ingress::Rejected(response))),
    }
}
/// Lenient decoding classifies a rejected frame only; it can never admit any request.
pub(crate) fn registration_rejection(bytes: &[u8]) -> Option<serde_json::Value> {
    if bytes.len() > 1024 * 1024 {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let reason_code = ramflux_protocol::IdentityDirectoryReason::InvalidRegistration;
    if value["frame_type"] == "identity_register" {
        return Some(serde_json::json!(
            ramflux_node_core::GatewayServerFrame::IdentityRegistrationRejected { reason_code }
        ));
    }
    if value["method"] == "POST" && value["path"] == "/mvp1/identity/register" {
        return Some(serde_json::json!(crate::registration::rejected(reason_code)));
    }
    None
}
fn parse_inner(bytes: &[u8], source: std::net::IpAddr) -> anyhow::Result<Ingress> {
    if bytes.len() > 1024 * 1024 {
        anyhow::bail!("gateway frame exceeds byte budget");
    }
    let value: serde_json::Value = ramflux_protocol::parse_i_json(bytes)?;
    if value.get("frame_type").is_some() {
        return Ok(Ingress::Session(Box::new(serde_json::from_value(value)?)));
    }
    let request = serde_json::from_value(value)?;
    crate::device_set_limit::admit_request(&request, source)?;
    Ok(Ingress::Request(request))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quinn_tcp_and_compio_ingress_share_strict_shape_and_size_checks() -> anyhow::Result<()> {
        let source = "127.0.0.1".parse()?;
        let duplicate=br#"{"method":"POST","path":"/mvp2/device-set","body":{"record":{"device_set_epoch":1,"device_set_epoch":2}}}"#;
        assert!(parse(duplicate, source).is_err());
        assert!(parse(&vec![b' '; 1024 * 1024 + 1], source).is_err());
        assert!(parse(br#"{"method":"POST","path":"/mvp2/device-set","body":{"record":{"principal_commitment":"victim"}}}"#,source).is_err());
        assert!(matches!(
            parse(br#"{"method":"GET","path":"/health","body":null}"#, source)?,
            Ingress::Request(_)
        ));
        Ok(())
    }
}

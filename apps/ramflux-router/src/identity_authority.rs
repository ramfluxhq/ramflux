// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed identity authority HTTP publication and unfiltered reads.

pub(crate) fn handle_signed_device_set(
    body: &[u8],
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<ramflux_protocol::SignedDeviceSetRecord> {
    if body.len() > 512 * 1024 {
        anyhow::bail!("device set exceeds byte budget");
    }
    let request: ramflux_node_core::DeviceSetPublishRequest = ramflux_protocol::parse_i_json(body)?;
    Ok(router.state().publish_signed_device_set(&request, router.store())?)
}

#[cfg(feature = "itest-http")]
pub(crate) fn handle_itest_identity_authority(
    stream: &mut std::net::TcpStream,
    request: &ramflux_node_core::NodeHttpRequest,
    router: &crate::router_runtime::RouterHandle,
) -> anyhow::Result<bool> {
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/mvp2/device-set") => {
            let response = handle_signed_device_set(&request.body, router)?;
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        ("GET", path) if path.starts_with("/mvp2/device-set/") => {
            let response =
                router.state().signed_device_set(path.trim_start_matches("/mvp2/device-set/"));
            ramflux_node_core::write_itest_json_response(stream, "200 OK", &response)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

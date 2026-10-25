// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded HTTP(S) client-record retrieval.
use super::{
    Duration, SdkError, WellKnownClientRecord, node_error, now_unix_timestamp,
    verify_client_discovery_record,
};
pub(crate) async fn fetch_client_record(input: &str) -> Result<WellKnownClientRecord, SdkError> {
    let origin = if input.contains("://") { input.to_owned() } else { format!("https://{input}") };
    let mut url = reqwest::Url::parse(&origin).map_err(|error| node_error(&error.to_string()))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(node_error("node URL must be an HTTP(S) origin without credentials"));
    }
    url.set_path("/.well-known/ramflux/client");
    url.set_query(None);
    url.set_fragment(None);
    let client =
        discovery_builder(reqwest::Client::builder(), &url).build().map_err(discovery_error)?;
    #[cfg(test)]
    let client = super::DISCOVERY_CLIENT.try_with(Clone::clone).unwrap_or(client);
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(discovery_error)?
        .error_for_status()
        .map_err(discovery_error)?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(discovery_error)? {
        if bytes.len().saturating_add(chunk.len()) > 1024 * 1024 {
            return Err(node_error("discovery record exceeds size limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    let record: WellKnownClientRecord = serde_json::from_slice(&bytes)?;
    verify_client_discovery_record(&record, now_unix_timestamp().unsigned_abs())?;
    if !input.contains("://") && record.node_id != input {
        return Err(node_error("discovery node_id mismatch"));
    }
    Ok(record)
}

fn discovery_error(error: reqwest::Error) -> SdkError {
    ramflux_transport::TransportError::HttpClient(error.without_url()).into()
}

fn discovery_builder(
    builder: reqwest::ClientBuilder,
    url: &reqwest::Url,
) -> reqwest::ClientBuilder {
    let host = url.host_str().unwrap_or_default().trim_start_matches('[').trim_end_matches(']');
    let local = host == "localhost"
        || match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => {
                ip.is_loopback() || ip.is_private() || ip.is_link_local()
            }
            Ok(std::net::IpAddr::V6(ip)) => {
                ip.is_loopback()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local()
                    || ip
                        .to_ipv4_mapped()
                        .is_some_and(|ip| ip.is_loopback() || ip.is_private() || ip.is_link_local())
            }
            Err(_) => false,
        };
    // Private discovery addresses must not be disclosed to an environment-configured proxy.
    let builder = if local { builder.no_proxy() } else { builder };
    builder.timeout(Duration::from_secs(10)).redirect(reqwest::redirect::Policy::none())
}

#[cfg(test)]
#[path = "discovery_proxy_tests.rs"]
mod proxy_tests;

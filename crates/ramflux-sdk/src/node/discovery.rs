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
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| node_error(&error.to_string()))?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|error| node_error(&error.to_string()))?
        .error_for_status()
        .map_err(|error| node_error(&error.to_string()))?;
    let mut bytes = Vec::new();
    while let Some(chunk) =
        response.chunk().await.map_err(|error| node_error(&error.to_string()))?
    {
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

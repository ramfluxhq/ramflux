// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cancellable counterpart of the explicit HTTP directory and federation transport.

use crate::SdkError;
use serde::{Serialize, de::DeserializeOwned};
use std::{sync::OnceLock, time::Duration};

pub(crate) async fn get<R: DeserializeOwned>(
    base: &str,
    path: &str,
    budget: Duration,
) -> Result<R, SdkError> {
    request(base, path, None, budget).await
}
pub(crate) async fn post<T: Serialize, R: DeserializeOwned>(
    base: &str,
    path: &str,
    value: &T,
    budget: Duration,
) -> Result<R, SdkError> {
    request(base, path, Some(serde_json::to_vec(value)?), budget).await
}
async fn request<R: DeserializeOwned>(
    base: &str,
    path: &str,
    body: Option<Vec<u8>>,
    budget: Duration,
) -> Result<R, SdkError> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    let client = CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .pool_max_idle_per_host(0)
                .build()
                .map_err(|error| error.without_url().to_string())
        })
        .as_ref()
        .map_err(|error| SdkError::LocalBus(error.clone()))?;
    let host = super::sdk_http_host_port(base)?;
    tokio::time::timeout(budget, async {
        let url = format!("http://{host}{path}");
        let request = body.map_or_else(
            || client.get(&url),
            |body| {
                client
                    .post(&url)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body)
            },
        );
        let response = request
            .header(reqwest::header::CONNECTION, "close")
            .send()
            .await
            .map_err(http_error)?;
        let status = response.status();
        if response.content_length().is_none() {
            return Err(SdkError::LocalBus("SDK HTTP response missing Content-Length".into()));
        }
        let body = response.bytes().await.map_err(http_error)?;
        if status != reqwest::StatusCode::OK {
            return Err(SdkError::LocalBus(format!(
                "SDK HTTP request failed: {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(serde_json::from_slice(&body)?)
    })
    .await
    .map_err(|_| {
        SdkError::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "SDK HTTP step deadline expired",
        ))
    })?
}
fn http_error(error: reqwest::Error) -> SdkError {
    SdkError::LocalBus(error.without_url().to_string())
}

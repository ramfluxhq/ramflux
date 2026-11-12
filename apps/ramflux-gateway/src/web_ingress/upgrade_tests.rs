// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::{Accepted, MAX_REQUEST_HEAD_BYTES, Refused, accept_token, check, read_head};
use crate::web_ingress::config::{RawSettings, WebIngressConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn config() -> Result<WebIngressConfig, Box<dyn std::error::Error>> {
    Ok(WebIngressConfig::parse(&RawSettings {
        listen: Some("127.0.0.1:8443".to_owned()),
        tls_cert: Some("cert.pem".to_owned()),
        tls_key: Some("key.pem".to_owned()),
        url: Some("wss://gw.example.org/v1/session".to_owned()),
        origins: Some("https://app.example.org".to_owned()),
        dev_origins: None,
    })?
    .ok_or("listener must be configured")?)
}

const GOOD: &[(&str, &str)] = &[
    ("Host", "gw.example.org"),
    ("Upgrade", "websocket"),
    ("Connection", "keep-alive, Upgrade"),
    ("Origin", "https://app.example.org"),
    ("Sec-WebSocket-Version", "13"),
    ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ("Sec-WebSocket-Protocol", "ramflux.gateway_session.v1"),
    ("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits"),
];

fn request(line: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut head = format!("{line}\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    head.into_bytes()
}

fn with(replace: &str, value: Option<&str>) -> Vec<(&'static str, String)> {
    GOOD.iter()
        .filter_map(|(name, original)| {
            if name.eq_ignore_ascii_case(replace) {
                value.map(|value| (*name, value.to_owned()))
            } else {
                Some((*name, (*original).to_owned()))
            }
        })
        .collect()
}

fn checked(line: &str, headers: &[(&'static str, String)]) -> Result<Accepted, Refused> {
    let borrowed: Vec<(&str, &str)> =
        headers.iter().map(|(name, value)| (*name, value.as_str())).collect();
    let config = config().map_err(|_| Refused::BadRequest)?;
    check(&request(line, &borrowed), &config)
}

const LINE: &str = "GET /v1/session HTTP/1.1";

#[test]
fn accept_token_matches_the_rfc_6455_example() {
    // RFC 6455 §1.3: key "dGhlIHNhbXBsZSBub25jZQ==" → "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".
    assert_eq!(accept_token("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

#[test]
fn good_request_is_accepted_and_the_response_offers_no_extension() -> TestResult {
    let accepted = checked(LINE, &with("", None)).map_err(|refused| format!("{refused:?}"))?;
    assert_eq!(accepted.origin, "https://app.example.org");
    let response = accepted.response();
    assert!(response.starts_with("HTTP/1.1 101 "));
    assert!(response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
    assert!(response.contains("Sec-WebSocket-Protocol: ramflux.gateway_session.v1\r\n"));
    assert!(!response.to_ascii_lowercase().contains("sec-websocket-extensions"));
    assert!(!response.to_ascii_lowercase().contains("set-cookie"));
    assert!(!response.to_ascii_lowercase().contains("access-control"));
    Ok(())
}

#[test]
fn foreign_missing_null_or_repeated_origin_is_refused_before_any_frame() {
    for origin in [
        "https://evil.example",
        "https://app.example.org.evil.example",
        "https://sub.app.example.org",
        "https://APP.example.org",
        "https://app.example.org/",
        "http://app.example.org",
        "null",
        "*",
    ] {
        assert_eq!(checked(LINE, &with("Origin", Some(origin))), Err(Refused::Forbidden), "{origin}");
    }
    assert_eq!(checked(LINE, &with("Origin", None)), Err(Refused::Forbidden));
    let mut twice = with("", None);
    twice.push(("Origin", "https://app.example.org".to_owned()));
    assert_eq!(checked(LINE, &twice), Err(Refused::Forbidden));
}

#[test]
fn wrong_method_path_or_version_is_not_found_and_a_query_is_a_bad_request() {
    for line in [
        "POST /v1/session HTTP/1.1",
        "GET /v1/other HTTP/1.1",
        "GET /v1/session/ HTTP/1.1",
        "GET / HTTP/1.1",
        "GET /v1/session HTTP/1.0",
    ] {
        assert_eq!(checked(line, &with("", None)), Err(Refused::NotFound), "{line}");
    }
    assert_eq!(checked("GET /v1/session?x=1 HTTP/1.1", &with("", None)), Err(Refused::BadRequest));
    assert_eq!(checked("GET /v1/session", &with("", None)), Err(Refused::BadRequest));
}

#[test]
fn host_must_be_the_configured_authority() {
    assert_eq!(checked(LINE, &with("Host", Some("rebind.example"))), Err(Refused::BadRequest));
    assert_eq!(checked(LINE, &with("Host", None)), Err(Refused::BadRequest));
    assert!(checked(LINE, &with("Host", Some("GW.example.org:443"))).is_ok());
}

#[test]
fn subprotocol_key_and_upgrade_headers_are_required() {
    assert_eq!(checked(LINE, &with("Sec-WebSocket-Protocol", None)), Err(Refused::BadRequest));
    assert_eq!(
        checked(LINE, &with("Sec-WebSocket-Protocol", Some("chat, ramflux.gateway_session.v2"))),
        Err(Refused::BadRequest)
    );
    assert!(
        checked(LINE, &with("Sec-WebSocket-Protocol", Some("chat, ramflux.gateway_session.v1")))
            .is_ok()
    );
    assert_eq!(checked(LINE, &with("Sec-WebSocket-Key", Some("c2hvcnQ="))), Err(Refused::BadRequest));
    assert_eq!(checked(LINE, &with("Sec-WebSocket-Key", None)), Err(Refused::BadRequest));
    assert_eq!(checked(LINE, &with("Upgrade", Some("h2c"))), Err(Refused::BadRequest));
    assert_eq!(checked(LINE, &with("Connection", Some("keep-alive"))), Err(Refused::BadRequest));
}

#[test]
fn wrong_version_is_answered_with_426_and_the_supported_version() {
    assert_eq!(
        checked(LINE, &with("Sec-WebSocket-Version", Some("8"))),
        Err(Refused::UpgradeRequired)
    );
    assert!(Refused::UpgradeRequired.response().contains("Sec-WebSocket-Version: 13\r\n"));
    assert_eq!(checked(LINE, &with("Sec-WebSocket-Version", None)), Err(Refused::BadRequest));
}

#[test]
fn checks_run_in_contract_order() {
    // A bad path wins over a foreign origin; a foreign origin wins over a missing key.
    let mut headers = with("Origin", Some("https://evil.example"));
    assert_eq!(checked("GET /nope HTTP/1.1", &headers), Err(Refused::NotFound));
    headers.retain(|(name, _)| *name != "Sec-WebSocket-Key");
    assert_eq!(checked(LINE, &headers), Err(Refused::Forbidden));
}

#[test]
fn cookies_and_proxy_headers_change_nothing() -> TestResult {
    let baseline = checked(LINE, &with("", None)).map_err(|refused| format!("{refused:?}"))?;
    let mut noisy = with("", None);
    for (name, value) in [
        ("Cookie", "session=abc"),
        ("Authorization", "Bearer abc"),
        ("X-Forwarded-For", "203.0.113.9"),
        ("X-Forwarded-Proto", "http"),
        ("X-Forwarded-Host", "evil.example"),
        ("Forwarded", "for=203.0.113.9;host=evil.example"),
        ("X-Real-IP", "203.0.113.9"),
        ("Via", "1.1 proxy"),
    ] {
        noisy.push((name, value.to_owned()));
    }
    let accepted = checked(LINE, &noisy).map_err(|refused| format!("{refused:?}"))?;
    assert_eq!(accepted, baseline);
    Ok(())
}

#[test]
fn refusals_carry_no_body_and_no_websocket_or_cors_headers() {
    for refused in [
        Refused::BadRequest,
        Refused::Forbidden,
        Refused::NotFound,
        Refused::TooManyRequests,
    ] {
        let response = refused.response().to_ascii_lowercase();
        assert!(response.contains("connection: close\r\n"));
        assert!(response.contains("content-length: 0\r\n"));
        assert!(response.ends_with("\r\n\r\n"));
        assert!(!response.contains("sec-websocket"));
        assert!(!response.contains("access-control"));
        assert!(!response.contains("set-cookie"));
        assert!(!response.contains("retry-after"));
    }
}

#[test]
fn folded_or_malformed_header_lines_are_refused() -> TestResult {
    let config = config()?;
    let folded = b"GET /v1/session HTTP/1.1\r\nHost: gw.example.org\r\n continued\r\n\r\n";
    assert_eq!(check(folded, &config), Err(Refused::BadRequest));
    let spaced = b"GET /v1/session HTTP/1.1\r\nHost : gw.example.org\r\n\r\n";
    assert_eq!(check(spaced, &config), Err(Refused::BadRequest));
    Ok(())
}

#[tokio::test]
async fn oversized_head_and_early_frame_bytes_are_dropped_without_a_response() {
    let mut oversized = b"GET /v1/session HTTP/1.1\r\nX-Pad: ".to_vec();
    oversized.extend(std::iter::repeat_n(b'a', MAX_REQUEST_HEAD_BYTES));
    oversized.extend_from_slice(b"\r\n\r\n");
    assert_eq!(read_head(&mut std::io::Cursor::new(oversized)).await, None);

    let mut early = request(LINE, GOOD);
    early.extend_from_slice(&[0x82, 0x80, 0, 0, 0, 0]);
    assert_eq!(read_head(&mut std::io::Cursor::new(early)).await, None);

    let truncated = b"GET /v1/session HTTP/1.1\r\nHost: gw".to_vec();
    assert_eq!(read_head(&mut std::io::Cursor::new(truncated)).await, None);

    let good = request(LINE, GOOD);
    assert_eq!(read_head(&mut std::io::Cursor::new(good.clone())).await, Some(good));
}

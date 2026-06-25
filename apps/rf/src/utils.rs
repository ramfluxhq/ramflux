// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use crate::RfError;
use ramflux_sdk::LocalBusClientMode;
use ramflux_sync::{McpCapability, RiskLevel};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn repeated_seed(hex_byte: &str) -> Result<[u8; 32], RfError> {
    let value = u8::from_str_radix(hex_byte, 16)
        .map_err(|error| RfError::Message(format!("invalid seed byte hex {hex_byte}: {error}")))?;
    Ok([value; 32])
}

pub(crate) fn parse_client_mode(mode: &str) -> Result<LocalBusClientMode, RfError> {
    match mode {
        "attended_cli" => Ok(LocalBusClientMode::AttendedCli),
        "headless_ai" => Ok(LocalBusClientMode::HeadlessAi),
        other => Err(RfError::Message(format!("unsupported client mode: {other}"))),
    }
}

pub(crate) fn parse_mcp_capability(
    capability: &str,
) -> Result<(McpCapability, Option<String>), RfError> {
    ramflux_sync::parse_mcp_capability(capability)
        .map_err(|error| RfError::Message(error.to_string()))
}

pub(crate) fn parse_mcp_risk(risk: &str) -> Result<RiskLevel, RfError> {
    match risk {
        "low" => Ok(RiskLevel::Low),
        "medium" => Ok(RiskLevel::Medium),
        "high" => Ok(RiskLevel::High),
        "critical" => Ok(RiskLevel::Critical),
        other => Err(RfError::Message(format!("unsupported MCP risk: {other}"))),
    }
}

pub(crate) fn rf_now_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
}

pub(crate) fn rf_now_unix_timestamp_u64() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

pub(crate) fn with_message_plaintext(mut value: serde_json::Value) -> serde_json::Value {
    let Some(messages) = value.get_mut("messages").and_then(serde_json::Value::as_array_mut) else {
        return value;
    };
    for message in messages {
        let Some(body) = message.get("encrypted_body").and_then(serde_json::Value::as_array) else {
            continue;
        };
        let bytes = body
            .iter()
            .filter_map(|byte| byte.as_u64().and_then(|value| u8::try_from(value).ok()))
            .collect::<Vec<_>>();
        if bytes.len() != body.len() {
            continue;
        }
        message["body_base64"] =
            serde_json::Value::String(ramflux_protocol::encode_base64url(&bytes));
        if let Ok(text) = String::from_utf8(bytes) {
            message["body_utf8"] = serde_json::Value::String(text);
        }
    }
    value
}

pub(crate) fn print_json(value: &serde_json::Value) -> Result<(), RfError> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(serde_json::to_string_pretty(&value)?.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

pub(crate) fn rf_http_post_json<T: serde::Serialize>(
    base_url: &str,
    path: &str,
    body: &T,
) -> Result<serde_json::Value, RfError> {
    let (host, port, base_path) = parse_http_base_url(base_url)?;
    let body = serde_json::to_vec(body)?;
    let mut stream = TcpStream::connect((host.as_str(), port))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(15)))?;
    let request_path = format!("{base_path}{path}");
    let request = format!(
        "POST {request_path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(&body)?;
    let (status, body) = read_rf_http_response_by_content_length(&mut stream)?;
    if !status.contains(" 200 ") {
        return Err(RfError::Message(format!(
            "admin HTTP request failed: status={status} body={}",
            String::from_utf8_lossy(&body)
        )));
    }
    Ok(serde_json::from_slice(&body)?)
}

pub(crate) fn parse_http_base_url(url: &str) -> Result<(String, u16, String), RfError> {
    let Some(rest) = url.strip_prefix("http://") else {
        return Err(RfError::Message("admin URL must start with http://".to_owned()));
    };
    let (authority, path) =
        rest.split_once('/').map_or((rest, ""), |(authority, path)| (authority, path));
    let (host, port) = authority.rsplit_once(':').ok_or_else(|| {
        RfError::Message("admin URL must include an explicit host:port".to_owned())
    })?;
    let port = port
        .parse::<u16>()
        .map_err(|error| RfError::Message(format!("admin URL has invalid port {port}: {error}")))?;
    let base_path = if path.is_empty() { String::new() } else { format!("/{path}") };
    Ok((host.to_owned(), port, base_path))
}

fn read_rf_http_response_by_content_length(
    stream: &mut TcpStream,
) -> Result<(String, Vec<u8>), RfError> {
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    if status_line.is_empty() {
        return Err(RfError::Message("admin HTTP response missing status line".to_owned()));
    }
    let mut content_length = None;
    loop {
        let mut header = String::new();
        let bytes = reader.read_line(&mut header)?;
        if bytes == 0 {
            return Err(RfError::Message(
                "admin HTTP response ended before header terminator".to_owned(),
            ));
        }
        let trimmed = header.trim_end();
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length = Some(value.trim().parse::<usize>().map_err(|source| {
                RfError::Message(format!("bad admin HTTP content length: {source}"))
            })?);
        }
    }
    let content_length = content_length
        .ok_or_else(|| RfError::Message("admin HTTP response missing Content-Length".to_owned()))?;
    let mut body = vec![0_u8; content_length];
    reader.read_exact(&mut body)?;
    Ok((status_line.trim_end().to_owned(), body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn rf_http_client_reads_content_length_without_waiting_for_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let (response_written_tx, response_written_rx) = mpsc::channel();
        let (release_server_tx, release_server_rx) = mpsc::channel();
        let server = thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener.accept().map_err(|source| source.to_string())?;
            let request = read_stub_request(&mut stream)?;
            if request.path != "/admin" {
                return Err(format!("unexpected path {}", request.path));
            }
            let body = serde_json::to_vec(&serde_json::json!({"ok": true}))
                .map_err(|source| source.to_string())?;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .map_err(|source| source.to_string())?;
            stream.write_all(&body).map_err(|source| source.to_string())?;
            stream.flush().map_err(|source| source.to_string())?;
            response_written_tx.send(()).map_err(|source| source.to_string())?;
            let _ = release_server_rx.recv_timeout(Duration::from_secs(2));
            Ok(())
        });
        let (client_tx, client_rx) = mpsc::channel();
        thread::spawn(move || {
            let result = rf_http_post_json(&endpoint, "/admin", &serde_json::json!({"ping": true}))
                .map_err(|source| source.to_string());
            let _ = client_tx.send(result);
        });
        response_written_rx.recv_timeout(Duration::from_secs(2))?;
        let value = if let Ok(result) = client_rx.recv_timeout(Duration::from_millis(500)) {
            result.map_err(|source| -> Box<dyn std::error::Error> { source.into() })?
        } else {
            let _ = release_server_tx.send(());
            let _ = join_stub_server(server);
            return Err("rf HTTP client waited for EOF after Content-Length".into());
        };
        release_server_tx.send(())?;
        join_stub_server(server)?;
        assert_eq!(value.get("ok").and_then(serde_json::Value::as_bool), Some(true));
        Ok(())
    }

    struct StubRequest {
        path: String,
    }

    fn read_stub_request(stream: &mut TcpStream) -> Result<StubRequest, String> {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).map_err(|source| source.to_string())?;
        let parts = request_line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 || parts[0] != "POST" {
            return Err(format!("unexpected request line: {request_line}"));
        }
        let mut content_length = None;
        loop {
            let mut header = String::new();
            let bytes = reader.read_line(&mut header).map_err(|source| source.to_string())?;
            if bytes == 0 {
                return Err("request ended before headers complete".to_owned());
            }
            let trimmed = header.trim_end();
            if trimmed.is_empty() {
                break;
            }
            let Some((name, value)) = trimmed.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length =
                    Some(value.trim().parse::<usize>().map_err(|source| source.to_string())?);
            }
        }
        let content_length =
            content_length.ok_or_else(|| "request missing Content-Length".to_owned())?;
        let mut body = vec![0_u8; content_length];
        reader.read_exact(&mut body).map_err(|source| source.to_string())?;
        Ok(StubRequest { path: parts[1].to_owned() })
    }

    fn join_stub_server(
        server: thread::JoinHandle<Result<(), String>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match server.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(source)) => Err(source.into()),
            Err(_) => Err("stub server panicked".into()),
        }
    }
}

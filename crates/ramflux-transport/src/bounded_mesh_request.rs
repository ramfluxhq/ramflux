// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Original mesh HTTP request bytes are capped before any body allocation.
use crate::{MeshHttpRequest, TransportError, bounded_http::line};
use std::io::{BufRead, BufReader, Read};
/// Read a bounded request, retaining original JSON bytes for strict typed decoding.
/// # Errors
/// Rejects oversized/malformed headers or body declarations, duplicate lengths and early EOF.
pub fn read_bounded_mesh_http_request<R: Read>(
    reader: &mut R,
    cap: usize,
) -> Result<Option<MeshHttpRequest>, TransportError> {
    let mut reader = BufReader::new(reader);
    if reader.fill_buf()?.is_empty() {
        return Ok(None);
    }
    let mut budget = 16 * 1024;
    let request_line = line(&mut reader, &mut budget)?;
    let request_line = std::str::from_utf8(&request_line).map_err(|_| invalid())?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or_else(invalid)?.to_owned();
    let path = parts.next().ok_or_else(invalid)?.to_owned();
    if !path.starts_with('/')
        || !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1"))
        || parts.next().is_some()
    {
        return Err(invalid());
    }
    let mut length = None;
    loop {
        let header = line(&mut reader, &mut budget)?;
        if header == b"\n" || header == b"\r\n" {
            break;
        }
        let header = std::str::from_utf8(&header).map_err(|_| invalid())?;
        let (name, value) = header.trim_end().split_once(':').ok_or_else(invalid)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid());
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim();
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            let size = value.parse::<usize>().map_err(|_| invalid())?;
            if size > cap {
                return Err(TransportError::Http("mesh body exceeds budget".into()));
            }
            length = Some(size);
        }
    }
    let mut left = length.unwrap_or(0);
    let mut body = Vec::new();
    let mut chunk = [0; 8192];
    while left != 0 {
        let size = left.min(chunk.len());
        let size = reader.read(&mut chunk[..size])?;
        if size == 0 {
            return Err(invalid());
        }
        body.extend_from_slice(&chunk[..size]);
        left -= size;
    }
    Ok(Some(MeshHttpRequest { method, path, body }))
}
fn invalid() -> TransportError {
    TransportError::Http("invalid bounded mesh HTTP request".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn declared_lengths_cannot_allocate_or_read_beyond_the_request_budget() {
        for length in ["18446744073709551615", "999999999999999999999999999", "+1", "-1", "17"] {
            let input = format!("POST /migration HTTP/1.1\r\nContent-Length: {length}\r\n\r\n");
            assert!(read_bounded_mesh_http_request(&mut input.as_bytes(), 16).is_err());
        }
    }
    #[test]
    fn preserves_original_json_and_accepts_empty_get() -> Result<(), TransportError> {
        let mut input =
            b"POST /migration HTTP/1.1\r\ncontent-length: 9\r\n\r\n{\"n\": 1}\n".as_slice();
        assert_eq!(
            read_bounded_mesh_http_request(&mut input, 16)?.ok_or_else(invalid)?.body,
            b"{\"n\": 1}\n"
        );
        let mut input = b"GET /healthz HTTP/1.1\r\n\r\n".as_slice();
        assert_eq!(
            read_bounded_mesh_http_request(&mut input, 16)?.ok_or_else(invalid)?.body,
            Vec::<u8>::new()
        );
        Ok(())
    }
}

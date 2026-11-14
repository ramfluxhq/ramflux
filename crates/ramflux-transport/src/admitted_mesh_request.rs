// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! An owned pre-body admission follows exact raw mesh bytes through cancellation and dispatch.
use crate::{MeshHttpRequest, TransportError};
use std::io::Read;
use zeroize::{Zeroize, Zeroizing};
const HEADER_BYTES: usize = 16 * 1024;

/// Dropping an unread/unhandled body wipes it before its admission guard releases the budget.
/// No Debug: original body bytes can contain confidential pairing capabilities.
pub struct AdmittedMeshHttpRequest<P> {
    request: MeshHttpRequest,
    permit: Option<P>,
}
impl<P> Drop for AdmittedMeshHttpRequest<P> {
    fn drop(&mut self) {
        self.request.body.zeroize();
    }
}
impl<P> AdmittedMeshHttpRequest<P> {
    #[must_use]
    pub fn request(&self) -> &MeshHttpRequest {
        &self.request
    }
    /// Move the original allocation and its guard together into the actual route owner.
    #[must_use]
    pub fn into_parts(mut self) -> (MeshHttpRequest, Option<P>) {
        let request = MeshHttpRequest {
            method: std::mem::take(&mut self.request.method),
            path: std::mem::take(&mut self.request.path),
            body: std::mem::take(&mut self.request.body),
        };
        (request, self.permit.take())
    }
}
/// Read only the fixed header window before obtaining the route's owning admission guard.
/// The callback must authenticate/reserve full routes; return None only for ordinary routes.
/// It sees the exact original header, which is erased and never placed in a Value or log.
/// # Errors
/// Refuses oversized/malformed framing, failed admission, duplicate length, chunking or EOF.
pub fn read_bounded_mesh_http_request_with_admission<R: Read, P>(
    reader: &mut R,
    cap_for: &dyn Fn(&str, &str) -> usize,
    admit: impl FnOnce(&str, &str, &str, usize) -> Result<Option<P>, TransportError>,
) -> Result<Option<AdmittedMeshHttpRequest<P>>, TransportError> {
    let Some(raw) = read_headers(reader)? else {
        return Ok(None);
    };
    let header = std::str::from_utf8(&raw).map_err(|_| invalid())?;
    let mut lines = header.lines();
    let mut line = lines.next().ok_or_else(invalid)?.split_whitespace();
    let method = line.next().ok_or_else(invalid)?;
    let path = line.next().ok_or_else(invalid)?;
    if !path.starts_with('/')
        || !matches!(line.next(), Some("HTTP/1.0" | "HTTP/1.1"))
        || line.next().is_some()
    {
        return Err(invalid());
    }
    let mut length = None;
    for line in lines.take_while(|line| !line.is_empty()) {
        if line.starts_with([' ', '\t']) {
            return Err(invalid());
        }
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        if name.trim() != name || name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid());
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim_matches([' ', '\t']);
            if length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(invalid());
            }
            length = Some(value.parse::<usize>().map_err(|_| invalid())?);
        }
    }
    let length = length.unwrap_or(0);
    if length > cap_for(method, path) {
        return Err(invalid());
    }
    // No body prefetch or body allocation precedes this call. A failed callback releases
    // no other request's claimed guard; an early EOF below drops only this owned guard.
    let permit = admit(method, path, header, length)?;
    let mut body = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut body).map_err(|_| invalid())?;
    Ok(Some(AdmittedMeshHttpRequest {
        request: MeshHttpRequest {
            method: method.into(),
            path: path.into(),
            body: std::mem::take(&mut *body),
        },
        permit,
    }))
}
fn read_headers(reader: &mut impl Read) -> Result<Option<Zeroizing<Vec<u8>>>, TransportError> {
    let mut raw = Zeroizing::new(Vec::with_capacity(HEADER_BYTES));
    while raw.len() < HEADER_BYTES {
        let mut byte = [0];
        match reader.read(&mut byte)? {
            0 if raw.is_empty() => return Ok(None),
            0 => return Err(invalid()),
            _ => raw.push(byte[0]),
        }
        if raw.ends_with(b"\r\n\r\n") || raw.ends_with(b"\n\n") {
            return Ok(Some(raw));
        }
    }
    Err(invalid())
}
fn invalid() -> TransportError {
    TransportError::Http("invalid admitted mesh request".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    struct Reader {
        bytes: std::io::Cursor<Vec<u8>>,
        read: Arc<AtomicUsize>,
    }
    impl Read for Reader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let n = self.bytes.read(output)?;
            self.read.fetch_add(n, Ordering::SeqCst);
            Ok(n)
        }
    }
    struct Permit(Arc<AtomicUsize>);
    impl Drop for Permit {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn reader(header: &str, bytes: usize) -> (Reader, Arc<AtomicUsize>) {
        let mut input = header.as_bytes().to_vec();
        input.resize(input.len() + bytes, 7);
        let read = Arc::new(AtomicUsize::new(0));
        (Reader { bytes: std::io::Cursor::new(input), read: read.clone() }, read)
    }
    #[test]
    fn full_mesh_body_requires_admission_before_read_or_allocation() {
        let header = "POST /pairing/v1/full/send HTTP/1.1\r\nContent-Length: 60000\r\nAuthorization: never-log-this\r\n\r\n";
        let (mut input, read) = reader(header, 60_000);
        let result = read_bounded_mesh_http_request_with_admission::<_, Permit>(
            &mut input,
            &|_, _| 524_288,
            |method, path, original, length| {
                assert_eq!(
                    (method, path, original, length),
                    ("POST", "/pairing/v1/full/send", header, 60_000)
                );
                assert_eq!(read.load(Ordering::SeqCst), header.len());
                Err(invalid())
            },
        );
        assert!(result.is_err());
        assert_eq!(read.load(Ordering::SeqCst), header.len());
    }
    #[test]
    fn full_mesh_exact_allocation_keeps_guard_until_consumption_or_disconnect() -> Result {
        let header = "POST /pairing/v1/full/send HTTP/1.1\r\nContent-Length: 60000\r\n\r\n";
        let drops = Arc::new(AtomicUsize::new(0));
        let (mut input, read) = reader(header, 60_000);
        let request = read_bounded_mesh_http_request_with_admission(
            &mut input,
            &|_, _| 524_288,
            |_, _, _, _| {
                assert_eq!(read.load(Ordering::SeqCst), header.len());
                Ok(Some(Permit(drops.clone())))
            },
        )?
        .ok_or("request missing")?;
        assert_eq!(request.request().body.len(), 60_000);
        assert_eq!(request.request().body.capacity(), 60_000);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(request);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        let (mut short, _) = reader(header, 100);
        assert!(
            read_bounded_mesh_http_request_with_admission(
                &mut short,
                &|_, _| 524_288,
                |_, _, _, _| Ok(Some(Permit(drops.clone())))
            )
            .is_err()
        );
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        Ok(())
    }
    #[test]
    fn full_mesh_rejects_bad_headers_before_claim_and_secret_error_output() -> Result {
        for fields in [
            "Content-Length: 2\r\nContent-Length: 2",
            "Content-Length: +2",
            "Content-Length: 2\r\nTransfer-Encoding: chunked",
            " Content-Length: 2",
        ] {
            let header = format!(
                "POST /pairing/v1/full/send HTTP/1.1\r\n{fields}\r\nAuthorization: secret-marker\r\n\r\n"
            );
            let (mut input, _) = reader(&header, 2);
            let calls = AtomicUsize::new(0);
            let result = read_bounded_mesh_http_request_with_admission::<_, Permit>(
                &mut input,
                &|_, _| 524_288,
                |_, _, _, _| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(invalid())
                },
            );
            let error = result.err().ok_or("invalid request accepted")?;
            assert!(!format!("{error:?} {error}").contains("secret-marker"));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
        Ok(())
    }
}

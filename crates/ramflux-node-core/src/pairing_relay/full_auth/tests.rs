// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;
use ramflux_protocol::custody::pairing::full_transfer::{
    PROFILE, SecretBase64, U64,
    relay::{EncryptedPacket, SendFull},
};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn header() -> String {
    format!(
        "POST /client/pairing/v1/send HTTP/1.1\r\nAuthorization: PairingFull {}.{}.initiator.{}\r\nContent-Length: 60000\r\n\r\n",
        ramflux_protocol::encode_base64url([1; 32]),
        ramflux_protocol::encode_base64url([2; 32]),
        ramflux_protocol::encode_base64url([3; 32])
    )
}
fn parse(header: &str) -> Result<FullAuthorization<'_>, PairingRelayError> {
    FullAuthorization::parse("POST", "/client/pairing/v1/send", true, header)
}
#[test]
fn full_auth_missing_duplicate_other_scheme_and_wrong_role_refused() -> TestResult {
    let valid = header();
    parse(&valid)?;
    for bad in [
        "POST /client/pairing/v1/send HTTP/1.1\r\nContent-Length: 60000\r\n\r\n".to_owned(),
        valid.replace("Content-Length:", "aUtHoRiZaTiOn: Bearer duplicate\r\nContent-Length:"),
        valid.replace("PairingFull ", "Bearer "),
        valid.replace("PairingFull ", "pairingfull "),
        valid.replace(".initiator.", ".primary."),
        valid.replace(".initiator.", ".initiator.extra."),
    ] {
        assert!(matches!(parse(&bad), Err(PairingRelayError::WrongContext)));
    }
    assert!(FullAuthorization::parse("POST", "/client/pairing/v1/send", false, &valid).is_err());
    assert!(FullAuthorization::parse("POST", "/healthz", true, &valid).is_err());
    assert!(FullAuthorization::parse("GET", "/client/pairing/v1/send", true, &valid).is_err());
    Ok(())
}
#[test]
fn full_auth_header_body_scope_and_reflected_token_must_agree() -> TestResult {
    let header = header();
    let auth = parse(&header)?;
    let mut send = SendFull {
        kind: "send_full".into(),
        profile: PROFILE.into(),
        token: SecretBase64::from_bytes(&[3; 32]),
        packet: EncryptedPacket {
            ciphertext: ramflux_protocol::encode_base64url([9; 16]),
            counter: U64(0),
            epoch: ramflux_protocol::encode_base64url([2; 32]),
            lease_id: ramflux_protocol::encode_base64url([1; 32]),
            role: "initiator".into(),
        },
    };
    let bytes = send.encode_secret()?;
    auth.verify_send(&BorrowedSendFull::from_wire_bytes(&bytes)?)?;
    for part in 0..4 {
        let mut changed = send.clone();
        match part {
            0 => changed.packet.lease_id = ramflux_protocol::encode_base64url([4; 32]),
            1 => changed.packet.epoch = ramflux_protocol::encode_base64url([4; 32]),
            2 => changed.packet.role = "responder".into(),
            _ => changed.token = SecretBase64::from_bytes(&[4; 32]),
        }
        let bytes = changed.encode_secret()?;
        assert!(matches!(
            auth.verify_send(&BorrowedSendFull::from_wire_bytes(&bytes)?),
            Err(PairingRelayError::WrongContext)
        ));
    }
    send.packet.counter = U64(1);
    let bytes = send.encode_secret()?;
    auth.verify_send(&BorrowedSendFull::from_wire_bytes(&bytes)?)?;
    Ok(())
}
#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().map_err(|_| std::io::ErrorKind::Other)?.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}
#[test]
fn full_auth_logs_and_errors_never_contain_header_or_token() -> TestResult {
    let captured = Capture(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(captured.clone())
        .finish();
    let canary = ramflux_protocol::encode_base64url([3; 32]);
    let valid = header();
    let authorization = valid.lines().nth(1).ok_or("authorization line")?;
    let errors = tracing::subscriber::with_default(subscriber, || -> TestResult<String> {
        let mut errors = String::new();
        for bad in
            [valid.replace("PairingFull ", "Bearer "), valid.replace(".initiator.", ".unknown.")]
        {
            let Err(error) = parse(&bad) else {
                return Err("malformed header accepted".into());
            };
            tracing::warn!(error = %error, "pairing admission refused");
            write!(errors, "{error:?} {error}")?;
        }
        Ok(errors)
    })?;
    let logs = String::from_utf8(captured.0.lock().map_err(|_| "capture lock")?.clone())?;
    assert!(logs.contains("pairing admission refused"));
    for output in [&logs, &errors] {
        assert!(!output.contains(&canary));
        assert!(!output.contains(authorization));
        assert!(!output.contains("PairingFull"));
    }
    Ok(())
}

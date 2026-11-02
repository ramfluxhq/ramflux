// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compatible descriptor decoding without a second ciphertext JSON array in memory.
use crate::{StorageError, database::Connection};
use serde::de::DeserializeOwned;
use std::io::Read;

pub(super) fn decode<T: DeserializeOwned>(
    connection: &Connection,
    rowid: i64,
    body: &[u8],
) -> Result<T, StorageError> {
    if !body.windows(b"ramflux:column:1".len()).any(|s| s == b"ramflux:column:1")
        && !body.windows(b"\"revocation\"".len()).any(|s| s == b"\"revocation\"")
    {
        return Ok(serde_json::from_slice(body)?);
    }
    let mut descriptor: serde_json::Value = serde_json::from_slice(body)?;
    if descriptor["tombstoned"] == true && descriptor.get("revocation").is_some() {
        // A pre-import fence intentionally has no payload descriptor. Materialize only the
        // empty reader projection; the persisted body retains its revocation provenance.
        let manifest = descriptor["revocation"]["manifest_hash"]
            .as_str()
            .map_or_else(|| ramflux_protocol::encode_base64url([0_u8; 32]), str::to_owned);
        let object = descriptor.as_object_mut().ok_or(StorageError::AuthorizationRejected)?;
        object.insert("manifest_hash".into(), manifest.into());
        object.insert("nonce".into(), ramflux_protocol::encode_base64url([0_u8; 12]).into());
        object.insert("ciphertext".into(), serde_json::json!([]));
        object.insert("plaintext_hash".into(), "".into());
        object.insert("backup_excluded".into(), false.into());
        return Ok(serde_json::from_value(descriptor)?);
    }
    if descriptor.get("ciphertext").and_then(serde_json::Value::as_str) != Some("ramflux:column:1")
    {
        return Ok(serde_json::from_slice(body)?);
    }
    descriptor.as_object_mut().ok_or(StorageError::AuthorizationRejected)?.remove("ciphertext");
    let mut prefix = serde_json::to_vec(&descriptor)?;
    prefix.pop();
    prefix.extend_from_slice(b",\"ciphertext\":[");
    let bytes: Vec<u8> = connection.query_row(
        "SELECT ciphertext FROM object_index WHERE rowid=?1",
        rusqlite::params![rowid],
        |r| r.get(0),
    )?;
    // serde consumes the decimal byte stream directly into the final Vec<u8>.
    let reader = std::io::Cursor::new(prefix)
        .chain(DecimalBytes {
            bytes: bytes.into_iter(),
            pending: Vec::new(),
            position: 0,
            first: true,
        })
        .chain(std::io::Cursor::new(b"]}"));
    Ok(serde_json::from_reader(reader)?)
}
struct DecimalBytes {
    bytes: std::vec::IntoIter<u8>,
    pending: Vec<u8>,
    position: usize,
    first: bool,
}
impl Read for DecimalBytes {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let mut done = 0;
        while done < output.len() {
            if self.position == self.pending.len() {
                let Some(byte) = self.bytes.next() else { break };
                self.pending.clear();
                self.position = 0;
                if !self.first {
                    self.pending.push(b',');
                }
                self.first = false;
                self.pending.extend_from_slice(byte.to_string().as_bytes());
            }
            let count = (output.len() - done).min(self.pending.len() - self.position);
            output[done..done + count]
                .copy_from_slice(&self.pending[self.position..self.position + count]);
            done += count;
            self.position += count;
        }
        Ok(done)
    }
}

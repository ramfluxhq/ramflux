// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded canonical private RPC frames; peer credentials are checked before decoding any frame.
use super::{Result, error, refuse};
use ramflux_node_core::username_directory as directory;
use serde::{Serialize, de::DeserializeOwned};
use std::io::{Read, Write};

pub const MAX_FRAME: usize = 2 * 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Heartbeat,
    Sync { head: directory::CheckpointHead },
    Applied { head: directory::CheckpointHead },
    Image { head: directory::CheckpointHead, after: Option<Vec<u8>> },
    Batch { head: directory::CheckpointHead, id: String },
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Alive,
    Welcome { writer: directory::WriterIdentity, head: directory::CheckpointHead, recovery: bool },
    Group { group: Option<directory::RecoveryGroup> },
    Ready,
    Image { page: directory::ImagePage },
    Batch { group: directory::RecoveryGroup },
}

pub fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = ramflux_protocol::canonical_json_bytes(value)?;
    if bytes.len() > MAX_FRAME {
        return refuse("private frame bound");
    }
    let length = u32::try_from(bytes.len())?;
    let mut frame = length.to_be_bytes().to_vec();
    frame.extend(bytes);
    Ok(frame)
}

pub fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_FRAME {
        return refuse("private frame bound");
    }
    let value: T = ramflux_protocol::parse_i_json(bytes)?;
    if ramflux_protocol::canonical_json_bytes(&value)? != bytes {
        return refuse("private frame canonical");
    }
    Ok(value)
}

pub fn send(stream: &mut impl Write, value: &impl Serialize) -> Result<()> {
    stream.write_all(&encode(value)?)?;
    Ok(())
}

pub fn receive<T: DeserializeOwned + Serialize>(stream: &mut impl Read) -> Result<T> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME {
        return refuse("private frame bound");
    }
    let mut bytes = Vec::new();
    stream.take(length as u64).read_to_end(&mut bytes)?;
    if bytes.len() != length {
        return refuse("private truncated frame");
    }
    decode(&bytes)
}

/// Nonblocking single-frame state; never allocates using an unchecked length prefix.
#[derive(Default)]
pub struct Reader {
    bytes: Vec<u8>,
    needed: Option<usize>,
}

impl Reader {
    pub fn poll<T: DeserializeOwned + Serialize>(
        &mut self,
        stream: &mut impl Read,
    ) -> Result<Option<T>> {
        loop {
            let target = self.needed.unwrap_or(4);
            if self.bytes.len() == target {
                if self.needed.is_some() {
                    let value =
                        decode(self.bytes.get(4..).ok_or_else(|| error("private frame offset"))?)?;
                    self.bytes.clear();
                    self.needed = None;
                    return Ok(Some(value));
                }
                let prefix: [u8; 4] = self.bytes.as_slice().try_into()?;
                let length = u32::from_be_bytes(prefix) as usize;
                if length > MAX_FRAME {
                    return refuse("private frame bound");
                }
                self.needed = Some(length + 4);
                continue;
            }
            let mut chunk = [0; 4096];
            let count = (target - self.bytes.len()).min(chunk.len());
            match stream.read(chunk.get_mut(..count).ok_or_else(|| error("private read bound"))?) {
                Ok(0) => return refuse("private peer disconnected"),
                Ok(count) => self
                    .bytes
                    .extend(chunk.get(..count).ok_or_else(|| error("private read bound"))?),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

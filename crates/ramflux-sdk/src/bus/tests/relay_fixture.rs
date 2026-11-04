// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Scripted relay requests expose durable-state observations and controlled network holds.

use super::fixture::{Case, GatewayHold};
use crate::object::{SdkRelayChunkEntry, SdkRelayChunkStatus};
use crate::prelude::{EncryptedObject, now_unix_timestamp};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    Put,
    Get,
    Ack,
}
pub(super) type Observe = Rc<dyn Fn(Step, u32, &Value) -> Case>;
#[derive(Default)]
pub(super) struct State {
    pub chunks: BTreeMap<String, SdkRelayChunkEntry>,
    pub requests: Vec<(Step, u32)>,
    pub dropped: Vec<(Step, u32)>,
    pub hold: Option<(Step, u32, Arc<GatewayHold>)>,
    pub failure: Option<(Step, u32)>,
    pub close_before_response: Option<(Step, u32)>,
    pub errors: Vec<String>,
}
pub(super) struct Relay {
    pub endpoint: String,
    pub state: Arc<Mutex<State>>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Relay {
    pub async fn start(observe: Observe) -> Case<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let state = Arc::new(Mutex::new(State::default()));
        let shared = Arc::clone(&state);
        let server = tokio::task::spawn_local(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((mut socket, _)) = listener.accept().await {
                let shared = Arc::clone(&shared);
                let observe = Rc::clone(&observe);
                connections.spawn_local(async move {
                    if let Err(error) = serve(&mut socket, &shared, &observe).await
                        && let Ok(mut state) = shared.lock()
                    {
                        state.errors.push(error.to_string());
                    }
                });
            }
        });
        Ok(Self { endpoint, state, server })
    }
    pub fn seed(
        &self,
        object: &EncryptedObject,
        key: &[u8; 32],
        chunk_size: usize,
    ) -> Case<ramflux_sync::ChunkManifest> {
        let manifest = ramflux_sync::chunk_manifest_for_object(
            &object.object_id,
            &object.ciphertext,
            chunk_size,
            None,
        );
        let mut state = self.state.lock().map_err(|_| "relay")?;
        for (index, bytes) in object.ciphertext.chunks(chunk_size).enumerate() {
            let index = u32::try_from(index)?;
            let encrypted =
                serde_json::to_vec(&ramflux_sync::chunk_payload(key, &manifest, index, bytes))?;
            let id = crate::object::object_relay_chunk_id(
                &object.object_id,
                &object.manifest_hash,
                index,
            );
            state.chunks.insert(
                id.clone(),
                SdkRelayChunkEntry {
                    chunk_id: id,
                    object_id: object.object_id.clone(),
                    manifest_hash: object.manifest_hash.clone(),
                    chunk_index: index,
                    chunk_cipher_hash: crate::object::object_relay_chunk_cipher_hash(
                        &object.manifest_hash,
                        index,
                        &encrypted,
                    ),
                    encrypted_chunk: encrypted,
                    stored_at: u64::try_from(now_unix_timestamp())?,
                    expires_at: u64::try_from(now_unix_timestamp() + 600)?,
                    delete_after_ack: false,
                    acked_by: BTreeSet::new(),
                    status: SdkRelayChunkStatus::Available,
                },
            );
        }
        Ok(manifest)
    }
}
async fn serve(socket: &mut TcpStream, shared: &Arc<Mutex<State>>, observe: &Observe) -> Case {
    let (path, body) = read_request(socket).await?;
    let (step, index, hold) = {
        let mut state = shared.lock().map_err(|_| "relay")?;
        let step = match path.as_str() {
            "/relay/v1/object/put_chunk" => Step::Put,
            "/relay/v1/object/get_chunk" => Step::Get,
            "/relay/v1/object/ack" => Step::Ack,
            _ => return Err(format!("unexpected relay path {path}").into()),
        };
        let index = if step == Step::Put {
            u32::try_from(body["chunk_index"].as_u64().ok_or("chunk index")?)?
        } else {
            state
                .chunks
                .get(body["chunk_id"].as_str().ok_or("chunk id")?)
                .ok_or("unknown chunk")?
                .chunk_index
        };
        state.requests.push((step, index));
        let hold =
            if state.hold.as_ref().is_some_and(|(kind, held, _)| *kind == step && *held == index) {
                state.hold.take().map(|(_, _, hold)| hold)
            } else {
                None
            };
        (step, index, hold)
    };
    if let Some(hold) = hold {
        hold.entered.notify_one();
        let mut byte = [0];
        tokio::select! {
            ()=hold.release.notified()=>{},
            result=socket.read(&mut byte)=>{
                if result?!=0 {return Err("unexpected bytes after relay request".into());}
                shared.lock().map_err(|_|"relay")?.dropped.push((step,index));
                return Ok(());
            }
        }
    }
    observe(step, index, &body)?;
    if shared.lock().map_err(|_| "relay")?.close_before_response == Some((step, index)) {
        return Ok(());
    }
    let failed = shared.lock().map_err(|_| "relay")?.failure == Some((step, index));
    if failed {
        socket.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
        return Ok(());
    }
    let response = {
        let mut state = shared.lock().map_err(|_| "relay")?;
        match step {
            Step::Put => {
                let mut chunk = body.clone();
                chunk["stored_at"] = json!(now_unix_timestamp());
                chunk["acked_by"] = json!([]);
                chunk["status"] = json!(SdkRelayChunkStatus::Available);
                let chunk: SdkRelayChunkEntry = serde_json::from_value(chunk)?;
                let response = json!({"chunk_id":chunk.chunk_id,"object_id":chunk.object_id,"manifest_hash":chunk.manifest_hash,"expires_at":chunk.expires_at,"status":chunk.status});
                state.chunks.insert(chunk.chunk_id.clone(), chunk);
                response
            }
            Step::Get => {
                json!({"chunk":state.chunks.get(body["chunk_id"].as_str().ok_or("chunk id")?).ok_or("missing chunk")?})
            }
            Step::Ack => {
                json!({"chunk_id":body["chunk_id"],"status":SdkRelayChunkStatus::Available,"acked_by_count":1})
            }
        }
    };
    let bytes = serde_json::to_vec(&response)?;
    socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            )
            .as_bytes(),
        )
        .await?;
    socket.write_all(&bytes).await?;
    Ok(())
}
async fn read_request(socket: &mut TcpStream) -> Case<(String, Value)> {
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 4096];
        let count = socket.read(&mut buffer).await?;
        if count == 0 {
            return Err("relay request closed".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("oversized relay request".into());
        }
        if let Some(offset) = bytes.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let header = std::str::from_utf8(&bytes[..offset])?;
            let path = header
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .ok_or("request path")?;
            let length: usize = header
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                .ok_or("content length")?
                .1
                .trim()
                .parse()?;
            if bytes.len() >= offset + 4 + length {
                return Ok((
                    path.into(),
                    serde_json::from_slice(&bytes[offset + 4..offset + 4 + length])?,
                ));
            }
        }
    }
}

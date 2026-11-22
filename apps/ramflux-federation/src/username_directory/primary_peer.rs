// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One bounded IPC owner keeps the writer live during projection fsyncs. A heartbeat never
//! acknowledges an applied head or enables publication.
use super::{Result, directory, error, ipc, refuse, wire};
use std::{
    net::Shutdown,
    os::unix::net::UnixStream,
    sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    thread::JoinHandle,
    time::Duration,
};

struct Query {
    request: wire::Request,
    response: SyncSender<Result<wire::Response>>,
}

pub(super) struct Peer {
    sender: SyncSender<Query>,
    close: UnixStream,
    worker: Option<JoinHandle<()>>,
}

impl Peer {
    pub fn connect(pins: &directory::WitnessPeer) -> Result<(Self, wire::Response)> {
        ipc::socket_path(&pins.socket, pins.witness_uid)?;
        let mut stream = UnixStream::connect(&pins.socket)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        ipc::peer(&stream, pins.witness_uid)?;
        let welcome = wire::receive(&mut stream)?;
        let close = stream.try_clone()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("username-primary-peer".into())
            .spawn(move || serve(stream, receiver))?;
        Ok((Self { sender, close, worker: Some(worker) }, welcome))
    }

    pub fn request(&self, request: wire::Request) -> Result<wire::Response> {
        let (response, receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(Query { request, response })
            .map_err(|_| error("username primary peer unavailable"))?;
        receiver
            .recv_timeout(Duration::from_secs(6))
            .map_err(|_| error("username primary peer deadline"))?
    }
}

fn exchange(stream: &mut UnixStream, request: &wire::Request) -> Result<wire::Response> {
    wire::send(stream, request)?;
    wire::receive(stream)
}

fn heartbeat(stream: &mut UnixStream) -> Result<()> {
    if !matches!(exchange(stream, &wire::Request::Heartbeat)?, wire::Response::Alive) {
        return refuse("username primary heartbeat response");
    }
    Ok(())
}

fn serve(mut stream: UnixStream, receiver: Receiver<Query>) {
    while !ramflux_node_core::service_shutdown_token().is_cancelled() {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(query) => {
                let reply = exchange(&mut stream, &query.request);
                let failed = reply.is_err();
                let _ = query.response.try_send(reply);
                if failed {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if let Err(error) = heartbeat(&mut stream) {
                    tracing::warn!(%error, "username primary heartbeat failed");
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.close.shutdown(Shutdown::Both);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

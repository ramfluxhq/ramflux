// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Single protected authority actor. No positive bytes leave via the private primary daemon.
use super::{
    Result, directory, error, flag, ipc, quic, refuse, registered_nodes::RegisteredNodes,
    source::Sources, tcp, tls, warn_drop, wire,
};
use std::{
    io::Write,
    net::TcpListener,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

struct Peer {
    stream: UnixStream,
    writer: directory::WriterIdentity,
    reader: wire::Reader,
    output: Option<(Vec<u8>, usize)>,
    last: Instant,
    ready: bool,
}

struct Pending {
    incoming: tcp::Incoming,
    call: Option<directory::ServingCall>,
    channel: String,
    refusal: Option<ramflux_protocol::username_directory::DirectoryCode>,
    call_id: Option<String>,
}

pub fn run(
    node: &ramflux_node_core::NodeServiceConfig,
    config: &directory::DirectoryConfig,
) -> Result<()> {
    let directory::DirectoryRole::Witness {
        database,
        peer: pins,
        listen,
        registered_nodes,
        node_rate_per_min,
    } = &config.role
    else {
        return refuse("witness role");
    };
    // Before any socket is bound: a missing or invalid list refuses to start.
    let nodes = RegisteredNodes::load(registered_nodes)?;
    let witness = open_checkpoint(database, pins, &config.center)?;
    // Only after acquiring the exclusive protected DB lock can this UID replace its stale socket.
    if pins.socket.exists() {
        std::fs::remove_file(&pins.socket)?;
    }
    let listener = UnixListener::bind(&pins.socket)?;
    std::fs::set_permissions(&pins.socket, std::fs::Permissions::from_mode(0o660))?;
    listener.set_nonblocking(true)?;
    let public = TcpListener::bind(listen)?;
    public.set_nonblocking(true)?;
    let tls = Arc::new(tls::server(node)?);
    let secret =
        ramflux_node_core::NodeSecret::required_env("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE")?;
    let signer = secret.with_bytes(directory::DirectorySigner::from_seed);
    if node.node_id != config.center.id || signer.public_key() != config.center.public_key {
        return refuse("witness signing pin mismatch");
    }
    let authority = directory::DirectoryAuthority::new(witness)?;
    let (sender, receiver) = mpsc::sync_channel(64);
    let slots = Arc::new(tokio::sync::Semaphore::new(16));
    let sources = Arc::new(Sources::new());
    quic::start(
        *listen,
        (*tls).clone(),
        node.node_id.clone(),
        secret.with_bytes(|seed| *seed),
        sender.clone(),
        quic::Admission { slots: Arc::clone(&slots), sources: Arc::clone(&sources) },
    )?;
    let mut state =
        WitnessState {
            authority,
            signer,
            nodes,
            workers: Vec::new(),
            peer: None,
            pending: Vec::new(),
        };
    let recovery = flag("--username-initialize") || flag("--username-recovery");
    let io = WitnessIo {
        node,
        config,
        listener: &listener,
        public: &public,
        tls,
        secret: &secret,
        sender,
        receiver,
        slots,
        sources,
        pins,
        recovery,
        node_rate_per_min: *node_rate_per_min,
    };
    while !ramflux_node_core::service_shutdown_token().is_cancelled() {
        state.workers.retain(|worker| !worker.is_finished());
        state.nodes.poll();
        state.poll_primary(&io)?;
        state.accept_public(&io)?;
        state.serve_pending(&io)?;
        if !ramflux_node_core::service_shutdown_sleep(Duration::from_millis(5)) {
            break;
        }
    }
    state.authority.disconnect();
    drop((state.pending, io.receiver));
    for worker in state.workers {
        let _ = worker.join();
    }
    drop(listener);
    std::fs::remove_file(&pins.socket)?;
    Ok(())
}

struct WitnessState {
    authority: directory::DirectoryAuthority,
    signer: directory::DirectorySigner,
    nodes: RegisteredNodes,
    workers: Vec<std::thread::JoinHandle<()>>,
    peer: Option<Peer>,
    pending: Vec<Pending>,
}
struct WitnessIo<'a> {
    node: &'a ramflux_node_core::NodeServiceConfig,
    config: &'a directory::DirectoryConfig,
    listener: &'a UnixListener,
    public: &'a TcpListener,
    tls: Arc<rustls::ServerConfig>,
    secret: &'a ramflux_node_core::NodeSecret,
    sender: mpsc::SyncSender<tcp::Incoming>,
    receiver: mpsc::Receiver<tcp::Incoming>,
    slots: Arc<tokio::sync::Semaphore>,
    sources: Arc<Sources>,
    pins: &'a directory::WitnessPeer,
    recovery: bool,
    node_rate_per_min: u64,
}
impl WitnessState {
    fn poll_primary(&mut self, io: &WitnessIo<'_>) -> Result<()> {
        let WitnessIo { listener, pins, recovery, .. } = io;
        if self.peer.is_none() {
            match listener.accept() {
                Ok((stream, _)) => {
                    if ipc::peer(&stream, pins.center_uid).is_ok() {
                        stream.set_nonblocking(true)?;
                        let writer = self.authority.acquire()?;
                        let welcome = wire::encode(&wire::Response::Welcome {
                            writer: writer.clone(),
                            head: self.authority.head(),
                            recovery: *recovery,
                        })?;
                        self.peer = Some(Peer {
                            stream,
                            writer,
                            reader: wire::Reader::default(),
                            output: Some((welcome, 0)),
                            last: Instant::now(),
                            ready: false,
                        });
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }
        let mut lost = false;
        if let Some(current) = &mut self.peer {
            // Three seconds is the renewal cadence; self.authority expires with the ten-second lease.
            if current.last.elapsed() >= Duration::from_secs(10) {
                tracing::warn!("username primary heartbeat deadline exceeded");
                lost = true;
            } else if let Err(error) = poll_peer(current, &mut self.authority, *recovery) {
                tracing::warn!(%error, "username primary disconnected");
                lost = true;
            }
        }
        if lost {
            self.peer = None;
            self.authority.disconnect();
            self.pending.clear();
        }
        Ok(())
    }
    fn accept_public(&mut self, io: &WitnessIo<'_>) -> Result<()> {
        let WitnessIo { public, tls, sender, node, secret, slots, sources, .. } = io;
        match public.accept() {
            Ok((socket, address)) => {
                if self.workers.len() < 16
                    && self.pending.len() < 64
                    && sources.admit(address.ip())
                    && self.peer.is_some()
                    && let Ok(permit) = Arc::clone(slots).try_acquire_owned()
                {
                    let tls = Arc::clone(tls);
                    let sender = (*sender).clone();
                    let node_id = node.node_id.clone();
                    let seed = secret.with_bytes(|seed| *seed);
                    self.workers.push(
                        std::thread::Builder::new().name("username-tls-read".into()).spawn(
                            move || {
                                let _permit = permit;
                                match tcp::accept(socket, tls, &node_id, &seed) {
                                    Ok(incoming) => {
                                        if sender.try_send(incoming).is_err() {
                                            warn_drop(
                                                "witness_public",
                                                address.ip(),
                                                "accept",
                                                &"hand-off channel full or closed",
                                            );
                                        }
                                    }
                                    Err(error) => {
                                        warn_drop(
                                            "witness_public",
                                            address.ip(),
                                            "tls/request",
                                            &error,
                                        );
                                    }
                                }
                            },
                        )?,
                    );
                } else {
                    warn_drop(
                        "witness_public",
                        address.ip(),
                        "accept",
                        &"connection refused by admission limits",
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
    fn serve_pending(&mut self, io: &WitnessIo<'_>) -> Result<()> {
        let WitnessIo { receiver, config, node_rate_per_min, .. } = io;
        if let Some(current) = &mut self.peer {
            if current.ready
                && let Ok(incoming) = receiver.try_recv()
                && self.pending.len() < 64
            {
                match admit(
                    &mut self.authority,
                    &mut self.nodes,
                    *node_rate_per_min,
                    &current.writer,
                    incoming,
                    &config.center,
                ) {
                    Ok(call) => {
                        current.ready = self.authority.head() == call.1;
                        if !current.ready {
                            self.pending.clear();
                        }
                        self.pending.push(call.0);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "username request refused before publication");
                    }
                }
            }
            self.pending.retain_mut(|call| {
                if Instant::now() < call.incoming.deadline {
                    return true;
                }
                let stage = if call.call_id.is_some() { "response" } else { "request" };
                warn_drop("witness_public", call.incoming.source, stage, &"deadline exceeded");
                if let Some(id) = &call.call_id {
                    self.authority.cancel_call(id);
                }
                false
            });
            if current.ready {
                self.pending.retain_mut(|call| {
                    let result = serve(call, &mut self.authority, &current.writer, &self.signer);
                    match result {
                        Ok(done) => !done,
                        Err(error) => {
                            if let Some(id) = &call.call_id {
                                self.authority.cancel_call(id);
                            }
                            warn_drop("witness_public", call.incoming.source, "response", &error);
                            false
                        }
                    }
                });
                if self.pending.is_empty() && self.authority.cleanup_next(&current.writer)? {
                    current.ready = false;
                }
            }
        }
        Ok(())
    }
}
fn open_checkpoint(
    database: &std::path::Path,
    pins: &directory::WitnessPeer,
    center: &directory::CenterPin,
) -> Result<directory::CheckpointWitness> {
    ipc::self_uid(pins.witness_uid)?;
    ipc::owner(
        database.parent().ok_or_else(|| error("witness parent"))?,
        pins.witness_uid,
        0o700,
        true,
    )?;
    ipc::socket_path(&pins.socket, pins.witness_uid)?;
    let clock = Arc::new(directory::SystemCheckpointClock::default());
    let checkpoint = if flag("--username-initialize") {
        directory::CheckpointWitness::initialize(database, &center.id, center.generation, clock)?
    } else {
        ipc::owner(database, pins.witness_uid, 0o600, false)?;
        directory::CheckpointWitness::open(database, &center.id, center.generation, clock)?
    };
    Ok(checkpoint)
}

fn poll_peer(
    peer: &mut Peer,
    authority: &mut directory::DirectoryAuthority,
    recovery: bool,
) -> Result<()> {
    if let Some((bytes, offset)) = &mut peer.output {
        match peer.stream.write(bytes.get(*offset..).ok_or_else(|| error("private write offset"))?)
        {
            Ok(0) => return refuse("private peer closed"),
            Ok(count) => *offset += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        if *offset == bytes.len() {
            peer.output = None;
        }
        return Ok(());
    }
    let Some(request) = peer.reader.poll(&mut peer.stream)? else {
        return Ok(());
    };
    authority.renew(&peer.writer)?;
    peer.last = Instant::now();
    let response = match request {
        wire::Request::Heartbeat => wire::Response::Alive,
        wire::Request::Sync { head } => {
            peer.ready = false;
            wire::Response::Group { group: authority.recovery_group(&peer.writer, &head)? }
        }
        wire::Request::Applied { head } => {
            authority.primary_applied(&peer.writer, &head)?;
            peer.ready = true;
            wire::Response::Ready
        }
        wire::Request::Image { head, after } => {
            if !recovery || peer.ready {
                return refuse("image recovery requires controller authority");
            }
            wire::Response::Image {
                page: authority.recovery_image_page(&peer.writer, &head, after.as_deref(), 128)?,
            }
        }
        wire::Request::Batch { head, id } => {
            if !recovery || peer.ready {
                return refuse("batch recovery requires controller authority");
            }
            wire::Response::Batch { group: authority.recovery_batch(&peer.writer, &head, &id)? }
        }
    };
    peer.output = Some((wire::encode(&response)?, 0));
    Ok(())
}

fn admit(
    authority: &mut directory::DirectoryAuthority,
    nodes: &mut RegisteredNodes,
    node_rate_per_min: u64,
    writer: &directory::WriterIdentity,
    incoming: tcp::Incoming,
    pin: &directory::CenterPin,
) -> Result<(Pending, directory::CheckpointHead)> {
    let (report, reporter) = match authenticate(authority, nodes, node_rate_per_min, &incoming, pin) {
        Ok(value) => value,
        Err(error) => {
            use ramflux_protocol::username_directory::DirectoryCode as Code;
            let code = match error.downcast_ref::<directory::CheckpointError>() {
                Some(directory::CheckpointError::Directory(Code::RateLimited)) => Code::RateLimited,
                Some(directory::CheckpointError::Directory(Code::Capacity)) => Code::Capacity,
                _ => Code::AuthenticationRequired,
            };
            let before = authority.head();
            let channel = ramflux_protocol::encode_base64url(incoming.exporter);
            return Ok((
                Pending { incoming, call: None, channel, refusal: Some(code), call_id: None },
                before,
            ));
        }
    };
    let before = authority.head();
    let refusal = if let directory::DirectoryRequest::Mutate { phase, operation, profile } =
        &report.request
    {
        match authority.mutate(writer, &reporter, *phase, operation, profile.as_deref()) {
            Ok(_) => None,
            Err(directory::CheckpointError::Directory(code)) => Some(code),
            Err(error) => return Err(error.into()),
        }
    } else {
        None
    };
    let call = directory::ServingCall {
        root: reporter.root().into(),
        home: reporter.home().into(),
        channel: ramflux_protocol::encode_base64url(incoming.exporter),
        request: report.request,
    };
    Ok((
        Pending {
            incoming,
            channel: call.channel.clone(),
            call: Some(call),
            refusal,
            call_id: None,
        },
        before,
    ))
}

fn authenticate(
    authority: &mut directory::DirectoryAuthority,
    nodes: &mut RegisteredNodes,
    node_rate_per_min: u64,
    incoming: &tcp::Incoming,
    pin: &directory::CenterPin,
) -> Result<(directory::ReportingRequest, directory::VerifiedReporter)> {
    let report = directory::decode_reporting_request(&incoming.body)?;
    if report.request.path() != incoming.path {
        return refuse("reporting HTTP path mismatch");
    }
    let chain = incoming.certificates().ok_or_else(|| error("reporting TLS certificate"))?;
    let now = crate::now_unix_seconds()?;
    tls::verify_reporter(chain, &report.evidence, now)?;
    // Refused before nonce and rate charges. The key is authenticated by the node-signed proof
    // bound to this TLS channel's exporter, which `admit_reporting` verifies before any charge.
    if !nodes.authorize(&report.evidence.discovery.node_public_key, now) {
        return refuse("reporting node is not registered");
    }
    let channel = directory::ReportingChannel {
        node_id: &report.evidence.discovery.node_id,
        node_key: &report.evidence.discovery.node_public_key,
        exporter: &incoming.exporter,
        node_rate_per_min,
    };
    Ok(authority.admit_reporting(&incoming.body, &channel, pin, incoming.source)?)
}

fn serve(
    pending: &mut Pending,
    authority: &mut directory::DirectoryAuthority,
    writer: &directory::WriterIdentity,
    signer: &directory::DirectorySigner,
) -> Result<bool> {
    if Instant::now() >= pending.incoming.deadline {
        return refuse("directory request deadline");
    }
    if pending.call_id.is_none() {
        let id = if let Some(call) = &pending.call {
            authority.admit_call(writer, call.clone())?
        } else {
            authority.admit_anonymous_refusal(
                writer,
                &pending.channel,
                pending.refusal.ok_or_else(|| error("anonymous refusal missing"))?,
            )?
        };
        pending.call_id = Some(id.clone());
        if let Some(code) = pending.refusal {
            authority.prepare_http_refusal(writer, &id, &pending.channel, code)?;
        } else {
            signer.prepare_http_response(authority, writer, &id, &pending.channel)?;
        }
        pending.call_id = Some(id);
    }
    let id = pending.call_id.as_ref().ok_or_else(|| error("directory serving context"))?;
    Ok(authority.write_response_step(writer, id, &pending.channel, |bytes| {
        pending.incoming.try_write(bytes)
    })?)
}

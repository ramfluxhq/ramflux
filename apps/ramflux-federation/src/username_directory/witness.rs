// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Single protected authority actor. No positive bytes leave via the private primary daemon.
use super::{Result, directory, error, flag, ipc, refuse, tcp, tls, wire};
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
    call: directory::ServingCall,
    refusal: Option<ramflux_protocol::username_directory::DirectoryCode>,
    call_id: Option<String>,
}

pub fn run(
    node: &ramflux_node_core::NodeServiceConfig,
    config: &directory::DirectoryConfig,
) -> Result<()> {
    let directory::DirectoryRole::Witness { database, peer: pins, listen } = &config.role else {
        return refuse("witness role");
    };
    ipc::self_uid(pins.witness_uid)?;
    ipc::owner(
        database.parent().ok_or_else(|| error("witness parent"))?,
        pins.witness_uid,
        0o700,
        true,
    )?;
    ipc::socket_path(&pins.socket, pins.witness_uid)?;
    let clock = Arc::new(directory::SystemCheckpointClock::default());
    let witness = if flag("--username-initialize") {
        directory::CheckpointWitness::initialize(
            database,
            &config.center.id,
            config.center.generation,
            clock,
        )?
    } else {
        ipc::owner(database, pins.witness_uid, 0o600, false)?;
        directory::CheckpointWitness::open(
            database,
            &config.center.id,
            config.center.generation,
            clock,
        )?
    };
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
    let mut authority = directory::DirectoryAuthority::new(witness)?;
    let (sender, receiver) = mpsc::sync_channel(64);
    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    let mut peer: Option<Peer> = None;
    let mut pending: Vec<Pending> = Vec::new();
    let recovery = flag("--username-initialize") || flag("--username-recovery");
    let mut source_rates = std::collections::BTreeMap::new();
    let started = Instant::now();
    while !ramflux_node_core::service_shutdown_token().is_cancelled() {
        workers.retain(|worker| !worker.is_finished());
        if peer.is_none() {
            match listener.accept() {
                Ok((stream, _)) => {
                    if ipc::peer(&stream, pins.center_uid).is_ok() {
                        stream.set_nonblocking(true)?;
                        let writer = authority.acquire()?;
                        let welcome = wire::encode(&wire::Response::Welcome {
                            writer: writer.clone(),
                            head: authority.head(),
                            recovery,
                        })?;
                        peer = Some(Peer {
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
        if let Some(current) = &mut peer {
            if current.last.elapsed() >= Duration::from_secs(3) {
                lost = true;
            } else if let Err(error) = poll_peer(current, &mut authority, recovery) {
                tracing::warn!(%error, "username primary disconnected");
                lost = true;
            }
        }
        if lost {
            peer = None;
            authority.disconnect();
            pending.clear();
        }
        match public.accept() {
            Ok((socket, address)) => {
                let window = started.elapsed().as_secs() / 60;
                source_rates.retain(|_, (old, _)| *old == window);
                let source = address.ip();
                let rate = if source_rates.contains_key(&source) || source_rates.len() < 4096 {
                    let entry = source_rates.entry(source).or_insert((window, 0u32));
                    entry.1 += 1;
                    entry.1 <= 60
                } else {
                    false
                };
                if workers.len() < 16 && pending.len() < 64 && rate && peer.is_some() {
                    let tls = Arc::clone(&tls);
                    let sender = sender.clone();
                    let node_id = node.node_id.clone();
                    let seed = secret.with_bytes(|seed| *seed);
                    workers.push(
                        std::thread::Builder::new().name("username-tls-read".into()).spawn(
                            move || {
                                if let Ok(incoming) = tcp::accept(socket, tls, &node_id, &seed) {
                                    let _ = sender.try_send(incoming);
                                }
                            },
                        )?,
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(current) = &mut peer {
            if current.ready
                && let Ok(incoming) = receiver.try_recv()
            {
                if current.ready && pending.len() < 64 {
                    match admit(&mut authority, &current.writer, incoming, &config.center) {
                        Ok(call) => {
                            current.ready = authority.head() == call.1;
                            if !current.ready {
                                pending.clear();
                            }
                            pending.push(call.0);
                        }
                        Err(error) => {
                            tracing::debug!(%error, "username request refused before publication")
                        }
                    }
                }
            }
            pending.retain_mut(|call| {
                if Instant::now() < call.incoming.deadline {
                    return true;
                }
                if let Some(id) = &call.call_id {
                    authority.cancel_call(id);
                }
                false
            });
            if current.ready {
                pending.retain_mut(|call| {
                    let result = serve(call, &mut authority, &current.writer, &signer);
                    match result {
                        Ok(done) => !done,
                        Err(error) => {
                            if let Some(id) = &call.call_id {
                                authority.cancel_call(id);
                            }
                            tracing::debug!(%error, "username response closed");
                            false
                        }
                    }
                });
                if pending.is_empty() && authority.cleanup_next(&current.writer)? {
                    current.ready = false;
                }
            }
        }
        if ramflux_node_core::service_shutdown_sleep(Duration::from_millis(5)) {
            break;
        }
    }
    authority.disconnect();
    drop((pending, receiver));
    for worker in workers {
        let _ = worker.join();
    }
    drop(listener);
    std::fs::remove_file(&pins.socket)?;
    Ok(())
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
    writer: &directory::WriterIdentity,
    incoming: tcp::Incoming,
    pin: &directory::CenterPin,
) -> Result<(Pending, directory::CheckpointHead)> {
    let report = directory::decode_reporting_request(&incoming.body)?;
    if report.request.path() != incoming.path {
        return refuse("reporting HTTP path mismatch");
    }
    let chain = incoming
        .stream
        .conn
        .peer_certificates()
        .ok_or_else(|| error("reporting TLS certificate"))?;
    tls::verify_reporter(chain, &report.evidence, crate::now_unix_seconds()?)?;
    let channel = directory::ReportingChannel {
        node_id: &report.evidence.discovery.node_id,
        node_key: &report.evidence.discovery.node_public_key,
        exporter: &incoming.exporter,
    };
    let (report, reporter) =
        authority.admit_reporting(&incoming.body, &channel, pin, incoming.source)?;
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
    Ok((Pending { incoming, call, refusal, call_id: None }, before))
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
        let id = authority.admit_call(writer, pending.call.clone())?;
        if let Some(code) = pending.refusal {
            authority.prepare_http_refusal(writer, &id, &pending.call.channel, code)?;
        } else {
            signer.prepare_http_response(authority, writer, &id, &pending.call.channel)?;
        }
        pending.call_id = Some(id);
    }
    let id = pending.call_id.as_ref().ok_or_else(|| error("directory serving context"))?;
    Ok(authority.write_response_step(writer, id, &pending.call.channel, |bytes| {
        pending.incoming.try_write(bytes)
    })?)
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use stun::message::Setter;

const DEFAULT_TURN_LIFETIME_SECS: u32 = 600;

fn main() {
    if let Err(error) = run_service("ramflux-signaling") {
        eprintln!("ramflux-signaling: {error}");
        std::process::exit(2);
    }
}

fn run_service(service: &'static str) -> anyhow::Result<()> {
    if std::env::args().any(|arg| arg == "--health-check") {
        println!("{service}:healthy");
        return Ok(());
    }
    tracing_subscriber::fmt().with_target(false).init();
    if let Some(config) =
        ramflux_node_core::load_config_from_args(std::env::args().skip(1), service)?
    {
        let redb_path = ramflux_node_core::effective_redb_path(&config);
        let store = ramflux_node_core::SignalingRedbStore::open(redb_path)?;
        let state = match store.load_state()? {
            Some(state) => state,
            None => ramflux_node_core::SignalingState::new(),
        };
        store.save_state(&state)?;
        tracing::info!(service, node_id = config.node_id, "signaling state initialized");
        let service_key = config
            .signaling
            .as_ref()
            .and_then(|signaling| signaling.service_key_ref.as_deref())
            .map(read_signaling_secret_ref)
            .transpose()?;
        serve_itest_turn_udp(config.signaling.as_ref(), Arc::new(Mutex::new(state)), service_key)?;
    }
    tracing::info!(service, "service initialized");
    if std::env::args().any(|arg| arg == "--once") {
        return Ok(());
    }
    std::thread::park();
    Ok(())
}

fn serve_itest_turn_udp(
    signaling: Option<&ramflux_node_core::SignalingConfig>,
    state: Arc<Mutex<ramflux_node_core::SignalingState>>,
    service_key: Option<Vec<u8>>,
) -> anyhow::Result<()> {
    let addr = std::env::var("RAMFLUX_ITEST_SIGNALING_TURN_UDP_ADDR")
        .ok()
        .or_else(|| signaling.map(|config| config.turn_udp_addr.clone()))
        .unwrap_or_else(|| "0.0.0.0:3478".to_owned());
    let socket = UdpSocket::bind(&addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    std::thread::Builder::new().name("ramflux-signaling-turn-udp-itest".to_owned()).spawn(
        move || {
            tracing::info!(addr, "signaling itest STUN/TURN UDP surface listening");
            let mut buf = [0_u8; 1500];
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((len, peer)) => match stun_turn_response(
                        &buf[..len],
                        peer,
                        &state,
                        service_key.as_deref(),
                    ) {
                        Ok(response) => {
                            if let Err(error) = socket.send_to(&response, peer) {
                                tracing::warn!(%error, %peer, "failed to send STUN/TURN response");
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, %peer, "invalid STUN/TURN packet");
                        }
                    },
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => {
                        tracing::error!(%error, "STUN/TURN UDP listener stopped");
                        return;
                    }
                }
            }
        },
    )?;
    Ok(())
}

fn stun_turn_response(
    request: &[u8],
    peer: std::net::SocketAddr,
    state: &Arc<Mutex<ramflux_node_core::SignalingState>>,
    service_key: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    if turn::proto::chandata::ChannelData::is_channel_data(request) {
        let mut channel =
            turn::proto::chandata::ChannelData { raw: request.to_vec(), ..Default::default() };
        channel.decode()?;
        anyhow::bail!("ChannelData relay requires a bound SRTP flow, channel={}", channel.number);
    }
    let mut message = stun::message::Message::new();
    message.unmarshal_binary(request)?;
    if message.typ == stun::message::BINDING_REQUEST {
        return stun_success_response_with_attrs(
            &message,
            stun::message::BINDING_SUCCESS,
            |response| {
                stun::xoraddr::XorMappedAddress { ip: peer.ip(), port: peer.port() }
                    .add_to(response)
            },
        );
    }
    if message.typ == turn::proto::allocate_request() {
        validate_allocate_credentials(&message, state, service_key)?;
        let allocate_success = stun::message::MessageType::new(
            stun::message::METHOD_ALLOCATE,
            stun::message::CLASS_SUCCESS_RESPONSE,
        );
        return stun_success_response_with_attrs(&message, allocate_success, |response| {
            turn::proto::relayaddr::XorRelayedAddress { ip: peer.ip(), port: peer.port() }
                .add_to(response)?;
            response
                .add(stun::attributes::ATTR_LIFETIME, &DEFAULT_TURN_LIFETIME_SECS.to_be_bytes());
            Ok(())
        });
    }
    anyhow::bail!("unsupported STUN/TURN method {}", message.typ)
}

fn validate_allocate_credentials(
    message: &stun::message::Message,
    state: &Arc<Mutex<ramflux_node_core::SignalingState>>,
    service_key: Option<&[u8]>,
) -> anyhow::Result<()> {
    let Some(service_key) = service_key else {
        return Ok(());
    };
    let username = stun::textattrs::Username::get_from_as(message, stun::attributes::ATTR_USERNAME)
        .map_err(|source| anyhow::anyhow!("missing or invalid TURN USERNAME: {source}"))?;
    let password = ramflux_node_core::turn_credential_password(service_key, &username.text)?;
    let mut integrity_message = message.clone();
    stun::integrity::MessageIntegrity::new_short_term_integrity(password.clone())
        .check(&mut integrity_message)
        .map_err(|source| anyhow::anyhow!("TURN MESSAGE-INTEGRITY rejected: {source}"))?;
    let now = ramflux_node_core::now_unix_seconds();
    let mut state = state.lock().map_err(|_| anyhow::anyhow!("signaling state lock poisoned"))?;
    state.validate_turn_credential(&username.text, &password, service_key, now)?;
    Ok(())
}

fn stun_success_response_with_attrs(
    request: &stun::message::Message,
    response_type: stun::message::MessageType,
    add_attrs: impl FnOnce(&mut stun::message::Message) -> Result<(), stun::Error>,
) -> anyhow::Result<Vec<u8>> {
    let mut response = stun::message::Message::new();
    response.transaction_id = request.transaction_id;
    response.set_type(response_type);
    add_attrs(&mut response)?;
    response.encode();
    Ok(response.raw)
}

fn read_signaling_secret_ref(secret_ref: &str) -> anyhow::Result<Vec<u8>> {
    let value = if let Some(literal) = secret_ref.strip_prefix("literal:") {
        literal.to_owned()
    } else if let Some(name) = secret_ref.strip_prefix("env:") {
        std::env::var(name)?
    } else if let Some(path) = secret_ref.strip_prefix("file:") {
        std::fs::read_to_string(path)?
    } else {
        anyhow::bail!("unsupported signaling secret ref scheme")
    };
    Ok(value.into_bytes())
}

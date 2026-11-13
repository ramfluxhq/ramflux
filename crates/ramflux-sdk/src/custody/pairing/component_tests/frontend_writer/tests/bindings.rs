// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The SDK actor, rf's public transport and narrow ABI observe one durable operation.
use super::*;
use crate::custody::pairing::private_credential::PairingBusClient;
use crate::platform::listener::BusListener as _;
use ramflux_protocol::custody::pairing::{PairingWire, local_dto::StatusRequest};

#[tokio::test(start_paused = true)]
async fn pairing_sdk_bus_cli_mobile_binding_share_one_state_machine() -> TestResult {
    let hold = ClockHold::new();
    let result = crate::bus::credentials::contract_tests::deadline(Box::pin(run())).await;
    hold.finish().await?;
    result
}
async fn run() -> TestResult {
    let rig = Box::pin(Rig::open_profile(true)).await?;
    let Rig {
        primary: mut actor,
        mut source,
        participant_a: participant,
        now,
        _node_root,
        _clock,
        ..
    } = rig;
    participant.return_client(&mut source.client)?;
    let service = actor.bind_frontend_writer(source.client.account_db()?)?;
    crate::custody::pairing::install_actor_with_writer(
        &participant.root,
        participant.account_id.clone(),
        actor,
        Some(service),
    )?;
    let _registered = Registered(participant.root.clone(), participant.account_id.clone());
    let signal = crate::custody::pairing::work_signal(&participant.root, &participant.account_id)
        .ok_or("test: registered signal missing")?;
    let begin = crate::custody::pairing::handle_bus(
        &participant.root,
        &participant.account_id,
        "device.transfer.begin",
        serde_json::to_value(full_begin(now))?,
    );
    tokio::pin!(begin);
    let issued = loop {
        tokio::select! {
            result = &mut begin => break result?,
            () = signal.notified() => { crate::custody::pairing::service_frontend(&participant.root, &participant.account_id, &mut source.client)?; }
        }
    };
    let Outcome::Begin { value } = issued.outcome else {
        return Err("test: actual SDK begin failed".into());
    };
    let request = StatusRequest {
        schema: "ramflux.pairing.StatusRequest.v2".into(),
        version: 2,
        operation_id: value.operation_id.clone(),
        generation: value.generation,
    };
    let socket = participant.root.join("bindings.sock");
    let listener = crate::platform::listener::bind(&socket)?;
    let host = observe(&participant, &socket, &request);
    let daemon = serve(&participant, &listener);
    let (host, daemon) = tokio::join!(host, daemon);
    host?;
    daemon?;
    let rows = source.client.account_db()?.pairing_live_rows()?;
    assert_eq!(
        rows.iter().filter(|row| row.operation_id == request.operation_id).count(),
        1,
        "test: frontend transports allocated duplicate operation owners"
    );
    crate::custody::pairing::remove_actor_and_drain(&participant.root, &participant.account_id)
        .await?;
    Ok(())
}

async fn observe(
    participant: &LocalPairingParticipant,
    socket: &std::path::Path,
    request: &StatusRequest,
) -> TestResult {
    let mut cli = PairingBusClient::connect(socket, participant.provider.clone()).await?;
    let expected = cli
        .request(
            Some(participant.account_id.clone()),
            "device",
            "device.transfer.status",
            serde_json::to_value(request)?,
        )
        .await?;
    let config = ramflux_protocol::canonical_json_bytes(
        &serde_json::json!({"account_root":participant.root,"pairing_socket":socket,"pairing_account_id":participant.account_id}),
    )?;
    let body = request.to_wire_bytes()?;
    let actual = tokio::task::spawn_blocking(move || abi(&config, &body))
        .await?
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    assert_eq!(actual, expected, "test: ABI forked rf transport's actual SDK operation state");
    Ok::<_, Box<dyn std::error::Error>>(())
}
async fn serve(
    participant: &LocalPairingParticipant,
    listener: &impl crate::platform::listener::BusListener<
        Stream = crate::platform::fs::LocalSocketStream,
    >,
) -> TestResult {
    use crate::platform::listener::BusStream as _;
    for _ in 0..2 {
        let mut stream = listener.accept().await?;
        stream.matches_peer(listener.owner()?)?;
        let frame = crate::bus::io::read_local_bus_frame(&mut stream).await?;
        assert_eq!(
            frame.method, "device.transfer.status",
            "test: binding used a different state-machine method"
        );
        assert_eq!(
            frame.account_id.as_deref(),
            Some(participant.account_id.as_str()),
            "test: binding crossed account scope"
        );
        let result = crate::custody::pairing::handle_bus(
            &participant.root,
            &participant.account_id,
            &frame.method,
            frame.body.clone(),
        )
        .await?;
        let response = crate::bus::io::local_bus_response(&frame, serde_json::to_value(result)?);
        crate::bus::io::write_local_bus_frame(&mut stream, &response).await?;
    }
    Ok::<_, Box<dyn std::error::Error>>(())
}

struct Client(*mut crate::c_abi::RamfluxClient);
impl Drop for Client {
    fn drop(&mut self) {
        crate::c_abi::ramflux_client_close(self.0);
        crate::c_abi::ramflux_client_free(self.0);
    }
}
struct Buffer(*mut crate::c_abi::RamfluxBuffer);
impl Drop for Buffer {
    fn drop(&mut self) {
        crate::c_abi::ramflux_buffer_free(self.0);
    }
}
fn abi(config: &[u8], body: &[u8]) -> Result<serde_json::Value, String> {
    let mut client = std::ptr::null_mut();
    let mut error = std::ptr::null_mut();
    let code = crate::c_abi::ramflux_client_new(
        config.as_ptr(),
        config.len(),
        &raw mut client,
        &raw mut error,
    );
    let client = Client(client);
    let _error = Buffer(error);
    if code != 0 {
        return Err("test: ABI client setup refused".into());
    }
    let method =
        std::ffi::CString::new("device.transfer.status").map_err(|error| error.to_string())?;
    let mut output = std::ptr::null_mut();
    let code = crate::c_abi::ramflux_pairing_call(
        client.0,
        method.as_ptr(),
        body.as_ptr(),
        body.len(),
        &raw mut output,
    );
    let output = Buffer(output);
    if code != 0 {
        return Err(format!("test: actual ABI status refused with code {code}"));
    }
    // SAFETY: the wrapper retains this SDK-allocated buffer until its Drop frees it.
    let buffer = unsafe { output.0.as_ref() }.ok_or("test: ABI status buffer missing")?;
    if buffer.ptr.is_null() || buffer.len == 0 || buffer.len > LocalResult::LIMIT {
        return Err("test: ABI status buffer bounds".into());
    }
    // SAFETY: the live SDK allocation contains exactly the bounded initialized length above.
    let bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) };
    let result = LocalResult::from_wire_bytes(bytes).map_err(|error| error.to_string())?;
    serde_json::to_value(result).map_err(|error| error.to_string())
}

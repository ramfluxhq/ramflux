// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Conditional PUT admission preserves offline work and refuses relay work before receipts.

use super::spool_tests::{
    ACCOUNT, OBJECT_ID, OPERATION, begin_body, chunk_body, finish_body, make_state, plaintext_hash,
    temp_data_root,
};
use crate::bus::{actor::AccountCommand, mutation_intent::MutationIntent};
use crate::prelude::*;
use serde_json::json;

fn command(method: &str, body: serde_json::Value) -> AccountCommand {
    let (outbound, _) = mpsc::channel(1);
    let mut request = LocalBusFrame::request(method, Some(ACCOUNT.into()), "object", method, body);
    request.operation_id = Some(format!("generic-{method}"));
    AccountCommand {
        admission: None,
        private: None,
        request,
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: false,
        nodes: None,
        outbound,
        reply: None,
    }
}
async fn request(
    state: &mut LocalBusDaemonState,
    streaming: bool,
    relay: bool,
) -> Result<AccountCommand, SdkError> {
    let bytes = b"conditional put";
    let endpoint = relay.then(|| "http://127.0.0.1:9".to_owned());
    if !streaming {
        return Ok(command(
            "object.put",
            json!({"object_id":OBJECT_ID,"operation_id":OPERATION,
            "plaintext_base64":ramflux_protocol::encode_base64url(bytes), "chunk_size":1024,
            "relay_endpoint":endpoint}),
        ));
    }
    let mut begin = begin_body(bytes.len(), &plaintext_hash(bytes));
    begin["relay_endpoint"] = json!(endpoint);
    for (method, body) in [("object.put.begin", begin), ("object.put.chunk", chunk_body(0, bytes))]
    {
        let frame = LocalBusFrame::request(method, Some(ACCOUNT.into()), "object", method, body);
        super::dispatch_object_bus_request(&frame, state).await?;
    }
    Ok(command("object.put.finish", finish_body()))
}

#[tokio::test]
async fn conditional_puts_keep_local_work_offline_and_refuse_relay_before_any_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(30), Box::pin(offline_cases())).await?
}
async fn offline_cases() -> Result<(), Box<dyn std::error::Error>> {
    for streaming in [false, true] {
        for relay in [false, true] {
            let root = temp_data_root("conditional-gate");
            let mut state = make_state(root.clone());
            state
                .accounts
                .get_mut(ACCOUNT)
                .ok_or(SdkError::AccountDbNotUnlocked)?
                .timeouts
                .network_wait = Duration::ZERO;
            let command = request(&mut state, streaming, relay).await?;
            let intent = MutationIntent::new(&command.request)?;
            let result =
                Box::pin(crate::bus::mutations::execute(&mut state, ACCOUNT, &command)).await;
            let account = state.accounts.get(ACCOUNT).ok_or(SdkError::AccountDbNotUnlocked)?;
            if relay {
                assert!(
                    matches!(
                        result,
                        Err(SdkError::NetworkingPending | SdkError::NetworkingPendingContext { .. })
                    ),
                    "{} must refuse offline relay work",
                    command.request.method
                );
                assert!(
                    intent.lookup(account.client.account_db()?)?.is_none(),
                    "no generic Pending receipt before Live"
                );
                assert!(
                    account.client.object_operation(OBJECT_ID)?.is_none(),
                    "no object Pending or LocalCommitted row before Live"
                );
                if streaming {
                    let spool = account
                        .object_put_spools
                        .get(OPERATION)
                        .ok_or("finish removed its spool before the network gate")?;
                    assert!(spool.path.exists());
                }
            } else {
                assert_eq!(result?.body["committed"], true);
                assert!(intent.lookup(account.client.account_db()?)?.is_some());
                assert_eq!(
                    account
                        .client
                        .object_operation(OBJECT_ID)?
                        .ok_or("missing committed operation")?
                        .state,
                    OBJECT_OPERATION_COMMITTED
                );
            }
            if let Some(connection) = account.connection.as_ref() {
                connection.stop().await;
            }
            drop(state);
            std::fs::remove_dir_all(root)?;
        }
    }
    Ok(())
}

#[cfg(feature = "itest-local-mint")]
#[tokio::test]
async fn conditional_puts_with_a_default_relay_complete_when_live()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(30), Box::pin(live_cases())).await?
}
#[cfg(feature = "itest-local-mint")]
async fn live_cases() -> Result<(), Box<dyn std::error::Error>> {
    for streaming in [false, true] {
        let root = temp_data_root("conditional-live");
        let mut state = make_state(root.clone());
        let (endpoint, server) = relay()?;
        let account = state.accounts.get_mut(ACCOUNT).ok_or(SdkError::AccountDbNotUnlocked)?;
        let mut options =
            parse_relay_transfer_options(Some(endpoint), None, None)?.ok_or("relay config")?;
        options.token_provider =
            RelayTokenProvider::LocalMint { relay_service_key: b"fixture-relay-key".to_vec() };
        account.client.node_relay_options = Some(options);
        let (connection, _io) = crate::bus::connection_manager::tests::seeded(
            account.gateway_config.clone(),
            crate::bus::runtime_limits::RuntimeTimeouts::default(),
        );
        account.connection = Some(connection.clone());
        connection.require_live(Duration::from_secs(600)).await?;
        let command = request(&mut state, streaming, false).await?;
        let response =
            Box::pin(crate::bus::mutations::execute(&mut state, ACCOUNT, &command)).await?;
        assert_eq!(response.body["committed"], true);
        assert_eq!(
            server.join().map_err(|_| "relay fixture thread panicked")??,
            1,
            "the Live request must actually PUT its chunk"
        );
        connection.stop().await;
        drop(state);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[cfg(feature = "itest-local-mint")]
fn relay()
-> Result<(String, std::thread::JoinHandle<Result<usize, std::io::Error>>), std::io::Error> {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let mut request = Vec::new();
        let (offset, length) = loop {
            let mut buffer = [0_u8; 4096];
            let count = stream.read(&mut buffer)?;
            if count == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            request.extend_from_slice(&buffer[..count]);
            if let Some(offset) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let headers =
                    std::str::from_utf8(&request[..offset]).map_err(std::io::Error::other)?;
                let length = headers
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                    .ok_or_else(|| std::io::Error::other("content length missing"))?
                    .1
                    .trim()
                    .parse::<usize>()
                    .map_err(std::io::Error::other)?;
                if request.len() >= offset + 4 + length {
                    break (offset + 4, length);
                }
            }
        };
        let frame: serde_json::Value = serde_json::from_slice(&request[offset..offset + length])?;
        let response = serde_json::to_vec(
            &json!({"chunk_id":frame["chunk_id"],"object_id":frame["object_id"],
            "manifest_hash":frame["manifest_hash"],"expires_at":frame["expires_at"],"status":SdkRelayChunkStatus::Available}),
        )?;
        stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .as_bytes(),
        )?;
        stream.write_all(&response)?;
        Ok(1)
    });
    Ok((endpoint, server))
}

#[tokio::test]
async fn conditional_object_delete_keeps_local_tombstones_offline_and_gates_relay_before_reserve()
-> Result<(), Box<dyn std::error::Error>> {
    for relay in [false, true] {
        let root = temp_data_root("conditional-delete");
        let mut state = make_state(root.clone());
        state
            .accounts
            .get_mut(ACCOUNT)
            .ok_or(SdkError::AccountDbNotUnlocked)?
            .timeouts
            .network_wait = Duration::ZERO;
        let put = request(&mut state, false, false).await?;
        Box::pin(crate::bus::mutations::execute(&mut state, ACCOUNT, &put)).await?;
        let delete = command(
            "object.delete",
            json!({"object_id":OBJECT_ID,
            "relay_endpoint":relay.then(||"http://127.0.0.1:9".to_owned())}),
        );
        let intent = MutationIntent::new(&delete.request)?;
        let result = Box::pin(crate::bus::mutations::execute(&mut state, ACCOUNT, &delete)).await;
        let account = state.accounts.get(ACCOUNT).ok_or(SdkError::AccountDbNotUnlocked)?;
        if relay {
            assert!(
                matches!(
                    result,
                    Err(SdkError::NetworkingPending | SdkError::NetworkingPendingContext { .. })
                ),
                "a relay tombstone requires Live before any reserve"
            );
            assert!(
                intent.lookup(account.client.account_db()?)?.is_none(),
                "relay refusal must leave no Pending receipt"
            );
            assert!(!account.client.account_db()?.object_is_tombstoned(OBJECT_ID)?);
        } else {
            assert_eq!(result?.body["tombstoned"], true);
            assert!(account.client.account_db()?.object_is_tombstoned(OBJECT_ID)?);
            assert!(intent.lookup(account.client.account_db()?)?.is_some());
        }
        if let Some(connection) = account.connection.as_ref() {
            connection.stop().await;
        }
        drop(state);
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}

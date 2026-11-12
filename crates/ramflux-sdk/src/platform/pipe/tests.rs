// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Carrier tests for the M2 acceptance: a second user is refused, a pre-created pipe name is
//! refused by the daemon and by the client, and a low-integrity token is refused.
//!
//! The second-user tests need a second local account. They are ignored unless the job provides
//! `RAMFLUX_TEST_SECOND_USER` and `RAMFLUX_TEST_SECOND_USER_PASSWORD`.

use std::ffi::OsString;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ServerOptions;

use super::listener::{
    BusListener, BusStream, PeerCred, PipeBusListener, authorize, bind, connect, connect_named,
};
use super::name;
use super::win32::test_tokens::{impersonate_low_integrity, impersonate_user, sid_from_string};
use super::win32::{self, MEDIUM_INTEGRITY_RID, TokenFacts};
use crate::SdkError;

const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
const LOW_INTEGRITY_RID: u32 = 0x1000;
const HIGH_INTEGRITY_RID: u32 = 0x3000;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn unused_name() -> Result<(OsString, String, win32::Sid), String> {
    let me = win32::process_facts().map_err(text)?.user;
    let user_sid = me.to_sddl_string().map_err(text)?;
    let nonce = name::fresh_nonce().map_err(text)?;
    Ok((name::pipe_name(&user_sid, &nonce).map_err(text)?, user_sid, me))
}

fn second_user() -> Option<(String, String)> {
    Some((
        std::env::var("RAMFLUX_TEST_SECOND_USER").ok()?,
        std::env::var("RAMFLUX_TEST_SECOND_USER_PASSWORD").ok()?,
    ))
}

/// Open the pipe the way any other process could, on a thread that impersonates `token`.
fn open_while_impersonating<G: Send + 'static>(
    name: OsString,
    token: impl FnOnce() -> std::io::Result<G> + Send + 'static,
) -> Result<std::io::Result<()>, String> {
    std::thread::spawn(move || {
        let guard = token().map_err(text)?;
        let opened = std::fs::OpenOptions::new().read(true).write(true).open(&name).map(|_pipe| ());
        drop(guard);
        Ok(opened)
    })
    .join()
    .map_err(|_| "impersonating thread failed".to_owned())?
}

#[tokio::test]
async fn same_user_connects_and_bytes_round_trip() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(text)?;
    let path = dir.path().join("daemon.sock");
    let listener = bind(&path).map_err(text)?;
    let owner = listener.owner().map_err(text)?;
    let (accepted, client) = tokio::join!(listener.accept(), connect(&path));
    let accepted = accepted.map_err(text)?;
    let mut client = client.map_err(text)?;
    accepted.matches_peer(owner).map_err(text)?;
    let (mut reader, mut writer) = accepted.into_halves();
    client.write_all(&5_u32.to_be_bytes()).await.map_err(text)?;
    client.write_all(b"hello").await.map_err(text)?;
    let len = reader.read_u32().await.map_err(text)?;
    let mut body = vec![0_u8; usize::try_from(len).map_err(text)?];
    reader.read_exact(&mut body).await.map_err(text)?;
    if body != b"hello" {
        return Err("frame body changed in transit".to_owned());
    }
    writer.write_all(b"ok").await.map_err(text)?;
    let mut reply = [0_u8; 2];
    client.read_exact(&mut reply).await.map_err(text)?;
    if &reply == b"ok" { Ok(()) } else { Err("reply changed in transit".to_owned()) }
}

#[tokio::test]
async fn a_second_client_is_served_while_the_first_stays_connected() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(text)?;
    let path = dir.path().join("daemon.sock");
    let listener = bind(&path).map_err(text)?;
    let (first, _first_client) = tokio::join!(listener.accept(), connect(&path));
    let _first = first.map_err(text)?;
    let (second, second_client) = tokio::join!(listener.accept(), connect(&path));
    second.map_err(text)?;
    second_client.map(|_stream| ()).map_err(text)
}

#[test]
fn server_rule_refuses_other_user_low_integrity_and_app_container() -> Result<(), String> {
    let me = win32::process_facts().map_err(text)?.user;
    let other = sid_from_string(LOCAL_SYSTEM_SID).map_err(text)?;
    let facts =
        |user, integrity_rid, app_container| TokenFacts { user, integrity_rid, app_container };
    authorize(&facts(me, MEDIUM_INTEGRITY_RID, false), &me).map_err(text)?;
    authorize(&facts(me, HIGH_INTEGRITY_RID, false), &me).map_err(text)?;
    for refused in [
        facts(other, MEDIUM_INTEGRITY_RID, false),
        facts(me, LOW_INTEGRITY_RID, false),
        facts(me, MEDIUM_INTEGRITY_RID, true),
    ] {
        match authorize(&refused, &me) {
            Err(SdkError::LocalBusPermissionDenied) => {}
            Ok(()) => return Err("a refused token was accepted".to_owned()),
            Err(error) => return Err(text(error)),
        }
    }
    Ok(())
}

#[tokio::test]
async fn accepted_client_fails_the_check_against_another_owner_sid() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(text)?;
    let path = dir.path().join("daemon.sock");
    let listener = bind(&path).map_err(text)?;
    let (accepted, _client) = tokio::join!(listener.accept(), connect(&path));
    let accepted = accepted.map_err(text)?;
    let other = PeerCred { sid: sid_from_string(LOCAL_SYSTEM_SID).map_err(text)? };
    match accepted.matches_peer(other) {
        Err(SdkError::LocalBusPermissionDenied) => Ok(()),
        Ok(()) => Err("a different SID was accepted".to_owned()),
        Err(error) => Err(text(error)),
    }
}

#[tokio::test]
async fn daemon_refuses_a_pre_created_pipe_name() -> Result<(), String> {
    let (pipe_name, user_sid, me) = unused_name()?;
    let _squatter = ServerOptions::new().create(&pipe_name).map_err(text)?;
    match PipeBusListener::create(pipe_name, &user_sid, me) {
        Err(SdkError::DataRootInUse) => Ok(()),
        Ok(_) => Err("the daemon bound a name that already existed".to_owned()),
        Err(error) => Err(text(error)),
    }
}

#[tokio::test]
async fn a_second_listener_on_the_same_name_is_refused() -> Result<(), String> {
    let (pipe_name, user_sid, me) = unused_name()?;
    let _first = PipeBusListener::create(pipe_name.clone(), &user_sid, me).map_err(text)?;
    match PipeBusListener::create(pipe_name, &user_sid, me) {
        Err(SdkError::DataRootInUse) => Ok(()),
        Ok(_) => Err("two listeners share one pipe name".to_owned()),
        Err(error) => Err(text(error)),
    }
}

#[tokio::test]
async fn client_refuses_a_pipe_of_another_owner_before_sending_a_frame() -> Result<(), String> {
    let (pipe_name, user_sid, me) = unused_name()?;
    let listener = PipeBusListener::create(pipe_name, &user_sid, me).map_err(text)?;
    let other = sid_from_string(LOCAL_SYSTEM_SID).map_err(text)?;
    let (accepted, client) =
        tokio::join!(listener.accept(), connect_named(listener.name(), &other));
    match client {
        Err(SdkError::LocalBusPermissionDenied) => {}
        Ok(_) => return Err("the client trusted a pipe of another owner".to_owned()),
        Err(error) => return Err(text(error)),
    }
    let (mut reader, _writer) = accepted.map_err(text)?.into_halves();
    let mut received = Vec::new();
    // The refused client closed its end. The server sees end of stream and not one byte.
    let _ = reader.read_to_end(&mut received).await;
    if received.is_empty() { Ok(()) } else { Err("the client sent bytes".to_owned()) }
}

#[tokio::test]
async fn client_refuses_a_name_file_it_does_not_own_or_cannot_parse() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(text)?;
    let path = dir.path().join("daemon.sock");
    std::fs::write(&path, b"not a pipe name").map_err(text)?;
    match connect(&path).await {
        Err(SdkError::LocalBus(_)) => {}
        Ok(_) => return Err("a malformed name file was used".to_owned()),
        Err(error) => return Err(text(error)),
    }
    let other = sid_from_string(LOCAL_SYSTEM_SID).map_err(text)?;
    match name::read_name_file(&path, &other) {
        Err(SdkError::LocalBusPermissionDenied) => Ok(()),
        Ok(_) => Err("a name file of another owner was read".to_owned()),
        Err(error) => Err(text(error)),
    }
}

#[tokio::test]
async fn name_file_is_removed_only_while_it_publishes_this_listener() -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(text)?;
    let path = dir.path().join("daemon.sock");
    let listener = bind(&path).map_err(text)?;
    let Some(endpoint) = listener.endpoint().map_err(text)? else {
        return Err("the listener published no name file".to_owned());
    };
    std::fs::remove_file(&path).map_err(text)?;
    std::fs::write(&path, b"0123456789abcdef0123456789abcdef").map_err(text)?;
    endpoint.remove_if_unchanged().map_err(text)?;
    if !path.exists() {
        return Err("a name file of another listener was removed".to_owned());
    }
    std::fs::remove_file(&path).map_err(text)?;
    drop(listener);
    let listener = bind(&path).map_err(text)?;
    let Some(endpoint) = listener.endpoint().map_err(text)? else {
        return Err("the listener published no name file".to_owned());
    };
    endpoint.remove_if_unchanged().map_err(text)?;
    if path.exists() { Err("the name file was left behind".to_owned()) } else { Ok(()) }
}

#[tokio::test]
async fn low_integrity_token_of_the_same_user_cannot_open_the_pipe() -> Result<(), String> {
    let (pipe_name, user_sid, me) = unused_name()?;
    let listener = PipeBusListener::create(pipe_name, &user_sid, me).map_err(text)?;
    let name = listener.name().to_os_string();
    let opened = tokio::task::spawn_blocking(move || {
        open_while_impersonating(name, impersonate_low_integrity)
    })
    .await
    .map_err(text)??;
    match opened {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Ok(()) => Err("a low-integrity token opened the pipe".to_owned()),
        Err(error) => Err(text(error)),
    }
}

#[tokio::test]
#[ignore = "needs a second local user: RAMFLUX_TEST_SECOND_USER and RAMFLUX_TEST_SECOND_USER_PASSWORD"]
async fn second_user_cannot_open_the_pipe() -> Result<(), String> {
    let Some((user, password)) = second_user() else {
        return Err("second user credentials are not set".to_owned());
    };
    let (pipe_name, user_sid, me) = unused_name()?;
    let listener = PipeBusListener::create(pipe_name, &user_sid, me).map_err(text)?;
    let name = listener.name().to_os_string();
    let opened = tokio::task::spawn_blocking(move || {
        open_while_impersonating(name, move || impersonate_user(&user, &password))
    })
    .await
    .map_err(text)??;
    match opened {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Ok(()) => Err("a second user opened the pipe".to_owned()),
        Err(error) => Err(text(error)),
    }
}

#[tokio::test]
#[ignore = "needs a second local user: RAMFLUX_TEST_SECOND_USER and RAMFLUX_TEST_SECOND_USER_PASSWORD"]
async fn daemon_and_client_refuse_a_name_pre_created_by_a_second_user() -> Result<(), String> {
    let Some((user, password)) = second_user() else {
        return Err("second user credentials are not set".to_owned());
    };
    let (pipe_name, user_sid, me) = unused_name()?;
    let runtime = tokio::runtime::Handle::current();
    let squatted = pipe_name.clone();
    let squatter = tokio::task::spawn_blocking(move || {
        std::thread::spawn(move || {
            let guard = impersonate_user(&user, &password).map_err(text)?;
            let _context = runtime.enter();
            let pipe = ServerOptions::new().create(&squatted).map_err(text);
            drop(guard);
            pipe
        })
        .join()
        .map_err(|_| "squatting thread failed".to_owned())?
    })
    .await
    .map_err(text)??;
    match PipeBusListener::create(pipe_name.clone(), &user_sid, me) {
        Err(SdkError::DataRootInUse) => {}
        Ok(_) => return Err("the daemon bound a name another user created".to_owned()),
        Err(error) => return Err(text(error)),
    }
    let refused = match connect_named(&pipe_name, &me).await {
        Err(SdkError::LocalBusPermissionDenied) => Ok(()),
        Err(SdkError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Ok(_) => Err("the client trusted a pipe another user created".to_owned()),
        Err(error) => Err(text(error)),
    };
    drop(squatter);
    refused
}

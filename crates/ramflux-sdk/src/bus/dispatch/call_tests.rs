// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Real account storage and mutation-boundary regressions for public rows and secret media replies.
use super::*;
use crate::bus::actor::AccountCommand;
use crate::client::call;
use std::sync::{Arc, atomic::AtomicBool};
fn fixture(name: &str) -> Result<(PathBuf, LocalBusDaemonState, String), SdkError> {
    let root = crate::bus::runtime_tests::root(name);
    let mut account =
        crate::bus::runtime_tests::account(&root, "alice", None, Arc::new(AtomicBool::new(false)))?;
    let local = account.client.call_local_endpoint()?;
    let peer = CallEndpoint {
        principal_id: "bob".into(),
        device_id: "bob-device".into(),
        root_public_key: ramflux_crypto::public_key_base64url_from_seed([9; 32]),
    };
    let id = ramflux_protocol::encode_base64url([7; 16]);
    let mut call =
        LiveCall::outgoing(id.clone(), "thread".into(), local, vec![peer], now_unix_timestamp())?;
    call.row.state = "active".into();
    call.row.answered_at = Some(now_unix_timestamp());
    call.receive_key = Some(zeroize::Zeroizing::new([3; 32]));
    call.allocation = Some(ramflux_protocol::VoiceAllocation {
        endpoint: "relay.example:9000".into(),
        lease_id: ramflux_protocol::encode_base64url([8; 16]),
        side: 0,
        token: ramflux_protocol::encode_base64url([4; 32]),
        rebind_key: ramflux_protocol::encode_base64url([12; 32]),
        hard_expires_at: u64::MAX,
        expires_at: u64::MAX,
    });
    call.next_lease_refresh = i64::MAX;
    call.pending.clear();
    account.client.persist_call_row(&call.row)?;
    account.client.voice_calls.insert(id.clone(), call);
    let state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.join("bus.sock"), &root),
        accounts: BTreeMap::from([("alice".into(), account)]),
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    Ok((root, state, id))
}
fn request(method: &str, id: &str) -> LocalBusFrame {
    LocalBusFrame::request("call-test", Some("alice".into()), "test", method, json!({"call_id":id}))
}
#[tokio::test]
async fn media_key_replies_cannot_be_replayed_from_generic_operation_receipts()
-> Result<(), SdkError> {
    let (root, mut state, id) = fixture("call-media-receipt")?;
    let (outbound, _) = mpsc::channel(4);
    let mut frame = request("call.media.session", &id);
    frame.operation_id = Some("media-key-request".into());
    let command = AccountCommand {
        private: None,
        request: frame,
        connection_id: 1,
        topics: BTreeSet::new(),
        attended: true,
        nodes: None,
        outbound,
        reply: None,
    };
    let first = crate::bus::mutations::execute(&mut state, "alice", &command).await?.body;
    assert!(crate::bus::mutations::execute(&mut state, "alice", &command).await.is_err());
    let account = local_bus_account(&state, "alice")?;
    // A different fingerprint can reserve the key only if no generic receipt was retained.
    assert_eq!(
        account
            .client
            .account_db()?
            .reserve_operation("media-key-request", "probe-no-secret-receipt")?,
        None
    );
    let journal = serde_json::to_string(&account.client.account_db()?.journal_after(0, 128)?)?;
    for secret in [
        first["relay"]["token"].as_str(),
        first["sframe"]["send"]["base_key"].as_str(),
        first["sframe"]["receive"]["base_key"].as_str(),
    ]
    .into_iter()
    .flatten()
    {
        assert!(!journal.contains(secret));
    }
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test]
async fn a_media_engine_cannot_reacquire_keys_with_a_restart_flag() -> Result<(), SdkError> {
    let (root, mut state, id) = fixture("call-legacy-media")?;
    dispatch(&request("call.media.session", &id), &mut state).await?;
    assert!(dispatch(&request("call.media.session", &id), &mut state).await.is_err());
    let mut restart = request("call.media.session", &id);
    restart.body["counter_lease_v1"] = json!(true);
    assert!(dispatch(&restart, &mut state).await.is_err());
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[tokio::test]
async fn headless_and_nonhuman_accounts_cannot_mutate_calls_or_obtain_media_keys()
-> Result<(), SdkError> {
    let (root, mut state, id) = fixture("call-human-only")?;
    let path = local_bus_account_manifest_path(&root, "alice");
    let mut manifest = read_local_bus_account_manifest(&path)?;
    for (mode, kind) in [
        (LocalBusClientMode::HeadlessAi, None),
        (LocalBusClientMode::AttendedCli, Some("headless_ai")),
    ] {
        manifest.client_mode = mode;
        manifest.kind = kind.map(str::to_owned);
        write_local_bus_account_manifest(&root, &manifest)?;
        for method in
            ["call.invite", "call.answer", "call.reject", "call.hangup", "call.media.session"]
        {
            assert!(
                matches!(
                    dispatch(&request(method, &id), &mut state).await,
                    Err(SdkError::CapabilityDenied(_))
                ),
                "{method}"
            );
        }
    }
    assert_eq!(local_bus_account(&state, "alice")?.client.voice_calls[&id].row.state, "active");
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
#[test]
fn daemon_restart_ends_unrecoverable_calls_and_retains_a_public_timeline_record()
-> Result<(), SdkError> {
    let (root, mut state, id) = fixture("call-restart")?;
    let account = local_bus_account_mut(&mut state, "alice")?;
    account.client.voice_calls.clear();
    recover(account)?;
    let listed = list(&account.client)?;
    assert_eq!(listed["calls"][0]["state"], "ended");
    assert_eq!(listed["calls"][0]["end_reason"], "failed");
    assert_eq!(listed["calls"][0]["failure_reason"], "daemon_restarted");
    assert_eq!(listed["calls"][0]["call_id"], id);
    let page = crate::bus::readers::read(
        &account.client,
        &LocalBusFrame::request(
            "timeline",
            Some("alice".into()),
            "test",
            "message.list",
            json!({"conversation_id":"thread"}),
        ),
    )?;
    assert_eq!(page["messages"][0]["kind"], "call");
    assert_eq!(page["messages"][0]["call"]["state"], "ended");
    assert!(crate::bus::readers::is_reader_request("call.list"));
    assert_eq!(crate::bus::readers::read(&account.client, &request("call.list", &id))?, listed);
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn committed_call_cache_refresh_is_idempotent_and_cannot_revive_a_restarted_call()
-> Result<(), SdkError> {
    let (root, mut state, _) = fixture("call-control-cache")?;
    let account = local_bus_account_mut(&mut state, "alice")?;
    account.client.voice_calls.clear();
    recover(account)?;
    let local = account.client.call_local_endpoint()?;
    let remote = CallEndpoint {
        principal_id: "bob".into(),
        device_id: "bob-device".into(),
        root_public_key: ramflux_crypto::public_key_base64url_from_seed([9; 32]),
    };
    let caller = LiveCall::outgoing(
        ramflux_protocol::encode_base64url([8; 16]),
        "thread".into(),
        remote,
        vec![local.clone()],
        now_unix_timestamp(),
    )?;
    let control = &caller.pending[0];
    let body = call::bytes(control)?;
    let incoming = LiveCall::incoming(control, local, now_unix_timestamp())?;
    account.client.persist_call_row(&incoming.row)?;
    account
        .client
        .voice_transition
        .replace(Some((call::transition_key(&body), Box::new(incoming))));
    assert!(account.client.refresh_call_control(&body)?);
    let before = account.client.voice_calls[&control.call_id].clone();
    assert!(account.client.refresh_call_control(&body)?);
    let after = &account.client.voice_calls[&control.call_id];
    assert_eq!(after.row, before.row);
    assert_eq!(after.pending.len(), before.pending.len());
    if after.receive_key != before.receive_key {
        return Err(SdkError::LocalBus("committed refresh changed the media key".into()));
    }
    account.client.voice_calls.clear();
    recover(account)?;
    assert!(account.client.refresh_call_control(&body)?);
    assert_eq!(account.client.voice_calls.len(), 0);
    assert_eq!(
        account
            .client
            .account_db()?
            .load_actor_state::<ramflux_protocol::CallRow>(&format!(
                "voice/public/{}",
                control.call_id
            ))?
            .map(|r| r.end_reason),
        Some(Some("failed".into()))
    );
    drop(state);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn generated_call_ids_are_full_length_and_never_look_like_cli_flags() -> Result<(), SdkError> {
    for _ in 0..512 {
        let id = super::new_call_id()?;
        assert!(!id.starts_with('-'));
        assert_eq!(
            ramflux_protocol::decode_base64url(&id)
                .map_err(|_| super::invalid("call ID encoding"))?
                .len(),
            16
        );
    }
    Ok(())
}

#[tokio::test]
async fn native_call_mutation_gate_needs_no_legacy_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = crate::client::native_test_support::Fixture::new("native-call-gate").await?;
    let id = fixture.client.account_db()?.local_account_id.clone();
    let root = fixture.root.0.clone();
    assert!(!local_bus_account_manifest_path(&root, &id).exists());
    let account = LocalBusAccountState::disconnected(
        fixture.client,
        fixture.config,
        fixture.manifest.principal_commitment,
    );
    let state = LocalBusDaemonState {
        account_index: None,
        nodes: crate::node::NodeStore::default(),
        config: LocalBusConfig::new(root.join("bus.sock"), &root),
        accounts: BTreeMap::from([(id.clone(), account)]),
        active_account_id: None,
        attended_accounts: BTreeSet::new(),
        subscribers: BTreeMap::new(),
    };
    require_attended_human(&state, &id)?;
    Ok(())
}

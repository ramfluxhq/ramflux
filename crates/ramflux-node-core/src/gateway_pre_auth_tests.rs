// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deterministic boundary and crash tests for durable transport admission.
use super::*;
use crate::{
    GatewayPreAuthDecision as Decision, GatewayPreAuthPolicy, GatewayRedbStore, GatewayState,
};
use std::time::Duration;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn state() -> Result<GatewayState> {
    let mut state = GatewayState::new();
    state.set_fixture_pre_auth_cookie_key();
    state.set_pre_auth_policy(GatewayPreAuthPolicy {
        enabled: true,
        per_source_ip_handshake_rate: 1,
        window_seconds: 60,
        cookie_ttl_seconds: 60,
        ..GatewayPreAuthPolicy::default()
    })?;
    Ok(state)
}
fn source(index: u32) -> String {
    ramflux_protocol::encode_base64url(ramflux_crypto::blake3_256(
        "preauth-boundary",
        &index.to_be_bytes(),
    ))
}
fn challenge(state: &mut GatewayState, peer: &str, now: u64) -> Result<String> {
    match state.check_pre_auth(peer, None, now)? {
        Decision::Challenge(challenge) => Ok(challenge.pre_auth_cookie),
        Decision::Accepted => Err("expected saturated source".into()),
    }
}
struct Store {
    store: GatewayRedbStore,
    path: std::path::PathBuf,
}
impl Store {
    fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "preauth-boundary-{}.redb",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        Ok(Self { store: GatewayRedbStore::open(&path)?, path })
    }
    fn restored(&self) -> Result<GatewayState> {
        self.store.load_state()?.ok_or_else(|| "missing gateway state".into())
    }
    fn replace(&self, bytes: &[u8]) -> Result {
        let tx = self.store.db.begin_write()?;
        {
            let mut table = tx.open_table(GATEWAY_STATE_TABLE)?;
            table.insert(KEY, bytes)?;
        }
        tx.commit()?;
        Ok(())
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn preauth_boundary_matrix() -> Result {
    expiry_boundaries()?;
    capacity_and_hot_debt()?;
    restart_rollback_and_failed_commit()?;
    disabled_admission_preserves_durable_time_floor()?;
    bounded_snapshots_and_legacy()?;
    configuration_bounds()?;
    mounted_key_rotation_and_resume()?;
    Ok(())
}
fn expiry_boundaries() -> Result {
    let peer = source(1);
    for age in [59, 60, 61] {
        let mut state = state()?;
        assert_eq!(state.check_pre_auth(&peer, None, 100)?, Decision::Accepted);
        let cookie = challenge(&mut state, &peer, 100)?;
        assert_eq!(
            crate::verify_pre_auth_cookie(
                &peer,
                crate::PRE_AUTH_PROTOCOL_VERSION,
                &cookie,
                100 + age,
                60,
                &state.pre_auth_policy.cookie_secret
            ),
            age <= 60
        );
        assert_eq!(
            matches!(state.check_pre_auth(&peer, None, 100 + age)?, Decision::Accepted),
            age > 60
        );
    }
    let mut state = state()?;
    state.pre_auth_policy.per_source_ip_handshake_rate = 0;
    state.pre_auth_policy.window_seconds = 0;
    state.pre_auth_policy.cookie_ttl_seconds = 0;
    state.pre_auth_policy.auth_deadline_ms = 0;
    assert_eq!(state.pre_auth_read_timeout(), Duration::from_millis(1));
    let cookie = challenge(&mut state, &peer, 100)?;
    assert_eq!(state.check_pre_auth(&peer, Some(&cookie), 100)?, Decision::Accepted);
    assert!(state.check_pre_auth(&peer, Some(&cookie), 101).is_err());
    assert!(matches!(
        state.check_pre_auth_system_time(&peer, None, UNIX_EPOCH - Duration::from_secs(1)),
        Err(NodeCoreError::PreAuthClockInvalid)
    ));
    Ok(())
}
fn capacity_and_hot_debt() -> Result {
    let mut state = state()?;
    for n in 0..4096 {
        assert_eq!(state.check_pre_auth(&source(n), None, 100)?, Decision::Accepted);
    }
    assert!(matches!(
        state.check_pre_auth(&source(4096), None, 100),
        Err(NodeCoreError::PreAuthCapacity)
    ));
    let cookie = challenge(&mut state, &source(0), 100)?;
    assert_eq!(state.check_pre_auth(&source(0), Some(&cookie), 160)?, Decision::Accepted);
    assert_eq!(state.check_pre_auth(&source(4096), None, 161)?, Decision::Accepted);
    assert!(matches!(state.check_pre_auth(&source(0), None, 161)?, Decision::Challenge(_)));
    assert_eq!(state.pre_auth_handshakes_by_source_ip.len(), 4096 - 2 * 16 + 1);
    assert!(state.has_pre_auth_source(&source(0)));
    // The timer may drain the backlog; Opens themselves reclaim at most 16.
    state.prune_retained_sessions(161, 300, &std::collections::BTreeSet::new());
    assert_eq!(state.pre_auth_handshakes_by_source_ip.len(), 2);
    Ok(())
}
fn restart_rollback_and_failed_commit() -> Result {
    let fixture = Store::new()?;
    let mut state = state()?;
    state.check_pre_auth(&source(1), None, 100)?;
    fixture.store.save_state(&state)?;
    let mut restored = fixture.restored()?;
    restored.set_fixture_pre_auth_cookie_key();
    assert!(matches!(
        restored.check_pre_auth(&source(1), None, 99),
        Err(NodeCoreError::PreAuthClockRollback)
    ));
    assert_eq!(restored.pre_auth_time_floor, 100);
    assert_eq!(restored.pre_auth_handshakes_by_source_ip, state.pre_auth_handshakes_by_source_ip);
    challenge(&mut restored, &source(1), 100)?;
    // Abort a real redb transaction after writes; persisted debt/counters/floor stay together.
    fixture.store.fail_next_pre_auth_commit();
    restored.check_pre_auth(&source(2), None, 200)?;
    assert!(fixture.store.save_pre_auth_hot(&restored).is_err());
    let persisted = fixture.restored()?;
    assert_eq!(persisted.pre_auth_time_floor, 100);
    assert_eq!(persisted.pre_auth_metrics, state.pre_auth_metrics);
    assert_eq!(persisted.pre_auth_handshakes_by_source_ip, state.pre_auth_handshakes_by_source_ip);
    fixture.store.save_pre_auth_hot(&restored)?;
    assert_eq!(fixture.restored()?.pre_auth_time_floor, 200);
    Ok(())
}
fn disabled_admission_preserves_durable_time_floor() -> Result {
    let fixture = Store::new()?;
    let mut state = GatewayState::new();
    assert!(!state.pre_auth_policy.enabled);
    state.observe_pre_auth_time(UNIX_EPOCH + Duration::from_secs(100))?;
    fixture.store.save_state(&state)?;
    let mut restored = fixture.restored()?;
    let before = restored.admission_bytes()?;
    assert!(matches!(
        restored.check_pre_auth_system_time(&source(1), None, UNIX_EPOCH + Duration::from_secs(99)),
        Err(NodeCoreError::PreAuthClockRollback)
    ));
    assert!(matches!(
        restored.check_pre_auth_system_time(&source(1), None, UNIX_EPOCH - Duration::from_secs(1)),
        Err(NodeCoreError::PreAuthClockInvalid)
    ));
    assert_eq!(
        restored.admission_bytes()?,
        before,
        "disabled quota must not permit clock rollback before pruning"
    );
    assert_eq!(
        restored.check_pre_auth_system_time(
            &source(1),
            None,
            UNIX_EPOCH + Duration::from_secs(100)
        )?,
        Decision::Accepted
    );
    Ok(())
}
fn bounded_snapshots_and_legacy() -> Result {
    let fixture = Store::new()?;
    let mut state = state()?;
    state.check_pre_auth(&source(1), None, 100)?;
    fixture.store.save_state(&state)?;
    let original: serde_json::Value = serde_json::from_slice(&state.admission_bytes()?)?;
    let mut bad = Vec::new();
    let mut value = original.clone();
    value["version"] = 2.into();
    bad.push(value);
    let mut value = original.clone();
    value["source_scheme"] = "claimed".into();
    bad.push(value);
    let mut value = original.clone();
    value["buckets"] = serde_json::json!({"not-a-pseudonym":[100]});
    bad.push(value);
    let mut value = original.clone();
    value["buckets"][source(1)] = serde_json::json!([101]);
    bad.push(value);
    let mut value = original.clone();
    value["buckets"][source(1)] = serde_json::json!([100, 99]);
    bad.push(value);
    let mut value = original.clone();
    value["buckets"] = serde_json::to_value(
        (0..4097).map(|n| (source(n), vec![100])).collect::<BTreeMap<_, _>>(),
    )?;
    bad.push(value);
    for value in bad {
        fixture.replace(&serde_json::to_vec(&value)?)?;
        assert!(matches!(fixture.store.load_state(), Err(NodeCoreError::PreAuthSnapshotInvalid)));
    }
    fixture.replace(&vec![b' '; MAX_BYTES + 1])?;
    assert!(matches!(fixture.store.load_state(), Err(NodeCoreError::PreAuthSnapshotInvalid)));
    let tx = fixture.store.db.begin_write()?;
    {
        let mut table = tx.open_table(GATEWAY_STATE_TABLE)?;
        table.remove(KEY)?;
        table.insert(
            crate::GATEWAY_PRE_AUTH_RATE_STATE_KEY,
            b"{\"legacy-client-claim\":[100]}".as_slice(),
        )?;
    }
    tx.commit()?;
    assert!(matches!(fixture.store.load_state(), Err(NodeCoreError::GatewayStateResetRequired)));

    Ok(())
}
fn configuration_bounds() -> Result {
    for (rate, window, ttl, deadline, valid) in [
        (0, 0, 0, 0, true),
        (60, 3600, 3600, 10000, true),
        (61, 60, 60, 5000, false),
        (1, 3601, 60, 5000, false),
        (1, 60, 3601, 5000, false),
        (1, 60, 60, 10001, false),
    ] {
        let mut state = state()?;
        let mut policy = state.pre_auth_policy.clone();
        policy.per_source_ip_handshake_rate = rate;
        policy.window_seconds = window;
        policy.cookie_ttl_seconds = ttl;
        policy.auth_deadline_ms = deadline;
        assert_eq!(state.set_pre_auth_policy(policy).is_ok(), valid);
    }
    let mut state = state()?;
    state.check_pre_auth(&source(1), None, 100)?;
    let config = crate::GatewayPreAuthConfig::from(state.pre_auth_policy());
    state.configure_pre_auth_policy(&config)?;
    challenge(&mut state, &source(1), 100)?;
    assert!(!GatewayState::new().pre_auth_policy.enabled);
    Ok(())
}
fn mounted_key_rotation_and_resume() -> Result {
    use std::io::Write;
    let fixture = Store::new()?;
    let path = fixture.path.with_extension("key");
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut state = state()?;
    assert!(state.configure_pre_auth_cookie_key(&path).is_err());
    let mut file = options.open(&path)?;
    file.write_all(b"invalid")?;
    assert!(state.configure_pre_auth_cookie_key(&path).is_err());
    std::fs::write(&path, ramflux_protocol::encode_base64url([1; 31]))?;
    assert!(state.configure_pre_auth_cookie_key(&path).is_err());
    let first = ramflux_protocol::encode_base64url([37; 32]);
    std::fs::write(&path, &first)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert!(state.configure_pre_auth_cookie_key(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let link = path.with_extension("symlink");
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(state.configure_pre_auth_cookie_key(&link).is_err());
        std::fs::remove_file(link)?;
    }
    state.pre_auth_policy.cookie_secret = first.clone();
    assert!(matches!(
        state.configure_pre_auth_cookie_key(&path),
        Err(NodeCoreError::PreAuthConfigInvalid)
    ));
    state.pre_auth_policy.cookie_secret = "resume-secret".into();
    assert!(!format!("{state:?}").contains("resume-secret"));
    state.configure_pre_auth_cookie_key(&path)?;
    state.check_pre_auth(&source(1), None, 100)?;
    let cookie = challenge(&mut state, &source(1), 100)?;
    state.open_session(crate::GatewaySession {
        session_id: "session".into(),
        target_delivery_id: "target".into(),
        device_id: "device".into(),
        opened_at: 100,
        last_heartbeat_at: 100,
        lifecycle: crate::GatewaySessionLifecycle::Live,
    });
    let resume = state.issue_resume_token(crate::GatewayResumeIssueInput {
        session_id: "session",
        target_delivery_id: "target",
        device_id: "device",
        device_epoch: 1,
        issued_at: 100,
        window_seconds: 60,
    });
    fixture.store.save_state(&state)?;
    assert!(!String::from_utf8(state.admission_bytes()?)?.contains(&first));
    assert!(!format!("{state:?}").contains(&first));
    let mut restored = fixture.restored()?;
    assert!(restored.pre_auth_cookie_key.is_none());
    std::fs::write(&path, ramflux_protocol::encode_base64url([38; 32]))?;
    restored.configure_pre_auth_cookie_key(&path)?;
    assert!(restored.check_pre_auth(&source(1), Some(&cookie), 100).is_err());
    assert!(
        restored
            .validate_resume_token_hash(crate::GatewayResumeValidateInput {
                resume_token_hash: &resume.metadata.resume_token_hash,
                previous_session_id: "session",
                target_delivery_id: "target",
                device_id: "device",
                device_epoch: 1,
                now: 100,
                window_seconds: 60
            })
            .is_some()
    );
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn concurrent_callers_sample_after_acquiring_the_state_lock() -> Result {
    let state = std::sync::Arc::new(std::sync::Mutex::new(state()?));
    let held = state.lock().map_err(|_| "state lock")?;
    let (ready, waiting) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let shared = state.clone();
    let caller = std::thread::spawn(move || -> std::result::Result<(), String> {
        ready.send(()).map_err(|e| e.to_string())?;
        released.recv().map_err(|e| e.to_string())?;
        let mut state = shared.lock().map_err(|e| e.to_string())?;
        state
            .check_pre_auth_system_time(&source(2), None, UNIX_EPOCH + Duration::from_secs(101))
            .map_err(|e| e.to_string())?;
        Ok(())
    });
    waiting.recv()?;
    drop(held);
    state.lock().map_err(|_| "state lock")?.check_pre_auth_system_time(
        &source(1),
        None,
        UNIX_EPOCH + Duration::from_secs(100),
    )?;
    release.send(())?;
    caller.join().map_err(|_| "caller panicked")??;
    assert_eq!(state.lock().map_err(|_| "state lock")?.pre_auth_time_floor, 101);
    Ok(())
}

#[test]
fn preauth_runtime_policy_and_debt_commit_atomically_across_restart() -> Result {
    let path = std::env::temp_dir().join(format!(
        "preauth-policy-{}.redb",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    let runtime = crate::GatewayPreAuthConfig {
        enabled: true,
        per_source_ip_handshake_rate: 1,
        ..Default::default()
    };
    {
        let store = GatewayRedbStore::open(&path)?;
        let mut state = state()?;
        let mut policy = state.pre_auth_policy.clone();
        policy.per_source_ip_handshake_rate = 2;
        state.set_pre_auth_policy(policy)?;
        state.check_pre_auth(&source(1), None, 100)?;
        state.check_pre_auth(&source(1), None, 101)?;
        store.save_state(&state)?;
        let configured = store.load_state_with_pre_auth_config(&runtime)?.ok_or("missing state")?;
        assert_eq!(configured.pre_auth_handshakes_by_source_ip[&source(1)], [101]);
        store.fail_next_pre_auth_commit();
        assert!(store.save_state(&configured).is_err());
    }
    {
        let store = GatewayRedbStore::open(&path)?;
        let previous = store.load_state()?.ok_or("previous state missing")?;
        assert_eq!(previous.pre_auth_policy.per_source_ip_handshake_rate, 2);
        assert_eq!(previous.pre_auth_handshakes_by_source_ip[&source(1)], [100, 101]);
        let configured =
            store.load_state_with_pre_auth_config(&runtime)?.ok_or("configured state missing")?;
        store.save_pre_auth_hot(&configured)?;
    }
    {
        let store = GatewayRedbStore::open(&path)?;
        let configured = store.load_state()?.ok_or("committed state missing")?;
        assert_eq!(configured.pre_auth_policy.per_source_ip_handshake_rate, 1);
        assert_eq!(configured.pre_auth_handshakes_by_source_ip[&source(1)], [101]);
        // An old out-of-bounds policy must not prevent valid runtime configuration from repairing it.
        let mut invalid = configured.pre_auth_policy.clone();
        invalid.window_seconds = 3601;
        crate::save_snapshot(
            &store.db,
            GATEWAY_STATE_TABLE,
            crate::GATEWAY_PRE_AUTH_POLICY_KEY,
            &invalid,
        )?;
        assert!(store.load_state_with_pre_auth_config(&runtime)?.is_some());
        assert!(store.load_state()?.is_some());
    }
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn pre_auth_restart_cooldown_cannot_shrink_on_another_restart() -> Result {
    let path = std::env::temp_dir().join(format!(
        "preauth-cooldown-{}.redb",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    {
        let store = GatewayRedbStore::open(&path)?;
        let mut state = GatewayState::new();
        state.set_pre_auth_policy(GatewayPreAuthPolicy {
            enabled: true,
            per_source_ip_handshake_rate: 1,
            window_seconds: 3600,
            ..GatewayPreAuthPolicy::default()
        })?;
        store.save_admission_checkpoint(&state.admission_checkpoint(100))?;
    }
    {
        let store = GatewayRedbStore::open(&path)?;
        let mut state = store.load_state()?.ok_or("missing reservation")?;
        let mut config = crate::GatewayPreAuthConfig::from(state.pre_auth_policy());
        config.window_seconds = 1;
        state.configure_pre_auth_policy(&config)?;
        store.save_admission_checkpoint(&state.admission_checkpoint(131))?;
    }
    let store = GatewayRedbStore::open(&path)?;
    let mut state = store.load_state()?.ok_or("missing second reservation")?;
    state.set_fixture_pre_auth_cookie_key();
    let source = crate::source_ip_hash("192.0.2.1");
    assert!(matches!(
        state.check_pre_auth(&source, None, 162),
        Err(NodeCoreError::PreAuthCapacity)
    ));
    assert!(state.check_pre_auth(&source, None, 3731).is_ok());
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn disabled_admission_refuses_time_below_the_checkpoint_reservation() -> Result {
    let fixture = Store::new()?;
    fixture.store.save_admission_checkpoint(&GatewayState::new().admission_checkpoint(100))?;
    let mut restored = fixture.restored()?;
    let source = source(1);
    assert!(matches!(
        restored.check_pre_auth_system_time(&source, None, UNIX_EPOCH + Duration::from_secs(101)),
        Err(NodeCoreError::PreAuthClockRollback)
    ));
    assert_eq!(
        restored.check_pre_auth_system_time(
            &source,
            None,
            UNIX_EPOCH + Duration::from_secs(130)
        )?,
        Decision::Accepted
    );
    Ok(())
}

#[test]
fn restart_rejects_clock_below_committed_reservation_in_both_modes() -> Result {
    for enabled in [false, true] {
        let path = std::env::temp_dir().join(format!(
            "preauth-reservation-fence-{}.redb",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        {
            let store = GatewayRedbStore::open(&path)?;
            let mut current = state()?;
            current.pre_auth_policy.enabled = enabled;
            let checkpoint = current.admission_checkpoint(100);
            store.save_admission_checkpoint(&checkpoint)?;
            current.install_admission_checkpoint(&checkpoint);
            assert!(matches!(
                current.check_pre_auth_system_time(
                    &source(1),
                    None,
                    UNIX_EPOCH + Duration::from_secs(105)
                )?,
                Decision::Accepted
            ));
        }
        let store = GatewayRedbStore::open(&path)?;
        let mut restored = store.load_state()?.ok_or("reservation missing")?;
        restored.set_fixture_pre_auth_cookie_key();
        assert!(
            matches!(
                restored.observe_pre_auth_time(UNIX_EPOCH + Duration::from_secs(102)),
                Err(NodeCoreError::PreAuthClockRollback)
            ),
            "startup accepted a clock below its reservation, enabled={enabled}"
        );
        assert!(
            matches!(
                restored.check_pre_auth_system_time(
                    &source(1),
                    None,
                    UNIX_EPOCH + Duration::from_secs(102)
                ),
                Err(NodeCoreError::PreAuthClockRollback)
            ),
            "Open accepted rollback, enabled={enabled}"
        );
        assert_eq!(restored.pre_auth_time_floor, 130);
        drop(store);
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[test]
fn admission_checkpoint_payload_is_independent_of_sessions() -> Result {
    let mut current = state()?;
    current.check_pre_auth(&source(1), None, 100)?;
    let initial = current.admission_checkpoint(100).entries()?;
    for index in 0..2000 {
        let id = format!("session-{index}");
        current.open_session(crate::GatewaySession {
            session_id: id.clone(),
            target_delivery_id: id.clone(),
            device_id: "device".into(),
            opened_at: 100,
            last_heartbeat_at: 100,
            lifecycle: crate::GatewaySessionLifecycle::Live,
        });
        current.frames_by_session.insert(
            id.clone(),
            vec![crate::GatewayFrame::Deliver {
                session_id: id,
                envelope_id: "envelope".into(),
                payload_hash: "x".repeat(4096),
            }],
        );
    }
    assert_eq!(current.admission_checkpoint(100).entries()?, initial);
    Ok(())
}

#[test]
fn empty_rate_zero_sources_are_reclaimed_on_reopen() -> Result {
    let path = std::env::temp_dir().join(format!(
        "preauth-empty-sources-{}.redb",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    {
        let store = GatewayRedbStore::open(&path)?;
        let mut current = state()?;
        current.pre_auth_policy.per_source_ip_handshake_rate = 0;
        current.pre_auth_handshakes_by_source_ip =
            (0..4096).map(|index| (source(index), Vec::new())).collect();
        store.save_pre_auth_hot(&current)?;
    }
    let store = GatewayRedbStore::open(&path)?;
    let mut restored = store.load_state()?.ok_or("rate-zero state")?;
    restored.set_fixture_pre_auth_cookie_key();
    assert!(restored.pre_auth_handshakes_by_source_ip.is_empty());
    assert!(restored.pre_auth_expiry_by_source.is_empty());
    assert!(matches!(restored.check_pre_auth(&source(4097), None, 100)?, Decision::Challenge(_)));
    drop(store);
    std::fs::remove_file(path)?;
    Ok(())
}

#[test]
fn stale_checkpoint_cannot_overwrite_newer_runtime_policy() -> Result {
    let fixture = Store::new()?;
    let mut current = state()?;
    let stale = current.admission_checkpoint(100);
    let mut replacement = current.pre_auth_policy.clone();
    replacement.per_source_ip_handshake_rate = 2;
    current.set_pre_auth_policy(replacement)?;
    fixture.store.save_state(&current)?;
    assert!(matches!(
        fixture.store.save_admission_checkpoint(&stale),
        Err(NodeCoreError::PreAuthCheckpointStale)
    ));
    assert_eq!(fixture.restored()?.pre_auth_policy.per_source_ip_handshake_rate, 2);
    Ok(())
}

#[test]
fn failed_checkpoint_commit_keeps_the_previous_reservation() -> Result {
    let fixture = Store::new()?;
    let mut current = state()?;
    let first = current.admission_checkpoint(100);
    fixture.store.save_admission_checkpoint(&first)?;
    current.install_admission_checkpoint(&first);
    let second = current.admission_checkpoint(110);
    fixture.store.fail_next_pre_auth_commit();
    assert!(fixture.store.save_admission_checkpoint(&second).is_err());
    assert_eq!(current.pre_auth_runtime_deadline, Some(130));
    assert_eq!(fixture.restored()?.pre_auth_time_floor, 130);
    fixture.store.save_admission_checkpoint(&second)?;
    current.install_admission_checkpoint(&second);
    assert_eq!(current.pre_auth_runtime_deadline, Some(140));
    assert_eq!(fixture.restored()?.pre_auth_time_floor, 140);
    Ok(())
}

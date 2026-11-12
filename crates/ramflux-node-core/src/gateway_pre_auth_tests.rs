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
    assert_eq!(state.pre_auth_handshakes_by_source_ip.len(), 2);
    Ok(())
}
fn restart_rollback_and_failed_commit() -> Result {
    let fixture = Store::new()?;
    let mut state = state()?;
    state.check_pre_auth(&source(1), None, 100)?;
    fixture.store.save_state(&state)?;
    let mut restored = fixture.restored()?;
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
    value["buckets"][source(1)] = serde_json::json!([99, 100]);
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
    let mut restored = fixture.restored()?;
    assert!(matches!(
        restored.validate_pre_auth_configuration(),
        Err(NodeCoreError::PreAuthMigrationRequired)
    ));
    restored.pre_auth_policy.enabled = false;
    fixture.store.save_state(&restored)?;
    let mut restored = fixture.restored()?;
    restored.pre_auth_policy.enabled = true;
    assert!(matches!(
        restored.validate_pre_auth_configuration(),
        Err(NodeCoreError::PreAuthMigrationRequired)
    ));
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

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Operator output interoperates with the receiving router and dedicated gateway signer.

#![cfg(unix)]

use ed25519_dalek::SigningKey;
use ramflux_crypto::custody::{
    branch_exporter_hash, sign_proxy_acceptance, verify_node_identity_record,
};
use ramflux_protocol::{
    custody::{
        BindingMode, BranchProofV3, DeviceRef, Envelope, MAX_BRANCH_LEASE_SECONDS,
        NodeIdentityRecord, ReceiptKeyStatus, decode, object_hash,
    },
    encode_base64url,
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::{Command, Output},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Process(std::process::Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Fixture {
    root: PathBuf,
    seed: PathBuf,
    output: PathBuf,
    public: String,
}

impl Fixture {
    fn new() -> Result<Self> {
        let root = std::env::temp_dir()
            .join(format!("rf-custody-{}", encode_base64url(ramflux_crypto::random_32()?)));
        fs::create_dir(&root)?;
        let seed = root.join("node-signing.key");
        fs::write(&seed, encode_base64url([7; 32]))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&seed, fs::Permissions::from_mode(0o640))?;
        }
        Ok(Self {
            output: root.join("custody output's"),
            root,
            seed,
            public: ramflux_crypto::public_key_base64url_from_seed([7; 32]),
        })
    }

    fn run(&self, action: &str, extra: &[&str]) -> Result<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_rf"))
            .args([
                "--socket",
                "/nonexistent/operator-no-daemon.sock",
                "node",
                action,
                "--node-id",
                "demo.example",
                "--node-signing-seed",
            ])
            .arg(&self.seed)
            .args(["--expected-public-key", &self.public, "--output-dir"])
            .arg(&self.output)
            .args(extra)
            .output()?)
    }

    fn values_at(path: &std::path::Path) -> Result<BTreeMap<String, String>> {
        let output = Command::new("sh").env_clear().args(["-c",
            ". \"$1\"; printf 'RAMFLUX_CUSTODY_NODE_PUBLIC_KEY=%s\\nRAMFLUX_CUSTODY_NODE_RECORD_FILE=%s\\nRAMFLUX_CUSTODY_PROXY_SIGNING_SEED=%s\\n' \"$RAMFLUX_CUSTODY_NODE_PUBLIC_KEY\" \"$RAMFLUX_CUSTODY_NODE_RECORD_FILE\" \"$RAMFLUX_CUSTODY_PROXY_SIGNING_SEED\"",
            "sh"]).arg(path).output()?;
        assert!(output.status.success());
        Ok(String::from_utf8(output.stdout)?
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect())
    }

    fn values(&self) -> Result<BTreeMap<String, String>> {
        Self::values_at(&self.output.join("custody.env"))
    }

    fn prepared(output: &Output) -> Result<PathBuf> {
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8(output.stdout.clone())?
            .lines()
            .find_map(|line| line.strip_prefix("custody env: "))
            .map(PathBuf::from)
            .ok_or_else(|| "missing prepared fragment path".into())
    }

    fn record(&self) -> Result<Envelope<NodeIdentityRecord>> {
        let values = self.values()?;
        Ok(decode(
            &fs::read(values.get("RAMFLUX_CUSTODY_NODE_RECORD_FILE").ok_or("missing record")?)?,
            512 * 1024,
        )?)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn verify(
    record: &Envelope<NodeIdentityRecord>,
    fixture: &Fixture,
) -> Result<ramflux_crypto::custody::VerifiedNodeRecord> {
    Ok(verify_node_identity_record(
        record,
        "demo.example",
        &fixture.public,
        ramflux_node_core::now_unix_seconds(),
    )?)
}

fn record_at(values: &BTreeMap<String, String>) -> Result<Envelope<NodeIdentityRecord>> {
    Ok(decode(&fs::read(&values["RAMFLUX_CUSTODY_NODE_RECORD_FILE"])?, 512 * 1024)?)
}

#[test]
fn init_uses_the_discovery_pin_and_authorizes_the_gateway_signer() -> Result {
    let fixture = Fixture::new()?;
    let output = fixture.run("custody-init", &[])?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let values = fixture.values()?;
    assert_eq!(values.len(), 3);
    assert_eq!(values["RAMFLUX_CUSTODY_NODE_PUBLIC_KEY"], fixture.public);
    let seed_file = ramflux_node_core::NodeSecret::from_file(&fixture.seed)?;
    assert_eq!(
        values["RAMFLUX_CUSTODY_NODE_PUBLIC_KEY"],
        seed_file.with_bytes(|seed| ramflux_crypto::public_key_base64url_from_seed(*seed))
    );
    let record = fixture.record()?;
    let now = ramflux_node_core::now_unix_seconds();
    let node = verify_node_identity_record(&record, "demo.example", &fixture.public, now)?;
    let store = ramflux_node_core::RouterRedbStore::open(fixture.root.join("router.redb"))?;
    ramflux_node_core::CustodyService::new(node.clone(), false, &store, now)
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(record.body.epoch, 1);
    assert_eq!(record.body.proxy_keys.len(), 1);
    assert_eq!(record.body.channel_binding_modes, [BindingMode::HomeRelayReceipt]);
    let proxy = &record.body.proxy_keys[0];
    assert_eq!(proxy.sign_until - proxy.not_before, MAX_BRANCH_LEASE_SECONDS);
    assert_eq!(proxy.proxy_id, "ramflux-gateway");
    assert_eq!(proxy.audiences, ["demo.example"]);
    let seed: [u8; 32] =
        ramflux_protocol::decode_base64url(&values["RAMFLUX_CUSTODY_PROXY_SIGNING_SEED"])?
            .try_into()
            .map_err(|_| "proxy seed length")?;
    let signer = SigningKey::from_bytes(&seed);
    assert_eq!(proxy.public_key, encode_base64url(signer.verifying_key().to_bytes()));
    let hash = encode_base64url([1; 32]);
    let observed = branch_exporter_hash(&[2; 32]);
    let proof = ramflux_crypto::custody::sign_branch_proof_v3(
        &ramflux_crypto::create_device_branch("alice", "primary", 1, [3; 32]),
        BranchProofV3 {
            schema: ramflux_protocol::domain::BRANCH_PROOF_V3.into(),
            version: 3,
            device_ref: DeviceRef {
                account_anchor: hash.clone(),
                device_id: "primary".into(),
                device_epoch: 1,
            },
            certificate_hash: hash.clone(),
            record_hash: hash.clone(),
            proof_id: hash.clone(),
            challenge_nonce: hash.clone(),
            action_hash: hash.clone(),
            audience: "demo.example".into(),
            binding_mode: BindingMode::HomeRelayReceipt,
            transport_binding: observed.clone(),
            issued_at: now,
            expires_at: now + 300,
        },
    )?;
    let receipt = sign_proxy_acceptance(&signer, &node, &proof, &observed, hash, now)?;
    assert_eq!(receipt.body.relay_key_id, proxy.key_id);
    assert_eq!(receipt.body.relay_id, "ramflux-gateway");
    assert_eq!(receipt.body.node_identity_record_hash, node.hash());
    assert!(
        !String::from_utf8(output.stdout)?.contains(&values["RAMFLUX_CUSTODY_PROXY_SIGNING_SEED"])
    );
    assert!(
        verify_node_identity_record(
            &record,
            "demo.example",
            &ramflux_crypto::public_key_base64url_from_seed([8; 32]),
            now
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn renewal_links_the_predecessor_without_extending_old_signing_intervals() -> Result {
    let fixture = Fixture::new()?;
    assert!(fixture.run("custody-init", &["--validity-days", "1"])?.status.success());
    let original_seed = fs::read(&fixture.seed)?;
    let old = fixture.record()?;
    let old_values = fixture.values()?;
    let deployed = old_values["RAMFLUX_CUSTODY_NODE_RECORD_FILE"].as_str();
    let prepared =
        Fixture::prepared(&fixture.run("custody-renew", &["--deployed-record", deployed])?)?;
    let new_values = Fixture::values_at(&prepared)?;
    let new: Envelope<NodeIdentityRecord> =
        decode(&fs::read(&new_values["RAMFLUX_CUSTODY_NODE_RECORD_FILE"])?, 512 * 1024)?;
    assert_eq!(fixture.values()?, old_values, "renewal must never rewrite custody.env");
    assert_eq!(new.body.epoch, old.body.epoch + 1);
    assert_eq!(new.body.previous_record_hash, Some(object_hash(&old)?));
    assert_eq!(new.body.node_signing_public_key, old.body.node_signing_public_key);
    assert_eq!(fs::read(&fixture.seed)?, original_seed);
    assert_ne!(
        new_values["RAMFLUX_CUSTODY_PROXY_SIGNING_SEED"],
        old_values["RAMFLUX_CUSTODY_PROXY_SIGNING_SEED"]
    );
    assert!(PathBuf::from(&old_values["RAMFLUX_CUSTODY_NODE_RECORD_FILE"]).is_file());
    let retained = new
        .body
        .proxy_keys
        .iter()
        .find(|key| key.key_id == old.body.proxy_keys[0].key_id)
        .ok_or("missing overlap key")?;
    assert_eq!(retained.status, ReceiptKeyStatus::Retiring);
    assert_eq!(retained.not_before, old.body.proxy_keys[0].not_before);
    assert_eq!(retained.sign_until, old.body.proxy_keys[0].sign_until);
    assert!(retained.overlap_until >= new.body.issued_at + 604_800 + 600);
    let now = ramflux_node_core::now_unix_seconds();
    let old = verify_node_identity_record(&old, "demo.example", &fixture.public, now)?;
    let new = verify_node_identity_record(&new, "demo.example", &fixture.public, now)?;
    let store = ramflux_node_core::RouterRedbStore::open(fixture.root.join("router.redb"))?;
    ramflux_node_core::CustodyService::new(old.clone(), false, &store, now)
        .map_err(|error| format!("{error:?}"))?;
    ramflux_node_core::CustodyService::new(new, false, &store, now)
        .map_err(|error| format!("{error:?}"))?;
    assert!(ramflux_node_core::CustodyService::new(old, false, &store, now).is_err());
    Ok(())
}

#[test]
fn existing_init_requires_explicit_deployed_record_and_preserves_initial_fragment() -> Result {
    let fixture = Fixture::new()?;
    assert!(fixture.run("custody-init", &[])?.status.success());
    let env = fs::read(fixture.output.join("custody.env"))?;
    for action in ["custody-init", "custody-renew"] {
        assert!(!fixture.run(action, &[])?.status.success());
        assert_eq!(fs::read(fixture.output.join("custody.env"))?, env);
    }
    assert!(!fixture.run("custody-init", &["--force-new-proxy"])?.status.success());
    let values = fixture.values()?;
    let prepared = Fixture::prepared(&fixture.run(
        "custody-init",
        &["--force-new-proxy", "--deployed-record", &values["RAMFLUX_CUSTODY_NODE_RECORD_FILE"]],
    )?)?;
    let prepared = Fixture::values_at(&prepared)?;
    let record: Envelope<NodeIdentityRecord> =
        decode(&fs::read(&prepared["RAMFLUX_CUSTODY_NODE_RECORD_FILE"])?, 512 * 1024)?;
    assert_eq!(record.body.epoch, 2);
    assert_eq!(fs::read(fixture.output.join("custody.env"))?, env);
    Ok(())
}

#[test]
fn renew_twice_uses_only_the_deployed_head_and_retains_both_epoch_two_seeds() -> Result {
    let fixture = Fixture::new()?;
    assert!(fixture.run("custody-init", &[])?.status.success());
    let first = fixture.values()?;
    let deployed_record = record_at(&first)?;
    let deployed = fixture.root.join("deployed-record.json");
    fs::copy(&first["RAMFLUX_CUSTODY_NODE_RECORD_FILE"], &deployed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&deployed, fs::Permissions::from_mode(0o644))?;
    }
    let path = deployed.to_str().ok_or("deployed path")?;
    assert!(
        !fixture.run("custody-renew", &[])?.status.success(),
        "deployed-record must be required"
    );
    let a = Fixture::prepared(&fixture.run("custody-renew", &["--deployed-record", path])?)?;
    assert_eq!(a.file_name().and_then(|name| name.to_str()), Some("custody-epoch-2.env"));
    let a_bytes = fs::read(&a)?;
    let a_values = Fixture::values_at(&a)?;
    let refused = fixture.run("custody-renew", &["--deployed-record", path])?;
    assert!(!refused.status.success());
    assert!(String::from_utf8(refused.stderr)?.contains("DEMO_CUSTODY_ALREADY_PREPARED"));
    let b = Fixture::prepared(
        &fixture.run("custody-renew", &["--deployed-record", path, "--force-new-proxy"])?,
    )?;
    assert_ne!(a, b);
    assert_eq!(fs::read(&a)?, a_bytes);
    assert_eq!(fixture.values()?, first, "custody.env must remain the initial fragment");
    let b_values = Fixture::values_at(&b)?;
    assert_ne!(
        a_values["RAMFLUX_CUSTODY_PROXY_SIGNING_SEED"],
        b_values["RAMFLUX_CUSTODY_PROXY_SIGNING_SEED"]
    );
    for (index, values) in [&a_values, &b_values].iter().enumerate() {
        let candidate = record_at(values)?;
        assert_eq!(candidate.body.epoch, 2);
        assert_eq!(candidate.body.previous_record_hash, Some(object_hash(&deployed_record)?));
        let decoded: [u8; 32] =
            ramflux_protocol::decode_base64url(&values["RAMFLUX_CUSTODY_PROXY_SIGNING_SEED"])?
                .try_into()
                .map_err(|_| "seed length")?;
        let public = encode_base64url(SigningKey::from_bytes(&decoded).verifying_key().to_bytes());
        assert!(
            candidate
                .body
                .proxy_keys
                .iter()
                .any(|key| key.public_key == public && key.status == ReceiptKeyStatus::Active)
        );
        let store = ramflux_node_core::RouterRedbStore::open(
            fixture.root.join(format!("router-{index}.redb")),
        )?;
        let now = ramflux_node_core::now_unix_seconds();
        ramflux_node_core::CustodyService::new(
            verify(&deployed_record, &fixture)?,
            false,
            &store,
            now,
        )
        .map_err(|error| format!("{error:?}"))?;
        ramflux_node_core::CustodyService::new(verify(&candidate, &fixture)?, false, &store, now)
            .map_err(|error| format!("{error:?}"))?;
    }
    // Only a deliberately updated deployed copy permits the next epoch.
    fs::copy(&b_values["RAMFLUX_CUSTODY_NODE_RECORD_FILE"], &deployed)?;
    let c = Fixture::prepared(&fixture.run("custody-renew", &["--deployed-record", path])?)?;
    let c = record_at(&Fixture::values_at(&c)?)?;
    assert_eq!(c.body.epoch, 3);
    assert_eq!(c.body.previous_record_hash, Some(object_hash(&record_at(&b_values)?)?));
    Ok(())
}

#[test]
fn deployed_record_requires_the_pinned_signature_before_any_preparation() -> Result {
    let mut donor = Fixture::new()?;
    fs::write(&donor.seed, encode_base64url([8; 32]))?;
    donor.public = ramflux_crypto::public_key_base64url_from_seed([8; 32]);
    assert!(donor.run("custody-init", &[])?.status.success());
    let path = donor.values()?["RAMFLUX_CUSTODY_NODE_RECORD_FILE"].clone();
    let fixture = Fixture::new()?;
    assert!(!fixture.run("custody-renew", &["--deployed-record", &path])?.status.success());
    assert!(!fixture.output.exists());
    assert!(fixture.run("custody-init", &[])?.status.success());
    let mut tampered = fixture.record()?;
    tampered.body.epoch += 1;
    let path = fixture.root.join("tampered.json");
    fs::write(&path, serde_json::to_vec(&tampered)?)?;
    let result =
        fixture.run("custody-renew", &["--deployed-record", path.to_str().ok_or("path")?])?;
    assert!(!result.status.success());
    assert!(!fixture.output.join("custody-epoch-2.env").exists());
    Ok(())
}

#[test]
fn legacy_r2_preparation_is_retained_and_never_treated_as_the_deployed_head() -> Result {
    let fixture = Fixture::new()?;
    assert!(fixture.run("custody-init", &[])?.status.success());
    let initial = fixture.values()?;
    let deployed = &initial["RAMFLUX_CUSTODY_NODE_RECORD_FILE"];
    let prepared =
        Fixture::prepared(&fixture.run("custody-renew", &["--deployed-record", deployed])?)?;
    let old_fragment = fs::read(&prepared)?;
    fs::write(fixture.output.join("custody.env"), &old_fragment)?;
    fs::remove_file(&prepared)?;
    let refused = fixture.run("custody-renew", &["--deployed-record", deployed])?;
    assert!(!refused.status.success());
    assert!(String::from_utf8(refused.stderr)?.contains("DEMO_CUSTODY_ALREADY_PREPARED"));
    let forced = Fixture::prepared(
        &fixture.run("custody-renew", &["--deployed-record", deployed, "--force-new-proxy"])?,
    )?;
    assert_eq!(fs::read(fixture.output.join("custody.env"))?, old_fragment);
    let next = record_at(&Fixture::values_at(&forced)?)?;
    assert_eq!(next.body.epoch, 2);
    assert_eq!(next.body.previous_record_hash, Some(object_hash(&record_at(&initial)?)?));
    Ok(())
}

#[cfg(unix)]
#[test]
fn live_process_lock_is_typed_and_killed_owner_is_reclaimed() -> Result {
    use std::io::Write;
    use std::time::{Duration, Instant};
    const HELPER: &str = "RAMFLUX_TEST_CUSTODY_LOCK_HELPER";
    if let Some(path) = std::env::var_os(HELPER) {
        let path = PathBuf::from(path);
        let mut file = fs::OpenOptions::new().read(true).write(true).open(path.join(".lock"))?;
        file.try_lock()?;
        file.set_len(0)?;
        file.write_all(&serde_json::to_vec(&serde_json::json!({"pid": std::process::id(), "started_at_unix_seconds": ramflux_node_core::now_unix_seconds()}))?)?;
        file.sync_all()?;
        let temporary = path.join(format!(".custody-pending-{}", encode_base64url([55; 32])));
        fs::write(&temporary, b"abandoned test preparation")?;
        fs::write(path.join("helper-ready"), b"ready")?;
        loop {
            std::thread::park();
        }
    }
    let fixture = Fixture::new()?;
    assert!(fixture.run("custody-init", &[])?.status.success());
    let values = fixture.values()?;
    let deployed = &values["RAMFLUX_CUSTODY_NODE_RECORD_FILE"];
    let mut process = Process(
        Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "live_process_lock_is_typed_and_killed_owner_is_reclaimed",
                "--nocapture",
            ])
            .env(HELPER, &fixture.output)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !fixture.output.join("helper-ready").exists() {
        if Instant::now() >= deadline {
            return Err("lock helper did not start".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.output.join(".lock"))?)?;
    assert_eq!(metadata["pid"], process.0.id());
    assert!(metadata["started_at_unix_seconds"].as_u64().is_some_and(|time| time > 0));
    let refused = fixture.run("custody-renew", &["--deployed-record", deployed])?;
    assert!(!refused.status.success());
    assert!(
        String::from_utf8(refused.stderr)?
            .contains("DEMO_CUSTODY_OPERATION_RUNNING: another custody operation is running")
    );
    process.0.kill()?;
    process.0.wait()?;
    let renewed = fixture.run("custody-renew", &["--deployed-record", deployed])?;
    assert!(renewed.status.success(), "{}", String::from_utf8_lossy(&renewed.stderr));
    assert!(String::from_utf8(renewed.stderr)?.contains("DEMO_CUSTODY_STALE_LOCK_RECLAIMED"));
    assert!(
        !fixture.output.join(format!(".custody-pending-{}", encode_base64url([55; 32]))).exists()
    );
    let idle: serde_json::Value = serde_json::from_slice(&fs::read(fixture.output.join(".lock"))?)?;
    assert!(idle["pid"].is_null());
    Ok(())
}

#[cfg(unix)]
#[test]
fn fifo_seed_refuses_without_waiting_for_a_writer() -> Result {
    use std::time::{Duration, Instant};
    let fixture = Fixture::new()?;
    fs::remove_file(&fixture.seed)?;
    assert!(Command::new("mkfifo").args(["-m", "600"]).arg(&fixture.seed).status()?.success());
    let mut process = Command::new(env!("CARGO_BIN_EXE_rf"))
        .args(["node", "custody-init", "--node-id", "demo.example", "--node-signing-seed"])
        .arg(&fixture.seed)
        .args(["--expected-public-key", &fixture.public, "--output-dir"])
        .arg(&fixture.output)
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = process.try_wait()? {
            assert!(!status.success());
            break;
        }
        if Instant::now() >= deadline {
            process.kill()?;
            process.wait()?;
            return Err("FIFO input blocked the operator tool".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!fixture.output.exists());
    Ok(())
}

#[test]
fn validity_wrong_pin_and_missing_seed_refuse_before_creating_output() -> Result {
    let fixture = Fixture::new()?;
    for days in ["0", "31", "18446744073709551615"] {
        assert!(!fixture.run("custody-init", &["--validity-days", days])?.status.success());
        assert!(!fixture.output.exists());
    }
    fs::write(&fixture.seed, encode_base64url([8; 32]))?;
    assert!(!fixture.run("custody-init", &[])?.status.success());
    assert!(!fixture.output.exists());
    fs::remove_file(&fixture.seed)?;
    assert!(!fixture.run("custody-init", &[])?.status.success());
    assert!(!fixture.output.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn output_permissions_are_private_and_symlinked_inputs_are_refused() -> Result {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = Fixture::new()?;
    let real_seed = fixture.root.join("real-seed");
    fs::rename(&fixture.seed, &real_seed)?;
    symlink(&real_seed, &fixture.seed)?;
    assert!(!fixture.run("custody-init", &[])?.status.success());
    fs::remove_file(&fixture.seed)?;
    fs::rename(real_seed, &fixture.seed)?;
    assert!(fixture.run("custody-init", &[])?.status.success());
    assert_eq!(fs::metadata(&fixture.output)?.permissions().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(fixture.output.join("custody.env"))?.permissions().mode() & 0o777,
        0o600
    );
    let record = &fixture.values()?["RAMFLUX_CUSTODY_NODE_RECORD_FILE"];
    assert_eq!(fs::metadata(record)?.permissions().mode() & 0o777, 0o600);
    let env = fixture.output.join("custody.env");
    let saved = fixture.output.join("saved.env");
    fs::rename(&env, &saved)?;
    symlink(fixture.output.join("missing.env"), &env)?;
    assert!(!fixture.run("custody-init", &[])?.status.success());
    assert!(fs::symlink_metadata(&env)?.file_type().is_symlink());
    fs::remove_file(&env)?;
    fs::rename(saved, env)?;
    let idle: serde_json::Value = serde_json::from_slice(&fs::read(fixture.output.join(".lock"))?)?;
    assert!(idle["pid"].is_null());
    Ok(())
}

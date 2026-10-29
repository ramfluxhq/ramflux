// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Operator output interoperates with the receiving router and dedicated gateway signer.

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

    fn values(&self) -> Result<BTreeMap<String, String>> {
        let output = Command::new("sh").env_clear().args(["-c",
            ". \"$1\"; printf 'RAMFLUX_CUSTODY_NODE_PUBLIC_KEY=%s\\nRAMFLUX_CUSTODY_NODE_RECORD_FILE=%s\\nRAMFLUX_CUSTODY_PROXY_SIGNING_SEED=%s\\n' \"$RAMFLUX_CUSTODY_NODE_PUBLIC_KEY\" \"$RAMFLUX_CUSTODY_NODE_RECORD_FILE\" \"$RAMFLUX_CUSTODY_PROXY_SIGNING_SEED\"",
            "sh"]).arg(self.output.join("custody.env")).output()?;
        assert!(output.status.success());
        Ok(String::from_utf8(output.stdout)?
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect())
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
    assert!(fixture.run("custody-renew", &["--force-new-proxy"])?.status.success());
    let new = fixture.record()?;
    assert_eq!(new.body.epoch, old.body.epoch + 1);
    assert_eq!(new.body.previous_record_hash, Some(object_hash(&old)?));
    assert_eq!(new.body.node_signing_public_key, old.body.node_signing_public_key);
    assert_eq!(fs::read(&fixture.seed)?, original_seed);
    assert_ne!(
        fixture.values()?["RAMFLUX_CUSTODY_PROXY_SIGNING_SEED"],
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
fn existing_output_requires_explicit_rotation_and_init_force_is_a_successor() -> Result {
    let fixture = Fixture::new()?;
    assert!(fixture.run("custody-init", &[])?.status.success());
    let env = fs::read(fixture.output.join("custody.env"))?;
    for action in ["custody-init", "custody-renew"] {
        assert!(!fixture.run(action, &[])?.status.success());
        assert_eq!(fs::read(fixture.output.join("custody.env"))?, env);
    }
    assert!(fixture.run("custody-init", &["--force-new-proxy"])?.status.success());
    assert_eq!(fixture.record()?.body.epoch, 2);
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
    assert!(!fixture.output.join(".lock").exists());
    Ok(())
}

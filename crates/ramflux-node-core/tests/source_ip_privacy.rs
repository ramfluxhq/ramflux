// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exercise configured process startup, rather than an injected in-memory hash key.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const HASH_PREFIX: &str = "SOURCE_PRIVACY_HASH=";
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(ramflux_test_support::TestPath);
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        loop {
            let nonce = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = ramflux_test_support::TestPath::new()?
                .child(format!("rf-source-privacy-{}-{nonce}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    fn config(&self, file: &str, node: &str, service: &str) -> Result<PathBuf, std::io::Error> {
        let path = self.0.join(file);
        std::fs::write(
            &path,
            format!(
                "node_id='{node}'\nservice_id='{service}'\nredb_path='unused.redb'\n\
            [mesh]\nlisten_addr='127.0.0.1:0'\nca_cert='unused'\nservice_cert='unused'\n\
            service_key='unused'\nallowed_service_ids=['{service}']\n\
            [mesh.endpoints]\nrouter='127.0.0.1:0'\n"
            ),
        )?;
        Ok(path)
    }
    fn keys(&self) -> Result<Vec<PathBuf>, std::io::Error> {
        std::fs::read_dir(self.0.join("node-identity"))?
            .map(|entry| entry.map(|e| e.path()))
            .collect()
    }
}
fn probe(config: &Path, service: &str, mounted: Option<&Path>) -> Result<Output, std::io::Error> {
    probe_command(config, service, mounted)?.output()
}

fn probe_command(
    config: &Path,
    service: &str,
    mounted: Option<&Path>,
) -> Result<Command, std::io::Error> {
    let mut command = Command::new(std::env::current_exe()?);
    command.args(["--exact", "configured_source_privacy_probe", "--nocapture"]);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("RAMFLUX_") {
            command.env_remove(name);
        }
    }
    command.env("RF_SOURCE_PRIVACY_PROBE_CONFIG", config);
    command.env("RF_SOURCE_PRIVACY_PROBE_SERVICE", service);
    if let Some(path) = mounted {
        command.env("RAMFLUX_NODE_PRIVACY_KEY_FILE", path);
    }
    Ok(command)
}

fn hash(output: &Output) -> Result<String, Box<dyn std::error::Error>> {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix(HASH_PREFIX))
        .ok_or("missing hash probe")?
        .to_owned())
}

#[test]
fn configured_source_privacy_probe() -> TestResult {
    let Some(path) = std::env::var_os("RF_SOURCE_PRIVACY_PROBE_CONFIG") else { return Ok(()) };
    let service = std::env::var("RF_SOURCE_PRIVACY_PROBE_SERVICE")?;
    let args = ["--config".into(), PathBuf::from(path).to_string_lossy().into_owned()];
    let config = if std::env::var_os("RF_SOURCE_PRIVACY_PROBE_READ_ONLY").is_some() {
        ramflux_node_core::read_config_from_args(args, &service)?
    } else {
        ramflux_node_core::load_config_from_args(args, &service)?
    };
    config.ok_or("missing config")?;
    println!("{HASH_PREFIX}{}", ramflux_node_core::source_ip_hash("192.0.2.1"));
    Ok(())
}

#[test]
fn read_only_config_loading_does_not_create_identity_files() -> TestResult {
    let fixture = Fixture::new()?;
    let config = fixture.config("router.toml", "node_a", "ramflux-router")?;
    let output = probe_command(&config, "ramflux-router", None)?
        .env("RF_SOURCE_PRIVACY_PROBE_READ_ONLY", "1")
        .output()?;
    assert!(output.status.success());
    assert!(!fixture.0.join("node-identity").exists());
    Ok(())
}

#[test]
fn configured_nodes_separate_sources_and_restart_with_the_same_private_key() -> TestResult {
    let fixture = Fixture::new()?;
    let gateway = fixture.config("gateway.toml", "node_a", "ramflux-gateway")?;
    let router = fixture.config("router.toml", "node_a", "ramflux-router")?;
    let other = fixture.config("other.toml", "node_b", "ramflux-gateway")?;
    let initial = hash(&probe(&gateway, "ramflux-gateway", None)?)?;
    assert_eq!(initial, hash(&probe(&gateway, "ramflux-gateway", None)?)?);
    assert_eq!(initial, hash(&probe(&router, "ramflux-router", None)?)?);
    assert_ne!(initial, hash(&probe(&other, "ramflux-gateway", None)?)?);
    let keys = fixture.keys()?;
    assert_eq!(keys.len(), 2, "only complete identity keys remain");
    #[cfg(unix)]
    for key in keys {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(key)?.permissions().mode() & 0o777, 0o600);
    }
    Ok(())
}

#[test]
fn concurrent_first_start_publishes_one_complete_key_without_replacement() -> TestResult {
    let fixture = Fixture::new()?;
    let config = fixture.config("gateway.toml", "node_a", "ramflux-gateway")?;
    let results = std::thread::scope(|scope| {
        let jobs = (0..4)
            .map(|_| scope.spawn(|| probe(&config, "ramflux-gateway", None)))
            .collect::<Vec<_>>();
        jobs.into_iter()
            .map(|job| match job.join() {
                Ok(result) => result,
                Err(_) => Err(std::io::Error::other("privacy probe thread panicked")),
            })
            .collect::<Vec<_>>()
    });
    let hashes = results.into_iter().map(|output| hash(&output?)).collect::<Result<Vec<_>, _>>()?;
    assert!(hashes.iter().all(|value| value == &hashes[0]));
    assert_eq!(fixture.keys()?.len(), 1);
    assert_eq!(hashes[0], hash(&probe(&config, "ramflux-gateway", None)?)?);
    Ok(())
}

#[test]
fn invalid_default_key_refuses_startup_without_replacing_the_file() -> TestResult {
    let fixture = Fixture::new()?;
    let config = fixture.config("gateway.toml", "node_a", "ramflux-gateway")?;
    hash(&probe(&config, "ramflux-gateway", None)?)?;
    let key = fixture.keys()?.pop().ok_or("missing key")?;
    std::fs::write(&key, b"invalid-private-key")?;
    let output = probe(&config, "ramflux-gateway", None)?;
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(HASH_PREFIX));
    assert_eq!(std::fs::read(&key)?, b"invalid-private-key");
    Ok(())
}

#[cfg(unix)]
#[test]
fn default_key_refuses_group_access_and_symlink_substitution() -> TestResult {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = Fixture::new()?;
    let config = fixture.config("gateway.toml", "node_a", "ramflux-gateway")?;
    hash(&probe(&config, "ramflux-gateway", None)?)?;
    let key = fixture.keys()?.pop().ok_or("missing key")?;
    let original = std::fs::read(&key)?;
    for mode in [0o640, 0o644] {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode))?;
        assert!(!probe(&config, "ramflux-gateway", None)?.status.success());
        assert_eq!(std::fs::read(&key)?, original);
    }
    let outside = fixture.0.join("other.key");
    std::fs::write(&outside, &original)?;
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600))?;
    std::fs::remove_file(&key)?;
    symlink(&outside, &key)?;
    assert!(!probe(&config, "ramflux-gateway", None)?.status.success());
    assert_eq!(std::fs::read(&outside)?, original);
    Ok(())
}

#[cfg(unix)]
#[test]
fn identity_directory_is_private_and_group_writable_replacements_are_refused() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new()?;
    let config = fixture.config("gateway.toml", "node_a", "ramflux-gateway")?;
    hash(&probe(&config, "ramflux-gateway", None)?)?;
    let directory = fixture.0.join("node-identity");
    assert_eq!(std::fs::metadata(&directory)?.permissions().mode() & 0o777, 0o700);
    let key = fixture.keys()?.pop().ok_or("missing key")?;
    let original = std::fs::read(&key)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o770))?;
    assert!(!probe(&config, "ramflux-gateway", None)?.status.success());
    assert_eq!(std::fs::read(key)?, original);
    Ok(())
}

#[test]
fn explicit_mounted_key_is_preserved_and_missing_mounts_are_refused() -> TestResult {
    let fixture = Fixture::new()?;
    let config = fixture.config("gateway.toml", "node_a", "ramflux-gateway")?;
    let key = fixture.0.join("mounted.key");
    std::fs::write(&key, ramflux_protocol::encode_base64url([7_u8; 32]))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    }
    let first = hash(&probe(&config, "ramflux-gateway", Some(&key))?)?;
    assert_eq!(first, hash(&probe(&config, "ramflux-gateway", Some(&key))?)?);
    assert!(!fixture.0.join("node-identity").exists());
    std::fs::remove_file(&key)?;
    let output = probe(&config, "ramflux-gateway", Some(&key))?;
    assert!(!output.status.success());
    assert!(!key.exists());
    Ok(())
}

#[test]
fn startup_error_names_the_identity_directory_and_recovery_options() -> TestResult {
    let fixture = Fixture::new()?;
    let config = fixture.config("gateway.toml", "node_a", "ramflux-gateway")?;
    let directory = fixture.0.join("node-identity");
    // A file at the directory path fails deterministically, even for privileged test users.
    std::fs::write(&directory, b"not a directory")?;
    let output = probe(&config, "ramflux-gateway", None)?;
    assert!(!output.status.success());
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(diagnostic.contains(&directory.display().to_string()), "{diagnostic}");
    assert!(diagnostic.contains("mount a writable volume"), "{diagnostic}");
    assert!(diagnostic.contains("RAMFLUX_NODE_PRIVACY_KEY_FILE"), "{diagnostic}");
    assert_eq!(std::fs::read(&directory)?, b"not a directory");
    Ok(())
}

#[test]
fn startup_removes_only_old_staged_keys_without_changing_the_published_key() -> TestResult {
    let fixture = Fixture::new()?;
    let config = fixture.config("gateway.toml", "node_a", "ramflux-gateway")?;
    let initial = hash(&probe(&config, "ramflux-gateway", None)?)?;
    let key = fixture.keys()?.pop().ok_or("missing key")?;
    let original = std::fs::read(&key)?;
    let old = key.with_extension(format!("{}.tmp", ramflux_protocol::encode_base64url([1_u8; 32])));
    let recent =
        key.with_extension(format!("{}.tmp", ramflux_protocol::encode_base64url([2_u8; 32])));
    let unrelated = key.parent().ok_or("missing directory")?.join("unrelated.tmp");
    let other_node = fixture.config("other.toml", "node_b", "ramflux-gateway")?;
    hash(&probe(&other_node, "ramflux-gateway", None)?)?;
    let other_key = fixture.keys()?.into_iter().find(|path| path != &key).ok_or("other key")?;
    let other_stage =
        other_key.with_extension(format!("{}.tmp", ramflux_protocol::encode_base64url([3_u8; 32])));
    let old_time = std::time::SystemTime::now() - std::time::Duration::from_hours(2);
    for path in [&old, &unrelated, &other_stage] {
        let file = std::fs::File::create(path)?;
        file.set_times(std::fs::FileTimes::new().set_modified(old_time))?;
    }
    std::fs::write(&recent, b"active staging file")?;
    #[cfg(unix)]
    let link = {
        let link =
            key.with_extension(format!("{}.tmp", ramflux_protocol::encode_base64url([4_u8; 32])));
        std::os::unix::fs::symlink(&unrelated, &link)?;
        link
    };
    assert_eq!(initial, hash(&probe(&config, "ramflux-gateway", None)?)?);
    assert!(!old.exists());
    assert_eq!(std::fs::read(&recent)?, b"active staging file");
    assert!(unrelated.exists());
    assert!(other_stage.exists());
    #[cfg(unix)]
    assert!(std::fs::symlink_metadata(link)?.file_type().is_symlink());
    assert_eq!(std::fs::read(&key)?, original);
    Ok(())
}

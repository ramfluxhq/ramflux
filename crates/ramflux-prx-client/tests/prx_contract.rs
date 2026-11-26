// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contract tests against a real `prx daemon` built at the pinned commit.
//!
//! Ignored by default. Run with `RAMFLUX_PRX_BIN=<path to prx built at 46e829e5245238150a96802a7cea2b0f1babe778>` and
//! `cargo test -p ramflux-prx-client --test prx_contract -- --ignored --test-threads=1`.
//! Every daemon gets a fresh config dir on a free loopback port and is stopped and removed
//! at the end. The bearer token and the pairing code are never printed.

// Test code may panic on a failed assertion (RUST-CODE-RULES, test section); the crate's
// clippy settings only cover #[test] bodies, not the helpers of this integration-test crate.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stderr
)]

use ramflux_prx_client::{
    AGENT_CATALOG_V1, AGENT_CRUD_V1, AGENT_LIMITS_V1, AGENT_MAIN_READBACK_V1,
    AGENT_MEMORY_PURGE_V1, AgentConfig, AgentName, AgentRuns, AgentStatus, ApiCode, ApplyOutcome,
    Autonomy, BatchItem, BuildCommit, CAPABILITIES_V1, Capabilities, Chat, ChatKind, ClientConfig,
    ConfigRevision, EraseNotice, ForgetCounts, ForgetReport, ForgetWrites, HISTORY_ERASE_V1,
    HOST_BOOTSTRAP_V1, HistoryRow, JobState, JobStatus, LimitsFacts, MESSAGE_CONTEXT_DELIVERY_V1,
    MESSAGE_DELETE_V1, MESSAGE_FORGET_WRITES_V1, MESSAGE_IDEMPOTENCY_V1, MESSAGE_TARGET_V1,
    NotReadyReason, OWNER_ID_STABLE_V1, PROMPT_MAX_BYTES, PrxClient, PrxError, PutKind,
    RUN_APPROVALS_V1, ReloadStatus, RfMessage, RowBody, RunCode, RunState, SESSION_KEY_V1,
    STREAM_FRAMES_V1, SYNC_SNAPSHOT_V1, SYNC_WS_V1, Sender, TARGETED_AGENTS_V1, Target, Tools,
    TurnDisposition,
};
use serde_json::Value;
use std::fs::File;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// The commit the binary must report (`GET /api/capabilities` `commit`).
const PIN: &str = "6e39b39670548ddf123fac98f169fb17b599ea59";
/// Overall deadline of one contract test.
const TEST_DEADLINE: Duration = Duration::from_secs(600);
/// Deadline of one wait (readiness, pairing code, hot reload).
const WAIT_DEADLINE: Duration = Duration::from_secs(40);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Spacing for catalog polls, which count against the API's shared rate limit.
const SLOW_POLL_INTERVAL: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const SENTINEL: &str = "sk-rf-contract-sentinel-0001";
/// Upper bound of requests in K-AC2-12 (the API limit is 60 a minute by default).
const PROBE_LIMIT: usize = 120;
/// A dummy key for the default provider; it is never a real credential.
const DEFAULT_PROVIDER_KEY: &str = "test-key-not-real";
const GROQ_ROUTE: &str = "\n[[model_routes]]\nhint = \"fast\"\nprovider = \"groq\"\nmodel = \"llama-3.3-70b-versatile\"\ncredential_ref = \"cred-groq\"\n";
const HAND_WRITTEN_AGENT: &str =
    "\n[agents.worker1]\nprovider = \"openrouter\"\nmodel = \"openai/gpt-4o-mini\"\n";
const MODEL_ROW: &str = "\n[[providers.models]]\nprovider = \"ollama\"\nmodel = \"qwen3:8b\"\noperations = [\"chat\"]\n";
const GROQ_MODEL_ROW: &str = "\n[[providers.models]]\nprovider = \"groq\"\nmodel = \"llama-3.3-70b-versatile\"\noperations = [\"chat\"]\n";

fn prx_binary() -> PathBuf {
    let raw = std::env::var_os("RAMFLUX_PRX_BIN")
        .expect("test: RAMFLUX_PRX_BIN must name a prx binary built at the pinned commit");
    PathBuf::from(raw)
}

fn report(row: &str) {
    eprintln!("ROW {row} PASS");
}

/// One `prx daemon` with its own config dir, workspace and token file.
struct Daemon {
    bin: PathBuf,
    dir: TempDir,
    port: u16,
    child: Option<Child>,
    http: reqwest::Client,
    /// False only for the row that documents what a group-writable state directory does.
    check_ancestors: bool,
}

/// The base directory of every daemon state dir: `RAMFLUX_PRX_STATE_ROOT`, else `$HOME/prx-live`.
/// Never `/tmp` or `/opt/ops`: PRX refuses its recovery key under a group- or other-writable
/// ancestor, and then every turn's terminal write fails (PRX, 2026-11-22).
fn state_base() -> PathBuf {
    match std::env::var_os("RAMFLUX_PRX_STATE_ROOT") {
        Some(root) => PathBuf::from(root),
        None => PathBuf::from(
            std::env::var_os("HOME").expect("test: HOME or RAMFLUX_PRX_STATE_ROOT must be set"),
        )
        .join("prx-live"),
    }
}

/// G6 budget admission refuses an unpriced model, so the stub's model gets a price row; the
/// prices are dummies and the stub charges nothing. The operator also declares its chat facts.
fn priced(provider: &str, extra: &str) -> String {
    format!(
        "{extra}\n[[providers.models]]\nprovider = \"{provider}\"\nmodel = \"stub-model\"\noperations = [\"chat\"]\n\n[cost.prices.\"{provider}/stub-model\"]\ninput = 1.0\noutput = 1.0\ncache_read = 0.0\ncache_write = 0.0\n"
    )
}

/// Local catalog-only models exercised by the agent CRUD and concurrent-edit rows.
fn local_agent_models(extra: &str) -> String {
    use std::fmt::Write as _;
    let mut config = extra.to_owned();
    for model in ["codellama", "llama3", "m", "mistral", "llama3-8b", "gemma", "phi"] {
        writeln!(
            config,
            "\n[[providers.models]]\nprovider = \"ollama\"\nmodel = \"{model}\"\noperations = [\"chat\"]"
        )
        .expect("test: append local model declaration");
    }
    config
}

/// The temporary directory for the daemon and the harness: `RAMFLUX_PRX_TMPDIR`, else
/// `<state base>/tmp`. Created 0700; the daemon gets it as `TMPDIR`, so nothing it creates with
/// mktemp lands under `/tmp` or `/opt/ops`.
fn tmp_base() -> PathBuf {
    match std::env::var_os("RAMFLUX_PRX_TMPDIR") {
        Some(dir) => PathBuf::from(dir),
        None => state_base().join("tmp"),
    }
}

/// Creates `dir` (and parents) as 0700 whatever the umask.
fn ensure_private_dir(dir: &Path) {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .unwrap_or_else(|error| panic!("test: create {}: {error}", dir.display()));
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

/// Fails fast, naming the directory, when `dir` or any ancestor is group- or other-writable.
fn check_private_ancestors(dir: &Path) {
    check_one_chain(dir);
    check_one_chain(&tmp_base());
}

fn check_one_chain(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut current = Some(dir);
    while let Some(path) = current {
        let mode = std::fs::metadata(path)
            .unwrap_or_else(|error| panic!("test: stat {}: {error}", path.display()))
            .permissions()
            .mode()
            & 0o777;
        assert!(
            mode & 0o022 == 0,
            "test: state directory ancestor {} has mode {:o} (group- or other-writable). PRX refuses \
             its recovery key under such an ancestor, and every turn's terminal write then fails. \
             Set RAMFLUX_PRX_STATE_ROOT to a private path (for example $HOME/prx-live).",
            path.display(),
            mode
        );
        current = path.parent();
    }
}

impl Daemon {
    /// A fresh state: `config.toml` with the gateway on a free loopback port, plus `extra`.
    fn prepare(extra: &str) -> Self {
        Self::prepare_state(extra, true)
    }

    /// Like `prepare`, but the default provider has no stored credential: the daemon starts
    /// with its turn runtime not ready (the state a fresh install is in).
    fn prepare_without_credential(extra: &str) -> Self {
        Self::prepare_state(extra, false)
    }

    /// Like `prepare`, but the default provider is `provider` (no credential is stored for it).
    /// Used with a `ModelStub`, so that no request leaves the host.
    fn prepare_with_provider(provider: &str, extra: &str) -> Self {
        Self::prepare_config(provider, "stub-model", &priced(provider, extra), false)
    }

    fn prepare_state(extra: &str, default_credential: bool) -> Self {
        Self::prepare_config("openrouter", "openai/gpt-4o-mini", extra, default_credential)
    }

    fn prepare_config(provider: &str, model: &str, extra: &str, default_credential: bool) -> Self {
        Self::prepare_in(&state_base(), provider, model, extra, default_credential, true)
    }

    /// A daemon whose state dir is under `base`, with the ancestor check off. Used only by the row
    /// that documents the group-writable case.
    fn prepare_unchecked_in(base: &Path, provider: &str, extra: &str) -> Self {
        Self::prepare_in(base, provider, "stub-model", &priced(provider, extra), false, false)
    }

    fn prepare_in(
        base: &Path,
        provider: &str,
        model: &str,
        extra: &str,
        default_credential: bool,
        check_ancestors: bool,
    ) -> Self {
        let bin = prx_binary();
        ensure_private_dir(&tmp_base());
        // Private by construction: the base and the state dir are 0700 whatever the umask.
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(base)
                .expect("test: state base dir");
            let _ = std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o700));
        }
        let dir = TempDir::new_in(base).expect("test: temp dir under the state base");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("test: chmod state dir");
        }
        // cfg and workspace are 0700 too: PRX checks every ancestor of its recovery path.
        ensure_private_dir(&dir.path().join("cfg"));
        ensure_private_dir(&dir.path().join("workspace"));
        let port = {
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("test: free loopback port");
            listener.local_addr().expect("test: local addr").port()
        };
        let config = format!(
            "default_provider = \"{provider}\"\ndefault_model = \"{model}\"\n\n[gateway]\nhost = \"127.0.0.1\"\nport = {port}\nrequire_pairing = true\n{extra}"
        );
        std::fs::write(dir.path().join("cfg/config.toml"), config).expect("test: write config");
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .expect("test: http client");
        let daemon = Self { bin, dir, port, child: None, http, check_ancestors };
        if check_ancestors {
            check_private_ancestors(daemon.dir.path());
        }
        if default_credential {
            daemon.credential_set("openrouter", DEFAULT_PROVIDER_KEY);
        }
        daemon
    }

    fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn token_path(&self) -> PathBuf {
        self.dir.path().join("token")
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.bin);
        command
            .env("OPENPRX_CONFIG_DIR", self.dir.path().join("cfg"))
            .env("OPENPRX_WORKSPACE", self.dir.path().join("workspace"))
            .env("TMPDIR", tmp_base())
            .env("RUST_LOG", "warn");
        command
    }

    /// Stores a provider credential through the CLI, from stdin (never on a command line).
    fn credential_set(&self, provider: &str, value: &str) {
        use std::io::Write;
        let mut child = self
            .command()
            .args(["providers", "credential", "set", provider, "--name", provider, "--from-stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("test: prx providers credential set starts");
        {
            let mut stdin = child.stdin.take().expect("test: stdin piped");
            stdin.write_all(value.as_bytes()).expect("test: write credential to stdin");
        }
        let status = child.wait().expect("test: credential set finishes");
        assert!(status.success(), "credential set for {provider} must exit 0");
    }

    fn start(&mut self) {
        if self.check_ancestors {
            check_private_ancestors(self.dir.path());
        }
        let out =
            File::create(self.dir.path().join("daemon.out")).expect("test: daemon stdout file");
        let err =
            File::create(self.dir.path().join("daemon.err")).expect("test: daemon stderr file");
        let port = self.port.to_string();
        // Its own process group, so a crash can take the daemon and the turn workers it spawned.
        let child = self
            .command()
            .process_group(0)
            .args(["daemon", "--host", "127.0.0.1", "-p", port.as_str()])
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("test: prx daemon starts");
        self.child = Some(child);
    }

    /// SIGKILL to the daemon's whole process group: the crash of the host and its workers.
    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let group = format!("-{}", child.id());
            let _ = Command::new("kill").args(["-KILL", "--", group.as_str()]).status();
            let _ = child.kill();
            let _ = child.wait();
            // Wait (bounded) until no member of the group is left, so the ingress lock is free.
            let started = Instant::now();
            while started.elapsed() < WAIT_DEADLINE {
                let alive = Command::new("kill")
                    .args(["-0", "--", group.as_str()])
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|status| status.success());
                if !alive {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    /// The error lines of the daemon's log (for a failure message only).
    fn error_lines(&self) -> Vec<String> {
        let log = std::fs::read_to_string(self.dir.path().join("daemon.out")).unwrap_or_default();
        log.lines()
            .filter(|line| line.contains("ERROR") || line.contains("recovery"))
            .rev()
            .take(12)
            .map(|line| line.chars().take(400).collect())
            .collect()
    }

    async fn wait_ready(&self) {
        let started = Instant::now();
        loop {
            if let Ok(resp) = self.http.get(format!("{}/health", self.base())).send().await
                && resp.status().is_success()
            {
                return;
            }
            assert!(
                started.elapsed() < WAIT_DEADLINE,
                "test: daemon did not answer /health in time"
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    fn pairing_code(&self) -> Option<String> {
        let mut text =
            std::fs::read_to_string(self.dir.path().join("daemon.out")).unwrap_or_default();
        text.push_str(
            &std::fs::read_to_string(self.dir.path().join("daemon.err")).unwrap_or_default(),
        );
        text.lines().find_map(|line| {
            let code = line.split("X-Pairing-Code: ").nth(1)?.trim().to_owned();
            (code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit())).then_some(code)
        })
    }

    /// Pairs once (fresh state only) and writes the token to a 0600 file. Returns nothing:
    /// the token never leaves the file.
    async fn pair(&self) {
        let started = Instant::now();
        let code = loop {
            if let Some(code) = self.pairing_code() {
                break code;
            }
            assert!(started.elapsed() < WAIT_DEADLINE, "test: no pairing code in the daemon log");
            tokio::time::sleep(POLL_INTERVAL).await;
        };
        let resp = self
            .http
            .post(format!("{}/pair", self.base()))
            .header("X-Pairing-Code", code)
            .send()
            .await
            .expect("test: POST /pair answers");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "test: POST /pair with the printed code must be 200"
        );
        let body: Value = resp.json().await.expect("test: pair body is JSON");
        let token = body
            .get("token")
            .and_then(Value::as_str)
            .expect("test: pair body carries a token")
            .to_owned();
        std::fs::write(self.token_path(), &token).expect("test: write token file");
        set_owner_only(&self.token_path());
    }

    fn client(&self) -> PrxClient {
        PrxClient::new(&ClientConfig::new(self.base(), self.token_path()))
            .expect("test: client builds")
    }

    /// The bearer token, for raw requests only (the client reads it from the file itself).
    fn token(&self) -> String {
        std::fs::read_to_string(self.token_path()).expect("test: token file").trim().to_owned()
    }

    async fn raw(
        &self,
        method: reqwest::Method,
        path: &str,
        headers: &[(&str, String)],
        body: Option<Value>,
    ) -> (u16, String) {
        let mut request = self.http.request(method, format!("{}{}", self.base(), path));
        for (name, value) in headers {
            request = request.header(*name, value.as_str());
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let resp = request.send().await.expect("test: raw request answers");
        let status = resp.status().as_u16();
        (status, resp.text().await.expect("test: raw body is text"))
    }

    async fn raw_authorized(
        &self,
        method: reqwest::Method,
        path: &str,
        if_match: Option<&str>,
        body: Option<Value>,
    ) -> (u16, String) {
        let mut headers = vec![("Authorization", format!("Bearer {}", self.token()))];
        if let Some(revision) = if_match {
            headers.push(("If-Match", revision.to_owned()));
        }
        self.raw(method, path, &headers, body).await
    }

    /// One turn request (`POST /api/sessions/{id}/message`). The turn readiness check runs
    /// before the body is read, so any session id probes it. A request still running when the
    /// client deadline passes returns status 0: a running turn is not a refusal.
    async fn send_turn(&self) -> (u16, String) {
        let request = self
            .http
            .post(format!("{}/api/sessions/contract-probe/message", self.base()))
            .header("Authorization", format!("Bearer {}", self.token()))
            .json(&serde_json::json!({ "message": "contract probe" }));
        match request.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                (status, resp.text().await.unwrap_or_default())
            }
            Err(error) if error.is_timeout() => (0, String::new()),
            Err(error) => panic!("test: turn request must answer or time out: {error}"),
        }
    }

    async fn catalog_revision(&self) -> String {
        self.client().catalog().await.expect("test: catalog reads").revision.as_str().to_owned()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
    }
}

fn set_owner_only(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("test: chmod token file");
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Sets `[autonomy] level` in the config file. PRX rewrites the file when a client pairs, so
/// the table may already exist: edit its `level` line in place; append the table only if absent.
fn set_main_level(path: &Path, level: &str) {
    let text = std::fs::read_to_string(path).expect("test: read config");
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let header = lines.iter().position(|line| line.trim() == "[autonomy]");
    if let Some(start) = header {
        let mut edited = false;
        for line in lines.iter_mut().skip(start + 1) {
            if line.trim_start().starts_with('[') {
                break;
            }
            if line.trim_start().starts_with("level") {
                *line = format!("level = \"{level}\"");
                edited = true;
                break;
            }
        }
        if !edited {
            lines.insert(start + 1, format!("level = \"{level}\""));
        }
    } else {
        lines.push("[autonomy]".to_owned());
        lines.push(format!("level = \"{level}\""));
    }
    std::fs::write(path, lines.join("\n") + "\n").expect("test: write config");
}

fn error_code(text: &str) -> Option<String> {
    let value: Value = serde_json::from_str(text).ok()?;
    value.pointer("/error/code")?.as_str().map(str::to_owned)
}

fn error_reason(text: &str) -> Option<String> {
    let value: Value = serde_json::from_str(text).ok()?;
    value.pointer("/error/reason")?.as_str().map(str::to_owned)
}

fn config(
    provider: &str,
    model: &str,
    prompt: Option<&str>,
    tools: Tools,
    enabled: bool,
) -> AgentConfig {
    AgentConfig {
        provider: provider.to_owned(),
        model: model.to_owned(),
        prompt: prompt.map(str::to_owned),
        autonomy: Autonomy::Full,
        tools,
        enabled,
        limits: None,
        approval_wait_secs: ramflux_prx_client::DEFAULT_APPROVAL_WAIT_SECS,
    }
}

async fn capabilities(client: &PrxClient) -> Capabilities {
    client.capabilities().await.expect("test: capabilities read")
}

async fn list_revision(client: &PrxClient, caps: &Capabilities) -> ConfigRevision {
    client.list(caps).await.expect("test: list reads").revision
}

fn anchor_name(byte: u8) -> AgentName {
    AgentName::from_anchor(&[byte; 32])
}

async fn bounded<F: std::future::Future<Output = ()>>(body: F) {
    tokio::time::timeout(TEST_DEADLINE, body)
        .await
        .expect("test: contract test exceeded its deadline");
}

/// The tokens K-AC2-1 accepts at the pin. `host_bootstrap_v1` is advertised and not
/// called. `targeted_agents_v1` is in `capabilities` while targeting is effective (the default at
/// 6e39b396, PRX d4681e3b) and in `available` while it is off.
const LANDED_AT_PIN: [&str; 20] = [
    CAPABILITIES_V1,
    AGENT_CATALOG_V1,
    AGENT_CRUD_V1,
    AGENT_LIMITS_V1,
    AGENT_MAIN_READBACK_V1,
    AGENT_MEMORY_PURGE_V1,
    HISTORY_ERASE_V1,
    SESSION_KEY_V1,
    MESSAGE_TARGET_V1,
    MESSAGE_CONTEXT_DELIVERY_V1,
    OWNER_ID_STABLE_V1,
    MESSAGE_IDEMPOTENCY_V1,
    MESSAGE_DELETE_V1,
    MESSAGE_FORGET_WRITES_V1,
    SYNC_SNAPSHOT_V1,
    SYNC_WS_V1,
    STREAM_FRAMES_V1,
    RUN_APPROVALS_V1,
    HOST_BOOTSTRAP_V1,
    TARGETED_AGENTS_V1,
];

/// Turn and job waits: PRX 429/502/504 retries can make one turn up to ~110 s slower.
const TURN_DEADLINE: Duration = Duration::from_secs(150);

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_ac2_capabilities_and_catalog() {
    bounded(async {
        let mut daemon = Daemon::prepare(GROQ_ROUTE);
        daemon.credential_set("groq", SENTINEL);
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();

        // K-AC2-1
        let caps = capabilities(&client).await;
        assert!(
            caps.has(CAPABILITIES_V1) && caps.has(AGENT_CATALOG_V1),
            "K-AC2-1: documented tokens advertised"
        );
        assert!(
            caps.capabilities.iter().all(|t| LANDED_AT_PIN.contains(&t.as_str())),
            "K-AC2-1: no token beyond the landed cards: {:?}",
            caps.capabilities
        );
        assert_eq!(
            caps.commit,
            BuildCommit::Sha(PIN.to_owned()),
            "K-AC2-1: commit must equal the pin"
        );
        report("K-AC2-1");

        // K-AC2-2
        let catalog =
            client.catalog().await.expect("K-AC2-2: catalog decodes with the documented fields");
        assert!(
            catalog.reserved_names.iter().any(|n| n == "main")
                && catalog.reserved_names.iter().any(|n| n == "catalog"),
            "K-AC2-2: reserved names"
        );
        assert_eq!(catalog.defaults_autonomy, Autonomy::Full, "K-AC2-2: defaults autonomy full");
        assert!(!catalog.models.is_empty(), "K-AC2-2: model rows present");
        report("K-AC2-2");

        // K-AC2-3
        let groq_row = catalog
            .models
            .iter()
            .find(|m| m.provider == "groq" && m.model == "llama-3.3-70b-versatile");
        assert_eq!(
            groq_row.map(|m| m.credentials_ready),
            Some(Some(true)),
            "K-AC2-3: groq row with credential and route is ready"
        );
        let bare: Vec<_> = catalog.models.iter().filter(|m| m.provider == "anthropic").collect();
        assert!(
            !bare.is_empty() && bare.iter().all(|m| m.credentials_ready == Some(false)),
            "K-AC2-3: anthropic rows without credential are not ready"
        );
        let (status, text) =
            daemon.raw_authorized(reqwest::Method::GET, "/api/agents/catalog", None, None).await;
        assert_eq!(status, 200, "K-AC2-3: catalog status");
        assert!(!text.contains(SENTINEL), "K-AC2-3: the sentinel appears nowhere in the body");
        report("K-AC2-3");

        // K-AC2-4: no header, then the token in the query string
        let (status, text) =
            daemon.raw(reqwest::Method::GET, "/api/agents/catalog", &[], None).await;
        assert_eq!(
            (status, error_code(&text).as_deref()),
            (401, Some("auth_failed")),
            "K-AC2-4: no header is 401 auth_failed"
        );
        let query = format!("/api/agents/catalog?token={}", daemon.token());
        let (status, text) = daemon.raw(reqwest::Method::GET, &query, &[], None).await;
        assert_eq!(
            (status, error_code(&text).as_deref()),
            (401, Some("auth_failed")),
            "K-AC2-4: token in ?token= is 401 auth_failed"
        );
        report("K-AC2-4");

        // K-AC2-5: same revision with no change, a different one after a model row is added
        let first = catalog.revision.as_str().to_owned();
        let second = daemon.catalog_revision().await;
        assert_eq!(first, second, "K-AC2-5: revision is stable with no config change");
        let config_path = daemon.dir.path().join("cfg/config.toml");
        let mut current = std::fs::read_to_string(&config_path).expect("test: read config");
        current.push_str(MODEL_ROW);
        std::fs::write(&config_path, current).expect("test: append model row");
        let started = Instant::now();
        loop {
            if daemon.catalog_revision().await != first {
                break;
            }
            assert!(
                started.elapsed() < WAIT_DEADLINE,
                "K-AC2-5: revision did not change after the model row was added"
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        report("K-AC2-5");
        daemon.stop();
    })
    .await;
}

/// K-AC2-6 (repin row): a credential stored for a NON-default provider through the credential
/// route, then a named agent bound to that provider and one of its catalog models.
///
/// `credentials_ready: true` means "a credential is stored and would be used", not "the
/// credential is valid": an expired or wrong key also reads `true`. This row checks only the
/// first meaning; it never sends a request to the provider.
#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_ac2_6_stored_credential_for_non_default_provider() {
    bounded(async {
        // Groq is not the default provider (openrouter is); the model row has no route, so the
        // only credential source is the one stored under `cred-groq`.
        let mut daemon = Daemon::prepare(GROQ_MODEL_ROW);
        daemon.credential_set("groq", SENTINEL);
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        let name = anchor_name(2);
        let agent = AgentConfig {
            provider: "groq".to_owned(),
            model: "llama-3.3-70b-versatile".to_owned(),
            prompt: None,
            autonomy: Autonomy::Supervised,
            tools: Tools::All,
            enabled: true,
            limits: None,
            approval_wait_secs: ramflux_prx_client::DEFAULT_APPROVAL_WAIT_SECS,
        };
        let rev = list_revision(&client, &caps).await;
        let outcome = client
            .put(&caps, &name, &agent, &rev, false)
            .await
            .expect("K-AC2-6: PUT of a groq agent with a stored credential");
        assert_eq!(outcome.kind, PutKind::Created, "K-AC2-6: first PUT is a create");

        let catalog = client.catalog().await.expect("K-AC2-6: catalog reads");
        let row = catalog
            .models
            .iter()
            .find(|m| m.provider == "groq" && m.model == "llama-3.3-70b-versatile");
        assert_eq!(
            row.map(|m| m.credentials_ready),
            Some(Some(true)),
            "K-AC2-6: groq row is ready from the stored cred-groq reference"
        );
        let (status, text) =
            daemon.raw_authorized(reqwest::Method::GET, "/api/agents/catalog", None, None).await;
        assert_eq!(status, 200, "K-AC2-6: catalog status");
        assert!(!text.contains(SENTINEL), "K-AC2-6: the stored value appears nowhere in the body");

        let read = client.get(&caps, &name).await.expect("K-AC2-6: agent reads back");
        assert_eq!(read.config, agent, "K-AC2-6: config round-trips");
        assert_eq!(read.status, AgentStatus::Active, "K-AC2-6: enabled agent is active");
        report("K-AC2-6");
        daemon.stop();
    })
    .await;
}

/// K-AC2-7 to K-AC2-11 (repin rows, PRX main 67c5274ef, kept at 5d92a43a4): a daemon with NO provider credential,
/// then the credential PUT without a reload, then the reload. Also: /health while not ready,
/// and the two tool names the catalog no longer lists.
#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
#[allow(clippy::too_many_lines)]
async fn k_ac2_no_credential_store_then_reload() {
    bounded(async {
        let mut daemon = Daemon::prepare_without_credential("");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;

        // K-AC2-7: capabilities and catalog serve; a turn route refuses with its reason
        assert!(
            caps.has(CAPABILITIES_V1) && caps.has(AGENT_CATALOG_V1),
            "K-AC2-7: documented tokens advertised with no credential"
        );
        let catalog = client.catalog().await.expect("K-AC2-7: catalog reads with no credential");
        let anthropic: Vec<_> =
            catalog.models.iter().filter(|m| m.provider == "anthropic").collect();
        assert!(
            !anthropic.is_empty() && anthropic.iter().all(|m| m.credentials_ready == Some(false)),
            "K-AC2-7: rows without a stored credential are not ready"
        );
        let (status, text) = daemon.send_turn().await;
        assert_eq!(
            (status, error_code(&text).as_deref(), error_reason(&text).as_deref()),
            (503, Some("provider_not_ready"), Some("missing_provider_credential")),
            "K-AC2-7: turn route answers 503 provider_not_ready with its reason"
        );
        report("K-AC2-7");

        // K-AC2-10: /health stays ok while the turn runtime is not ready
        let (status, text) = daemon.raw(reqwest::Method::GET, "/health", &[], None).await;
        let health: Value = serde_json::from_str(&text).expect("K-AC2-10: health body is JSON");
        assert_eq!(
            (status, health.get("status").and_then(Value::as_str)),
            (200, Some("ready")),
            "K-AC2-10: /health answers ready while not ready for turns"
        );
        report("K-AC2-10");

        // K-AC2-8: a stored credential shows in the catalog at once; turn routes still refuse
        let (status, _) = daemon
            .raw_authorized(
                reqwest::Method::PUT,
                "/api/providers/openrouter/credential",
                None,
                Some(serde_json::json!({ "name": "openrouter", "value": DEFAULT_PROVIDER_KEY })),
            )
            .await;
        assert_eq!(status, 204, "K-AC2-8: credential PUT answers 204");
        let catalog = client.catalog().await.expect("K-AC2-8: catalog reads after the PUT");
        assert!(
            catalog
                .models
                .iter()
                .any(|m| m.provider == "openrouter" && m.credentials_ready == Some(true)),
            "K-AC2-8: an openrouter row is ready after the credential PUT"
        );
        let (status, text) = daemon.send_turn().await;
        assert_eq!(
            (status, error_code(&text).as_deref()),
            (503, Some("provider_not_ready")),
            "K-AC2-8: turn route still answers 503 until a reload"
        );
        report("K-AC2-8");

        // K-AC2-9: reload answers applied with gateway_turn_runtime rebuilt; turns serve
        let reloaded = client.reload_config(&caps).await.expect("K-AC2-9: reload answers");
        assert_eq!(reloaded.status, ReloadStatus::Applied, "K-AC2-9: reload status applied");
        assert!(
            reloaded.rebuilt.iter().any(|name| name == "gateway_turn_runtime"),
            "K-AC2-9: gateway_turn_runtime is rebuilt: {:?}",
            reloaded.rebuilt
        );
        let (status, text) = daemon.send_turn().await;
        assert!(
            status == 0 || error_code(&text).as_deref() != Some("provider_not_ready"),
            "K-AC2-9: turn route no longer answers provider_not_ready (HTTP {status}: {text})"
        );
        report("K-AC2-9");

        // K-AC2-11: neither dropped tool is listed, and an agent that names one is refused
        let catalog = client.catalog().await.expect("K-AC2-11: catalog reads after the reload");
        assert!(
            catalog
                .tools
                .iter()
                .all(|tool| tool.name != "capability_search" && tool.name != "stay_silent"),
            "K-AC2-11: the catalog lists neither capability_search nor stay_silent"
        );
        let revision = list_revision(&client, &caps).await;
        for dropped in ["capability_search", "stay_silent"] {
            let agent = config(
                "openrouter",
                "openai/gpt-4o-mini",
                None,
                Tools::List(vec![dropped.to_owned()]),
                true,
            );
            match client.put(&caps, &anchor_name(4), &agent, &revision, false).await {
                Err(PrxError::Api { status: 400, code: ApiCode::AgentToolsInvalid, .. }) => {}
                other => panic!(
                    "K-AC2-11: PUT naming {dropped} must be 400 agent_tools_invalid, got {other:?}"
                ),
            }
        }
        report("K-AC2-11");
        daemon.stop();
    })
    .await;
}

/// K-AC2-12 (repin row): the shared API limit answers the coded 429. The client returns
/// `RateLimited` with the body's `retry_after_ms`; the raw answer carries the documented
/// `Retry-After` header as well. The limit is 60 requests a minute, so the probe makes at most
/// `PROBE_LIMIT` calls.
#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_ac2_12_rate_limit_is_coded() {
    bounded(async {
        let mut daemon = Daemon::prepare("");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let mut limited = None;
        for _ in 0..PROBE_LIMIT {
            if let Err(error) = client.capabilities().await {
                limited = Some(error);
                break;
            }
        }
        assert_eq!(
            limited,
            Some(PrxError::RateLimited { retry_after_ms: Some(60_000) }),
            "K-AC2-12: the client maps the coded 429 to RateLimited with retry_after_ms 60000"
        );
        let resp = daemon
            .http
            .get(format!("{}/api/capabilities", daemon.base()))
            .header("Authorization", format!("Bearer {}", daemon.token()))
            .send()
            .await
            .expect("K-AC2-12: raw request answers");
        assert_eq!(resp.status().as_u16(), 429, "K-AC2-12: still limited");
        assert_eq!(
            resp.headers().get("retry-after").and_then(|v| v.to_str().ok()),
            Some("60"),
            "K-AC2-12: Retry-After header is 60"
        );
        let body: Value = resp.json().await.expect("K-AC2-12: 429 body is JSON");
        let code = body.pointer("/error/code").and_then(Value::as_str);
        let retry_after_ms = body.pointer("/error/retry_after_ms").and_then(Value::as_u64);
        assert_eq!(
            (code, retry_after_ms),
            (Some("rate_limited"), Some(60_000)),
            "K-AC2-12: coded body rate_limited with retry_after_ms"
        );
        report("K-AC2-12");
        daemon.stop();
    })
    .await;
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
#[allow(clippy::too_many_lines)]
async fn k_ac1a_agent_rows() {
    bounded(async {
        // Pairing is refused while Main is readonly (PRX gates POST /pair by Main's level), so
        // pair first, then set Main to readonly for K-AC1a-6 and the rows after it.
        // A hand-written agent (not rf-derived) that the list must also return.
        let mut daemon = Daemon::prepare(&local_agent_models(HAND_WRITTEN_AGENT));
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        set_main_level(&daemon.dir.path().join("cfg/config.toml"), "readonly");
        let client = daemon.client();
        let started = Instant::now();
        loop {
            // Polls are spaced out: the API has a shared rate limit (HTTP 429 after a burst).
            if let Ok(catalog) = client.catalog().await
                && catalog.defaults_autonomy == Autonomy::Readonly
            {
                break;
            }
            assert!(started.elapsed() < WAIT_DEADLINE, "test: Main readonly was not hot-reloaded");
            tokio::time::sleep(SLOW_POLL_INTERVAL).await;
        }
        let caps = capabilities(&client).await;
        let name = anchor_name(1);

        // K-AC1a-1
        let main = client.main(&caps).await.expect("K-AC1a-1: Main readback decodes");
        assert_eq!(main.autonomy, Autonomy::Readonly, "K-AC1a-1: Main autonomy as configured");
        report("K-AC1a-1");

        // K-AC1a-2: PUT and DELETE on main are refused; Main unchanged
        let before = client.main(&caps).await.expect("K-AC1a-2: Main reads");
        let rev = list_revision(&client, &caps).await;
        let (status, text) = daemon
            .raw_authorized(reqwest::Method::PUT, "/api/agents/main", Some(rev.as_str()), Some(serde_json::json!({"provider":"ollama","model":"m","autonomy":"full","tools":["*"],"enabled":true})))
            .await;
        assert_eq!((status, error_code(&text).as_deref()), (400, Some("agent_invalid")), "K-AC1a-2: PUT main");
        let (status, text) = daemon
            .raw_authorized(reqwest::Method::DELETE, "/api/agents/main", Some(rev.as_str()), None)
            .await;
        assert_eq!((status, error_code(&text).as_deref()), (400, Some("agent_invalid")), "K-AC1a-2: DELETE main");
        assert_eq!(client.main(&caps).await.expect("K-AC1a-2: Main reads"), before, "K-AC1a-2: Main unchanged");
        report("K-AC1a-2");

        // K-AC1a-3
        let absent = client.get(&caps, &name).await;
        assert!(matches!(absent, Err(PrxError::Api { status: 404, code: ApiCode::AgentUnknown, .. })), "K-AC1a-3: {absent:?}");
        report("K-AC1a-3");

        // K-AC1a-4: If-Match is the config revision from list (not the catalog revision)
        let outcome = client
            .put(&caps, &name, &config("ollama", "codellama", None, Tools::All, true), &rev, false)
            .await
            .expect("K-AC1a-4: create with the config revision");
        assert_eq!(outcome.kind, PutKind::Created, "K-AC1a-4: first PUT is a create (201)");
        let read = client.get(&caps, &name).await.expect("K-AC1a-4: readback");
        assert_eq!(read.config, config("ollama", "codellama", None, Tools::All, true), "K-AC1a-4: config round-trips");
        assert_eq!(read.status, AgentStatus::Active, "K-AC1a-4: enabled agent is active");
        assert!(read.name.is_rf_derived(), "K-AC1a-4: anchor name is rf-derived");
        report("K-AC1a-4");

        // K-AC1a-5: the stale revision is a conflict and changes nothing
        let stale = rev.clone();
        let result = client
            .put(&caps, &name, &config("ollama", "llama3", None, Tools::All, true), &stale, false)
            .await;
        match result {
            Err(PrxError::Api { status: 409, code: ApiCode::RevisionConflict, current_revision: Some(current), .. }) => {
                assert_eq!(current, list_revision(&client, &caps).await, "K-AC1a-5: current_revision is the live one");
            }
            other => panic!("K-AC1a-5: expected 409 revision_conflict with current_revision, got {other:?}"),
        }
        assert_eq!(client.get(&caps, &name).await.expect("K-AC1a-5: readback").config.model, "codellama", "K-AC1a-5: config unchanged");
        report("K-AC1a-5");

        // K-AC1a-6: readonly and back to full while Main is readonly; incarnation unchanged
        let incarnation = read.incarnation.clone();
        let rev = list_revision(&client, &caps).await;
        let readonly = client
            .put(&caps, &name, &AgentConfig { autonomy: Autonomy::Readonly, ..config("ollama", "codellama", None, Tools::All, true) }, &rev, false)
            .await
            .expect("K-AC1a-6: PUT readonly under readonly Main");
        let rev = readonly.readback.revision.clone();
        let full = client
            .put(&caps, &name, &config("ollama", "codellama", None, Tools::All, true), &rev, false)
            .await
            .expect("K-AC1a-6: PUT full under readonly Main");
        assert_eq!(full.kind, PutKind::Replaced, "K-AC1a-6: second PUT replaces");
        assert_eq!(readonly.readback.incarnation, incarnation, "K-AC1a-6: incarnation unchanged");
        assert_eq!(full.readback.incarnation, incarnation, "K-AC1a-6: incarnation unchanged");
        report("K-AC1a-6");

        // K-AC1a-7: enabled follows, incarnation unchanged
        let rev = full.readback.revision.clone();
        let disabled = client
            .put(&caps, &name, &config("ollama", "codellama", None, Tools::All, false), &rev, false)
            .await
            .expect("K-AC1a-7: PUT disabled");
        assert_eq!((disabled.readback.status, disabled.readback.config.enabled), (AgentStatus::Disabled, false), "K-AC1a-7: disabled");
        let enabled = client
            .put(&caps, &name, &config("ollama", "codellama", None, Tools::All, true), &disabled.readback.revision, false)
            .await
            .expect("K-AC1a-7: PUT enabled");
        assert_eq!((enabled.readback.status, enabled.readback.incarnation.as_str()), (AgentStatus::Active, incarnation.as_str()), "K-AC1a-7: enabled, same incarnation");
        report("K-AC1a-7");

        // K-AC1a-8: refusals by name, tool and unknown field
        let rev = enabled.readback.revision.clone();
        for (path, expected) in [("/api/agents/catalog", "agent_invalid"), ("/api/agents/A_BAD", "agent_invalid")] {
            let (status, text) = daemon
                .raw_authorized(reqwest::Method::PUT, path, Some(rev.as_str()), Some(serde_json::json!({"provider":"ollama","model":"m","autonomy":"full","tools":["*"],"enabled":true})))
                .await;
            assert_eq!((status, error_code(&text).as_deref()), (400, Some(expected)), "K-AC1a-8: {path}");
        }
        assert!(matches!(AgentName::parse("catalog"), Err(PrxError::Api { code: ApiCode::AgentInvalid, .. })), "K-AC1a-8: local refusal of catalog");
        let unknown_tool = client
            .put(&caps, &name, &config("ollama", "codellama", None, Tools::List(vec!["no_such_tool_zz".to_owned()]), true), &rev, false)
            .await;
        assert!(matches!(unknown_tool, Err(PrxError::Api { status: 400, code: ApiCode::AgentToolsInvalid, .. })), "K-AC1a-8: unknown tool: {unknown_tool:?}");
        assert!(caps.has(AGENT_LIMITS_V1), "K-AC1a-8: agent_limits_v1 is advertised");
        let (status, text) = daemon
            .raw_authorized(reqwest::Method::PUT, &format!("/api/agents/{}", name.as_str()), Some(rev.as_str()), Some(serde_json::json!({"provider":"ollama","model":"m","autonomy":"full","tools":["*"],"enabled":true,"limits":{}})))
            .await;
        assert_eq!((status, error_code(&text).as_deref()), (200, None), "K-AC1a-8: empty limits object");
        let body: Value = serde_json::from_str(&text).expect("K-AC1a-8: readback is JSON");
        assert!(
            body.pointer("/config/limits/max_concurrent_turns").is_some_and(Value::is_null)
                && body.pointer("/config/limits/max_cost_per_day_cents").is_some_and(Value::is_null),
            "K-AC1a-8: empty limits stores no bound"
        );
        report("K-AC1a-8");

        // K-AC1a-11 (with a second agent, which also covers the list shape and retirement later)
        let second = anchor_name(2);
        let rev = list_revision(&client, &caps).await;
        client
            .put(&caps, &second, &config("ollama", "llama3", None, Tools::All, true), &rev, false)
            .await
            .expect("K-AC1a-11: create second agent");
        let listed = client.list(&caps).await.expect("K-AC1a-11: list");
        let names: Vec<&str> = listed.agents.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&name.as_str()) && names.contains(&second.as_str()), "K-AC1a-11: both listed: {names:?}");
        assert!(!names.contains(&"main"), "K-AC1a-11: Main is not a named agent");
        assert!(listed.agents.iter().all(|a| !a.incarnation.is_empty()), "K-AC1a-11: incarnation on each entry");
        report("K-AC1a-11");

        // Fact 3 (AC-1a1 notes): the hand-written agent is listed, and it is not rf-derived.
        let worker = listed.agents.iter().find(|a| a.name.as_str() == "worker1");
        assert!(worker.is_some_and(|w| !w.name.is_rf_derived()), "fact 3: hand-written agent listed, not rf-derived");
        report("FACT3-hand-written-listed");

        // Fact 1: a PUT that repeats the stored config still changes the config revision.
        let before = list_revision(&client, &caps).await;
        let repeated = client
            .put(&caps, &name, &config("ollama", "codellama", None, Tools::All, true), &before, false)
            .await
            .expect("fact 1: identical PUT is accepted");
        assert_eq!(repeated.kind, PutKind::Replaced, "fact 1: identical PUT replaces");
        assert_ne!(repeated.readback.revision, before, "fact 1: the revision changes on an identical PUT");
        report("FACT1-revision-changes-on-identical-put");

        // Retirement, prompt and tool round trips, and the size bound
        let rev = list_revision(&client, &caps).await;
        let retired = client.retire(&caps, &second, &rev).await.expect("retire: first DELETE");
        let again = client.retire(&caps, &second, &retired.revision).await.expect("retire: repeated DELETE");
        assert_eq!(again.name, second, "retire: repeated DELETE names the same agent");
        assert_eq!(client.get(&caps, &second).await.expect("retire: readback").status, AgentStatus::Retired, "retire: status retired");
        let listed = client.list(&caps).await.expect("retire: list");
        assert!(listed.agents.iter().any(|a| a.name == second && a.status == AgentStatus::Retired), "retire: listed with status retired");
        let on_retired = client
            .put(&caps, &second, &config("ollama", "llama3", None, Tools::All, true), &again.revision, false)
            .await;
        assert!(matches!(on_retired, Err(PrxError::Api { status: 409, code: ApiCode::AgentDisabled, .. })), "retire: PUT on retired: {on_retired:?}");
        let never = client.retire(&caps, &anchor_name(9), &again.revision).await;
        assert!(matches!(never, Err(PrxError::Api { status: 404, code: ApiCode::AgentUnknown, .. })), "retire: never existed: {never:?}");

        let rev = list_revision(&client, &caps).await;
        let absent_prompt = client
            .put(&caps, &anchor_name(3), &config("ollama", "m", None, Tools::All, true), &rev, false)
            .await
            .expect("prompt: absent");
        assert_eq!(absent_prompt.readback.config.prompt, None, "prompt absent stays absent");
        let rev = absent_prompt.readback.revision.clone();
        let empty_prompt = client
            .put(&caps, &anchor_name(3), &config("ollama", "m", Some(""), Tools::List(Vec::new()), true), &rev, false)
            .await
            .expect("prompt: empty");
        assert_eq!(empty_prompt.readback.config.prompt, Some(String::new()), "prompt \"\" round-trips");
        assert_eq!(empty_prompt.readback.config.tools, Tools::List(Vec::new()), "tools [] round-trips");
        let rev = empty_prompt.readback.revision.clone();
        let text_prompt = "caf\u{e9} line\n";
        let text_put = client
            .put(&caps, &anchor_name(3), &config("ollama", "m", Some(text_prompt), Tools::All, true), &rev, false)
            .await
            .expect("prompt: text");
        assert_eq!(text_put.readback.config.prompt.as_deref(), Some(text_prompt), "prompt byte-identical");
        assert_eq!(text_put.readback.config.tools, Tools::All, "tools [\"*\"] round-trips");

        let rev = text_put.readback.revision.clone();
        let oversized = "x".repeat(PROMPT_MAX_BYTES + 1);
        let local = client
            .put(&caps, &anchor_name(3), &config("ollama", "m", Some(&oversized), Tools::All, true), &rev, false)
            .await;
        assert!(matches!(local, Err(PrxError::Api { code: ApiCode::FieldInvalid, .. })), "prompt: oversize refused locally");
        let (status, text) = daemon
            .raw_authorized(
                reqwest::Method::PUT,
                &format!("/api/agents/{}", anchor_name(3).as_str()),
                Some(rev.as_str()),
                Some(serde_json::json!({"provider":"ollama","model":"m","autonomy":"full","tools":["*"],"enabled":true,"prompt":oversized})),
            )
            .await;
        assert_eq!((status, error_code(&text).as_deref()), (400, Some("field_invalid")), "prompt: PRX refuses oversize too");
        let exact = "y".repeat(PROMPT_MAX_BYTES);
        let at_limit = client
            .put(&caps, &anchor_name(3), &config("ollama", "m", Some(&exact), Tools::All, true), &rev, false)
            .await
            .expect("prompt: exactly the bound is accepted");
        assert_eq!(at_limit.readback.config.prompt.map(|p| p.len()), Some(PROMPT_MAX_BYTES), "prompt: stored at the bound");
        report("EXTRA-retire-prompt-bounds");
        daemon.stop();
    })
    .await;
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_ac1a_10_targeted_agents_across_restart() {
    bounded(async {
        let mut daemon = Daemon::prepare("");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;

        // K-AC1a-10: targeting defaults to true at 6e39b396, so set the opposite of the current
        // effective value; the response says a restart is required and the old value still runs.
        let before = client.targeted_agents(&caps).await.expect("K-AC1a-10: targeted read");
        let target = !before.effective;
        assert!(before.effective, "K-AC1a-10: default is effective at the pin: {before:?}");
        let changed = client
            .set_targeted_agents(&caps, target, &before.revision)
            .await
            .expect("K-AC1a-10: change");
        assert!(
            changed.configured == target && changed.restart_required,
            "K-AC1a-10: configured is the new value and restart required: {changed:?}"
        );
        assert_eq!(
            changed.effective, before.effective,
            "K-AC1a-10: effective keeps the old value before the restart: {changed:?}"
        );
        daemon.stop();
        daemon.start();
        daemon.wait_ready().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        let after =
            client.targeted_agents(&caps).await.expect("K-AC1a-10: targeted read after restart");
        assert!(
            after.configured == target && after.effective == target && !after.restart_required,
            "K-AC1a-10: all three agree after the restart: {after:?}"
        );
        report("K-AC1a-10");
        daemon.stop();
    })
    .await;
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn apply_helper_against_real_concurrent_changes() {
    bounded(async {
        let mut daemon = Daemon::prepare(&local_agent_models(""));
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let other = daemon.client();
        let caps = capabilities(&client).await;
        let agent_a = anchor_name(4);
        let agent_b = anchor_name(5);
        let a1 = config("ollama", "codellama", None, Tools::All, true);
        let b1 = config("ollama", "llama3", None, Tools::All, true);
        let rev = list_revision(&client, &caps).await;
        client.put(&caps, &agent_a, &a1, &rev, false).await.expect("apply: create A");
        let rev = list_revision(&client, &caps).await;
        client.put(&caps, &agent_b, &b1, &rev, false).await.expect("apply: create B");

        // (1) Another agent changes between list and PUT: the helper retries and applies.
        let a2 = config("ollama", "mistral", None, Tools::All, true);
        let listed = list_revision(&client, &caps).await;
        let b2 = config("ollama", "llama3-8b", None, Tools::All, true);
        other
            .put(&caps, &agent_b, &b2, &listed, false)
            .await
            .expect("apply: concurrent change to B");
        let outcome = client
            .apply_agent_at(&caps, &agent_a, &a2, Some(&a1), &listed)
            .await
            .expect("apply: other agent changed");
        assert!(
            matches!(outcome, ApplyOutcome::Applied(_)),
            "apply: automatic retry succeeds, got {outcome:?}"
        );
        assert_eq!(
            client.get(&caps, &agent_a).await.expect("apply: readback A").config,
            a2,
            "apply: A has the intended config"
        );
        report("P8-other-agent-retry");

        // (2) The same agent changes between review and PUT: NeedsReview, nothing overwritten.
        let a3 = config("ollama", "gemma", None, Tools::All, true);
        let listed = list_revision(&client, &caps).await;
        other
            .put(&caps, &agent_a, &a3, &listed, false)
            .await
            .expect("apply: concurrent change to A");
        let a4 = config("ollama", "phi", None, Tools::All, true);
        let outcome = client
            .apply_agent_at(&caps, &agent_a, &a4, Some(&a2), &listed)
            .await
            .expect("apply: same agent changed");
        match outcome {
            ApplyOutcome::NeedsReview { current: Some(current) } => {
                assert_eq!(current.config, a3, "apply: shows the changed config");
            }
            other => panic!("apply: expected NeedsReview with the current config, got {other:?}"),
        }
        assert_eq!(
            client.get(&caps, &agent_a).await.expect("apply: readback A").config,
            a3,
            "apply: A not overwritten"
        );
        report("P8-same-agent-needs-review");

        // (3) The intended config is already stored: AlreadyApplied, decided by the config.
        let listed = list_revision(&client, &caps).await;
        other
            .put(&caps, &agent_b, &b1, &listed, false)
            .await
            .expect("apply: B changes to the intended config");
        let outcome = client
            .apply_agent_at(&caps, &agent_b, &b1, Some(&b2), &listed)
            .await
            .expect("apply: intended already stored");
        assert!(
            matches!(outcome, ApplyOutcome::AlreadyApplied(_)),
            "apply: intended config already stored, got {outcome:?}"
        );
        report("P8-already-applied");
        daemon.stop();
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// rf message routes (B1: session_key_v1, message_target_v1, message_context_delivery_v1) and the
// install owner id (HOST-1a: owner_id_stable_v1). Rows K-B1-n and K-HOST1a-n.
// ---------------------------------------------------------------------------------------------

/// A caller-keyed session of the owner (`session_key` grammar: 8 to 128 characters).
const RF_SESSION: &str = "rf-contract-session-0001";
/// Extra paired tokens, written to `gateway.paired_tokens` (PRX hashes plaintext on load). They
/// stand for a second and a third paired device of the same install.
const SECOND_TOKEN: &str = "zc_rf-contract-second-device-0001";
const THIRD_TOKEN: &str = "zc_rf-contract-third-device-0002";
/// Cap of an rf message body in the gateway (`MAX_BODY_SIZE`, bytes of the whole request).
const GATEWAY_BODY_CAP: usize = 65_536;

fn rf_chat() -> Chat {
    Chat { id: "chat-contract-1".to_owned(), kind: ChatKind::Dm, title: None, member_count: 2 }
}

fn rf_sender() -> Sender {
    Sender {
        principal_id: "principal-contract-1".to_owned(),
        display: "Contract Sender".to_owned(),
    }
}

fn rf_message(client_message_id: &str, target: Target, text: &str) -> RfMessage {
    RfMessage {
        client_message_id: client_message_id.to_owned(),
        target,
        message: text.to_owned(),
        chat: rf_chat(),
        sender: rf_sender(),
        mentions: Vec::new(),
        reply_to: None,
    }
}

/// The rf fields a body must carry besides `client_message_id` (raw bodies for negative rows).
fn rf_body(deliver: &str, client_message_id: Option<&str>) -> Value {
    let mut body = serde_json::json!({
        "deliver": deliver,
        "message": "raw contract body",
        "chat": { "id": "chat-contract-1", "kind": "dm", "member_count": 2 },
        "sender": { "principal_id": "principal-contract-1", "display": "Contract Sender" },
    });
    if let Some(id) = client_message_id {
        body["client_message_id"] = Value::String(id.to_owned());
    }
    body
}

/// `GET /api/sessions` (a bare array of session summaries) with the daemon's bearer.
async fn sessions_list(daemon: &Daemon) -> Vec<Value> {
    let (status, text) =
        daemon.raw_authorized(reqwest::Method::GET, "/api/sessions", None, None).await;
    assert_eq!(status, 200, "sessions list must be 200: {text}");
    serde_json::from_str(&text).expect("test: sessions list is JSON")
}

/// Starts a daemon with a stub model on the default provider and pairs it.
async fn paired_rf_daemon(extra: &str) -> (Daemon, ModelStub) {
    let stub = ModelStub::start(Duration::ZERO).await;
    let mut daemon = Daemon::prepare_with_provider(&stub.provider(), extra);
    daemon.start();
    daemon.wait_ready().await;
    daemon.pair().await;
    (daemon, stub)
}

/// A `ModelStub`: a loopback OpenAI-compatible endpoint that counts the model requests it
/// receives and answers `500` after `hold` (zero: at once). It is the only model endpoint the
/// rf rows use, so a count that does not move proves that no model request was made, and a
/// long `hold` keeps a turn live for the rows that need one. A completing stub answers a JSON
/// chat completion, or an SSE stream when the request sets `"stream":true`.
struct ModelStub {
    port: u16,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl ModelStub {
    async fn start(hold: Duration) -> Self {
        Self::start_mode(hold, false).await
    }

    /// Like `start`, but answers a valid chat completion (200) instead of a 500.
    async fn start_completing(hold: Duration) -> Self {
        Self::start_mode(hold, true).await
    }

    async fn start_mode(hold: Duration, complete: bool) -> Self {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("test: bind model stub");
        let port = listener.local_addr().expect("test: stub addr").port();
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let counter = counter.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = Vec::new();
                    let mut chunk = [0_u8; 8_192];
                    loop {
                        if buf.len() >= 262_144
                            || http_request_complete(&buf)
                            || headers_without_content_length(&buf)
                        {
                            break;
                        }
                        match stream.read(&mut chunk).await {
                            Ok(n @ 1..) => {
                                if buf.is_empty() {
                                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                }
                                buf.extend_from_slice(&chunk[..n]);
                            }
                            Ok(0) | Err(_) => break,
                        }
                    }
                    let streaming = request_asks_for_stream(&buf);
                    tokio::time::sleep(hold).await;
                    let (status, content_type, body): (&str, &str, &str) = if !complete {
                        (
                            "500 Internal Server Error",
                            "application/json",
                            r#"{"error":{"message":"contract stub: no model","type":"stub"}}"#,
                        )
                    } else if streaming {
                        (
                            "200 OK",
                            "text/event-stream",
                            "data: {\"choices\":[{\"delta\":{\"content\":\"stub reply\"}}]}\n\n\
                             data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n\
                             data: [DONE]\n\n",
                        )
                    } else {
                        (
                            "200 OK",
                            "application/json",
                            r#"{"id":"stub-1","object":"chat.completion","created":0,"model":"stub-model","choices":[{"index":0,"message":{"role":"assistant","content":"stub reply"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
                        )
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self { port, requests, task }
    }

    /// The `custom:` provider spelling that points the daemon at this stub.
    fn provider(&self) -> String {
        format!("custom:http://127.0.0.1:{}/v1", self.port)
    }

    fn count(&self) -> usize {
        self.requests.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Headers with no `Content-Length` are complete. Waiting for EOF would stall the client.
fn headers_without_content_length(buf: &[u8]) -> bool {
    let Some(split) = buf.windows(4).position(|mark| mark == b"\r\n\r\n") else {
        return false;
    };
    content_length(&String::from_utf8_lossy(&buf[..split])).is_none()
}

fn request_asks_for_stream(bytes: &[u8]) -> bool {
    let body = match bytes.windows(4).position(|window| window == b"\r\n\r\n") {
        Some(split) => {
            let header = String::from_utf8_lossy(&bytes[..split]);
            let body = &bytes[split + 4..];
            match content_length(&header) {
                Some(length) if body.len() >= length => &body[..length],
                _ => body,
            }
        }
        None => bytes,
    };
    body.windows(13).any(|window| window == b"\"stream\":true")
}

impl Drop for ModelStub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_b1_sessions_and_message_validation() {
    bounded(async {
        let (mut daemon, _stub) = paired_rf_daemon("").await;
        let client = daemon.client();
        let caps = capabilities(&client).await;

        // K-B1-16: exactly the tokens landed at this pin, none of the not-yet-landed ones.
        let expected: std::collections::BTreeSet<String> =
            LANDED_AT_PIN.iter().map(|token| (*token).to_owned()).collect();
        assert_eq!(caps.capabilities, expected, "K-B1-16: advertised tokens at the pin");
        assert!(
            caps.has(TARGETED_AGENTS_V1),
            "K-B1-16: targeted_agents_v1 is effective by default"
        );
        assert_eq!(caps.commit, BuildCommit::Sha(PIN.to_owned()), "K-B1-16: commit is the pin");
        report("K-B1-16");

        // K-B1-1 / K-B1-2: create 201 created:true, then the same key 200 created:false
        let first = client.create_session(&caps, RF_SESSION).await.expect("K-B1-1: create");
        assert!(first.created && first.session_id == RF_SESSION, "K-B1-1: {first:?}");
        let again = client.create_session(&caps, RF_SESSION).await.expect("K-B1-2: create again");
        assert!(!again.created && again.session_id == RF_SESSION, "K-B1-2: {again:?}");
        report("K-B1-1");
        report("K-B1-2");

        // K-B1-3: a bad key is refused by PRX (field_invalid); a console- prefix too
        for bad in ["bad key with space", "console-abcdef12"] {
            match client.create_session(&caps, bad).await {
                Err(PrxError::Api { status: 400, code: ApiCode::FieldInvalid, .. }) => {}
                other => panic!("K-B1-3: bad key {bad:?} must be 400 field_invalid, got {other:?}"),
            }
        }
        report("K-B1-3");

        // K-B1-4: the session lists with channel rf
        let listed = sessions_list(&daemon).await;
        let row = listed
            .iter()
            .find(|row| row.get("session_id").and_then(Value::as_str) == Some(RF_SESSION))
            .expect("K-B1-4: the session is listed");
        assert_eq!(row.get("channel").and_then(Value::as_str), Some("rf"), "K-B1-4: channel rf");
        report("K-B1-4");

        // K-B1-5: an rf session refuses a plain Console body
        let path = format!("/api/sessions/{RF_SESSION}/message");
        let (status, text) = daemon
            .raw_authorized(
                reqwest::Method::POST,
                &path,
                None,
                Some(serde_json::json!({"message":"plain"})),
            )
            .await;
        assert_eq!(
            (status, error_code(&text).as_deref()),
            (400, Some("field_invalid")),
            "K-B1-5: {text}"
        );
        report("K-B1-5");

        // K-B1-6: any rf field without client_message_id is refused
        let (status, text) = daemon
            .raw_authorized(reqwest::Method::POST, &path, None, Some(rf_body("context", None)))
            .await;
        assert_eq!(
            (status, error_code(&text).as_deref()),
            (400, Some("field_invalid")),
            "K-B1-6: {text}"
        );
        report("K-B1-6");

        // K-B1-7: bounds, through the typed client (its types allow every value).
        let too_long = "x".repeat(257);
        let mut title = rf_message("rf-bound-title", Target::Main, "bounds");
        title.chat.title = Some(too_long.clone());
        let mut display = rf_message("rf-bound-display", Target::Main, "bounds");
        display.sender.display = too_long.clone();
        let mut mentions = rf_message("rf-bound-mentions", Target::Main, "bounds");
        mentions.mentions = (0..65).map(|i| format!("principal-{i}")).collect();
        let size = rf_message("rf-bound-size", Target::Main, &"y".repeat(GATEWAY_BODY_CAP + 1));
        for (row, message) in [("title", &title), ("display", &display), ("mentions", &mentions)] {
            match client.post_context(&caps, RF_SESSION, message).await {
                Err(PrxError::Api { status: 400, code: ApiCode::FieldInvalid, .. }) => {}
                other => panic!("K-B1-7 {row}: must be 400 field_invalid, got {other:?}"),
            }
        }
        // The size bound: real behaviour recorded verbatim by the caller (see report).
        let size_answer = client.post_context(&caps, RF_SESSION, &size).await;
        eprintln!(
            "ROW K-B1-7 size: body {} bytes, typed answer {size_answer:?}",
            GATEWAY_BODY_CAP + 1
        );
        // Positive control: a title of exactly 256 characters is accepted (recorded as context).
        let mut edge = rf_message("rf-bound-edge", Target::Main, "bounds ok");
        edge.chat.title = Some("t".repeat(256));
        client
            .post_context(&caps, RF_SESSION, &edge)
            .await
            .expect("K-B1-7: 256-character title is accepted");
        report("K-B1-7");
        daemon.stop();
    })
    .await;
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_host1a_owner_id_is_stable_across_paired_tokens() {
    bounded(async {
        let extra = format!("paired_tokens = [\"{SECOND_TOKEN}\", \"{THIRD_TOKEN}\"]\n");
        let stub = ModelStub::start(Duration::ZERO).await;
        let mut daemon = Daemon::prepare_with_provider(&stub.provider(), &extra);
        daemon.start();
        daemon.wait_ready().await;
        // Two paired tokens (the first was written to the config, not paired by POST /pair).
        write_token_file(&daemon.dir.path().join("second-token"), SECOND_TOKEN);
        write_token_file(&daemon.dir.path().join("third-token"), THIRD_TOKEN);
        let second = PrxClient::new(&ClientConfig::new(
            daemon.base(),
            daemon.dir.path().join("second-token"),
        ))
        .expect("test: second client");
        let caps = capabilities(&second).await;

        // K-HOST1a-1: the same owner id for both paired tokens, in the documented form.
        let third = PrxClient::new(&ClientConfig::new(
            daemon.base(),
            daemon.dir.path().join("third-token"),
        ))
        .expect("test: third client");
        let a = second.owner_id(&caps).await.expect("K-HOST1a-1: owner for the second token");
        let b = third.owner_id(&caps).await.expect("K-HOST1a-1: owner for the third token");
        assert_eq!(a, b, "K-HOST1a-1: one install owner for every paired token");
        assert!(
            a.as_str().starts_with("api:install:") && a.as_str().len() == 44,
            "K-HOST1a-1: {a:?}"
        );
        report("K-HOST1a-1");

        // K-HOST1a-2: no paired bearer, and a bearer that is not paired, are both 401 auth_failed
        let (status, text) = daemon.raw(reqwest::Method::GET, "/api/owner", &[], None).await;
        assert_eq!(
            (status, error_code(&text).as_deref()),
            (401, Some("auth_failed")),
            "K-HOST1a-2: {text}"
        );
        let (status, text) = daemon
            .raw(
                reqwest::Method::GET,
                "/api/owner",
                &[("Authorization", "Bearer zc_not_paired_token".to_owned())],
                None,
            )
            .await;
        assert_eq!(
            (status, error_code(&text).as_deref()),
            (401, Some("auth_failed")),
            "K-HOST1a-2: {text}"
        );
        report("K-HOST1a-2");
        daemon.stop();
    })
    .await;
}

fn write_token_file(path: &Path, token: &str) {
    std::fs::write(path, token).expect("test: write token file");
    set_owner_only(path);
}

/// Polls `GET /api/jobs/{job_id}` until the job ends (spaced polls; the API has a shared limit).
async fn wait_job_terminal(client: &PrxClient, caps: &Capabilities, job_id: &str) -> JobStatus {
    let started = Instant::now();
    loop {
        let job = client.job_status(caps, job_id).await.expect("test: job status reads");
        if job.status.is_terminal() {
            return job;
        }
        assert!(started.elapsed() < TURN_DEADLINE, "test: job {job_id} did not end in time");
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Creates or replaces a named agent through the typed client.
async fn put_agent(
    client: &PrxClient,
    caps: &Capabilities,
    name: &str,
    provider: &str,
    enabled: bool,
) {
    let name = AgentName::parse(name).expect("test: agent name");
    let rev = list_revision(client, caps).await;
    let cfg = config(provider, "stub-model", None, Tools::All, enabled);
    // A `custom:` endpoint names a new credential recipient: PRX answers 428 until the change is
    // confirmed (recorded as a finding of this card). The helper confirms it.
    client.put(caps, &name, &cfg, &rev, true).await.expect("test: agent put");
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_b1_turn_context_and_agent_checks_with_targeting_off() {
    bounded(async {
        let fast = ModelStub::start(Duration::ZERO).await;
        let hold = ModelStub::start(Duration::from_secs(600)).await;
        let mut daemon =
            Daemon::prepare_with_provider(&fast.provider(), &priced(&hold.provider(), ""));
        // First start creates the `.defaults-migration` marker in the config dir.
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        client.create_session(&caps, RF_SESSION).await.expect("test: session");
        put_agent(&client, &caps, "worker", &hold.provider(), true).await;
        put_agent(&client, &caps, "other", &fast.provider(), true).await;
        put_agent(&client, &caps, "off1", &fast.provider(), false).await;
        // Targeting off, then restart: the switch is effective only after the restart.
        let switch = client.targeted_agents(&caps).await.expect("K-B1-12: targeted read");
        let off = client
            .set_targeted_agents(&caps, false, &switch.revision)
            .await
            .expect("K-B1-12: targeting off");
        assert!(off.configured && !off.effective && off.restart_required, "K-B1-12: {off:?}");
        daemon.stop();
        daemon.start();
        daemon.wait_ready().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        let now =
            client.targeted_agents(&caps).await.expect("K-B1-12: targeted read after restart");
        assert!(
            !now.effective && !now.configured,
            "K-B1-12: effective false after restart: {now:?}"
        );

        // K-B1-11 (targeting off): an unknown agent is 404 agent_unknown; existence comes first.
        match client
            .post_turn(
                &caps,
                RF_SESSION,
                &rf_message(
                    "rf-ghost-1",
                    Target::Named(AgentName::parse("ghost").expect("test: name")),
                    "hi",
                ),
            )
            .await
        {
            Err(PrxError::Api { status: 404, code: ApiCode::AgentUnknown, .. }) => {}
            other => panic!("K-B1-11: unknown agent must be 404 agent_unknown, got {other:?}"),
        }
        report("K-B1-11 (targeting off)");

        // K-B1-12: an existing agent with targeting off is 409 agent_targeting_disabled, whatever its state.
        for name in ["worker", "off1"] {
            let target = Target::Named(AgentName::parse(name).expect("test: name"));
            match client
                .post_turn(&caps, RF_SESSION, &rf_message("rf-targeted-off-1", target, "hi"))
                .await
            {
                Err(PrxError::Api {
                    status: 409, code: ApiCode::AgentTargetingDisabled, ..
                }) => {}
                other => {
                    panic!("K-B1-12 {name}: must be 409 agent_targeting_disabled, got {other:?}")
                }
            }
        }
        report("K-B1-12");

        // K-B1-14: Main still runs with targeting off (agent omitted, and "main" is the same key).
        let main = client
            .post_turn(&caps, RF_SESSION, &rf_message("rf-main-1", Target::Main, "hello main"))
            .await
            .expect("K-B1-14: Main turn is admitted with targeting off");
        report("K-B1-14");

        // K-B1-8: the admitted turn carries exactly run_id and job_id (typed decode is strict).
        assert!(!main.run_id.is_empty() && !main.job_id.is_empty(), "K-B1-8: {main:?}");
        report("K-B1-8");

        // K-B1-15: the job reaches a terminal state, carries the run id, and fails with the stub.
        let job = wait_job_terminal(&client, &caps, &main.job_id).await;
        assert_eq!(job.job_id, main.job_id, "K-B1-15: job id echoes");
        assert_eq!(job.run_id.as_deref(), Some(main.run_id.as_str()), "K-B1-15: top-level run_id");
        assert_eq!(job.status, JobState::Failed, "K-B1-15: the stub answers 500, so the run fails");
        report("K-B1-15");

        // K-B1-9: a context input starts no run and makes no model request. The Main run above has
        // ended; the stub count and the job total must not move across the context post.
        let jobs_before = daemon_job_total(&daemon).await;
        let model_before = fast.count();
        let recorded = client
            .post_context(
                &caps,
                RF_SESSION,
                &rf_message("rf-context-1", Target::Main, "context only"),
            )
            .await
            .expect("K-B1-9: context is recorded");
        assert!(!recorded.message_id.is_empty(), "K-B1-9: a message id");
        tokio::time::sleep(POLL_INTERVAL).await;
        assert_eq!(fast.count(), model_before, "K-B1-9: no model request for a context");
        assert_eq!(daemon_job_total(&daemon).await, jobs_before, "K-B1-9: no job for a context");
        report("K-B1-9");
        daemon.stop();
    })
    .await;
}

/// The job total of `GET /api/jobs` (bearer required).
async fn daemon_job_total(daemon: &Daemon) -> u64 {
    let (status, text) = daemon.raw_authorized(reqwest::Method::GET, "/api/jobs", None, None).await;
    assert_eq!(status, 200, "job list must be 200: {text}");
    let value: Value = serde_json::from_str(&text).expect("test: job list is JSON");
    value.get("total").and_then(Value::as_u64).expect("test: job list carries total")
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_b1_busy_and_agent_states_with_targeting_on() {
    bounded(async {
        let fast = ModelStub::start(Duration::ZERO).await;
        let hold = ModelStub::start(Duration::from_secs(600)).await;
        let mut daemon = Daemon::prepare_with_provider(
            &fast.provider(),
            &priced(&hold.provider(), "targeted_agents = true\n"),
        );
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        let switch = client.targeted_agents(&caps).await.expect("test: targeted read");
        assert!(switch.effective, "test: targeted agents are effective after the restart");
        let session = "rf-contract-session-0002";
        client.create_session(&caps, session).await.expect("test: session");
        put_agent(&client, &caps, "worker", &hold.provider(), true).await;
        put_agent(&client, &caps, "other", &fast.provider(), true).await;
        put_agent(&client, &caps, "off1", &fast.provider(), false).await;
        put_agent(&client, &caps, "gone", &fast.provider(), true).await;
        let gone = AgentName::parse("gone").expect("test: name");
        let rev = list_revision(&client, &caps).await;
        let retired = client.retire(&caps, &gone, &rev).await.expect("test: retire");
        assert_eq!(retired.name, gone, "test: retired name");

        // K-B1-10: one turn per (session, agent) at a time; context still accepted; another agent admitted
        let worker = Target::Named(AgentName::parse("worker").expect("test: name"));
        let live = client
            .post_turn(&caps, session, &rf_message("rf-busy-1", worker.clone(), "long turn"))
            .await
            .expect("K-B1-10: first turn admitted");
        match client
            .post_turn(&caps, session, &rf_message("rf-busy-2", worker.clone(), "again"))
            .await
        {
            Err(PrxError::Api { status: 409, code: ApiCode::SessionBusy, .. }) => {}
            other => {
                panic!("K-B1-10: second turn while live must be 409 session_busy, got {other:?}")
            }
        }
        client
            .post_context(
                &caps,
                session,
                &rf_message("rf-busy-3", worker.clone(), "context while busy"),
            )
            .await
            .expect("K-B1-10: context is accepted while a turn is live");
        let other = Target::Named(AgentName::parse("other").expect("test: name"));
        let admitted = client
            .post_turn(&caps, session, &rf_message("rf-busy-4", other, "other agent"))
            .await
            .expect("K-B1-10: a turn to another agent is admitted");
        assert!(
            !admitted.run_id.is_empty() && admitted.run_id != live.run_id,
            "K-B1-10: a new run"
        );
        report("K-B1-10");

        // K-B1-11 (targeting on): unknown agent is still 404 agent_unknown
        match client
            .post_turn(
                &caps,
                session,
                &rf_message(
                    "rf-ghost-2",
                    Target::Named(AgentName::parse("ghost").expect("test: name")),
                    "hi",
                ),
            )
            .await
        {
            Err(PrxError::Api { status: 404, code: ApiCode::AgentUnknown, .. }) => {}
            other => panic!("K-B1-11 on: must be 404 agent_unknown, got {other:?}"),
        }
        report("K-B1-11 (targeting on)");

        // K-B1-13: a disabled agent and a retired agent are both 409 agent_disabled
        for name in ["off1", "gone"] {
            let target = Target::Named(AgentName::parse(name).expect("test: name"));
            match client.post_turn(&caps, session, &rf_message("rf-disabled-1", target, "hi")).await
            {
                Err(PrxError::Api { status: 409, code: ApiCode::AgentDisabled, .. }) => {}
                other => panic!("K-B1-13 {name}: must be 409 agent_disabled, got {other:?}"),
            }
        }
        report("K-B1-13");
        daemon.stop();
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// B2a (message_idempotency_v1) and B3 (targeted_agents_v1) rows, at the pin.
// ---------------------------------------------------------------------------------------------

/// A run or job id that PRX never issued.
const NEVER_ISSUED_ID: &str = "00000000-0000-4000-8000-0000000000ff";

/// Waits until the model stub has seen `count` requests (a turn is in flight at the model).
async fn wait_model_requests(daemon: &Daemon, stub: &ModelStub, count: usize) {
    let started = Instant::now();
    while stub.count() < count {
        if started.elapsed() >= TURN_DEADLINE {
            for name in ["daemon.err", "daemon.out"] {
                let log = std::fs::read_to_string(daemon.dir.path().join(name)).unwrap_or_default();
                let tail: Vec<&str> = log.lines().rev().take(30).collect();
                eprintln!("DIAG {name} tail (newest first): {tail:?}");
            }
            panic!("test: model stub did not see {count} request(s)");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// True for the typed `provider_not_ready` refusal of a turn or context post.
fn is_not_ready<T>(result: &Result<T, PrxError>) -> bool {
    matches!(
        result,
        Err(PrxError::ProviderNotReady {
            status: 503,
            reason: NotReadyReason::MissingProviderCredential
        })
    )
}

/// Asserts a typed API error with the given status and code.
#[allow(clippy::needless_pass_by_value)]
fn assert_api<T: std::fmt::Debug>(
    row: &str,
    result: Result<T, PrxError>,
    status: u16,
    code: ApiCode,
) {
    match result {
        Err(PrxError::Api { status: got, code: got_code, .. })
            if got == status && got_code == code => {}
        other => panic!("{row}: must be {status} {code:?}, got {other:?}"),
    }
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_b2a_turn_replay_conflict_main_key_and_cancel_of_ended_run() {
    bounded(async {
        // Named agents run on the stub (a Main turn without a credential fails before any model
        // request, so it cannot show a real failed run); Main is used only for the key-scope row.
        let stub = ModelStub::start_completing(Duration::ZERO).await;
        let mut daemon =
            Daemon::prepare_with_provider(&stub.provider(), "targeted_agents = true\n");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        client.create_session(&caps, RF_SESSION).await.expect("test: session");
        put_agent(&client, &caps, "fast1", &stub.provider(), true).await;
        let fast1 = Target::Named(AgentName::parse("fast1").expect("test: name"));
        let id = "rf-b2-turn-0001";

        // K-B2-1: the first admission is 202 without replay fields; the stub completes the turn.
        let first = client
            .post_turn(&caps, RF_SESSION, &rf_message(id, fast1.clone(), "replay me"))
            .await
            .expect("K-B2-1: first turn admitted");
        assert_eq!(first.disposition, TurnDisposition::Admitted, "K-B2-1: first admission");
        let job = wait_job_terminal(&client, &caps, &first.job_id).await;
        assert_eq!(
            job.status,
            JobState::Succeeded,
            "K-B2-1: the stub completes the turn; job error: {:?}; daemon: {:?}",
            job.error,
            daemon.error_lines()
        );
        report("K-B2-1");

        // K-B2-2: the same key and body answers the durable state and runs nothing.
        let (count_before, jobs_before) = (stub.count(), daemon_job_total(&daemon).await);
        // The live job reads failed before the durable terminal row is always visible: poll the
        // replay, bounded, and record how long the running answer lasted (finding, see report).
        let started = Instant::now();
        let replay = loop {
            let answer = client
                .post_turn(&caps, RF_SESSION, &rf_message(id, fast1.clone(), "replay me"))
                .await
                .expect("K-B2-2: replay answers");
            assert_eq!(answer.run_id, first.run_id, "K-B2-2: the original run id");
            if answer.disposition
                != (TurnDisposition::Replayed { status: RunState::Running, code: None })
            {
                break answer;
            }
            assert!(
                started.elapsed() < TURN_DEADLINE,
                "K-B2-2: replay stayed running; daemon: {:?}",
                daemon.error_lines()
            );
            tokio::time::sleep(SLOW_POLL_INTERVAL).await;
        };
        eprintln!("ROW K-B2-2 replay turned terminal after {:?}", started.elapsed());
        assert_eq!(
            replay.disposition,
            TurnDisposition::Replayed { status: RunState::Succeeded, code: None },
            "K-B2-2: succeeded, replayed; daemon: {:?}",
            daemon.error_lines()
        );
        assert_eq!(stub.count(), count_before, "K-B2-2: no model request for a replay");
        assert_eq!(daemon_job_total(&daemon).await, jobs_before, "K-B2-2: no second job");
        report("K-B2-2");

        // K-B2-3: the same key with another body is 409 idempotency_conflict and writes nothing.
        assert_api(
            "K-B2-3",
            client.post_turn(&caps, RF_SESSION, &rf_message(id, fast1.clone(), "other body")).await,
            409,
            ApiCode::IdempotencyConflict,
        );
        assert_eq!(daemon_job_total(&daemon).await, jobs_before, "K-B2-3: nothing admitted");
        report("K-B2-3");

        // K-B2-4: agent omitted and "main" are one key (raw body: the typed client omits agent).
        let main_id = "rf-b2-main-0002";
        let plain = rf_body("turn", Some(main_id));
        let (status, text) = daemon
            .raw_authorized(
                reqwest::Method::POST,
                &format!("/api/sessions/{RF_SESSION}/message"),
                None,
                Some(plain.clone()),
            )
            .await;
        assert_eq!(status, 202, "K-B2-4: first raw turn: {text}");
        let spelled = {
            let mut body = plain.clone();
            body["agent"] = Value::String("main".to_owned());
            body
        };
        let (status, text) = daemon
            .raw_authorized(
                reqwest::Method::POST,
                &format!("/api/sessions/{RF_SESSION}/message"),
                None,
                Some(spelled),
            )
            .await;
        let answer: Value = serde_json::from_str(&text).expect("test: replay body is JSON");
        eprintln!("ROW K-B2-4 raw replay with agent \"main\": {status} {text}");
        assert_eq!(
            (status, answer.get("replayed").and_then(Value::as_bool)),
            (200, Some(true)),
            "K-B2-4: agent \"main\" replays the omitted-agent key"
        );
        report("K-B2-4");

        // K-B2-5: cancel by run id of an ended run answers its terminal state.
        let ended = client
            .cancel_run(&caps, RF_SESSION, &first.run_id)
            .await
            .expect("K-B2-5: cancel of an ended run");
        assert_eq!(
            (ended.status, ended.code),
            (RunState::Succeeded, None),
            "K-B2-5: terminal state"
        );
        report("K-B2-5");

        // K-B2-6: an unknown run id is 404 run_unknown, never read as "not run".
        assert_api(
            "K-B2-6",
            client.cancel_run(&caps, RF_SESSION, NEVER_ISSUED_ID).await,
            404,
            ApiCode::RunUnknown,
        );
        report("K-B2-6");

        // K-B2-7: a job id PRX never issued: the uncoded 404 is a typed JobUnknown.
        let (status, text) = daemon
            .raw_authorized(
                reqwest::Method::POST,
                &format!("/api/jobs/{NEVER_ISSUED_ID}/cancel"),
                None,
                None,
            )
            .await;
        eprintln!("ROW K-B2-7 raw job cancel of a never-issued id: {status} {text}");
        assert_api(
            "K-B2-7",
            client.cancel_job(&caps, NEVER_ISSUED_ID).await,
            404,
            ApiCode::JobUnknown,
        );
        report("K-B2-7");
        daemon.stop();
    })
    .await;
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_b2a_running_replay_and_cancel_by_run_id() {
    bounded(async {
        let stub = ModelStub::start(Duration::from_secs(600)).await;
        let mut daemon =
            Daemon::prepare_with_provider(&stub.provider(), "targeted_agents = true\n");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        client.create_session(&caps, RF_SESSION).await.expect("test: session");
        put_agent(&client, &caps, "hold1", &stub.provider(), true).await;
        let hold1 = Target::Named(AgentName::parse("hold1").expect("test: name"));
        let id = "rf-b2-live-0001";
        let live = client
            .post_turn(&caps, RF_SESSION, &rf_message(id, hold1.clone(), "long turn"))
            .await
            .expect("test: live turn admitted");
        tokio::time::sleep(SLOW_POLL_INTERVAL).await;
        eprintln!("DIAG job {:?}", client.job_status(&caps, &live.job_id).await);
        wait_model_requests(&daemon, &stub, 1).await;

        // K-B2-8: a replay while the turn runs answers running, not session_busy; no new request.
        let replay = client
            .post_turn(&caps, RF_SESSION, &rf_message(id, hold1.clone(), "long turn"))
            .await
            .expect("K-B2-8: replay of a running turn answers");
        assert_eq!(replay.run_id, live.run_id, "K-B2-8: same run");
        assert_eq!(
            replay.disposition,
            TurnDisposition::Replayed { status: RunState::Running, code: None },
            "K-B2-8: running"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
        assert_eq!(stub.count(), 1, "K-B2-8: no second model request");
        report("K-B2-8");

        // K-B2-9: cancel by run id of a running turn: cancelling or cancelled; the job then ends.
        let cancel = client
            .cancel_run(&caps, RF_SESSION, &live.run_id)
            .await
            .expect("K-B2-9: cancel of a running turn");
        eprintln!("ROW K-B2-9 cancel answer: {cancel:?}");
        assert!(
            matches!(cancel.status, RunState::Cancelling | RunState::Cancelled),
            "K-B2-9: cancelling or cancelled, got {:?}",
            cancel.status
        );
        let ended = wait_job_terminal(&client, &caps, &live.job_id).await;
        eprintln!("ROW K-B2-9 job after cancel: {:?}", ended.status);
        report("K-B2-9");

        // K-B2-10: a replay of the cancelled turn answers cancelled and runs nothing.
        let after = client
            .post_turn(&caps, RF_SESSION, &rf_message(id, hold1.clone(), "long turn"))
            .await
            .expect("K-B2-10: replay of a cancelled turn answers");
        assert_eq!(
            after.disposition,
            TurnDisposition::Replayed { status: RunState::Cancelled, code: None },
            "K-B2-10: the cancelled state"
        );
        let settled = client
            .cancel_run(&caps, RF_SESSION, &live.run_id)
            .await
            .expect("K-B2-10: cancel of the ended run");
        assert_eq!(settled.status, RunState::Cancelled, "K-B2-10: the terminal state again");
        tokio::time::sleep(POLL_INTERVAL).await;
        assert_eq!(stub.count(), 1, "K-B2-10: a cancelled key never runs again");
        report("K-B2-10");
        daemon.stop();
    })
    .await;
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_b2a_crash_retry_and_interrupted_readback() {
    bounded(async {
        let stub = ModelStub::start(Duration::from_secs(600)).await;
        let mut daemon =
            Daemon::prepare_with_provider(&stub.provider(), "targeted_agents = true\n");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        client.create_session(&caps, RF_SESSION).await.expect("test: session");
        put_agent(&client, &caps, "hold1", &stub.provider(), true).await;
        let hold1 = Target::Named(AgentName::parse("hold1").expect("test: name"));
        let id = "rf-b2-crash-0001";
        let before = client
            .post_turn(&caps, RF_SESSION, &rf_message(id, hold1.clone(), "crash me"))
            .await
            .expect("test: turn admitted");
        wait_model_requests(&daemon, &stub, 1).await;

        // SIGKILL the daemon mid-turn (Child::kill), then start it on the same state directory.
        daemon.stop();
        daemon.start();
        daemon.wait_ready().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;

        // K-B2-11: the resend after the crash is a new attempt with attempt >= 2 and previous_run_id.
        let retry = client
            .post_turn(&caps, RF_SESSION, &rf_message(id, hold1.clone(), "crash me"))
            .await
            .expect("K-B2-11: resend after the crash");
        assert_eq!(
            retry.disposition,
            TurnDisposition::Restarted { attempt: 2, previous_run_id: before.run_id.clone() },
            "K-B2-11: attempt 2 names the interrupted run"
        );
        assert_ne!(retry.run_id, before.run_id, "K-B2-11: a new run id");
        report("K-B2-11");

        // K-B2-12: the interrupted run reads back as failed with code interrupted.
        let interrupted = client
            .cancel_run(&caps, RF_SESSION, &before.run_id)
            .await
            .expect("K-B2-12: the interrupted run answers");
        assert_eq!(
            (interrupted.status, interrupted.code),
            (RunState::Failed, Some(RunCode::Interrupted)),
            "K-B2-12: interrupted"
        );
        report("K-B2-12");

        // K-B2-13: the job of the interrupted run is gone after the restart: an uncoded 404 is
        // a contract error for job_status, never "no run happened".
        assert!(
            client.job_status(&caps, &before.job_id).await.is_err(),
            "K-B2-13: a job from before the restart is not readable"
        );
        report("K-B2-13");

        // K-B2-14: the replay now answers the new attempt, running.
        let replay = client
            .post_turn(&caps, RF_SESSION, &rf_message(id, hold1.clone(), "crash me"))
            .await
            .expect("K-B2-14: replay of the new attempt");
        assert_eq!(replay.run_id, retry.run_id, "K-B2-14: the new attempt's run");
        assert_eq!(
            replay.disposition,
            TurnDisposition::Replayed { status: RunState::Running, code: None },
            "K-B2-14: running"
        );
        report("K-B2-14");
        client.cancel_run(&caps, RF_SESSION, &retry.run_id).await.expect("test: cleanup cancel");
        daemon.stop();
    })
    .await;
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_b2a_context_replay_and_conflict() {
    bounded(async {
        let (mut daemon, _stub) = paired_rf_daemon("").await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        client.create_session(&caps, RF_SESSION).await.expect("test: session");
        let id = "rf-b2-ctx-0001";
        let marker = "ctx marker b2 one";
        let first = client
            .post_context(&caps, RF_SESSION, &rf_message(id, Target::Main, marker))
            .await
            .expect("K-B2-15: context recorded");
        assert!(!first.replayed, "K-B2-15: first answer carries no replay");

        // K-B2-15 (cont.): replay returns the original message id and adds no row and no job.
        let jobs = daemon_job_total(&daemon).await;
        let replay = client
            .post_context(&caps, RF_SESSION, &rf_message(id, Target::Main, marker))
            .await
            .expect("K-B2-15: replay of a context answers");
        assert!(replay.replayed && replay.message_id == first.message_id, "K-B2-15: {replay:?}");
        assert_eq!(daemon_job_total(&daemon).await, jobs, "K-B2-15: no job for a context");
        let raw = daemon
            .raw_authorized(
                reqwest::Method::GET,
                &format!("/api/sessions/{RF_SESSION}/messages"),
                None,
                None,
            )
            .await;
        let rows: Vec<Value> = serde_json::from_str(&raw.1).expect("test: history is JSON");
        let copies = rows
            .iter()
            .filter(|row| {
                row.get("content").and_then(Value::as_str).is_some_and(|c| c.contains(marker))
            })
            .count();
        assert_eq!(copies, 1, "K-B2-15: one row for the key, not two");
        report("K-B2-15");

        // K-B2-16: the same key with another body is 409 idempotency_conflict.
        assert_api(
            "K-B2-16",
            client
                .post_context(&caps, RF_SESSION, &rf_message(id, Target::Main, "other context"))
                .await,
            409,
            ApiCode::IdempotencyConflict,
        );
        report("K-B2-16");
        daemon.stop();
    })
    .await;
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_b3_partitioned_reads_and_capabilities() {
    bounded(async {
        let fast = ModelStub::start(Duration::ZERO).await;
        let mut daemon =
            Daemon::prepare_with_provider(&fast.provider(), "targeted_agents = true\n");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;

        // K-B3-0: the advertised set at the pin with targeting on, including stream frames,
        // run approvals, and host bootstrap.
        for token in [
            TARGETED_AGENTS_V1,
            MESSAGE_IDEMPOTENCY_V1,
            MESSAGE_DELETE_V1,
            HISTORY_ERASE_V1,
            AGENT_MEMORY_PURGE_V1,
            AGENT_LIMITS_V1,
            SYNC_SNAPSHOT_V1,
            SYNC_WS_V1,
            STREAM_FRAMES_V1,
            RUN_APPROVALS_V1,
            HOST_BOOTSTRAP_V1,
        ] {
            assert!(caps.has(token), "K-B3-0: {token} is advertised");
        }
        report("K-B3-0");

        let session = "rf-contract-session-0003";
        client.create_session(&caps, session).await.expect("test: session");
        put_agent(&client, &caps, "worker", &fast.provider(), true).await;
        put_agent(&client, &caps, "other", &fast.provider(), true).await;
        put_agent(&client, &caps, "idle1", &fast.provider(), true).await;
        let worker = Target::Named(AgentName::parse("worker").expect("test: name"));
        let other = Target::Named(AgentName::parse("other").expect("test: name"));
        let n1 = "b3 partition marker N1";
        let n2 = "b3 partition marker N2";
        let main_turn = client
            .post_turn(&caps, session, &rf_message("rf-b3-main-1", Target::Main, "main turn"))
            .await
            .expect("test: main turn admitted");
        wait_job_terminal(&client, &caps, &main_turn.job_id).await;
        client
            .post_context(&caps, session, &rf_message("rf-b3-n1-1", worker.clone(), n1))
            .await
            .expect("test: context for N1");
        client
            .post_context(&caps, session, &rf_message("rf-b3-n2-1", other.clone(), n2))
            .await
            .expect("test: context for N2");

        let has = |rows: &[HistoryRow], marker: &str| {
            rows.iter().any(|row| row.content().is_some_and(|text| text.contains(marker)))
        };
        let all = client.session_messages(&caps, session, None).await.expect("K-B3-1: read all");
        assert!(all.iter().all(|row| matches!(row.agent, Target::Main | Target::Named(_))));
        assert!(has(&all, n1) && has(&all, n2), "K-B3-1: every partition is readable unfiltered");
        assert!(all.iter().any(|row| row.agent == Target::Main), "K-B3-1: Main rows exist");
        report("K-B3-1");

        // K-B3-2: ?agent=<N1> keeps N1 rows only.
        let only_n1 = client.session_messages(&caps, session, Some(&worker)).await.expect("K-B3-2");
        assert!(!only_n1.is_empty() && only_n1.iter().all(|row| row.agent == worker), "K-B3-2");
        assert!(has(&only_n1, n1) && !has(&only_n1, n2), "K-B3-2: N2 context is not in N1");
        report("K-B3-2");

        // K-B3-3: ?agent=main keeps Main rows; neither N1 nor N2 context appears.
        let main_rows =
            client.session_messages(&caps, session, Some(&Target::Main)).await.expect("K-B3-3");
        assert!(
            !main_rows.is_empty()
                && main_rows.iter().all(|row| row.agent == Target::Main)
                && !has(&main_rows, n1)
                && !has(&main_rows, n2),
            "K-B3-3: a context of N1 or N2 is not returned for Main"
        );
        report("K-B3-3");

        // K-B3-4: N2's partition does not hold N1's context.
        let only_n2 = client.session_messages(&caps, session, Some(&other)).await.expect("K-B3-4");
        assert!(has(&only_n2, n2) && !has(&only_n2, n1), "K-B3-4");
        report("K-B3-4");

        // K-B3-5: a configured agent with no row yet gives an empty list.
        let idle = Target::Named(AgentName::parse("idle1").expect("test: name"));
        assert!(
            client.session_messages(&caps, session, Some(&idle)).await.expect("K-B3-5").is_empty(),
            "K-B3-5: no row, empty list"
        );
        report("K-B3-5");

        // K-B3-6: an unknown name is 404 agent_unknown.
        let ghost = Target::Named(AgentName::parse("ghost").expect("test: name"));
        assert_api(
            "K-B3-6",
            client.session_messages(&caps, session, Some(&ghost)).await,
            404,
            ApiCode::AgentUnknown,
        );
        report("K-B3-6");

        // K-B3-7: a session that does not exist is 404 session_unknown.
        let (status, text) = daemon
            .raw_authorized(
                reqwest::Method::GET,
                "/api/sessions/rf-no-such-session-0001/messages",
                None,
                None,
            )
            .await;
        // Changed at 4f1a8bc05 (was the uncoded 404 at 296a83367, D2): a key-shaped id that was
        // never created is the coded `session_unknown`, for reading and for sending.
        eprintln!("ROW K-B3-7 raw unknown session: {status} {text}");
        assert_eq!(status, 404, "K-B3-7: unknown session is 404");
        assert_eq!(error_code(&text).as_deref(), Some("session_unknown"), "K-B3-7 raw code");
        assert_api(
            "K-B3-7 read",
            client.session_messages(&caps, "rf-no-such-session-0001", None).await,
            404,
            ApiCode::SessionUnknown,
        );
        assert_api(
            "K-B3-7 send turn",
            client
                .post_turn(
                    &caps,
                    "rf-no-such-session-0001",
                    &rf_message("rf-b3-unknown-1", Target::Main, "unknown session"),
                )
                .await,
            404,
            ApiCode::SessionUnknown,
        );
        assert_api(
            "K-B3-7 send context",
            client
                .post_context(
                    &caps,
                    "rf-no-such-session-0001",
                    &rf_message("rf-b3-unknown-2", Target::Main, "unknown session"),
                )
                .await,
            404,
            ApiCode::SessionUnknown,
        );
        report("K-B3-7");

        // K-B3-8: the session list of the paired owner names this session (the cross-owner
        // half needs a second install: not testable with one daemon).
        let listed = sessions_list(&daemon).await;
        assert!(
            listed.iter().any(|row| row.get("session_id").and_then(Value::as_str) == Some(session)),
            "K-B3-8: the owner's session is listed"
        );
        report("K-B3-8");
        daemon.stop();
    })
    .await;
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_op3_context_and_turn_with_no_credential_and_k_op2_storage_refusal() {
    bounded(async {
        // Open point 3: a daemon with no provider credential. Does provider admission run before
        // the context branch? (Source reading: yes.)
        let mut daemon = Daemon::prepare_without_credential("");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        client.create_session(&caps, RF_SESSION).await.expect("test: session");
        let context = client
            .post_context(&caps, RF_SESSION, &rf_message("rf-op3-ctx-1", Target::Main, "op3"))
            .await;
        eprintln!("ROW K-OP3-1 context with no credential: {context:?}");
        assert!(is_not_ready(&context), "K-OP3-1: a context post is refused 503 before the branch");
        report("K-OP3-1");

        let turn = client
            .post_turn(&caps, RF_SESSION, &rf_message("rf-op3-turn-1", Target::Main, "op3"))
            .await;
        assert!(is_not_ready(&turn), "K-OP3-2: a turn is refused 503");
        report("K-OP3-2");
        assert_eq!(daemon_job_total(&daemon).await, 0, "K-OP3-2: no job was created");
        daemon.stop();
    })
    .await;
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_op2_storage_refusal_when_user_messages_are_not_recorded() {
    bounded(async {
        let (mut daemon, stub) =
            paired_rf_daemon("[memory.events]\nrecord_user_messages = false\n").await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        client.create_session(&caps, RF_SESSION).await.expect("test: session");
        let jobs = daemon_job_total(&daemon).await;
        let model_before = stub.count();

        // Changed at 4f1a8bc05 (was D1: a context answered 200 and was stored). With user-message
        // recording off, a turn and a context are both refused 500 storage_unavailable.
        let turn = client
            .post_turn(&caps, RF_SESSION, &rf_message("rf-op2-turn-1", Target::Main, "op2"))
            .await;
        eprintln!("ROW K-OP2-1 turn with user messages not recorded: {turn:?}");
        assert!(
            matches!(turn, Err(PrxError::OutcomeUnknown { http_status: Some(500) })),
            "K-OP2-1: 500 storage_unavailable is typed as an unknown outcome, got {turn:?}"
        );
        let (raw_status, raw_text) = daemon
            .raw_authorized(
                reqwest::Method::POST,
                &format!("/api/sessions/{RF_SESSION}/message"),
                None,
                Some(rf_body("turn", Some("rf-op2-turn-2"))),
            )
            .await;
        eprintln!("ROW K-OP2-1 raw turn answer: {raw_status} {raw_text}");
        assert_eq!(raw_status, 500, "K-OP2-1 raw status");
        assert_eq!(error_code(&raw_text).as_deref(), Some("storage_unavailable"), "K-OP2-1 raw");
        report("K-OP2-1");

        let context = client
            .post_context(&caps, RF_SESSION, &rf_message("rf-op2-ctx-1", Target::Main, "op2"))
            .await;
        eprintln!("ROW K-OP2-2 context with user messages not recorded: {context:?}");
        assert!(
            matches!(context, Err(PrxError::OutcomeUnknown { http_status: Some(500) })),
            "K-OP2-2: a context is refused 500 storage_unavailable, got {context:?}"
        );
        let (raw_status, raw_text) = daemon
            .raw_authorized(
                reqwest::Method::POST,
                &format!("/api/sessions/{RF_SESSION}/message"),
                None,
                Some(rf_body("context", Some("rf-op2-ctx-2"))),
            )
            .await;
        eprintln!("ROW K-OP2-2 raw context answer: {raw_status} {raw_text}");
        assert_eq!(raw_status, 500, "K-OP2-2 raw status");
        assert_eq!(error_code(&raw_text).as_deref(), Some("storage_unavailable"), "K-OP2-2 raw");
        let (_, history) = daemon
            .raw_authorized(
                reqwest::Method::GET,
                &format!("/api/sessions/{RF_SESSION}/messages"),
                None,
                None,
            )
            .await;
        let rows: Vec<Value> = serde_json::from_str(&history).expect("test: history is JSON");
        assert!(rows.is_empty(), "K-OP2-2: nothing is stored, got {} row(s)", rows.len());
        assert_eq!(daemon_job_total(&daemon).await, jobs, "K-OP2: no job admitted");
        assert_eq!(stub.count(), model_before, "K-OP2: no model request");
        report("K-OP2-2");
        daemon.stop();
    })
    .await;
}

#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_op1_agent_put_with_custom_endpoint_accepts_without_confirmation() {
    bounded(async {
        let stub = ModelStub::start(Duration::ZERO).await;
        let mut daemon = Daemon::prepare_with_provider("openrouter", &priced(&stub.provider(), ""));
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        let name = AgentName::parse("custom1").expect("test: name");
        let cfg = config(&stub.provider(), "stub-model", None, Tools::All, true);
        let rev = list_revision(&client, &caps).await;

        // Agent management accepts custom endpoints without high-risk confirmation.
        let created = client.put(&caps, &name, &cfg, &rev, false).await;
        eprintln!("ROW K-OP1-1 PUT custom endpoint without confirmation: {created:?}");
        let created = created.expect("K-OP1-1: unconfirmed agent PUT succeeds");
        assert_eq!(created.kind, PutKind::Created, "K-OP1-1: first PUT creates the agent");
        let raw_body = serde_json::json!({
            "provider": cfg.provider, "model": "stub-model", "autonomy": "full",
            "tools": ["*"], "enabled": true
        });
        let (status, text) = daemon
            .raw_authorized(
                reqwest::Method::PUT,
                &format!("/api/agents/{}", name.as_str()),
                Some(created.readback.revision.as_str()),
                Some(raw_body),
            )
            .await;
        eprintln!("ROW K-OP1-1 raw answer: {status} {text}");
        assert_eq!(status, 200, "K-OP1-1: raw unconfirmed replacement succeeds");
        report("K-OP1-1");

        // The apply helper succeeds directly for agent changes.
        match client.apply_agent(&caps, &name, &cfg, None).await {
            Ok(ApplyOutcome::Applied(outcome)) => {
                assert_eq!(outcome.readback.config, cfg, "K-OP1-2: intended config is stored");
            }
            other => panic!("K-OP1-2: apply must succeed without confirmation, got {other:?}"),
        }
        report("K-OP1-2");

        // The optional confirmation flag remains accepted for agent changes.
        let revision = list_revision(&client, &caps).await;
        let applied = client.put(&caps, &name, &cfg, &revision, true).await;
        assert!(applied.is_ok(), "K-OP1-3: confirmed agent PUT also applies: {applied:?}");
        report("K-OP1-3");
        daemon.stop();
    })
    .await;
}

/// K-B2-17: a turn that ends `failed` (provider answers 500) replays as `failed`, and a resend
/// runs nothing. (Was an observed deviation at the first run; it passes with the state directory
/// and TMPDIR under a private path.)
#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_b2a_failed_turn_replay_is_failed() {
    bounded(async {
        let stub = ModelStub::start(Duration::ZERO).await;
        let mut daemon =
            Daemon::prepare_with_provider(&stub.provider(), "targeted_agents = true\n");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        client.create_session(&caps, RF_SESSION).await.expect("test: session");
        put_agent(&client, &caps, "fail1", &stub.provider(), true).await;
        let fail1 = Target::Named(AgentName::parse("fail1").expect("test: name"));
        let id = "rf-b2-fail-0001";
        let first = client
            .post_turn(&caps, RF_SESSION, &rf_message(id, fail1.clone(), "fail me"))
            .await
            .expect("test: turn admitted");
        let job = wait_job_terminal(&client, &caps, &first.job_id).await;
        assert_eq!(job.status, JobState::Failed, "F-1: the stub answers 500, the job fails");
        wait_model_requests(&daemon, &stub, 1).await;
        let jobs_before = daemon_job_total(&daemon).await;
        let started = Instant::now();
        let mut replay = client
            .post_turn(&caps, RF_SESSION, &rf_message(id, fail1.clone(), "fail me"))
            .await
            .expect("F-2: replay answers");
        while started.elapsed() < TURN_DEADLINE
            && replay.disposition
                == (TurnDisposition::Replayed { status: RunState::Running, code: None })
        {
            tokio::time::sleep(SLOW_POLL_INTERVAL).await;
            replay = client
                .post_turn(&caps, RF_SESSION, &rf_message(id, fail1.clone(), "fail me"))
                .await
                .expect("F-2: replay answers");
        }
        assert_eq!(
            replay.disposition,
            TurnDisposition::Replayed { status: RunState::Failed, code: None },
            "K-B2-17: failed, replayed; waited {:?}; daemon: {:?}",
            started.elapsed(),
            daemon.error_lines()
        );
        assert_eq!(
            daemon_job_total(&daemon).await,
            jobs_before,
            "K-B2-17: the failed key admits no job"
        );
        report("K-B2-17");
        daemon.stop();
    })
    .await;
}

/// Live assistant rows of the rf session (the stub's reply text is "stub reply").
async fn assistant_replies(client: &PrxClient, caps: &Capabilities) -> usize {
    client
        .session_messages(caps, RF_SESSION, None)
        .await
        .expect("test: history reads")
        .iter()
        .filter(|row| {
            matches!(&row.body, RowBody::Text { role, content }
                if role == "assistant" && content.contains("stub reply"))
        })
        .count()
}

/// REC-ANCESTOR-1 (replaces PIN-296A-STATE, which asserted the 296a83367 behaviour). A state dir
/// under a group-writable ancestor. At 4f1a8bc05 PRX refuses the recovery key: a new turn answers
/// `500 storage_unavailable` with `reason: recovery_unavailable` and writes nothing, and a context
/// still answers `200` with its replay. At 296a83367 the same setup was admitted and the job
/// Succeeded (observed then, see the report).
#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn rec_ancestor_group_writable_refuses_turns_context_still_answers() {
    bounded(async {
        use std::os::unix::fs::PermissionsExt;
        let base = state_base().join("gw-probe");
        std::fs::create_dir_all(&base).expect("test: group-writable probe base");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o775))
            .expect("test: chmod probe base");
        let stub = ModelStub::start_completing(Duration::ZERO).await;
        let mut daemon =
            Daemon::prepare_unchecked_in(&base, &stub.provider(), "targeted_agents = true\n");
        // prepare_in sets the base to 0700 ("private by construction"), which made the earlier
        // version of this row a private ancestor, not a group-writable one. Set 0775 again.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o775))
            .expect("test: chmod probe base after the harness set it private");
        let mode = std::fs::metadata(&base).expect("test: stat probe base").permissions().mode();
        assert_eq!(mode & 0o777, 0o775, "REC-ANCESTOR-1: the probe base is group-writable");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        client.create_session(&caps, RF_SESSION).await.expect("test: session");
        let jobs = daemon_job_total(&daemon).await;

        // REC-ANCESTOR-1: <state>/gw-probe (0775) is on the physical path to <cfg>/workspace/memory.
        // PRX refuses the recovery key: a turn is 500 storage_unavailable with reason
        // recovery_unavailable, no job starts and no model request is made.
        let turn = client
            .post_turn(&caps, RF_SESSION, &rf_message("rf-gw-turn-0001", Target::Main, "probe"))
            .await;
        eprintln!("ROW REC-ANCESTOR-1 turn: {turn:?}");
        assert!(
            matches!(turn, Err(PrxError::OutcomeUnknown { http_status: Some(500) })),
            "REC-ANCESTOR-1: refused 500, got {turn:?}"
        );
        let (status, text) = daemon
            .raw_authorized(
                reqwest::Method::POST,
                &format!("/api/sessions/{RF_SESSION}/message"),
                None,
                Some(rf_body("turn", Some("rf-gw-turn-0002"))),
            )
            .await;
        eprintln!("ROW REC-ANCESTOR-1 raw: {status} {text}");
        assert_eq!(status, 500, "REC-ANCESTOR-1 raw status");
        assert_eq!(error_code(&text).as_deref(), Some("storage_unavailable"), "REC-ANCESTOR-1");
        assert_eq!(error_reason(&text).as_deref(), Some("recovery_unavailable"), "REC-ANCESTOR-1");
        assert_eq!(daemon_job_total(&daemon).await, jobs, "REC-ANCESTOR-1: no job");
        assert_eq!(stub.count(), 0, "REC-ANCESTOR-1: no model request");
        report("REC-ANCESTOR-1");

        // REC-ANCESTOR-2: a context answers 200 and its replay is replayed:true with the same id.
        let context = client
            .post_context(&caps, RF_SESSION, &rf_message("rf-gw-ctx-0001", Target::Main, "rec ctx"))
            .await
            .expect("REC-ANCESTOR-2: context answers");
        assert!(!context.replayed, "REC-ANCESTOR-2: first answer");
        let replay = client
            .post_context(&caps, RF_SESSION, &rf_message("rf-gw-ctx-0001", Target::Main, "rec ctx"))
            .await
            .expect("REC-ANCESTOR-2: replay answers");
        assert!(
            replay.replayed && replay.message_id == context.message_id,
            "REC-ANCESTOR-2: replay of the context: {replay:?}"
        );
        report("REC-ANCESTOR-2");
        daemon.stop();
        drop(daemon);
        let _ = std::fs::remove_dir_all(&base);
    })
    .await;
}

/// REC-CFG-1 (item 5 of the repin card): the daemon runs with `OPENPRX_CONFIG_DIR=<dir>/cfg` and
/// `OPENPRX_WORKSPACE=<dir>/workspace`; since PRX b004c7ac the workspace is `OPENPRX_WORKSPACE`, so
/// the group-writable directory is `<dir>/workspace` (the one the gateway log prints), on the
/// physical path to `<dir>/workspace/memory`. Set after the state is built, so only it is 0775.
#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn rec_cfg_workspace_group_writable_refuses_turns() {
    bounded(async {
        use std::os::unix::fs::PermissionsExt;
        let stub = ModelStub::start_completing(Duration::ZERO).await;
        let mut daemon = Daemon::prepare_unchecked_in(&state_base(), &stub.provider(), "");
        // OPENPRX_WORKSPACE is <dir>/workspace (created 0700 by the harness); make that one 0775.
        let workspace = daemon.dir.path().join("workspace");
        std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o775))
            .expect("test: chmod workspace");
        let mode =
            std::fs::metadata(&workspace).expect("test: stat workspace").permissions().mode();
        assert_eq!(mode & 0o777, 0o775, "REC-CFG-1: the workspace PRX uses is group-writable");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        client.create_session(&caps, RF_SESSION).await.expect("test: session");
        let (status, text) = daemon
            .raw_authorized(
                reqwest::Method::POST,
                &format!("/api/sessions/{RF_SESSION}/message"),
                None,
                Some(rf_body("turn", Some("rf-cfg-turn-0001"))),
            )
            .await;
        eprintln!("ROW REC-CFG-1 raw turn: {status} {text}; daemon: {:?}", daemon.error_lines());
        assert_eq!(status, 500, "REC-CFG-1 raw status");
        assert_eq!(error_code(&text).as_deref(), Some("storage_unavailable"), "REC-CFG-1 code");
        assert_eq!(error_reason(&text).as_deref(), Some("recovery_unavailable"), "REC-CFG-1");
        assert_eq!(stub.count(), 0, "REC-CFG-1: no model request");
        report("REC-CFG-1");
        daemon.stop();
    })
    .await;
}

/// K-DEL-6..10: the reply of one run, an unknown run, a batch, an empty batch and a context
/// delete, on the rf session. Split out of the K-DEL row to keep it within the lint limit.
async fn del_reply_and_batches(client: &PrxClient, caps: &Capabilities) {
    // K-DEL-6: the reply of one run goes; its input stays; a repeat answers the same.
    let two = client
        .post_turn(caps, RF_SESSION, &rf_message("rf-del-2", Target::Main, "del marker two"))
        .await
        .expect("test: turn two admitted");
    let two_job = wait_job_terminal(client, caps, &two.job_id).await;
    assert_eq!(two_job.status, JobState::Succeeded, "K-DEL-6 precondition: {:?}", two_job.error);
    assert!(assistant_replies(client, caps).await >= 1, "K-DEL-6 precondition: a reply");
    let reply = client
        .delete_reply(caps, RF_SESSION, &two.run_id, ForgetWrites::Plain)
        .await
        .expect("K-DEL-6");
    assert_eq!(reply.run_id, two.run_id, "K-DEL-6: names the run");
    client
        .delete_reply(caps, RF_SESSION, &two.run_id, ForgetWrites::Plain)
        .await
        .expect("K-DEL-6: repeat");
    assert_eq!(assistant_replies(client, caps).await, 0, "K-DEL-6: no reply left");
    let rows = client.session_messages(caps, RF_SESSION, None).await.expect("K-DEL-6 read");
    assert!(
        rows.iter().any(|row| row.content().is_some_and(|text| text.contains("del marker two"))),
        "K-DEL-6: the input stays"
    );
    report("K-DEL-6");

    // K-DEL-7: an unknown run is 404 run_unknown.
    assert_api(
        "K-DEL-7",
        client
            .delete_reply(
                caps,
                RF_SESSION,
                "0f3c2a1e-0000-4000-8000-0000000000ff",
                ForgetWrites::Plain,
            )
            .await,
        404,
        ApiCode::RunUnknown,
    );
    report("K-DEL-7");

    // K-DEL-8: a batch with one live and one unknown id answers in request order.
    let items = client
        .delete_messages(
            caps,
            RF_SESSION,
            &["rf-del-2".to_owned(), "rf-del-none-2".to_owned()],
            None,
            ForgetWrites::Plain,
        )
        .await
        .expect("K-DEL-8");
    match items.as_slice() {
        [BatchItem::Deleted(first), BatchItem::Refused { message_id, code }] => {
            assert_eq!(first.message_id, "rf-del-2", "K-DEL-8: first id");
            assert_eq!(message_id, "rf-del-none-2", "K-DEL-8: second id");
            assert_eq!(*code, ApiCode::MessageUnknown, "K-DEL-8: code");
        }
        other => panic!("K-DEL-8: unexpected batch answer {other:?}"),
    }
    report("K-DEL-8");

    // K-DEL-9: an empty batch is refused 400 field_invalid.
    assert_api(
        "K-DEL-9",
        client.delete_messages(caps, RF_SESSION, &[], None, ForgetWrites::Plain).await,
        400,
        ApiCode::FieldInvalid,
    );
    report("K-DEL-9");

    // K-DEL-10: a context message deletes with no runs.
    client
        .post_context(caps, RF_SESSION, &rf_message("rf-del-ctx-1", Target::Main, "del ctx"))
        .await
        .expect("test: context recorded");
    let ctx = client
        .delete_message(caps, RF_SESSION, "rf-del-ctx-1", None, ForgetWrites::Plain)
        .await
        .expect("K-DEL-10");
    assert_eq!(ctx.agents, vec![AgentRuns { agent: Target::Main, runs: Vec::new(), forget: None }]);
    report("K-DEL-10");
}

/// K-DEL: message deletes at 4f1a8bc05 (`message_delete_v1`): a message, its replay, a repeat,
/// the reply of one run, a batch, a context, and the job result of a deleted run.
#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_del_message_reply_and_batch_deletes() {
    bounded(async {
        const DEL_TEXT: &str = "del marker one";
        let stub = ModelStub::start_completing(Duration::ZERO).await;
        let mut daemon =
            Daemon::prepare_with_provider(&stub.provider(), "targeted_agents = true\n");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        assert!(caps.has(MESSAGE_DELETE_V1), "K-DEL-0: message_delete_v1 is advertised");
        report("K-DEL-0");
        client.create_session(&caps, RF_SESSION).await.expect("test: session");

        let one = client
            .post_turn(&caps, RF_SESSION, &rf_message("rf-del-1", Target::Main, DEL_TEXT))
            .await
            .expect("test: turn one admitted");
        let one_job = wait_job_terminal(&client, &caps, &one.job_id).await;
        assert_eq!(one_job.status, JobState::Succeeded, "K-DEL precondition: {:?}", one_job.error);

        // K-DEL-1: the answer names Main and the run whose rows were deleted.
        let deleted = client
            .delete_message(&caps, RF_SESSION, "rf-del-1", None, ForgetWrites::Plain)
            .await
            .expect("K-DEL-1: delete answers");
        assert_eq!(
            deleted.agents,
            vec![AgentRuns { agent: Target::Main, runs: vec![one.run_id.clone()], forget: None }],
            "K-DEL-1: agents"
        );
        eprintln!("ROW K-DEL-1 answer: {deleted:?}");
        report("K-DEL-1");

        // K-DEL-2: the row is a tombstone, the text is gone, and the raw shape is the four keys.
        let rows = client.session_messages(&caps, RF_SESSION, None).await.expect("K-DEL-2");
        assert!(rows.iter().any(|row| row.body == RowBody::Deleted), "K-DEL-2: a tombstone");
        assert!(
            !rows.iter().any(|row| row.content().is_some_and(|text| text.contains(DEL_TEXT))),
            "K-DEL-2: the deleted text is not read back"
        );
        let (_, raw) = daemon
            .raw_authorized(
                reqwest::Method::GET,
                &format!("/api/sessions/{RF_SESSION}/messages"),
                None,
                None,
            )
            .await;
        let raw_rows: Vec<Value> = serde_json::from_str(&raw).expect("test: history JSON");
        assert!(
            raw_rows.iter().any(|row| {
                row.get("deleted") == Some(&Value::Bool(true))
                    && row.as_object().is_some_and(|object| object.len() == 4)
            }),
            "K-DEL-2 raw: tombstone is exactly message_id, agent, deleted, timestamp: {raw}"
        );
        report("K-DEL-2");

        // K-DEL-3: a repeat answers the same 200.
        let again = client
            .delete_message(&caps, RF_SESSION, "rf-del-1", None, ForgetWrites::Plain)
            .await
            .expect("K-DEL-3: repeat answers");
        assert_eq!(again, deleted, "K-DEL-3");
        report("K-DEL-3");

        // K-DEL-4: a resend of the deleted key is 409 message_deleted; nothing runs.
        let jobs = daemon_job_total(&daemon).await;
        let model = stub.count();
        let resend = client
            .post_turn(&caps, RF_SESSION, &rf_message("rf-del-1", Target::Main, DEL_TEXT))
            .await;
        assert_api("K-DEL-4", resend, 409, ApiCode::MessageDeleted);
        assert_eq!(daemon_job_total(&daemon).await, jobs, "K-DEL-4: no job");
        assert_eq!(stub.count(), model, "K-DEL-4: no model request");
        report("K-DEL-4");

        // K-DEL-5: an id with no record in this session is 404 message_unknown.
        assert_api(
            "K-DEL-5",
            client
                .delete_message(&caps, RF_SESSION, "rf-del-none-1", None, ForgetWrites::Plain)
                .await,
            404,
            ApiCode::MessageUnknown,
        );
        report("K-DEL-5");

        del_reply_and_batches(&client, &caps).await;

        // K-DEL-11: the job of a deleted run reads result {"deleted":true}.
        let job = client.job_status(&caps, &one.job_id).await.expect("K-DEL-11: job reads");
        assert_eq!(job.result, Some(serde_json::json!({ "deleted": true })), "K-DEL-11");
        report("K-DEL-11");
        daemon.stop();
    })
    .await;
}

/// K-DEL-12: the reply of a running run is `409 run_active` until it is cancelled.
#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_del_running_reply_is_run_active() {
    bounded(async {
        let stub = ModelStub::start(Duration::from_secs(20)).await;
        let mut daemon = Daemon::prepare_with_provider(&stub.provider(), "");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        client.create_session(&caps, RF_SESSION).await.expect("test: session");
        let turn = client
            .post_turn(&caps, RF_SESSION, &rf_message("rf-del-run-1", Target::Main, "held"))
            .await
            .expect("test: turn admitted");
        wait_model_requests(&daemon, &stub, 1).await;
        assert_api(
            "K-DEL-12",
            client.delete_reply(&caps, RF_SESSION, &turn.run_id, ForgetWrites::Plain).await,
            409,
            ApiCode::RunActive,
        );
        report("K-DEL-12");
        client.cancel_run(&caps, RF_SESSION, &turn.run_id).await.expect("test: cancel");
        wait_job_terminal(&client, &caps, &turn.job_id).await;
        daemon.stop();
    })
    .await;
}

fn zero_counts() -> ForgetCounts {
    ForgetCounts { created: 0, touched: 0 }
}

/// The forget report of the one Main partition.
fn main_forget(row: &str, deleted: &ramflux_prx_client::MessageDeleted) -> ForgetReport {
    match deleted.agents.as_slice() {
        [agent] if agent.agent == Target::Main => {
            agent.forget.expect("test: a forget answer carries a report")
        }
        other => panic!("{row}: one Main partition, got {other:?}"),
    }
}

/// K-FW-1..3: erase-for-everyone with the token returns counts and replays them; without the
/// token the delete is plain and the caller is told tool-written memory was not forgotten.
/// The stub turn writes no memory and no document, so both count pairs are zero and
/// `writes_traceable` is true (the run starts after write provenance).
#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_fw_erase_counts_replay_and_plain_without_the_token() {
    bounded(async {
        let stub = ModelStub::start_completing(Duration::ZERO).await;
        let mut daemon =
            Daemon::prepare_with_provider(&stub.provider(), "targeted_agents = true\n");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        assert!(caps.has(MESSAGE_FORGET_WRITES_V1), "K-FW-0: the token is advertised");
        report("K-FW-0");
        client.create_session(&caps, RF_SESSION).await.expect("test: session");

        let turn = client
            .post_turn(&caps, RF_SESSION, &rf_message("rf-fw-1", Target::Main, "forget marker"))
            .await
            .expect("test: turn admitted");
        let job = wait_job_terminal(&client, &caps, &turn.job_id).await;
        assert_eq!(job.status, JobState::Succeeded, "K-FW-1 precondition: {:?}", job.error);
        let erased = client.erase_for_everyone(&caps, RF_SESSION, "rf-fw-1").await.expect("K-FW-1");
        assert_eq!(erased.notice, None, "K-FW-1: a forget that is accepted has no notice");
        let counted = main_forget("K-FW-1", &erased.deleted);
        assert!(
            !counted.pending && counted.writes_traceable,
            "K-FW-1: settled and traceable, got {counted:?}"
        );
        let forgotten = counted.forgotten.expect("K-FW-1: counts");
        assert_eq!(forgotten.memories, zero_counts(), "K-FW-1: the stub writes no memory");
        assert_eq!(forgotten.documents, zero_counts(), "K-FW-1: the stub writes no document");
        assert_eq!(erased.deleted.agents[0].runs, vec![turn.run_id.clone()], "K-FW-1: the run");
        report("K-FW-1");

        let again = client.erase_for_everyone(&caps, RF_SESSION, "rf-fw-1").await.expect("K-FW-2");
        assert_eq!(again.deleted, erased.deleted, "K-FW-2: replay returns the first counts");
        assert_eq!(again.notice, None, "K-FW-2: replay adds no notice");
        report("K-FW-2");

        client
            .post_turn(&caps, RF_SESSION, &rf_message("rf-fw-2", Target::Main, "plain marker"))
            .await
            .expect("test: second turn admitted");
        let mut bare = caps.clone();
        assert!(
            bare.capabilities.remove(MESSAGE_FORGET_WRITES_V1),
            "test: the token was advertised"
        );
        let plain = client.erase_for_everyone(&bare, RF_SESSION, "rf-fw-2").await.expect("K-FW-3");
        assert_eq!(plain.notice, Some(EraseNotice::MemoryNotForgotten), "K-FW-3: notice");
        assert_eq!(
            plain.notice.expect("K-FW-3").user_text(),
            "tool-written memory was not forgotten",
            "K-FW-3: the sentence the caller shows"
        );
        assert!(
            plain.deleted.agents.iter().all(|agent| agent.forget.is_none()),
            "K-FW-3: a plain delete carries no forget fields: {:?}",
            plain.deleted
        );
        report("K-FW-3");
        daemon.stop();
    })
    .await;
}

/// K-FW-4: erasing the message of a run that is still in flight asks to forget and gets the
/// pending marker (`forgotten: null`, `forget_pending: true`). A reply delete of that same run
/// stays `409 run_active`; this row is the message route.
#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_fw_running_erase_is_pending() {
    bounded(async {
        let stub = ModelStub::start(Duration::from_secs(20)).await;
        let mut daemon = Daemon::prepare_with_provider(&stub.provider(), "");
        daemon.start();
        daemon.wait_ready().await;
        daemon.pair().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        client.create_session(&caps, RF_SESSION).await.expect("test: session");
        let turn = client
            .post_turn(&caps, RF_SESSION, &rf_message("rf-fw-run", Target::Main, "held forget"))
            .await
            .expect("test: turn admitted");
        wait_model_requests(&daemon, &stub, 1).await;
        let erased =
            client.erase_for_everyone(&caps, RF_SESSION, "rf-fw-run").await.expect("K-FW-4");
        assert_eq!(erased.notice, None, "K-FW-4: forget was asked");
        let counted = main_forget("K-FW-4", &erased.deleted);
        assert!(counted.pending, "K-FW-4: a live run is pending, got {counted:?}");
        assert!(counted.forgotten.is_none(), "K-FW-4: pending carries no counts");
        report("K-FW-4");
        client.cancel_run(&caps, RF_SESSION, &turn.run_id).await.expect("test: cancel");
        wait_job_terminal(&client, &caps, &turn.job_id).await;
        daemon.stop();
    })
    .await;
}

/// One loopback responder: the first delete is `422 forget_family_too_large`, the second is a
/// plain `200`. It stands in for a run family larger than 20,000 logged writes.
struct FamilyStub {
    port: u16,
    bodies: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl FamilyStub {
    async fn start() -> Self {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("test: bind family stub");
        let port = listener.local_addr().expect("test: stub addr").port();
        let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = bodies.clone();
        let task = tokio::spawn(async move {
            let mut seen = 0_u8;
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let recorded = recorded.clone();
                let which = seen;
                seen = seen.saturating_add(1);
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let raw = read_capped(&mut stream).await;
                    recorded.lock().expect("test: bodies").push(raw);
                    let body = if which == 0 {
                        r#"{"error":{"code":"forget_family_too_large","message":"the deleted run family wrote more than one delete can forget; nothing was deleted"}}"#
                    } else {
                        r#"{"message_id":"rf-fw-large","status":"deleted","agents":[{"agent":"main","runs":[]}]}"#
                    };
                    let status = if which == 0 { "422 Unprocessable Entity" } else { "200 OK" };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self { port, bodies, task }
    }
}

impl Drop for FamilyStub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_capped(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 1024];
    while buf.len() < 8192 {
        let n = stream.read(&mut chunk).await.expect("test: read the delete request");
        assert!(n > 0, "test: the client sent a request");
        buf.extend_from_slice(&chunk[..n]);
        if http_request_complete(&buf) {
            break;
        }
    }
    assert!(buf.len() <= 8192, "test: the request stayed inside 8 KiB");
    String::from_utf8(buf).expect("test: the request is UTF-8")
}

fn http_request_complete(buf: &[u8]) -> bool {
    let Some(split) = buf.windows(4).position(|mark| mark == b"\r\n\r\n") else {
        return false;
    };
    let header = String::from_utf8_lossy(&buf[..split]);
    let Some(length) = content_length(&header) else {
        return false;
    };
    buf.len() >= split.saturating_add(4).saturating_add(length)
}

fn content_length(header: &str) -> Option<usize> {
    header.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") { value.trim().parse().ok() } else { None }
    })
}

/// K-FW-5: `422 forget_family_too_large` tells the caller and retries once as a plain delete.
/// The real daemon refuses only after more than 20,000 logged writes, so this row speaks that
/// coded answer and checks the retry body.
#[tokio::test]
#[ignore = "needs RAMFLUX_PRX_BIN: a prx binary built at the pinned commit"]
async fn k_fw_family_too_large_retries_as_a_plain_delete() {
    bounded(async {
        use std::os::unix::fs::PermissionsExt;
        let stub = FamilyStub::start().await;
        let dir = tempfile::TempDir::new().expect("test: token dir");
        let token = dir.path().join("token");
        std::fs::write(&token, "contract-token").expect("test: token");
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))
            .expect("test: token mode");
        let client =
            PrxClient::new(&ClientConfig::new(format!("http://127.0.0.1:{}", stub.port), &token))
                .expect("test: client");
        let caps = Capabilities {
            prx_version: "0".to_owned(),
            commit: BuildCommit::Unknown,
            api: 1,
            capabilities: [MESSAGE_DELETE_V1, MESSAGE_FORGET_WRITES_V1]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            available: std::collections::BTreeSet::new(),
            limits_facts: LimitsFacts::default(),
        };
        let erased =
            client.erase_for_everyone(&caps, "rf-fw", "rf-fw-large").await.expect("K-FW-5");
        assert_eq!(erased.notice, Some(EraseNotice::FamilyTooLarge), "K-FW-5: the caller is told");
        assert_eq!(
            erased.notice.expect("K-FW-5").user_text(),
            EraseNotice::FamilyTooLarge.user_text(),
            "K-FW-5: user sentence"
        );
        assert!(
            erased.deleted.agents.iter().all(|agent| agent.forget.is_none()),
            "K-FW-5: the retry answer is a plain delete"
        );
        let bodies = stub.bodies.lock().expect("test: bodies").clone();
        assert_eq!(bodies.len(), 2, "K-FW-5: one forget and one plain retry");
        assert!(
            bodies[0].contains("\"forget_writes\":true"),
            "K-FW-5: the first body forgets: {}",
            bodies[0]
        );
        assert!(
            !bodies[1].contains("forget_writes"),
            "K-FW-5: the retry does not send the field: {}",
            bodies[1]
        );
        report("K-FW-5");
    })
    .await;
}

#[path = "prx_contract/unit_a.rs"]
mod unit_a;

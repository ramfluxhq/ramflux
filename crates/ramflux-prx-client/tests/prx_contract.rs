// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Contract tests against a real `prx daemon` built at the pinned commit.
//!
//! Ignored by default. Run with `RAMFLUX_PRX_BIN=<path to prx built at 67c5274ef9ee0eefa1521e45bdf9100ef8719fba>` and
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
    AGENT_CATALOG_V1, AGENT_CRUD_V1, AGENT_MAIN_READBACK_V1, AgentConfig, AgentName, AgentStatus,
    ApiCode, ApplyOutcome, Autonomy, BuildCommit, CAPABILITIES_V1, Capabilities, ClientConfig,
    ConfigRevision, PROMPT_MAX_BYTES, PrxClient, PrxError, PutKind, ReloadStatus, Tools,
};
use serde_json::Value;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// The commit the binary must report (`GET /api/capabilities` `commit`).
const PIN: &str = "67c5274ef9ee0eefa1521e45bdf9100ef8719fba";
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

    fn prepare_state(extra: &str, default_credential: bool) -> Self {
        let bin = prx_binary();
        let dir = TempDir::new().expect("test: temp dir");
        std::fs::create_dir_all(dir.path().join("cfg")).expect("test: config dir");
        std::fs::create_dir_all(dir.path().join("workspace")).expect("test: workspace dir");
        let port = {
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("test: free loopback port");
            listener.local_addr().expect("test: local addr").port()
        };
        let config = format!(
            "default_provider = \"openrouter\"\ndefault_model = \"openai/gpt-4o-mini\"\n\n[gateway]\nhost = \"127.0.0.1\"\nport = {port}\nrequire_pairing = true\n{extra}"
        );
        std::fs::write(dir.path().join("cfg/config.toml"), config).expect("test: write config");
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .expect("test: http client");
        let daemon = Self { bin, dir, port, child: None, http };
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
        let out =
            File::create(self.dir.path().join("daemon.out")).expect("test: daemon stdout file");
        let err =
            File::create(self.dir.path().join("daemon.err")).expect("test: daemon stderr file");
        let port = self.port.to_string();
        let child = self
            .command()
            .args(["daemon", "--host", "127.0.0.1", "-p", port.as_str()])
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("test: prx daemon starts");
        self.child = Some(child);
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
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
        let known = [CAPABILITIES_V1, AGENT_CATALOG_V1, AGENT_CRUD_V1, AGENT_MAIN_READBACK_V1];
        assert!(
            caps.capabilities.iter().all(|t| known.contains(&t.as_str())),
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

/// K-AC2-7 to K-AC2-11 (repin rows, PRX main 67c5274ef): a daemon with NO provider credential,
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
        let mut daemon = Daemon::prepare(HAND_WRITTEN_AGENT);
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
        let (status, text) = daemon
            .raw_authorized(reqwest::Method::PUT, &format!("/api/agents/{}", name.as_str()), Some(rev.as_str()), Some(serde_json::json!({"provider":"ollama","model":"m","autonomy":"full","tools":["*"],"enabled":true,"limits":{}})))
            .await;
        assert_eq!((status, error_code(&text).as_deref()), (400, Some("field_invalid")), "K-AC1a-8: extra field");
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

        // K-AC1a-10: enable on a fresh install; the response says a restart is required
        let before = client.targeted_agents(&caps).await.expect("K-AC1a-10: targeted read");
        let on = client
            .set_targeted_agents(&caps, true, &before.revision)
            .await
            .expect("K-AC1a-10: enable");
        assert!(
            on.configured && on.restart_required,
            "K-AC1a-10: configured and restart required: {on:?}"
        );
        assert!(!on.effective, "K-AC1a-10: not effective before the restart");
        daemon.stop();
        daemon.start();
        daemon.wait_ready().await;
        let client = daemon.client();
        let caps = capabilities(&client).await;
        let after =
            client.targeted_agents(&caps).await.expect("K-AC1a-10: targeted read after restart");
        assert!(
            after.configured && after.effective && !after.restart_required,
            "K-AC1a-10: effective after restart: {after:?}"
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
        let mut daemon = Daemon::prepare("");
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

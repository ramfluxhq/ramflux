// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded process-owned diagnostic sink, independent of stderr filtering.
pub(crate) mod fields;
mod files;
mod key;
use crate::SdkError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, LazyLock, Mutex, Weak,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use std::time::Instant;
use tracing_subscriber::{Layer, layer::Context, prelude::*};

/// Native diagnostic policy. Bounds may be lowered, never raised above the process budget.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct DiagnosticConfig {
    /// Minimum severity: error, warn, info, debug or trace.
    pub level: String,
    /// Native process role: app, nse or fgs. The CLI selects daemon internally.
    pub process: String,
    /// release, beta or realrun. Realrun requires the compiled diagnostic feature.
    pub build_class: String,
    /// Optional host-owned private key file outside the data root, containing exactly 32 bytes.
    pub key_file: Option<PathBuf>,
    /// Maximum file bytes, from 4096 to 1048576.
    pub max_file_bytes: u64,
    /// Current plus rotated files, from 1 to 5.
    pub max_files: usize,
    /// Retention age, from 1 to 7 days.
    pub max_age_days: u64,
}
impl Default for DiagnosticConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            process: "app".into(),
            build_class: "release".into(),
            key_file: None,
            max_file_bytes: 1_048_576,
            max_files: 5,
            max_age_days: 7,
        }
    }
}
impl DiagnosticConfig {
    pub(crate) fn validate(&self, native: bool) -> Result<(), SdkError> {
        if !matches!(self.level.as_str(), "error" | "warn" | "info" | "debug" | "trace")
            || !(matches!(self.process.as_str(), "app" | "nse" | "fgs")
                || (!native && self.process == "daemon"))
            || !matches!(self.build_class.as_str(), "release" | "beta" | "realrun")
            || !(4096..=1_048_576).contains(&self.max_file_bytes)
            || !(1..=5).contains(&self.max_files)
            || !(1..=7).contains(&self.max_age_days)
        {
            return Err(SdkError::LocalBus("invalid diagnostic configuration".into()));
        }
        Ok(())
    }
    fn is_default_policy(&self) -> bool {
        let defaults = Self::default();
        self.level == defaults.level
            && self.build_class == defaults.build_class
            && self.key_file.is_none()
            && self.max_file_bytes == defaults.max_file_bytes
            && self.max_files == defaults.max_files
            && self.max_age_days == defaults.max_age_days
    }
    fn effective(mut self) -> Self {
        if !cfg!(feature = "diag-realrun") {
            if self.build_class == "realrun" {
                self.build_class = "release".into();
            }
            if matches!(self.level.as_str(), "debug" | "trace") {
                self.level = "info".into();
            }
        }
        self
    }
}

/// One `ramflux.diag.v1` record before it is enveloped. `layer` is `sdk`, `ui` or `bridge`.
pub(crate) struct Record<'a> {
    pub(crate) layer: &'a str,
    pub(crate) level: &'a str,
    pub(crate) component: &'a str,
    pub(crate) event: &'a str,
    pub(crate) cid: Option<&'a str>,
    pub(crate) fields: Value,
    pub(crate) error: Option<Value>,
}

pub(crate) enum Command {
    Record(Value, bool),
    Flush(mpsc::SyncSender<()>),
    Stop,
}
pub(crate) struct Session {
    config: DiagnosticConfig,
    key: zeroize::Zeroizing<[u8; 32]>,
    epoch: u64,
    /// Host-requested verbose window (`set_level`): level and its end in Unix milliseconds.
    level_override: Mutex<Option<(tracing::Level, u64)>>,
    dropped: AtomicU64,
    /// Keys and host records refused by the field registry (`diag.rejected`).
    rejected: AtomicU64,
    sender: mpsc::SyncSender<Command>,
    writer: Mutex<Option<std::thread::JoinHandle<()>>>,
}
static ACTIVE: LazyLock<Mutex<Weak<Session>>> = LazyLock::new(|| Mutex::new(Weak::new()));
// These counters outlive individual root owners: closing and reopening is not a process restart.
static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);
static PROCESS_SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub(super) fn next_sequence() -> u64 {
    PROCESS_SEQUENCE.fetch_add(1, Ordering::Relaxed)
}
pub(super) fn elapsed_ms() -> u64 {
    u64::try_from(PROCESS_START.elapsed().as_millis()).unwrap_or(u64::MAX)
}

pub(crate) fn start(root: &Path, config: DiagnosticConfig) -> Result<Arc<Session>, SdkError> {
    config.validate(false)?;
    let config = config.effective();
    let root = std::fs::canonicalize(root)?;
    let mut active = ACTIVE.lock().map_err(|_| SdkError::LocalBus("diagnostic lock".into()))?;
    if let Some(session) = active.upgrade() {
        if session.config == config || config.is_default_policy() {
            return Ok(session);
        }
        return Err(SdkError::LocalBus("diagnostic process already configured".into()));
    }
    let key = key::load(&root, config.key_file.as_deref())?;
    let epoch = now_ms();
    let files = files::Files::open(&root, config.clone(), epoch)?;
    let (sender, receiver) = mpsc::sync_channel(2048);
    let writer = std::thread::Builder::new()
        .name("ramflux-diag".into())
        .spawn(move || files.run(&receiver))?;
    let session = Arc::new(Session {
        config,
        key,
        epoch,
        level_override: Mutex::new(None),
        dropped: AtomicU64::new(0),
        rejected: AtomicU64::new(0),
        sender,
        writer: Mutex::new(Some(writer)),
    });
    *active = Arc::downgrade(&session);
    // Hosts with their own subscriber can compose DiagnosticLayer; the native worker also scopes it.
    let _ = tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(DiagnosticLayer),
    );
    session.record("I", "sdk.diag", "proc.start", json!({"build_class":session.config.build_class,"level":session.config.level,"key_epoch":epoch}), None);
    Ok(session)
}

/// The live process sink, if one is open. Never blocks: a sink being opened is skipped.
pub(crate) fn active() -> Option<Arc<Session>> {
    ACTIVE.try_lock().ok().and_then(|active| active.upgrade())
}

fn severity_of(level: &str) -> tracing::Level {
    match level {
        "E" => tracing::Level::ERROR,
        "W" => tracing::Level::WARN,
        "D" => tracing::Level::DEBUG,
        "T" => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    }
}

fn maximum_of(level: &str) -> tracing::Level {
    match level {
        "error" => tracing::Level::ERROR,
        "warn" => tracing::Level::WARN,
        "debug" => tracing::Level::DEBUG,
        "trace" => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    }
}

impl Session {
    pub(crate) fn accepts(&self, level: tracing::Level) -> bool {
        let configured = maximum_of(&self.config.level);
        let maximum = match self.level_override.lock() {
            Ok(guard) => match *guard {
                Some((verbose, until)) if now_ms() < until => verbose,
                _ => configured,
            },
            Err(_) => configured,
        };
        level <= maximum
    }
    /// Opens the verbose window requested by the host. The caller checks the bounds.
    #[cfg(feature = "c-abi")]
    pub(crate) fn set_level_override(&self, level: tracing::Level, until: Option<u64>) {
        if let Ok(mut guard) = self.level_override.lock() {
            *guard = until.map(|until| (level, until));
        }
    }
    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
    pub(crate) fn process(&self) -> &str {
        &self.config.process
    }
    pub(crate) fn level(&self) -> &str {
        &self.config.level
    }
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
    pub(crate) fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
    /// Counts keys or host records refused by the field registry.
    pub(crate) fn note_rejected(&self, count: u64) {
        if count > 0 {
            self.rejected.fetch_add(count, Ordering::Relaxed);
        }
    }
    pub(crate) fn record(
        &self,
        level: &str,
        component: &str,
        event: &str,
        fields: Value,
        error: Option<Value>,
    ) {
        self.write(Record { layer: "sdk", level, component, event, cid: None, fields, error });
    }
    /// Writes one `ramflux.diag.v1` record. The caller has already filtered its fields.
    pub(crate) fn write(&self, record: Record<'_>) {
        if !self.accepts(severity_of(record.level)) {
            return;
        }
        self.report_dropped();
        let mut line = self.envelope(record.layer, record.level, record.component, record.event);
        if let Some(cid) = record.cid {
            line["cid"] = json!(cid);
        }
        line["f"] = record.fields;
        if let Some(error) = record.error {
            line["err"] = error;
        }
        let durable =
            matches!(record.level, "E" | "W") || matches!(record.event, "proc.start" | "proc.stop");
        if self.sender.try_send(Command::Record(line, durable)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn envelope(&self, layer: &str, level: &str, component: &str, event: &str) -> Value {
        json!({"schema":"ramflux.diag.v1","t":now_ms(),"m":elapsed_ms(),"lv":level,"p":self.config.process,"ly":layer,"c":component,"e":event})
    }
    fn report_dropped(&self) {
        let count = self.dropped.swap(0, Ordering::Relaxed);
        if count == 0 {
            return;
        }
        let mut record = self.envelope("sdk", "W", "sdk.diag", "diag.dropped");
        record["f"] = json!({"count":count});
        if self.sender.try_send(Command::Record(record, true)).is_err() {
            self.dropped.fetch_add(count, Ordering::Relaxed);
        }
    }
    /// Waits at most five seconds for the writer to drain. A full queue skips the wait.
    pub(crate) fn flush(&self) {
        let (sent, received) = mpsc::sync_channel(1);
        if self.sender.try_send(Command::Flush(sent)).is_ok() {
            let _ = received.recv_timeout(std::time::Duration::from_secs(5));
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.record("I", "sdk.diag", "proc.stop", json!({}), None);
        let _ = self.sender.send(Command::Stop);
        if let Ok(writer) = self.writer.get_mut()
            && let Some(writer) = writer.take()
        {
            let _ = writer.join();
        }
    }
}

/// Add this layer alongside a host's subscriber so SDK diagnostics bypass its stderr filter.
#[derive(Clone, Copy, Debug)]
pub struct DiagnosticLayer;
impl<S: tracing::Subscriber> Layer<S> for DiagnosticLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, S>) {
        let Some(session) = active() else { return };
        if !event.metadata().target().starts_with("ramflux_sdk")
            && event.metadata().target() != "rf_diag"
        {
            return;
        }
        if !session.accepts(*event.metadata().level()) {
            return;
        }
        let mut visitor = fields::Visitor::new(session.key());
        event.record(&mut visitor);
        let level = match *event.metadata().level() {
            tracing::Level::ERROR => "E",
            tracing::Level::WARN => "W",
            tracing::Level::INFO => "I",
            tracing::Level::DEBUG => "D",
            _ => "T",
        };
        // Visitor keeps registered keys only; sanitize repeats the check on the value types.
        let (fields, _refused) = fields::sanitize(Value::Object(visitor.fields));
        session.record(
            level,
            "sdk.trace",
            &fields::Visitor::event(event.metadata().line()),
            fields,
            None,
        );
    }
}
/// Window of the refused-call rate rule: one line per key per minute, with a suppressed count.
const RATE_WINDOW_MS: u64 = 60_000;
const RATE_KEYS: usize = 256;
/// Per key: the time of the last written line and the lines withheld since then.
static RATE: LazyLock<Mutex<std::collections::BTreeMap<String, (u64, u64)>>> =
    LazyLock::new(|| Mutex::new(std::collections::BTreeMap::new()));

/// The rate rule for refused-call `W` lines (M3). The first line of a key is written; later
/// ones at most once per 60 s. Returns the suppressed count to report, or `None` to skip.
/// Keys beyond `RATE_KEYS` are not tracked and are always written; the error table keeps exact counts.
pub(crate) fn rate_gate(key: &str, now: u64) -> Option<u64> {
    let Ok(mut table) = RATE.lock() else { return Some(0) };
    if let Some((last, suppressed)) = table.get_mut(key) {
        if now.saturating_sub(*last) < RATE_WINDOW_MS {
            *suppressed = suppressed.saturating_add(1);
            return None;
        }
        let withheld = *suppressed;
        *last = now;
        *suppressed = 0;
        return Some(withheld);
    }
    if table.len() < RATE_KEYS {
        table.insert(key.to_owned(), (now, 0));
    }
    Some(0)
}

/// Records a refused admission (status without an operation). Typed failures use `events`.
#[cfg(feature = "c-abi")]
pub(crate) fn refusal(value: &Value) {
    let Some(session) = active() else { return };
    let code = value.get("code").and_then(Value::as_i64).unwrap_or(0);
    if code == 0 {
        return;
    }
    let name = value.get("name").and_then(Value::as_str).unwrap_or("Internal");
    let reason = value.get("reason_code").and_then(Value::as_str).unwrap_or("internal_error");
    let effect = value
        .get("effects")
        .and_then(Value::as_str)
        .filter(|v| matches!(*v, "none" | "unknown" | "committed"))
        .unwrap_or("unknown");
    let method = value.pointer("/response/method").and_then(Value::as_str).unwrap_or("unknown");
    let method = if fields::token(method) { method } else { "invalid" };
    let Some(suppressed) = rate_gate(&format!("refused|{method}|{name}"), now_ms()) else {
        return;
    };
    let mut fields = json!({"method":method,"suppressed":suppressed});
    if let Some(account) = value.pointer("/response/account_id").and_then(Value::as_str)
        && let Ok(hash) =
            ramflux_crypto::diagnostic_short_hash(session.key(), "account", account.as_bytes())
    {
        fields["account_id"] = json!(hash);
    }
    session.record(
        "W",
        "abi.call",
        "abi.refused",
        fields,
        Some(json!({"code":code,"name":name,"reason":reason,"effect":effect,"variant":name})),
    );
}
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |v| u64::try_from(v.as_millis()).unwrap_or(u64::MAX))
}

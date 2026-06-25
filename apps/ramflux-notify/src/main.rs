#![cfg_attr(not(feature = "itest-http"), allow(dead_code))]

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as FmtWrite;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Once;
use std::time::Duration;

#[cfg(feature = "itest-http")]
use std::net::{TcpListener, TcpStream};

static RUSTLS_PROVIDER: Once = Once::new();
static JWT_PROVIDER: Once = Once::new();

const NOTIFY_RUNTIME_ENV: &str = "RAMFLUX_NOTIFY_RUNTIME";
const NOTIFY_ASYNC_ACCEPT_ENV: &str = "RAMFLUX_NOTIFY_ASYNC_ACCEPT";
const NOTIFY_ASYNC_INGRESS_ENV: &str = "RAMFLUX_NOTIFY_ASYNC_INGRESS";
const NOTIFY_WAL_RAW_ENQUEUE_ENV: &str = "RAMFLUX_NOTIFY_WAL_RAW_ENQUEUE";
const NOTIFY_BATCH_VERIFY_ENV: &str = "RAMFLUX_NOTIFY_BATCH_VERIFY";
const NOTIFY_VERIFY_BATCH_MAX_ENV: &str = "RAMFLUX_NOTIFY_VERIFY_BATCH_MAX";
const NOTIFY_VERIFY_WINDOW_US_ENV: &str = "RAMFLUX_NOTIFY_VERIFY_WINDOW_US";

fn main() {
    if let Err(error) = run_service("ramflux-notify") {
        eprintln!("ramflux-notify: {error}");
        std::process::exit(2);
    }
}

fn run_service(service: &'static str) -> Result<(), ramflux_node_core::NodeCoreError> {
    if std::env::args().any(|arg| arg == "--health-check") {
        println!("{service}:healthy");
        return Ok(());
    }
    tracing_subscriber::fmt().with_target(false).init();
    if let Some(config) =
        ramflux_node_core::load_config_from_args(std::env::args().skip(1), service)?
    {
        let redb_path = ramflux_node_core::effective_redb_path(&config);
        let store = Arc::new(ramflux_node_core::NotifyRedbStore::open(redb_path)?);
        log_notify_wal_recovery(&store);
        let state = match store.load_state()? {
            Some(state) => state,
            None => ramflux_node_core::NotifyQueueState::new(),
        };
        if !store.uses_notify_wal() {
            store.save_state(&state)?;
        }
        tracing::info!(service, node_id = config.node_id, "notify queue initialized");
        if std::env::args().any(|arg| arg == "--once") {
            return Ok(());
        }
        #[cfg(feature = "itest-http")]
        if std::env::var("RAMFLUX_ITEST_HTTP").ok().as_deref() == Some("1") {
            let store_gate = Arc::new(Mutex::new(()));
            let runtime = Arc::new(NotifyRuntime::from_env(&store, &store_gate)?);
            let wake_auth = NotifyWakeAuth::from_config(&config)?;
            let async_accept = notify_async_accept_enabled();
            if async_accept {
                start_notify_async_delivery_workers(&store)?;
            }
            let wake_verify_batcher = NotifyWakeVerifyBatcher::from_env(&wake_auth, &store)?;
            let ingress = Arc::new(NotifyIngressState {
                store,
                runtime,
                store_gate,
                async_accept,
                wake_auth,
                wake_verify_batcher,
            });
            return serve_itest_http(&ingress);
        }
        std::thread::park();
        return Ok(());
    }
    tracing::info!(service, "service initialized");
    if std::env::args().any(|arg| arg == "--once") {
        return Ok(());
    }
    std::thread::park();
    Ok(())
}

#[cfg(feature = "itest-http")]
struct NotifyIngressState {
    store: Arc<ramflux_node_core::NotifyRedbStore>,
    runtime: Arc<NotifyRuntime>,
    store_gate: Arc<Mutex<()>>,
    async_accept: bool,
    wake_auth: NotifyWakeAuth,
    wake_verify_batcher: Option<NotifyWakeVerifyBatcher>,
}

#[cfg(feature = "itest-http")]
#[derive(Clone)]
struct NotifyWakeAuth {
    require: bool,
    key: Option<ramflux_node_core::NodeServiceSigningKey>,
}

#[cfg(feature = "itest-http")]
impl NotifyWakeAuth {
    fn from_config(
        config: &ramflux_node_core::NodeServiceConfig,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        let require = notify_require_wake_auth();
        let key = if require {
            Some(ramflux_node_core::require_node_service_signing_key(config)?)
        } else {
            ramflux_node_core::node_service_signing_key_from_config(config)?
        };
        Ok(Self { require, key })
    }

    fn verify(
        &self,
        wake: &ramflux_protocol::NotificationWake,
    ) -> Result<(), ramflux_node_core::NodeCoreError> {
        if !self.require {
            return Ok(());
        }
        let key = self.key.as_ref().ok_or_else(|| {
            ramflux_node_core::NodeCoreError::Unauthorized(
                "notify wake auth is required but no node service key is configured".to_owned(),
            )
        })?;
        key.verify_notification_wake(wake)
    }

    fn verify_batch_indices(
        &self,
        wakes: &[&ramflux_protocol::NotificationWake],
    ) -> Result<(), Vec<usize>> {
        if !self.require {
            return Ok(());
        }
        let Some(key) = self.key.as_ref() else {
            return Err((0..wakes.len()).collect());
        };
        key.verify_notification_wakes_batch(wakes)
    }
}

#[cfg(feature = "itest-http")]
fn notify_require_wake_auth() -> bool {
    std::env::var("RAMFLUX_NOTIFY_REQUIRE_WAKE_AUTH")
        .map_or(true, |value| value != "0" && !value.eq_ignore_ascii_case("false"))
}

#[cfg(feature = "itest-http")]
#[derive(Clone)]
struct NotifyWakeVerifyBatcher {
    senders: Arc<Vec<tokio::sync::mpsc::Sender<WakeVerifyRequest>>>,
}

#[cfg(feature = "itest-http")]
impl NotifyWakeVerifyBatcher {
    fn from_env(
        wake_auth: &NotifyWakeAuth,
        store: &Arc<ramflux_node_core::NotifyRedbStore>,
    ) -> Result<Option<Self>, ramflux_node_core::NodeCoreError> {
        if !notify_batch_verify_enabled() || !wake_auth.require {
            return Ok(None);
        }
        let batch_max = notify_runtime_usize_env(NOTIFY_VERIFY_BATCH_MAX_ENV, || 1024).max(1);
        let window_us = notify_runtime_usize_env(NOTIFY_VERIFY_WINDOW_US_ENV, || 1_000);
        let window = Duration::from_micros(u64::try_from(window_us).unwrap_or(u64::MAX));
        let capacity = batch_max.saturating_mul(64).max(1);
        let shard_count = store.notify_ingest_shard_count();
        let mut senders = Vec::with_capacity(shard_count);
        for shard_id in 0..shard_count {
            let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
            let thread_auth = wake_auth.clone();
            let thread_store = Arc::clone(store);
            std::thread::Builder::new()
                .name(format!("ramflux-notify-wake-verify-batcher-{shard_id}"))
                .spawn(move || {
                    wake_verify_batcher_loop(
                        &thread_auth,
                        &thread_store,
                        shard_id,
                        receiver,
                        batch_max,
                        window,
                    );
                })
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })?;
            senders.push(sender);
        }
        tracing::info!(
            batch_max,
            window_us = window.as_micros(),
            capacity,
            shard_count,
            "notify wake batch verifier started"
        );
        Ok(Some(Self { senders: Arc::new(senders) }))
    }

    async fn verify_and_enqueue(
        &self,
        shard_id: usize,
        wake: ramflux_protocol::NotificationWake,
        raw_body: Vec<u8>,
        queued_at: u64,
    ) -> Result<(), ramflux_node_core::NodeCoreError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        let sender = self.senders.get(shard_id).ok_or_else(|| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify wake verifier shard {shard_id} not available"
            ))
        })?;
        sender.send(WakeVerifyRequest { wake, raw_body, queued_at, reply }).await.map_err(
            |source| {
                ramflux_node_core::NodeCoreError::ItestHttp(format!(
                    "notify wake verifier stopped: {source}"
                ))
            },
        )?;
        response.await.map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify wake verifier response dropped: {source}"
            ))
        })?
    }
}

#[cfg(feature = "itest-http")]
struct WakeVerifyRequest {
    wake: ramflux_protocol::NotificationWake,
    raw_body: Vec<u8>,
    queued_at: u64,
    reply: tokio::sync::oneshot::Sender<Result<(), ramflux_node_core::NodeCoreError>>,
}

#[cfg(feature = "itest-http")]
fn wake_verify_batcher_loop(
    wake_auth: &NotifyWakeAuth,
    store: &ramflux_node_core::NotifyRedbStore,
    shard_id: usize,
    mut receiver: tokio::sync::mpsc::Receiver<WakeVerifyRequest>,
    batch_max: usize,
    window: Duration,
) {
    while let Some(first) = receiver.blocking_recv() {
        let mut batch = Vec::with_capacity(batch_max);
        batch.push(first);
        let deadline = std::time::Instant::now() + window;
        while batch.len() < batch_max {
            match receiver.try_recv() {
                Ok(request) => batch.push(request),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    if std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_micros(50));
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
        verify_and_enqueue_wake_batch(wake_auth, store, shard_id, batch);
    }
}

#[cfg(feature = "itest-http")]
fn verify_and_enqueue_wake_batch(
    wake_auth: &NotifyWakeAuth,
    store: &ramflux_node_core::NotifyRedbStore,
    shard_id: usize,
    batch: Vec<WakeVerifyRequest>,
) {
    let wakes = batch.iter().map(|request| &request.wake).collect::<Vec<_>>();
    let failures = wake_auth.verify_batch_indices(&wakes).err().unwrap_or_default();
    let mut failed = vec![false; batch.len()];
    for index in failures {
        if let Some(slot) = failed.get_mut(index) {
            *slot = true;
        }
    }
    let mut valid = Vec::new();
    let mut replies = Vec::new();
    for (index, request) in batch.into_iter().enumerate() {
        if failed[index] {
            let _ = request.reply.send(Err(ramflux_node_core::NodeCoreError::Unauthorized(
                "notify wake signature rejected".to_owned(),
            )));
        } else {
            valid.push((request.raw_body, request.queued_at));
            replies.push(request.reply);
        }
    }
    if valid.is_empty() {
        return;
    }
    let result = store
        .queue_raw_wakes_for_async_accept_shard_batch(shard_id, valid)
        .map(|_raws| ())
        .map_err(|error| ramflux_node_core::NodeCoreError::ItestHttp(error.to_string()));
    match result {
        Ok(()) => {
            for reply in replies {
                let _ = reply.send(Ok(()));
            }
        }
        Err(error) => {
            let message = error.to_string();
            for reply in replies {
                let _ =
                    reply.send(Err(ramflux_node_core::NodeCoreError::ItestHttp(message.clone())));
            }
        }
    }
}

#[cfg(feature = "itest-http")]
fn notify_batch_verify_enabled() -> bool {
    notify_default_enabled_env(NOTIFY_BATCH_VERIFY_ENV)
}

#[cfg(feature = "itest-http")]
fn itest_error_status(error: &ramflux_node_core::NodeCoreError) -> &'static str {
    match error {
        ramflux_node_core::NodeCoreError::Unauthorized(_message) => "401 Unauthorized",
        _ => "500 Internal Server Error",
    }
}

#[cfg(feature = "itest-http")]
fn serve_itest_http(
    ingress: &Arc<NotifyIngressState>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    if notify_async_ingress_enabled() {
        return serve_itest_http_async(ingress);
    }
    let addr = std::env::var("RAMFLUX_ITEST_NOTIFY_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:18083".to_owned());
    let listener = TcpListener::bind(&addr)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    let worker_count = notify_ingress_worker_count();
    let queue_capacity = worker_count.saturating_mul(4).max(1);
    let (sender, receiver) = std::sync::mpsc::sync_channel(queue_capacity);
    let receiver = Arc::new(Mutex::new(receiver));
    for worker_id in 0..worker_count {
        let worker_receiver = Arc::clone(&receiver);
        let worker_ingress = Arc::clone(ingress);
        std::thread::Builder::new()
            .name(format!("ramflux-notify-http-ingress-{worker_id}"))
            .spawn(move || notify_ingress_worker_loop(&worker_receiver, &worker_ingress))
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    }
    tracing::info!(addr, worker_count, queue_capacity, "notify itest HTTP surface listening");
    for stream in listener.incoming() {
        let stream = stream
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(%error, "failed to enable TCP_NODELAY on notify ingress connection");
        }
        sender
            .send(stream)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    }
    Ok(())
}

#[cfg(feature = "itest-http")]
fn serve_itest_http_async(
    ingress: &Arc<NotifyIngressState>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let addr = std::env::var("RAMFLUX_ITEST_NOTIFY_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:18083".to_owned());
    let worker_count = notify_async_ingress_worker_count();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ramflux-notify-async-ingress")
        .worker_threads(worker_count)
        .build()
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    let runtime_ingress = Arc::clone(ingress);
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
        tracing::info!(addr, worker_count, "notify async itest HTTP surface listening");
        loop {
            let (stream, _peer) = listener.accept().await.map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
            })?;
            if let Err(error) = stream.set_nodelay(true) {
                tracing::warn!(
                    %error,
                    "failed to enable TCP_NODELAY on async notify ingress connection"
                );
            }
            let connection_ingress = Arc::clone(&runtime_ingress);
            tokio::spawn(async move {
                if let Err(error) =
                    notify_async_ingress_connection_loop(stream, connection_ingress).await
                {
                    tracing::debug!(%error, "notify async ingress connection ended");
                }
            });
        }
    })
}

#[cfg(feature = "itest-http")]
fn notify_ingress_worker_count() -> usize {
    notify_runtime_usize_env("RAMFLUX_NOTIFY_INGRESS_THREADS", || {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    })
    .max(1)
}

#[cfg(feature = "itest-http")]
fn notify_async_ingress_worker_count() -> usize {
    notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_INGRESS_WORKERS", || {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    })
    .max(1)
}

#[cfg(feature = "itest-http")]
fn notify_async_ingress_enabled() -> bool {
    notify_default_enabled_env(NOTIFY_ASYNC_INGRESS_ENV)
}

fn lock_notify_store(
    gate: &Arc<Mutex<()>>,
) -> Result<std::sync::MutexGuard<'_, ()>, ramflux_node_core::NodeCoreError> {
    gate.lock().map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

#[cfg(feature = "itest-http")]
fn notify_ingress_worker_loop(
    receiver: &Arc<Mutex<std::sync::mpsc::Receiver<TcpStream>>>,
    ingress: &Arc<NotifyIngressState>,
) {
    loop {
        let stream = {
            let Ok(receiver) = receiver.lock() else {
                tracing::error!("notify ingress receiver lock poisoned");
                return;
            };
            receiver.recv()
        };
        let Ok(mut stream) = stream else {
            return;
        };
        loop {
            match handle_itest_request(&mut stream, ingress) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    let body = format!("{error}");
                    let _result = ramflux_node_core::write_itest_text_response(
                        &mut stream,
                        itest_error_status(&error),
                        &body,
                    );
                    break;
                }
            }
        }
    }
}

#[cfg(feature = "itest-http")]
fn handle_itest_request(
    stream: &mut TcpStream,
    ingress: &NotifyIngressState,
) -> Result<bool, ramflux_node_core::NodeCoreError> {
    let Some(request) = ramflux_node_core::read_itest_http_request(stream)? else {
        return Ok(false);
    };
    let keep_alive = request.keep_alive;
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => {
            ramflux_node_core::write_itest_json_response_with_connection(
                stream,
                "200 OK",
                &serde_json::json!({
                    "service": "ramflux-notify",
                    "status": "ok"
                }),
                keep_alive,
            )?;
        }
        ("POST", "/mvp10/notify/wake") => {
            handle_mvp10_notify_wake(stream, ingress, &request.body, keep_alive)?;
        }
        ("POST", "/s13/notify/push-route") => {
            handle_s13_push_route(
                stream,
                &ingress.store,
                &ingress.store_gate,
                &request.body,
                keep_alive,
            )?;
        }
        ("POST", "/s13/notify/provider-credential") => {
            handle_s13_provider_credential(
                stream,
                &ingress.store,
                &ingress.store_gate,
                &request.body,
                keep_alive,
            )?;
        }
        ("POST", "/s13/notify/wake") => {
            let body: S13WakeRequest = serde_json::from_slice(&request.body).map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
            })?;
            ingress.wake_auth.verify(&body.wake)?;
            let response = if ingress.async_accept {
                handle_s13_wake_async_accept(&ingress.store, &body)?
            } else {
                handle_s13_wake_value(&ingress.store, &ingress.store_gate, &ingress.runtime, &body)?
            };
            ramflux_node_core::write_itest_json_response_with_connection(
                stream, "200 OK", &response, keep_alive,
            )?;
        }
        ("GET", path) if path.starts_with("/s13/notify/provider-attempts/") => {
            let queue_id = path.trim_start_matches("/s13/notify/provider-attempts/");
            handle_s13_provider_attempts(stream, ingress, queue_id, keep_alive)?;
        }
        ("POST", "/mvp10/notify/deliver") => {
            handle_mvp10_notify_deliver(stream, ingress, &request.body, keep_alive)?;
        }
        ("GET", "/mvp10/notify/state") => {
            handle_mvp10_notify_state(stream, ingress, keep_alive)?;
        }
        _ => {
            ramflux_node_core::write_itest_text_response_with_connection(
                stream,
                "404 Not Found",
                "not found",
                keep_alive,
            )?;
        }
    }
    Ok(keep_alive)
}

#[cfg(feature = "itest-http")]
struct AsyncItestHttpRequest {
    route: AsyncItestHttpRoute,
    body: Vec<u8>,
    keep_alive: bool,
}

#[cfg(feature = "itest-http")]
enum AsyncItestHttpRoute {
    Healthz,
    Mvp10NotifyWake,
    S13NotifyPushRoute,
    S13NotifyProviderCredential,
    S13NotifyWake,
    S13NotifyProviderAttempts(String),
    Mvp10NotifyDeliver,
    Mvp10NotifyState,
    NotFound,
}

#[cfg(feature = "itest-http")]
struct AsyncItestHttpResponse {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
    keep_alive: bool,
}

#[cfg(feature = "itest-http")]
async fn notify_async_ingress_connection_loop(
    mut stream: tokio::net::TcpStream,
    ingress: Arc<NotifyIngressState>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let mut buffer = Vec::with_capacity(16 * 1024);
    loop {
        let Some(request) = read_async_itest_http_request(&mut stream, &mut buffer).await? else {
            return Ok(());
        };
        let keep_alive = request.keep_alive;
        if is_raw_s13_wake_request(&request, &ingress) {
            if let Err(error) = ingest_raw_s13_wake_for_async_ingress(&ingress, request.body).await
            {
                write_async_text_response(
                    &mut stream,
                    itest_error_status(&error),
                    &error.to_string(),
                    false,
                )
                .await?;
                return Ok(());
            }
            write_async_fixed_json_ok_response(&mut stream, keep_alive).await?;
        } else {
            let response =
                match handle_itest_request_value_async(request, Arc::clone(&ingress)).await {
                    Ok(response) => response,
                    Err(error) => {
                        async_text_response(itest_error_status(&error), &error.to_string(), false)
                    }
                };
            write_async_itest_response(&mut stream, &response).await?;
        }
        if !keep_alive {
            return Ok(());
        }
    }
}

#[cfg(feature = "itest-http")]
async fn read_async_itest_http_request(
    reader: &mut tokio::net::TcpStream,
    buffer: &mut Vec<u8>,
) -> Result<Option<AsyncItestHttpRequest>, ramflux_node_core::NodeCoreError> {
    loop {
        if let Some(request) = parse_async_itest_http_request(buffer)? {
            return Ok(Some(request));
        }
        let mut chunk = [0_u8; 8192];
        let bytes = tokio::io::AsyncReadExt::read(reader, &mut chunk)
            .await
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
        if bytes == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err(ramflux_node_core::NodeCoreError::ItestHttp(
                "incomplete async itest HTTP request".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..bytes]);
        if buffer.len() > 2 * 1024 * 1024 {
            return Err(ramflux_node_core::NodeCoreError::ItestHttp(
                "async itest HTTP request too large".to_owned(),
            ));
        }
    }
}

#[cfg(feature = "itest-http")]
fn parse_async_itest_http_request(
    buffer: &mut Vec<u8>,
) -> Result<Option<AsyncItestHttpRequest>, ramflux_node_core::NodeCoreError> {
    let Some(header_end) = find_async_http_header_end(buffer) else {
        if buffer.len() > 64 * 1024 {
            return Err(ramflux_node_core::NodeCoreError::ItestHttp(
                "async request header too large".to_owned(),
            ));
        }
        return Ok(None);
    };
    let header = std::str::from_utf8(&buffer[..header_end])
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    let mut lines = header.lines();
    let request_line = lines.next().ok_or_else(|| {
        ramflux_node_core::NodeCoreError::ItestHttp("missing async request line".to_owned())
    })?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ramflux_node_core::NodeCoreError::ItestHttp("missing method".to_owned()))?;
    let path = parts
        .next()
        .ok_or_else(|| ramflux_node_core::NodeCoreError::ItestHttp("missing path".to_owned()))?;
    let mut content_length = 0usize;
    let mut keep_alive = false;
    for line in lines {
        let Some((name, value)) = line.trim_end().split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length = value.parse().map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestHttp(format!("bad content length: {source}"))
            })?;
        } else if name.eq_ignore_ascii_case("Connection") {
            keep_alive = async_connection_header_requests_keep_alive(value);
        }
    }
    let separator_len = async_http_header_separator_len(buffer, header_end);
    let body_start = header_end + separator_len;
    let request_len = body_start + content_length;
    if buffer.len() < request_len {
        return Ok(None);
    }
    let route = async_itest_route(method, path);
    let body = buffer[body_start..request_len].to_vec();
    buffer.drain(..request_len);
    Ok(Some(AsyncItestHttpRequest { route, body, keep_alive }))
}

#[cfg(feature = "itest-http")]
async fn handle_itest_request_value_async(
    request: AsyncItestHttpRequest,
    ingress: Arc<NotifyIngressState>,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let keep_alive = request.keep_alive;
    match request.route {
        AsyncItestHttpRoute::Healthz => async_json_response(
            "200 OK",
            &serde_json::json!({
                "service": "ramflux-notify",
                "status": "ok"
            }),
            keep_alive,
        ),
        AsyncItestHttpRoute::Mvp10NotifyWake => {
            handle_mvp10_notify_wake_value_async(ingress, request.body, keep_alive).await
        }
        AsyncItestHttpRoute::S13NotifyPushRoute => {
            handle_s13_push_route_value_async(ingress, request.body, keep_alive).await
        }
        AsyncItestHttpRoute::S13NotifyProviderCredential => {
            handle_s13_provider_credential_value_async(ingress, request.body, keep_alive).await
        }
        AsyncItestHttpRoute::S13NotifyWake => {
            if ingress.async_accept && notify_wal_raw_enqueue_enabled() {
                let response = handle_s13_wake_raw_async_accept_value_async(
                    &ingress.store,
                    &ingress.wake_auth,
                    request.body,
                )
                .await?;
                return async_json_response("200 OK", &response, keep_alive);
            }
            let body: S13WakeRequest = serde_json::from_slice(&request.body).map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestJson(source.to_string())
            })?;
            let response = if ingress.async_accept {
                handle_s13_wake_async_accept_value_async(&ingress.store, &ingress.wake_auth, &body)
                    .await?
            } else {
                let blocking_ingress = Arc::clone(&ingress);
                tokio::task::spawn_blocking(move || {
                    handle_s13_wake_value(
                        &blocking_ingress.store,
                        &blocking_ingress.store_gate,
                        &blocking_ingress.runtime,
                        &body,
                    )
                })
                .await
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })??
            };
            async_json_response("200 OK", &response, keep_alive)
        }
        AsyncItestHttpRoute::S13NotifyProviderAttempts(queue_id) => {
            let blocking_ingress = Arc::clone(&ingress);
            let attempts = tokio::task::spawn_blocking(move || {
                let _guard = lock_notify_store(&blocking_ingress.store_gate)?;
                let state = blocking_ingress.store.load_state()?.unwrap_or_default();
                Ok::<_, ramflux_node_core::NodeCoreError>(
                    state.provider_attempts(&queue_id).to_vec(),
                )
            })
            .await
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))??;
            async_json_response("200 OK", &attempts, keep_alive)
        }
        AsyncItestHttpRoute::Mvp10NotifyDeliver => {
            handle_mvp10_notify_deliver_value_async(ingress, request.body, keep_alive).await
        }
        AsyncItestHttpRoute::Mvp10NotifyState => {
            handle_mvp10_notify_state_value_async(ingress, keep_alive).await
        }
        AsyncItestHttpRoute::NotFound => {
            Ok(async_text_response("404 Not Found", "not found", keep_alive))
        }
    }
}

#[cfg(feature = "itest-http")]
fn is_raw_s13_wake_request(request: &AsyncItestHttpRequest, ingress: &NotifyIngressState) -> bool {
    ingress.async_accept
        && notify_wal_raw_enqueue_enabled()
        && matches!(request.route, AsyncItestHttpRoute::S13NotifyWake)
}

#[cfg(feature = "itest-http")]
fn async_itest_route(method: &str, path: &str) -> AsyncItestHttpRoute {
    match (method, path) {
        ("GET", "/healthz") => AsyncItestHttpRoute::Healthz,
        ("POST", "/mvp10/notify/wake") => AsyncItestHttpRoute::Mvp10NotifyWake,
        ("POST", "/s13/notify/push-route") => AsyncItestHttpRoute::S13NotifyPushRoute,
        ("POST", "/s13/notify/provider-credential") => {
            AsyncItestHttpRoute::S13NotifyProviderCredential
        }
        ("POST", "/s13/notify/wake") => AsyncItestHttpRoute::S13NotifyWake,
        ("POST", "/mvp10/notify/deliver") => AsyncItestHttpRoute::Mvp10NotifyDeliver,
        ("GET", "/mvp10/notify/state") => AsyncItestHttpRoute::Mvp10NotifyState,
        ("GET", value) if value.starts_with("/s13/notify/provider-attempts/") => {
            AsyncItestHttpRoute::S13NotifyProviderAttempts(
                value.trim_start_matches("/s13/notify/provider-attempts/").to_owned(),
            )
        }
        _ => AsyncItestHttpRoute::NotFound,
    }
}

#[cfg(feature = "itest-http")]
async fn handle_mvp10_notify_wake_value_async(
    ingress: Arc<NotifyIngressState>,
    body: Vec<u8>,
    keep_alive: bool,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let entry = tokio::task::spawn_blocking(move || {
        let body: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
        let wake_value = body.get("wake").cloned().ok_or_else(|| {
            ramflux_node_core::NodeCoreError::ItestJson("missing wake".to_owned())
        })?;
        let wake: ramflux_protocol::NotificationWake = serde_json::from_value(wake_value)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
        ingress.wake_auth.verify(&wake)?;
        let push_alias_hash = body
            .get("push_alias_hash")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("push_alias_hash")
            .to_owned();
        let queued_at =
            body.get("queued_at").and_then(serde_json::Value::as_u64).unwrap_or(1_760_000_000);
        let _guard = lock_notify_store(&ingress.store_gate)?;
        ingress.store.queue_wake(wake, push_alias_hash, queued_at)
    })
    .await
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))??;
    async_json_response("200 OK", &entry, keep_alive)
}

#[cfg(feature = "itest-http")]
async fn handle_s13_push_route_value_async(
    ingress: Arc<NotifyIngressState>,
    body: Vec<u8>,
    keep_alive: bool,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let route = tokio::task::spawn_blocking(move || {
        let route: ramflux_node_core::DevicePushRoute = serde_json::from_slice(&body)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
        tracing::info!(
            device_delivery_id = route.device_delivery_id,
            provider = ?route.provider,
            credential_id = route.credential_id.as_deref().unwrap_or(""),
            "notify push route registered"
        );
        let _guard = lock_notify_store(&ingress.store_gate)?;
        ingress.store.register_push_route(route.clone())?;
        Ok::<_, ramflux_node_core::NodeCoreError>(route)
    })
    .await
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))??;
    async_json_response("200 OK", &route, keep_alive)
}

#[cfg(feature = "itest-http")]
async fn handle_s13_provider_credential_value_async(
    ingress: Arc<NotifyIngressState>,
    body: Vec<u8>,
    keep_alive: bool,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let credential = tokio::task::spawn_blocking(move || {
        let credential: ramflux_node_core::ProviderCredential = serde_json::from_slice(&body)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
        tracing::info!(
            credential_id = credential.credential_id(),
            provider = ?credential.provider_kind(),
            "notify provider credential registered"
        );
        let _guard = lock_notify_store(&ingress.store_gate)?;
        ingress.store.update_provider_credential(credential.clone())?;
        Ok::<_, ramflux_node_core::NodeCoreError>(credential)
    })
    .await
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))??;
    async_json_response("200 OK", &credential, keep_alive)
}

#[cfg(feature = "itest-http")]
async fn handle_s13_wake_async_accept_value_async(
    store: &ramflux_node_core::NotifyRedbStore,
    wake_auth: &NotifyWakeAuth,
    request: &S13WakeRequest,
) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
    wake_auth.verify(&request.wake)?;
    let entry = store
        .queue_wake_for_async_accept_async(
            &request.device_delivery_id,
            &request.wake,
            request.queued_at.unwrap_or_else(ramflux_node_core::now_unix_seconds),
            request.dnd_active.unwrap_or(false),
        )
        .await?;
    Ok(S13WakeResponse { entry, attempts: Vec::new() })
}

#[cfg(feature = "itest-http")]
async fn handle_s13_wake_raw_async_accept_value_async(
    store: &ramflux_node_core::NotifyRedbStore,
    wake_auth: &NotifyWakeAuth,
    raw_body: Vec<u8>,
) -> Result<serde_json::Value, ramflux_node_core::NodeCoreError> {
    let request = parse_s13_wake_request_body(&raw_body)?;
    wake_auth.verify(&request.wake)?;
    let queued_at = ramflux_node_core::now_unix_seconds();
    let shard_id = store.notify_ingest_shard_for_key(&request.device_delivery_id);
    let raw =
        store.queue_raw_wake_for_async_accept_shard_async(shard_id, raw_body, queued_at).await?;
    Ok(serde_json::json!({
        "queue_id": raw.queue_id
    }))
}

#[cfg(feature = "itest-http")]
async fn ingest_raw_s13_wake_for_async_ingress(
    ingress: &NotifyIngressState,
    raw_body: Vec<u8>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let queued_at = ramflux_node_core::now_unix_seconds();
    let request = parse_s13_wake_request_body(&raw_body)?;
    let shard_id = ingress.store.notify_ingest_shard_for_key(&request.device_delivery_id);
    if let Some(batcher) = &ingress.wake_verify_batcher {
        return batcher.verify_and_enqueue(shard_id, request.wake, raw_body, queued_at).await;
    }
    ingress.wake_auth.verify(&request.wake)?;
    ingress
        .store
        .queue_raw_wake_for_async_accept_shard_async(shard_id, raw_body, queued_at)
        .await
        .map(|_raw| ())
}

#[cfg(feature = "itest-http")]
async fn handle_mvp10_notify_deliver_value_async(
    ingress: Arc<NotifyIngressState>,
    body: Vec<u8>,
    keep_alive: bool,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let entry = tokio::task::spawn_blocking(move || {
        let body: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
        let queue_id =
            body.get("queue_id").and_then(serde_json::Value::as_str).ok_or_else(|| {
                ramflux_node_core::NodeCoreError::ItestJson("missing queue_id".to_owned())
            })?;
        let _guard = lock_notify_store(&ingress.store_gate)?;
        let mut state = ingress.store.load_state()?.unwrap_or_default();
        state.mark_delivered(queue_id)?;
        let entry = state.entry(queue_id).cloned().ok_or_else(|| {
            ramflux_node_core::NodeCoreError::EnvelopeNotFound(queue_id.to_owned())
        })?;
        ingress.store.save_state(&state)?;
        Ok::<_, ramflux_node_core::NodeCoreError>(entry)
    })
    .await
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))??;
    async_json_response("200 OK", &entry, keep_alive)
}

#[cfg(feature = "itest-http")]
async fn handle_mvp10_notify_state_value_async(
    ingress: Arc<NotifyIngressState>,
    keep_alive: bool,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let state = tokio::task::spawn_blocking(move || {
        let _guard = lock_notify_store(&ingress.store_gate)?;
        ingress.store.load_state().map(std::option::Option::unwrap_or_default)
    })
    .await
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))??;
    async_json_response("200 OK", &state, keep_alive)
}

#[cfg(feature = "itest-http")]
fn async_json_response<T: serde::Serialize>(
    status: &'static str,
    value: &T,
    keep_alive: bool,
) -> Result<AsyncItestHttpResponse, ramflux_node_core::NodeCoreError> {
    let body = serde_json::to_vec(value)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    Ok(AsyncItestHttpResponse { status, content_type: "application/json", body, keep_alive })
}

#[cfg(feature = "itest-http")]
fn async_text_response(
    status: &'static str,
    body: &str,
    keep_alive: bool,
) -> AsyncItestHttpResponse {
    AsyncItestHttpResponse {
        status,
        content_type: "text/plain; charset=utf-8",
        body: body.as_bytes().to_vec(),
        keep_alive,
    }
}

#[cfg(feature = "itest-http")]
async fn write_async_itest_response(
    writer: &mut tokio::net::TcpStream,
    response: &AsyncItestHttpResponse,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let connection = if response.keep_alive { "keep-alive" } else { "close" };
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    tokio::io::AsyncWriteExt::write_all(writer, header.as_bytes())
        .await
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    tokio::io::AsyncWriteExt::write_all(writer, &response.body)
        .await
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    tokio::io::AsyncWriteExt::flush(writer)
        .await
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(())
}

#[cfg(feature = "itest-http")]
async fn write_async_fixed_json_ok_response(
    writer: &mut tokio::net::TcpStream,
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    const OK_KEEP_ALIVE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n{}";
    const OK_CLOSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
    let response = if keep_alive { OK_KEEP_ALIVE } else { OK_CLOSE };
    tokio::io::AsyncWriteExt::write_all(writer, response)
        .await
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    Ok(())
}

#[cfg(feature = "itest-http")]
async fn write_async_text_response(
    writer: &mut tokio::net::TcpStream,
    status: &'static str,
    body: &str,
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let response = async_text_response(status, body, keep_alive);
    write_async_itest_response(writer, &response).await
}

#[cfg(feature = "itest-http")]
fn find_async_http_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n").or_else(|| {
        buffer.windows(2).position(|window| window == b"\n\n").map(|position| position + 1)
    })
}

#[cfg(feature = "itest-http")]
fn async_http_header_separator_len(buffer: &[u8], header_end: usize) -> usize {
    if buffer.get(header_end..header_end + 4) == Some(b"\r\n\r\n") { 4 } else { 1 }
}

#[cfg(feature = "itest-http")]
fn async_connection_header_requests_keep_alive(value: &str) -> bool {
    value.split(',').map(str::trim).any(|token| token.eq_ignore_ascii_case("keep-alive"))
}

#[cfg(feature = "itest-http")]
fn handle_mvp10_notify_wake(
    stream: &mut TcpStream,
    ingress: &NotifyIngressState,
    body: &[u8],
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let body: serde_json::Value = serde_json::from_slice(body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    let wake_value = body
        .get("wake")
        .cloned()
        .ok_or_else(|| ramflux_node_core::NodeCoreError::ItestJson("missing wake".to_owned()))?;
    let wake: ramflux_protocol::NotificationWake = serde_json::from_value(wake_value)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    ingress.wake_auth.verify(&wake)?;
    let push_alias_hash = body
        .get("push_alias_hash")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("push_alias_hash")
        .to_owned();
    let queued_at =
        body.get("queued_at").and_then(serde_json::Value::as_u64).unwrap_or(1_760_000_000);
    let entry = {
        let _guard = lock_notify_store(&ingress.store_gate)?;
        ingress.store.queue_wake(wake, push_alias_hash, queued_at)?
    };
    ramflux_node_core::write_itest_json_response_with_connection(
        stream, "200 OK", &entry, keep_alive,
    )
}

#[cfg(feature = "itest-http")]
fn handle_s13_provider_attempts(
    stream: &mut TcpStream,
    ingress: &NotifyIngressState,
    queue_id: &str,
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let attempts = {
        let _guard = lock_notify_store(&ingress.store_gate)?;
        let state = ingress.store.load_state()?.unwrap_or_default();
        state.provider_attempts(queue_id).to_vec()
    };
    ramflux_node_core::write_itest_json_response_with_connection(
        stream, "200 OK", &attempts, keep_alive,
    )
}

#[cfg(feature = "itest-http")]
fn handle_mvp10_notify_deliver(
    stream: &mut TcpStream,
    ingress: &NotifyIngressState,
    body: &[u8],
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let body: serde_json::Value = serde_json::from_slice(body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    let queue_id = body.get("queue_id").and_then(serde_json::Value::as_str).ok_or_else(|| {
        ramflux_node_core::NodeCoreError::ItestJson("missing queue_id".to_owned())
    })?;
    let entry = {
        let _guard = lock_notify_store(&ingress.store_gate)?;
        let mut state = ingress.store.load_state()?.unwrap_or_default();
        state.mark_delivered(queue_id)?;
        let entry = state.entry(queue_id).cloned().ok_or_else(|| {
            ramflux_node_core::NodeCoreError::EnvelopeNotFound(queue_id.to_owned())
        })?;
        ingress.store.save_state(&state)?;
        entry
    };
    ramflux_node_core::write_itest_json_response_with_connection(
        stream, "200 OK", &entry, keep_alive,
    )
}

#[cfg(feature = "itest-http")]
fn handle_mvp10_notify_state(
    stream: &mut TcpStream,
    ingress: &NotifyIngressState,
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let state = {
        let _guard = lock_notify_store(&ingress.store_gate)?;
        ingress.store.load_state()?.unwrap_or_default()
    };
    ramflux_node_core::write_itest_json_response_with_connection(
        stream, "200 OK", &state, keep_alive,
    )
}

#[cfg(feature = "itest-http")]
fn handle_s13_push_route(
    stream: &mut TcpStream,
    store: &ramflux_node_core::NotifyRedbStore,
    store_gate: &Arc<Mutex<()>>,
    body: &[u8],
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let route: ramflux_node_core::DevicePushRoute = serde_json::from_slice(body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    tracing::info!(
        device_delivery_id = route.device_delivery_id,
        provider = ?route.provider,
        credential_id = route.credential_id.as_deref().unwrap_or(""),
        "notify push route registered"
    );
    {
        let _guard = lock_notify_store(store_gate)?;
        store.register_push_route(route.clone())?;
    }
    ramflux_node_core::write_itest_json_response_with_connection(
        stream, "200 OK", &route, keep_alive,
    )
}

#[cfg(feature = "itest-http")]
fn handle_s13_provider_credential(
    stream: &mut TcpStream,
    store: &ramflux_node_core::NotifyRedbStore,
    store_gate: &Arc<Mutex<()>>,
    body: &[u8],
    keep_alive: bool,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let credential: ramflux_node_core::ProviderCredential = serde_json::from_slice(body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    tracing::info!(
        credential_id = credential.credential_id(),
        provider = ?credential.provider_kind(),
        "notify provider credential registered"
    );
    {
        let _guard = lock_notify_store(store_gate)?;
        store.update_provider_credential(credential.clone())?;
    }
    ramflux_node_core::write_itest_json_response_with_connection(
        stream,
        "200 OK",
        &credential,
        keep_alive,
    )
}

enum NotifyRuntime {
    Current,
    TokioConcurrent(ConcurrentNotifyRuntime),
    #[cfg(all(target_os = "linux", feature = "compio-notify"))]
    Compio(CompioNotifyRuntime),
}

impl NotifyRuntime {
    fn from_env(
        store: &Arc<ramflux_node_core::NotifyRedbStore>,
        store_gate: &Arc<Mutex<()>>,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        match std::env::var(NOTIFY_RUNTIME_ENV).as_deref() {
            Ok("compio") => notify_compio_runtime_from_store(store, store_gate),
            Ok("tokio-concurrent") => Ok(Self::TokioConcurrent(ConcurrentNotifyRuntime::new(
                store,
                store_gate,
                "tokio-concurrent",
            )?)),
            Ok("current" | "tokio") | Err(_) => Ok(Self::Current),
            Ok(other) => Err(ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "unsupported notify runtime {other}"
            ))),
        }
    }

    fn dispatch_s13_wake(
        &self,
        store: &ramflux_node_core::NotifyRedbStore,
        store_gate: &Arc<Mutex<()>>,
        request: &S13WakeRequest,
    ) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
        match self {
            Self::Current => dispatch_s13_wake_current(store, store_gate, request),
            Self::TokioConcurrent(runtime) => runtime.dispatch_s13_wake(request),
            #[cfg(all(target_os = "linux", feature = "compio-notify"))]
            Self::Compio(runtime) => runtime.dispatch_s13_wake(request),
        }
    }
}

struct ConcurrentNotifyRuntime {
    workers: std::sync::Arc<ConcurrentNotifyFanoutWorkerPool>,
}

impl ConcurrentNotifyRuntime {
    fn new(
        store: &Arc<ramflux_node_core::NotifyRedbStore>,
        store_gate: &Arc<Mutex<()>>,
        env_prefix: &str,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        let worker_count = notify_runtime_usize_env(
            &format!("RAMFLUX_NOTIFY_{}_WORKERS", env_key(env_prefix)),
            || std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
        )
        .max(1);
        let queue_capacity = notify_runtime_usize_env(
            &format!("RAMFLUX_NOTIFY_{}_QUEUE_CAPACITY", env_key(env_prefix)),
            || 1024,
        )
        .max(1);
        let provider_worker_count = notify_runtime_usize_env(
            &format!("RAMFLUX_NOTIFY_{}_PROVIDER_WORKERS", env_key(env_prefix)),
            || worker_count.saturating_mul(2).max(1),
        )
        .max(1);
        let provider_workers =
            std::sync::Arc::new(ConcurrentProviderPushWorkerPool::new(provider_worker_count)?);
        let workers = std::sync::Arc::new(ConcurrentNotifyFanoutWorkerPool::new(
            worker_count,
            queue_capacity,
            store,
            store_gate,
            &provider_workers,
        )?);
        tracing::info!(
            worker_count,
            provider_worker_count,
            "notify tokio-concurrent fanout runtime initialized"
        );
        Ok(Self { workers })
    }

    fn dispatch_s13_wake(
        &self,
        request: &S13WakeRequest,
    ) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
        self.workers.dispatch(request)
    }
}

struct ConcurrentNotifyFanoutCommand {
    request: S13WakeRequest,
    reply: std::sync::mpsc::SyncSender<Result<S13WakeResponse, ramflux_node_core::NodeCoreError>>,
}

struct ConcurrentNotifyFanoutWorkerPool {
    senders: Vec<std::sync::mpsc::SyncSender<ConcurrentNotifyFanoutCommand>>,
    _threads: Vec<std::thread::JoinHandle<()>>,
}

impl ConcurrentNotifyFanoutWorkerPool {
    fn new(
        worker_count: usize,
        queue_capacity: usize,
        store: &Arc<ramflux_node_core::NotifyRedbStore>,
        store_gate: &Arc<Mutex<()>>,
        provider_workers: &std::sync::Arc<ConcurrentProviderPushWorkerPool>,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        let mut senders = Vec::with_capacity(worker_count);
        let mut threads = Vec::with_capacity(worker_count);
        for worker_id in 0..worker_count {
            let (sender, receiver) = std::sync::mpsc::sync_channel(queue_capacity);
            let thread_store = Arc::clone(store);
            let thread_store_gate = Arc::clone(store_gate);
            let thread_provider_workers = std::sync::Arc::clone(provider_workers);
            let thread = std::thread::Builder::new()
                .name(format!("ramflux-notify-tokio-fanout-worker-{worker_id}"))
                .spawn(move || {
                    concurrent_notify_fanout_worker_loop(
                        &receiver,
                        &thread_store,
                        &thread_store_gate,
                        &thread_provider_workers,
                    );
                })
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })?;
            senders.push(sender);
            threads.push(thread);
        }
        Ok(Self { senders, _threads: threads })
    }

    fn dispatch(
        &self,
        request: &S13WakeRequest,
    ) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
        let shard = notify_shard_index(&request.device_delivery_id, self.senders.len());
        let (reply, response) = std::sync::mpsc::sync_channel(1);
        let command = ConcurrentNotifyFanoutCommand { request: request.clone(), reply };
        self.senders[shard].send(command).map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify tokio-concurrent worker queue closed: {error}"
            ))
        })?;
        response.recv().map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify tokio-concurrent response closed: {error}"
            ))
        })?
    }
}

fn concurrent_notify_fanout_worker_loop(
    receiver: &std::sync::mpsc::Receiver<ConcurrentNotifyFanoutCommand>,
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    store_gate: &Arc<Mutex<()>>,
    provider_workers: &std::sync::Arc<ConcurrentProviderPushWorkerPool>,
) {
    while let Ok(command) = receiver.recv() {
        let result = dispatch_s13_wake_concurrent_worker(
            store,
            store_gate,
            provider_workers,
            &command.request,
        );
        let _result = command.reply.send(result);
    }
}

struct ConcurrentProviderPushWorkerPool {
    senders: Vec<std::sync::mpsc::SyncSender<ConcurrentProviderPushJob>>,
    next_worker: std::sync::atomic::AtomicUsize,
    _runtime: Arc<tokio::runtime::Runtime>,
    _h2_pool: Arc<ProviderH2ConnectionPool>,
    _threads: Vec<std::thread::JoinHandle<()>>,
}

impl ConcurrentProviderPushWorkerPool {
    fn new(worker_count: usize) -> Result<Self, ramflux_node_core::NodeCoreError> {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("ramflux-notify-provider-h2")
                .worker_threads(worker_count)
                .build()
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })?,
        );
        let h2_pool = Arc::new(ProviderH2ConnectionPool::from_env());
        let mut senders = Vec::with_capacity(worker_count);
        let mut threads = Vec::with_capacity(worker_count);
        for worker_id in 0..worker_count {
            let (sender, receiver) = std::sync::mpsc::sync_channel(1024);
            let thread_runtime = Arc::clone(&runtime);
            let thread_h2_pool = Arc::clone(&h2_pool);
            let thread = std::thread::Builder::new()
                .name(format!("ramflux-notify-provider-worker-{worker_id}"))
                .spawn(move || {
                    concurrent_provider_push_worker_loop(
                        &receiver,
                        &thread_runtime,
                        &thread_h2_pool,
                    );
                })
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })?;
            senders.push(sender);
            threads.push(thread);
        }
        Ok(Self {
            senders,
            next_worker: std::sync::atomic::AtomicUsize::new(0),
            _runtime: runtime,
            _h2_pool: h2_pool,
            _threads: threads,
        })
    }

    fn dispatch(
        &self,
        prepared: ramflux_node_core::PreparedProviderPush,
    ) -> Result<
        std::sync::mpsc::Receiver<Result<bool, ramflux_node_core::NodeCoreError>>,
        ramflux_node_core::NodeCoreError,
    > {
        let worker = self.next_worker.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.senders.len();
        let (reply, response) = std::sync::mpsc::sync_channel(1);
        self.senders[worker].try_send(ConcurrentProviderPushJob { prepared, reply }).map_err(
            |error| {
                ramflux_node_core::NodeCoreError::ItestHttp(format!(
                    "notify provider worker queue unavailable: {error}"
                ))
            },
        )?;
        Ok(response)
    }
}

struct ConcurrentProviderPushJob {
    prepared: ramflux_node_core::PreparedProviderPush,
    reply: std::sync::mpsc::SyncSender<Result<bool, ramflux_node_core::NodeCoreError>>,
}

fn concurrent_provider_push_worker_loop(
    receiver: &std::sync::mpsc::Receiver<ConcurrentProviderPushJob>,
    runtime: &tokio::runtime::Runtime,
    h2_pool: &ProviderH2ConnectionPool,
) {
    while let Ok(job) = receiver.recv() {
        let result = send_provider_push_with_runtime(runtime, h2_pool, &job.prepared);
        let _result = job.reply.send(result);
    }
}

fn dispatch_s13_wake_concurrent_worker(
    store: &ramflux_node_core::NotifyRedbStore,
    _store_gate: &Arc<Mutex<()>>,
    provider_workers: &ConcurrentProviderPushWorkerPool,
    request: &S13WakeRequest,
) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
    let (entry, pushes) = store.queue_wake_for_push(
        &request.device_delivery_id,
        &request.wake,
        request.queued_at.unwrap_or_else(ramflux_node_core::now_unix_seconds),
        request.dnd_active.unwrap_or(false),
    )?;
    tracing::debug!(
        queue_id = %entry.queue_id,
        device_delivery_id = request.device_delivery_id,
        prepared_push_count = pushes.len(),
        "notify concurrent fanout prepared provider pushes"
    );
    let mut pending = Vec::with_capacity(pushes.len());
    for prepared in pushes {
        let response = provider_workers.dispatch(prepared.clone())?;
        pending.push((prepared, response));
    }
    let mut attempts = Vec::with_capacity(pending.len());
    for (prepared, response) in pending {
        let accepted = match response.recv().map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify provider worker response closed: {error}"
            ))
        })? {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(
                    device_delivery_id = prepared.route.device_delivery_id,
                    provider = ?prepared.route.provider,
                    push_alias_hash = prepared.push_alias_hash,
                    collapse_key_hash = prepared.collapse_key_hash,
                    %error,
                    "push provider send failed"
                );
                false
            }
        };
        let attempt = ramflux_node_core::redacted_provider_attempt(
            &entry,
            &prepared,
            accepted,
            (!accepted).then(|| "provider_send_failed".to_owned()),
        );
        store.record_provider_attempt(attempt.clone())?;
        attempts.push(attempt);
    }
    Ok(S13WakeResponse { entry, attempts })
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
fn notify_compio_runtime_from_store(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    store_gate: &Arc<Mutex<()>>,
) -> Result<NotifyRuntime, ramflux_node_core::NodeCoreError> {
    notify_compio_runtime(store, store_gate)
}

#[cfg(not(all(target_os = "linux", feature = "compio-notify")))]
fn notify_compio_runtime_from_store(
    _store: &Arc<ramflux_node_core::NotifyRedbStore>,
    _store_gate: &Arc<Mutex<()>>,
) -> Result<NotifyRuntime, ramflux_node_core::NodeCoreError> {
    Err(notify_compio_runtime_error())
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
fn notify_compio_runtime(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    store_gate: &Arc<Mutex<()>>,
) -> Result<NotifyRuntime, ramflux_node_core::NodeCoreError> {
    Ok(NotifyRuntime::Compio(CompioNotifyRuntime::new(store, store_gate)?))
}

#[cfg(not(all(target_os = "linux", feature = "compio-notify")))]
fn notify_compio_runtime_error() -> ramflux_node_core::NodeCoreError {
    ramflux_node_core::NodeCoreError::ItestHttp(
        "RAMFLUX_NOTIFY_RUNTIME=compio requested but compio-notify is not compiled".to_owned(),
    )
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
struct CompioNotifyRuntime {
    shards: Vec<tokio::sync::mpsc::Sender<NotifyFanoutCommand>>,
    _fanout_workers: std::sync::Arc<NotifyFanoutWorkerPool>,
    _runtime_thread: std::thread::JoinHandle<()>,
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
impl CompioNotifyRuntime {
    fn new(
        store: &Arc<ramflux_node_core::NotifyRedbStore>,
        store_gate: &Arc<Mutex<()>>,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        let shard_count = notify_runtime_usize_env("RAMFLUX_NOTIFY_COMPIO_SHARDS", || {
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
        });
        let shard_count = shard_count.max(1);
        let command_capacity =
            notify_runtime_usize_env("RAMFLUX_NOTIFY_COMPIO_QUEUE_CAPACITY", || 1024).max(1);
        let provider_worker_count =
            notify_runtime_usize_env("RAMFLUX_NOTIFY_COMPIO_PROVIDER_WORKERS", || {
                shard_count.saturating_mul(2).max(1)
            })
            .max(1);
        let fanout_worker_count =
            notify_runtime_usize_env("RAMFLUX_NOTIFY_COMPIO_FANOUT_WORKERS", || shard_count).max(1);
        let provider_workers =
            std::sync::Arc::new(ConcurrentProviderPushWorkerPool::new(provider_worker_count)?);
        let fanout_workers = std::sync::Arc::new(NotifyFanoutWorkerPool::new(
            fanout_worker_count,
            command_capacity,
            store,
            store_gate,
            &provider_workers,
        )?);
        let mut senders = Vec::with_capacity(shard_count);
        let mut receivers = Vec::with_capacity(shard_count);
        for _index in 0..shard_count {
            let (sender, receiver) = tokio::sync::mpsc::channel(command_capacity);
            senders.push(sender);
            receivers.push(receiver);
        }
        let thread_fanout_workers = std::sync::Arc::clone(&fanout_workers);
        let runtime_thread = std::thread::Builder::new()
            .name("ramflux-notify-compio-fanout".to_owned())
            .spawn(move || {
                if let Err(error) = run_notify_compio_runtime(receivers, thread_fanout_workers) {
                    tracing::error!(%error, "notify compio runtime stopped");
                }
            })
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
        tracing::info!(
            shard_count,
            fanout_worker_count,
            provider_worker_count,
            "notify compio per-shard fanout runtime initialized"
        );
        Ok(Self {
            shards: senders,
            _fanout_workers: fanout_workers,
            _runtime_thread: runtime_thread,
        })
    }

    fn dispatch_s13_wake(
        &self,
        request: &S13WakeRequest,
    ) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
        let shard = notify_shard_index(&request.device_delivery_id, self.shards.len());
        let (reply, response) = std::sync::mpsc::sync_channel(1);
        let command = NotifyFanoutCommand { request: request.clone(), reply };
        self.shards[shard].blocking_send(command).map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify compio shard queue closed: {error}"
            ))
        })?;
        response.recv().map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify compio fanout response closed: {error}"
            ))
        })?
    }
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
struct NotifyFanoutCommand {
    request: S13WakeRequest,
    reply: std::sync::mpsc::SyncSender<Result<S13WakeResponse, ramflux_node_core::NodeCoreError>>,
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
struct NotifyFanoutJob {
    request: S13WakeRequest,
    reply: std::sync::mpsc::SyncSender<Result<S13WakeResponse, ramflux_node_core::NodeCoreError>>,
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
struct NotifyFanoutWorkerPool {
    senders: Vec<std::sync::mpsc::SyncSender<NotifyFanoutJob>>,
    next_worker: std::sync::atomic::AtomicUsize,
    _threads: Vec<std::thread::JoinHandle<()>>,
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
impl NotifyFanoutWorkerPool {
    fn new(
        worker_count: usize,
        queue_capacity: usize,
        store: &Arc<ramflux_node_core::NotifyRedbStore>,
        store_gate: &Arc<Mutex<()>>,
        provider_workers: &std::sync::Arc<ConcurrentProviderPushWorkerPool>,
    ) -> Result<Self, ramflux_node_core::NodeCoreError> {
        let mut senders = Vec::with_capacity(worker_count);
        let mut threads = Vec::with_capacity(worker_count);
        for worker_id in 0..worker_count {
            let (sender, receiver) = std::sync::mpsc::sync_channel(queue_capacity);
            let thread_provider_workers = std::sync::Arc::clone(provider_workers);
            let thread_store = Arc::clone(store);
            let thread_store_gate = Arc::clone(store_gate);
            let thread = std::thread::Builder::new()
                .name(format!("ramflux-notify-fanout-worker-{worker_id}"))
                .spawn(move || {
                    notify_fanout_worker_loop(
                        &receiver,
                        &thread_store,
                        &thread_store_gate,
                        &thread_provider_workers,
                    );
                })
                .map_err(|source| {
                    ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
                })?;
            senders.push(sender);
            threads.push(thread);
        }
        Ok(Self { senders, next_worker: std::sync::atomic::AtomicUsize::new(0), _threads: threads })
    }

    fn try_dispatch(&self, job: NotifyFanoutJob) -> Result<(), Box<NotifyFanoutJob>> {
        let worker = self.next_worker.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.senders.len();
        self.senders[worker].try_send(job).map_err(|error| match error {
            std::sync::mpsc::TrySendError::Full(job)
            | std::sync::mpsc::TrySendError::Disconnected(job) => Box::new(job),
        })
    }
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
fn run_notify_compio_runtime(
    receivers: Vec<tokio::sync::mpsc::Receiver<NotifyFanoutCommand>>,
    fanout_workers: std::sync::Arc<NotifyFanoutWorkerPool>,
) -> anyhow::Result<()> {
    let runtime = compio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        for receiver in receivers {
            let workers = std::sync::Arc::clone(&fanout_workers);
            compio::runtime::spawn(async move {
                notify_compio_shard_loop(receiver, workers).await;
            })
            .detach();
        }
        std::future::pending::<()>().await;
    });
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
async fn notify_compio_shard_loop(
    mut receiver: tokio::sync::mpsc::Receiver<NotifyFanoutCommand>,
    fanout_workers: std::sync::Arc<NotifyFanoutWorkerPool>,
) {
    while let Some(command) = receiver.recv().await {
        let job = NotifyFanoutJob { request: command.request, reply: command.reply };
        if let Err(job) = fanout_workers.try_dispatch(job) {
            let _result = job.reply.send(Err(ramflux_node_core::NodeCoreError::ItestHttp(
                "notify compio fanout worker queue is full".to_owned(),
            )));
        }
    }
}

#[cfg(all(target_os = "linux", feature = "compio-notify"))]
fn notify_fanout_worker_loop(
    receiver: &std::sync::mpsc::Receiver<NotifyFanoutJob>,
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    store_gate: &Arc<Mutex<()>>,
    provider_workers: &std::sync::Arc<ConcurrentProviderPushWorkerPool>,
) {
    while let Ok(job) = receiver.recv() {
        let result =
            dispatch_s13_wake_concurrent_worker(store, store_gate, provider_workers, &job.request);
        let _result = job.reply.send(result);
    }
}

fn notify_runtime_usize_env(name: &str, default: impl FnOnce() -> usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or_else(default)
}

fn env_key(value: &str) -> String {
    value.replace('-', "_").to_ascii_uppercase()
}

fn notify_shard_index(device_delivery_id: &str, shard_count: usize) -> usize {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    device_delivery_id.hash(&mut hasher);
    let hash = hasher.finish();
    let shard_count = u64::try_from(shard_count).unwrap_or(1).max(1);
    usize::try_from(hash % shard_count).unwrap_or(0)
}

fn handle_s13_wake_value(
    store: &ramflux_node_core::NotifyRedbStore,
    store_gate: &Arc<Mutex<()>>,
    runtime: &NotifyRuntime,
    request: &S13WakeRequest,
) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
    runtime.dispatch_s13_wake(store, store_gate, request)
}

fn handle_s13_wake_async_accept(
    store: &ramflux_node_core::NotifyRedbStore,
    request: &S13WakeRequest,
) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
    let entry = store.queue_wake_for_async_accept(
        &request.device_delivery_id,
        &request.wake,
        request.queued_at.unwrap_or_else(ramflux_node_core::now_unix_seconds),
        request.dnd_active.unwrap_or(false),
    )?;
    Ok(S13WakeResponse { entry, attempts: Vec::new() })
}

fn dispatch_s13_wake_current(
    store: &ramflux_node_core::NotifyRedbStore,
    _store_gate: &Arc<Mutex<()>>,
    request: &S13WakeRequest,
) -> Result<S13WakeResponse, ramflux_node_core::NodeCoreError> {
    let (entry, pushes) = store.queue_wake_for_push(
        &request.device_delivery_id,
        &request.wake,
        request.queued_at.unwrap_or_else(ramflux_node_core::now_unix_seconds),
        request.dnd_active.unwrap_or(false),
    )?;
    tracing::debug!(
        queue_id = %entry.queue_id,
        device_delivery_id = request.device_delivery_id,
        prepared_push_count = pushes.len(),
        "notify wake dispatch prepared provider pushes"
    );
    let mut attempts = Vec::with_capacity(pushes.len());
    for prepared in pushes {
        let accepted = match send_provider_push(&prepared) {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(
                    device_delivery_id = prepared.route.device_delivery_id,
                    provider = ?prepared.route.provider,
                    push_alias_hash = prepared.push_alias_hash,
                    collapse_key_hash = prepared.collapse_key_hash,
                    %error,
                    "push provider send failed"
                );
                false
            }
        };
        let attempt = ramflux_node_core::redacted_provider_attempt(
            &entry,
            &prepared,
            accepted,
            (!accepted).then(|| "provider_send_failed".to_owned()),
        );
        store.record_provider_attempt(attempt.clone())?;
        attempts.push(attempt);
    }
    Ok(S13WakeResponse { entry, attempts })
}

fn notify_async_accept_enabled() -> bool {
    notify_default_enabled_env(NOTIFY_ASYNC_ACCEPT_ENV)
}

#[cfg(feature = "itest-http")]
fn notify_wal_raw_enqueue_enabled() -> bool {
    std::env::var(NOTIFY_WAL_RAW_ENQUEUE_ENV).as_deref() == Ok("1")
}

fn notify_default_enabled_env(name: &str) -> bool {
    std::env::var(name).map_or(true, |value| {
        let trimmed = value.trim();
        !(trimmed == "0"
            || trimmed.eq_ignore_ascii_case("false")
            || trimmed.eq_ignore_ascii_case("off")
            || trimmed.eq_ignore_ascii_case("no"))
    })
}

fn start_notify_async_delivery_workers(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let worker_count = notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_DELIVERY_WORKERS", || {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    })
    .max(1);
    let scan_limit =
        notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_DELIVERY_SCAN_LIMIT", || 256).max(1);
    let idle_sleep_ms =
        notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_DELIVERY_IDLE_SLEEP_MS", || 10).max(1);
    let provider_worker_count =
        notify_runtime_usize_env("RAMFLUX_NOTIFY_ASYNC_PROVIDER_WORKERS", || {
            worker_count.saturating_mul(2).max(1)
        })
        .max(1);
    let provider_workers = Arc::new(ConcurrentProviderPushWorkerPool::new(provider_worker_count)?);
    let in_flight = Arc::new(Mutex::new(BTreeSet::<String>::new()));
    for worker_id in 0..worker_count {
        let thread_store = Arc::clone(store);
        let thread_provider_workers = Arc::clone(&provider_workers);
        let thread_in_flight = Arc::clone(&in_flight);
        std::thread::Builder::new()
            .name(format!("ramflux-notify-async-delivery-{worker_id}"))
            .spawn(move || {
                notify_async_delivery_worker_loop(
                    &thread_store,
                    &thread_provider_workers,
                    &thread_in_flight,
                    scan_limit,
                    Duration::from_millis(u64::try_from(idle_sleep_ms).unwrap_or(u64::MAX)),
                );
            })
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    }
    tracing::info!(
        worker_count,
        provider_worker_count,
        scan_limit,
        idle_sleep_ms,
        "notify async accept delivery workers initialized"
    );
    Ok(())
}

fn log_notify_wal_recovery(store: &ramflux_node_core::NotifyRedbStore) {
    for shard in store.notify_wal_recovered_counts() {
        tracing::debug!(
            shard_id = shard.shard_id,
            recovered_queue_entries = shard.counts.queue_entry_count,
            recovered_raw_wakes = shard.counts.raw_wake_count,
            recovered_provider_attempt_queues = shard.counts.provider_attempt_queue_count,
            "notify WAL shard recovered"
        );
    }
}

fn notify_async_delivery_worker_loop(
    store: &Arc<ramflux_node_core::NotifyRedbStore>,
    provider_workers: &ConcurrentProviderPushWorkerPool,
    in_flight: &Arc<Mutex<BTreeSet<String>>>,
    scan_limit: usize,
    idle_sleep: Duration,
) {
    loop {
        match notify_async_claim_entries(store, in_flight, scan_limit) {
            Ok(entries) if entries.is_empty() => std::thread::sleep(idle_sleep),
            Ok(entries) => {
                for entry in entries {
                    let queue_id = entry.queue_id.clone();
                    if let Err(error) = notify_async_deliver_entry(store, provider_workers, &entry)
                    {
                        tracing::warn!(
                            queue_id = queue_id,
                            %error,
                            "notify async delivery failed"
                        );
                    }
                    notify_async_release_entry(in_flight, &queue_id);
                }
            }
            Err(error) => {
                tracing::warn!(%error, "notify async delivery scan failed");
                std::thread::sleep(idle_sleep);
            }
        }
    }
}

fn notify_async_claim_entries(
    store: &ramflux_node_core::NotifyRedbStore,
    in_flight: &Arc<Mutex<BTreeSet<String>>>,
    scan_limit: usize,
) -> Result<Vec<ramflux_node_core::NotifyQueueEntry>, ramflux_node_core::NodeCoreError> {
    if tracing::enabled!(tracing::Level::TRACE) {
        for shard in store.notify_wal_pending_counts(scan_limit.saturating_mul(2)) {
            tracing::trace!(
                shard_id = shard.shard_id,
                pending_queue_entries = shard.counts.queue_entry_count,
                pending_raw_wakes = shard.counts.raw_wake_count,
                "notify async delivery WAL pending scan"
            );
        }
    }
    let candidates = store.pending_entries_without_attempts(scan_limit.saturating_mul(2))?;
    let candidate_count = candidates.len();
    let mut claimed = Vec::new();
    let mut guard = in_flight.lock().map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "notify async in-flight lock poisoned: {source}"
        ))
    })?;
    for entry in candidates {
        if claimed.len() >= scan_limit {
            break;
        }
        if guard.insert(entry.queue_id.clone()) {
            claimed.push(entry);
        }
    }
    tracing::trace!(
        candidate_count,
        claimed_count = claimed.len(),
        scan_limit,
        "notify async delivery claimed pending entries"
    );
    Ok(claimed)
}

fn notify_async_release_entry(in_flight: &Arc<Mutex<BTreeSet<String>>>, queue_id: &str) {
    match in_flight.lock() {
        Ok(mut guard) => {
            guard.remove(queue_id);
        }
        Err(error) => tracing::warn!(%error, "notify async in-flight lock poisoned on release"),
    }
}

fn notify_async_deliver_entry(
    store: &ramflux_node_core::NotifyRedbStore,
    provider_workers: &ConcurrentProviderPushWorkerPool,
    entry: &ramflux_node_core::NotifyQueueEntry,
) -> Result<(), ramflux_node_core::NodeCoreError> {
    let pushes = store.prepare_provider_pushes_for_entry(entry)?;
    if pushes.is_empty() {
        tracing::debug!(
            queue_id = entry.queue_id.as_str(),
            device_delivery_id = entry.device_delivery_id.as_str(),
            wake_id = entry.wake.wake_id.as_str(),
            "notify async delivery found no provider pushes for pending entry"
        );
        return Ok(());
    }
    tracing::trace!(
        queue_id = entry.queue_id.as_str(),
        device_delivery_id = entry.device_delivery_id.as_str(),
        wake_id = entry.wake.wake_id.as_str(),
        push_count = pushes.len(),
        "notify async delivery prepared provider pushes"
    );
    let mut pending = Vec::with_capacity(pushes.len());
    for prepared in pushes {
        let response = provider_workers.dispatch(prepared.clone())?;
        pending.push((prepared, response));
    }
    let total_count = pending.len();
    let mut accepted_count = 0_usize;
    for (prepared, response) in pending {
        let accepted = match response.recv().map_err(|error| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "notify async provider worker response closed: {error}"
            ))
        })? {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(
                    device_delivery_id = prepared.route.device_delivery_id,
                    provider = ?prepared.route.provider,
                    push_alias_hash = prepared.push_alias_hash,
                    collapse_key_hash = prepared.collapse_key_hash,
                    %error,
                    "async push provider send failed"
                );
                false
            }
        };
        if accepted {
            accepted_count = accepted_count.saturating_add(1);
        }
        let attempt = ramflux_node_core::redacted_provider_attempt(
            entry,
            &prepared,
            accepted,
            (!accepted).then(|| "provider_send_failed".to_owned()),
        );
        store.record_provider_attempt(attempt)?;
    }
    tracing::trace!(
        queue_id = entry.queue_id.as_str(),
        accepted_count,
        total_count,
        "notify async delivery recorded provider attempts"
    );
    Ok(())
}

fn send_provider_push(
    prepared: &ramflux_node_core::PreparedProviderPush,
) -> Result<bool, ramflux_node_core::NodeCoreError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    runtime.block_on(async { send_provider_push_h2(prepared).await })
}

fn send_provider_push_with_runtime(
    runtime: &tokio::runtime::Runtime,
    h2_pool: &ProviderH2ConnectionPool,
    prepared: &ramflux_node_core::PreparedProviderPush,
) -> Result<bool, ramflux_node_core::NodeCoreError> {
    runtime.block_on(async { send_provider_push_h2_pooled(prepared, h2_pool).await })
}

async fn send_provider_push_h2(
    prepared: &ramflux_node_core::PreparedProviderPush,
) -> Result<bool, ramflux_node_core::NodeCoreError> {
    let request = build_provider_request(prepared).await?;
    let response = h2_post_json(&request).await?;
    if is_hard_token_failure(response.status) {
        tracing::warn!(
            device_delivery_id = prepared.route.device_delivery_id,
            provider = ?prepared.route.provider,
            push_alias_hash = prepared.push_alias_hash,
            status = response.status,
            "push provider marked token stale"
        );
    }
    Ok((200..300).contains(&response.status))
}

async fn send_provider_push_h2_pooled(
    prepared: &ramflux_node_core::PreparedProviderPush,
    h2_pool: &ProviderH2ConnectionPool,
) -> Result<bool, ramflux_node_core::NodeCoreError> {
    let request = build_provider_request(prepared).await?;
    let response = h2_pool.post_json(&request).await?;
    if is_hard_token_failure(response.status) {
        tracing::warn!(
            device_delivery_id = prepared.route.device_delivery_id,
            provider = ?prepared.route.provider,
            push_alias_hash = prepared.push_alias_hash,
            status = response.status,
            "push provider marked token stale"
        );
    }
    Ok((200..300).contains(&response.status))
}

fn push_urgency(priority: &ramflux_protocol::PushPriority) -> &'static str {
    match priority {
        ramflux_protocol::PushPriority::Low => "low",
        ramflux_protocol::PushPriority::Normal => "normal",
        ramflux_protocol::PushPriority::High => "high",
    }
}

fn apns_priority(priority: &ramflux_protocol::PushPriority) -> &'static str {
    match priority {
        ramflux_protocol::PushPriority::High => "10",
        ramflux_protocol::PushPriority::Low | ramflux_protocol::PushPriority::Normal => "5",
    }
}

fn parse_https_url(url: &str) -> Result<ParsedHttpsUrl, ramflux_node_core::NodeCoreError> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "unsupported push provider url {url}"
        )));
    };
    let (host_port, path) = rest
        .split_once('/')
        .map_or((rest, "/"), |(host_port, path)| (host_port, &url[url.len() - path.len() - 1..]));
    let (host, port) = split_host_port(host_port)?;
    Ok(ParsedHttpsUrl { host, port, path: path.to_owned() })
}

fn split_host_port(host_port: &str) -> Result<(String, u16), ramflux_node_core::NodeCoreError> {
    let Some((host, port)) = host_port.rsplit_once(':') else {
        return Err(ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "provider endpoint missing port: {host_port}"
        )));
    };
    let port = port
        .parse::<u16>()
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    Ok((host.to_owned(), port))
}

#[derive(Clone, Debug)]
struct ParsedHttpsUrl {
    host: String,
    port: u16,
    path: String,
}

#[derive(Clone, Debug)]
struct ProviderHttpRequest {
    endpoint: ParsedHttpsUrl,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    ca_pem: Option<String>,
}

#[derive(Clone, Debug)]
struct ProviderHttpResponse {
    status: u16,
    body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ProviderH2ConnectionKey {
    host: String,
    port: u16,
    ca_fingerprint: String,
}

struct ProviderH2ConnectionPool {
    clients: Mutex<HashMap<ProviderH2ConnectionKey, h2::client::SendRequest<bytes::Bytes>>>,
    max_connections: usize,
}

impl ProviderH2ConnectionPool {
    fn from_env() -> Self {
        let max_connections =
            notify_runtime_usize_env("RAMFLUX_NOTIFY_PROVIDER_H2_POOL_MAX_CONNECTIONS", || 128)
                .max(1);
        Self { clients: Mutex::new(HashMap::new()), max_connections }
    }

    async fn post_json(
        &self,
        request: &ProviderHttpRequest,
    ) -> Result<ProviderHttpResponse, ramflux_node_core::NodeCoreError> {
        let key = ProviderH2ConnectionKey::from_request(request);
        match self.post_json_once(request, &key).await {
            Ok(response) => Ok(response),
            Err(first_error) => {
                self.evict(&key)?;
                tracing::debug!(
                    host = key.host,
                    port = key.port,
                    error = %first_error,
                    "provider h2 pooled request failed; reconnecting once"
                );
                self.post_json_once(request, &key).await
            }
        }
    }

    async fn post_json_once(
        &self,
        request: &ProviderHttpRequest,
        key: &ProviderH2ConnectionKey,
    ) -> Result<ProviderHttpResponse, ramflux_node_core::NodeCoreError> {
        let mut client = self.client_for(request, key).await?;
        post_json_with_h2_client(request, &mut client).await
    }

    async fn client_for(
        &self,
        request: &ProviderHttpRequest,
        key: &ProviderH2ConnectionKey,
    ) -> Result<h2::client::SendRequest<bytes::Bytes>, ramflux_node_core::NodeCoreError> {
        if let Some(client) = self.lock_clients()?.get(key).cloned() {
            return Ok(client);
        }
        let client = connect_provider_h2(request).await?;
        let mut clients = self.lock_clients()?;
        if clients.len() >= self.max_connections
            && let Some(oldest_key) = clients.keys().next().cloned()
        {
            clients.remove(&oldest_key);
        }
        clients.insert(key.clone(), client.clone());
        Ok(client)
    }

    fn evict(&self, key: &ProviderH2ConnectionKey) -> Result<(), ramflux_node_core::NodeCoreError> {
        self.lock_clients()?.remove(key);
        Ok(())
    }

    fn lock_clients(
        &self,
    ) -> Result<
        std::sync::MutexGuard<
            '_,
            HashMap<ProviderH2ConnectionKey, h2::client::SendRequest<bytes::Bytes>>,
        >,
        ramflux_node_core::NodeCoreError,
    > {
        self.clients.lock().map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "provider h2 pool lock poisoned: {source}"
            ))
        })
    }
}

impl ProviderH2ConnectionKey {
    fn from_request(request: &ProviderHttpRequest) -> Self {
        Self {
            host: request.endpoint.host.clone(),
            port: request.endpoint.port,
            ca_fingerprint: provider_ca_fingerprint(request.ca_pem.as_deref()),
        }
    }
}

fn provider_ca_fingerprint(ca_pem: Option<&str>) -> String {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"ramflux.notify.provider_h2_pool_ca.v1");
    hasher.update([0]);
    hasher.update(ca_pem.unwrap_or_default().as_bytes());
    let digest = hasher.finalize();
    let mut fingerprint = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _result = write!(&mut fingerprint, "{byte:02x}");
    }
    fingerprint
}

async fn build_provider_request(
    prepared: &ramflux_node_core::PreparedProviderPush,
) -> Result<ProviderHttpRequest, ramflux_node_core::NodeCoreError> {
    match &prepared.credential {
        ramflux_node_core::ProviderCredential::Apns(credential) => {
            build_apns_request(prepared, credential)
        }
        ramflux_node_core::ProviderCredential::Fcm(credential) => {
            build_fcm_request(prepared, credential).await
        }
        ramflux_node_core::ProviderCredential::WebPush(credential) => {
            build_webpush_request(prepared, credential)
        }
    }
}

fn build_apns_request(
    prepared: &ramflux_node_core::PreparedProviderPush,
    credential: &ramflux_node_core::ApnsProviderCredential,
) -> Result<ProviderHttpRequest, ramflux_node_core::NodeCoreError> {
    let mut endpoint = parse_https_url(&prepared.route.endpoint)?;
    if endpoint.path == "/" {
        endpoint.path = format!("/3/device/{}", prepared.route.token);
    }
    let jwt = apns_jwt(credential)?;
    let mut headers = generic_provider_headers(prepared);
    headers.extend([
        ("authorization".to_owned(), format!("bearer {jwt}")),
        ("apns-topic".to_owned(), credential.topic.clone()),
        ("apns-push-type".to_owned(), apns_push_type(&prepared.payload).to_owned()),
        ("apns-expiration".to_owned(), expiration_epoch(prepared).to_string()),
        ("apns-priority".to_owned(), apns_priority(&prepared.payload.priority).to_owned()),
    ]);
    if let Some(collapse_key) = prepared.payload.collapse_key.as_ref() {
        headers.push(("apns-collapse-id".to_owned(), collapse_key.clone()));
    }
    let body = serde_json::to_vec(&serde_json::json!({
        "aps": {
            "alert": {
                "title": "Ramflux",
                "body": "You have a new Ramflux update."
            },
            "mutable-content": 1
        },
        "wake_id": prepared.payload.wake_id,
        "delivery_class": prepared.payload.delivery_class,
        "encrypted_hint": prepared.payload.encrypted_hint
    }))
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    Ok(ProviderHttpRequest {
        endpoint,
        headers,
        body,
        ca_pem: read_optional_secret_ref(credential.provider_ca_pem_ref.as_deref())?,
    })
}

async fn build_fcm_request(
    prepared: &ramflux_node_core::PreparedProviderPush,
    credential: &ramflux_node_core::FcmProviderCredential,
) -> Result<ProviderHttpRequest, ramflux_node_core::NodeCoreError> {
    let endpoint = parse_https_url(&prepared.route.endpoint)?;
    let ca_pem = read_optional_secret_ref(credential.provider_ca_pem_ref.as_deref())?;
    let oauth_token = fcm_oauth_access_token(credential, ca_pem.clone()).await?;
    let mut headers = generic_provider_headers(prepared);
    headers.push(("authorization".to_owned(), format!("Bearer {oauth_token}")));
    let body = serde_json::to_vec(&serde_json::json!({
        "message": {
            "token": prepared.route.token,
            "notification": {
                "title": "Ramflux",
                "body": "You have a new Ramflux update."
            },
            "data": {
                "wake_id": prepared.payload.wake_id,
                "delivery_class": prepared.payload.delivery_class,
                "encrypted_hint": prepared.payload.encrypted_hint
            },
            "android": {
                "priority": fcm_priority(&prepared.payload.priority),
                "ttl": format!("{}s", prepared.payload.ttl),
                "collapse_key": prepared.payload.collapse_key
            }
        }
    }))
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    Ok(ProviderHttpRequest { endpoint, headers, body, ca_pem })
}

fn build_webpush_request(
    prepared: &ramflux_node_core::PreparedProviderPush,
    credential: &ramflux_node_core::WebPushProviderCredential,
) -> Result<ProviderHttpRequest, ramflux_node_core::NodeCoreError> {
    let endpoint = parse_https_url(&prepared.route.endpoint)?;
    let vapid_token = webpush_vapid_jwt(credential, &endpoint)?;
    let vapid_public_key = read_secret_ref(&credential.vapid_public_key_ref)?;
    let mut headers = generic_provider_headers(prepared);
    set_provider_header(&mut headers, "content-type", "application/octet-stream".to_owned());
    headers.extend([
        ("authorization".to_owned(), format!("vapid t={vapid_token}, k={vapid_public_key}")),
        ("content-encoding".to_owned(), "aes128gcm".to_owned()),
    ]);
    if let Some(collapse_key) = prepared.payload.collapse_key.as_ref() {
        headers.push(("topic".to_owned(), collapse_key.clone()));
    }
    let plaintext = serde_json::to_vec(&serde_json::json!({
        "wake_id": prepared.payload.wake_id,
        "delivery_class": prepared.payload.delivery_class,
        "encrypted_hint": prepared.payload.encrypted_hint
    }))
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    let body = encrypt_webpush_aes128gcm(
        prepared.route.webpush_p256dh.as_deref().ok_or_else(|| {
            ramflux_node_core::NodeCoreError::ItestHttp(
                "missing WebPush p256dh subscription key".to_owned(),
            )
        })?,
        prepared.route.webpush_auth.as_deref().ok_or_else(|| {
            ramflux_node_core::NodeCoreError::ItestHttp(
                "missing WebPush auth subscription secret".to_owned(),
            )
        })?,
        &plaintext,
    )?;
    Ok(ProviderHttpRequest {
        endpoint,
        headers,
        body,
        ca_pem: read_optional_secret_ref(credential.provider_ca_pem_ref.as_deref())?,
    })
}

fn set_provider_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    if let Some((_, existing)) = headers.iter_mut().find(|(key, _)| key.eq_ignore_ascii_case(name))
    {
        *existing = value;
    } else {
        headers.push((name.to_owned(), value));
    }
}

fn encrypt_webpush_aes128gcm(
    client_p256dh_base64url: &str,
    auth_secret_base64url: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, ramflux_node_core::NodeCoreError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use p256::elliptic_curve::rand_core::{OsRng, RngCore};
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    const WEBPUSH_RECORD_SIZE: u32 = 4096;
    const WEBPUSH_KEY_ID_LEN: u8 = 65;

    let client_public_bytes =
        ramflux_protocol::decode_base64url(client_p256dh_base64url).map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "invalid WebPush p256dh subscription key: {source}"
            ))
        })?;
    let client_public_bytes: [u8; 65] =
        client_public_bytes.try_into().map_err(|bytes: Vec<u8>| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "invalid WebPush p256dh length {}, expected 65",
                bytes.len()
            ))
        })?;
    let auth_secret =
        ramflux_protocol::decode_base64url(auth_secret_base64url).map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "invalid WebPush auth subscription secret: {source}"
            ))
        })?;
    let auth_secret: [u8; 16] = auth_secret.try_into().map_err(|bytes: Vec<u8>| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "invalid WebPush auth secret length {}, expected 16",
            bytes.len()
        ))
    })?;
    let client_public =
        p256::PublicKey::from_sec1_bytes(&client_public_bytes).map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "invalid WebPush P-256 public key: {source}"
            ))
        })?;
    let server_secret = p256::ecdh::EphemeralSecret::random(&mut OsRng);
    let server_public = p256::PublicKey::from(&server_secret);
    let server_public_bytes = server_public.to_encoded_point(false);
    let server_public_bytes = server_public_bytes.as_bytes();
    let shared_secret = server_secret.diffie_hellman(&client_public);

    let mut key_info = Vec::with_capacity("WebPush: info\0".len() + 65 + 65);
    key_info.extend_from_slice(b"WebPush: info\0");
    key_info.extend_from_slice(&client_public_bytes);
    key_info.extend_from_slice(server_public_bytes);
    let key_hkdf =
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&auth_secret), shared_secret.raw_secret_bytes());
    let mut ikm = [0_u8; 32];
    key_hkdf.expand(&key_info, &mut ikm).map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "WebPush key HKDF expand failed: {source:?}"
        ))
    })?;

    let mut salt = [0_u8; 16];
    OsRng.fill_bytes(&mut salt);
    let content_hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &ikm);
    let mut cek = [0_u8; 16];
    content_hkdf.expand(b"Content-Encoding: aes128gcm\0", &mut cek).map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "WebPush CEK HKDF expand failed: {source:?}"
        ))
    })?;
    let mut nonce = [0_u8; 12];
    content_hkdf.expand(b"Content-Encoding: nonce\0", &mut nonce).map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "WebPush nonce HKDF expand failed: {source:?}"
        ))
    })?;

    let mut record_plaintext = Vec::with_capacity(plaintext.len() + 1);
    record_plaintext.extend_from_slice(plaintext);
    record_plaintext.push(0x02);
    let cipher = aes_gcm::Aes128Gcm::new(aes_gcm::Key::<aes_gcm::Aes128Gcm>::from_slice(&cek));
    let ciphertext = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), record_plaintext.as_slice())
        .map_err(|_| {
            ramflux_node_core::NodeCoreError::ItestHttp(
                "WebPush aes128gcm encryption failed".to_owned(),
            )
        })?;

    let mut body = Vec::with_capacity(16 + 4 + 1 + 65 + ciphertext.len());
    body.extend_from_slice(&salt);
    body.extend_from_slice(&WEBPUSH_RECORD_SIZE.to_be_bytes());
    body.push(WEBPUSH_KEY_ID_LEN);
    body.extend_from_slice(server_public_bytes);
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

fn generic_provider_headers(
    prepared: &ramflux_node_core::PreparedProviderPush,
) -> Vec<(String, String)> {
    let mut headers = vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        (
            "ramflux-delivery-class".to_owned(),
            delivery_class_name(&prepared.payload.delivery_class).to_owned(),
        ),
        ("ttl".to_owned(), prepared.payload.ttl.to_string()),
        ("urgency".to_owned(), push_urgency(&prepared.payload.priority).to_owned()),
        ("ramflux-push-alias-hash".to_owned(), prepared.push_alias_hash.clone()),
        ("ramflux-collapse-key-hash".to_owned(), prepared.collapse_key_hash.clone()),
    ];
    if let Some(collapse_key) = prepared.payload.collapse_key.as_ref() {
        headers.push(("ramflux-collapse-key".to_owned(), collapse_key.clone()));
    }
    headers
}

async fn fcm_oauth_access_token(
    credential: &ramflux_node_core::FcmProviderCredential,
    ca_pem: Option<String>,
) -> Result<String, ramflux_node_core::NodeCoreError> {
    let service_account_json = read_secret_ref(&credential.service_account_json_ref)?;
    let account: FcmServiceAccount = serde_json::from_str(&service_account_json)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    let token_url = credential
        .oauth_token_url
        .as_deref()
        .or(account.token_uri.as_deref())
        .unwrap_or("https://oauth2.googleapis.com/token");
    let endpoint = parse_https_url(token_url)?;
    let assertion = fcm_oauth_assertion(credential, &account, token_url)?;
    let form = format!(
        "grant_type={}&assertion={}",
        percent_encode("urn:ietf:params:oauth:grant-type:jwt-bearer"),
        percent_encode(&assertion)
    );
    let response = h2_post_json(&ProviderHttpRequest {
        endpoint,
        headers: vec![("content-type".to_owned(), "application/x-www-form-urlencoded".to_owned())],
        body: form.into_bytes(),
        ca_pem,
    })
    .await?;
    if !(200..300).contains(&response.status) {
        return Err(ramflux_node_core::NodeCoreError::ItestHttp(format!(
            "fcm oauth token endpoint rejected request with status {}",
            response.status
        )));
    }
    let body: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))?;
    body.get("access_token").and_then(serde_json::Value::as_str).map(ToOwned::to_owned).ok_or_else(
        || ramflux_node_core::NodeCoreError::ItestJson("missing access_token".to_owned()),
    )
}

async fn h2_post_json(
    request: &ProviderHttpRequest,
) -> Result<ProviderHttpResponse, ramflux_node_core::NodeCoreError> {
    let mut client = connect_provider_h2(request).await?;
    post_json_with_h2_client(request, &mut client).await
}

async fn connect_provider_h2(
    request: &ProviderHttpRequest,
) -> Result<h2::client::SendRequest<bytes::Bytes>, ramflux_node_core::NodeCoreError> {
    let addr = format!("{}:{}", request.endpoint.host, request.endpoint.port);
    let tcp = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| {
            ramflux_node_core::NodeCoreError::ItestHttp("provider connect timed out".to_owned())
        })?
        .map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!("provider tcp connect: {source}"))
        })?;
    tcp.set_nodelay(true).map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!("provider tcp nodelay: {source}"))
    })?;
    let server_name = rustls_pki_types::ServerName::try_from(request.endpoint.host.clone())
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    let connector =
        tokio_rustls::TlsConnector::from(Arc::new(provider_tls_config(request.ca_pem.as_deref())?));
    let tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
        .await
        .map_err(|_| {
            ramflux_node_core::NodeCoreError::ItestHttp("provider tls timed out".to_owned())
        })?
        .map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!("provider tls connect: {source}"))
        })?;
    let (client, connection) = h2::client::handshake(tls).await.map_err(|source| {
        ramflux_node_core::NodeCoreError::ItestHttp(format!("provider h2 handshake: {source}"))
    })?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "provider h2 connection closed with error");
        }
    });
    Ok(client)
}

async fn post_json_with_h2_client(
    request: &ProviderHttpRequest,
    client: &mut h2::client::SendRequest<bytes::Bytes>,
) -> Result<ProviderHttpResponse, ramflux_node_core::NodeCoreError> {
    let authority = format!("{}:{}", request.endpoint.host, request.endpoint.port);
    let uri = format!("https://{}{}", authority, request.endpoint.path);
    let mut builder = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_LENGTH, request.body.len().to_string());
    for (key, value) in &request.headers {
        builder = builder.header(key.as_str(), value.as_str());
    }
    let http_request = builder
        .body(())
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?;
    let (response_future, mut send_stream) =
        client.send_request(http_request, false).map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!(
                "provider h2 send request: {source}"
            ))
        })?;
    send_stream.send_data(bytes::Bytes::copy_from_slice(&request.body), true).map_err(
        |source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!("provider h2 send body: {source}"))
        },
    )?;
    let response = tokio::time::timeout(Duration::from_secs(30), response_future)
        .await
        .map_err(|_| {
            ramflux_node_core::NodeCoreError::ItestHttp("provider response timed out".to_owned())
        })?
        .map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!("provider h2 response: {source}"))
        })?;
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) =
        tokio::time::timeout(Duration::from_secs(30), body.data()).await.map_err(|_| {
            ramflux_node_core::NodeCoreError::ItestHttp("provider body timed out".to_owned())
        })?
    {
        let chunk = chunk.map_err(|source| {
            ramflux_node_core::NodeCoreError::ItestHttp(format!("provider h2 body: {source}"))
        })?;
        bytes.extend_from_slice(&chunk);
    }
    Ok(ProviderHttpResponse { status, body: bytes })
}

fn provider_tls_config(
    ca_pem: Option<&str>,
) -> Result<rustls::ClientConfig, ramflux_node_core::NodeCoreError> {
    ensure_ring_crypto_provider_installed();
    let mut root_store = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    if let Some(ca_pem) = ca_pem {
        let mut reader = std::io::Cursor::new(ca_pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
            })?;
            root_store.add(cert).map_err(|source| {
                ramflux_node_core::NodeCoreError::ItestHttp(source.to_string())
            })?;
        }
    }
    let mut config =
        rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

fn ensure_ring_crypto_provider_installed() {
    RUSTLS_PROVIDER.call_once(|| {
        let _result = rustls::crypto::ring::default_provider().install_default();
    });
}

fn ensure_jwt_crypto_provider_installed() {
    JWT_PROVIDER.call_once(|| {
        let _result = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

fn apns_jwt(
    credential: &ramflux_node_core::ApnsProviderCredential,
) -> Result<String, ramflux_node_core::NodeCoreError> {
    ensure_jwt_crypto_provider_installed();
    let p8 = read_secret_ref(&credential.p8_key_ref)?;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(credential.key_id.clone());
    let claims = serde_json::json!({
        "iss": credential.team_id,
        "iat": ramflux_node_core::now_unix_seconds()
    });
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_ec_pem(p8.as_bytes())
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?,
    )
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

fn fcm_oauth_assertion(
    credential: &ramflux_node_core::FcmProviderCredential,
    account: &FcmServiceAccount,
    token_url: &str,
) -> Result<String, ramflux_node_core::NodeCoreError> {
    ensure_jwt_crypto_provider_installed();
    let iat = ramflux_node_core::now_unix_seconds();
    let private_key = account.private_key.as_deref().ok_or_else(|| {
        ramflux_node_core::NodeCoreError::ItestJson("missing fcm private_key".to_owned())
    })?;
    let client_email = account.client_email.as_deref().ok_or_else(|| {
        ramflux_node_core::NodeCoreError::ItestJson("missing fcm client_email".to_owned())
    })?;
    let claims = serde_json::json!({
        "iss": client_email,
        "scope": credential.oauth_scope,
        "aud": token_url,
        "iat": iat,
        "exp": iat.saturating_add(3_600)
    });
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes())
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?,
    )
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

fn webpush_vapid_jwt(
    credential: &ramflux_node_core::WebPushProviderCredential,
    endpoint: &ParsedHttpsUrl,
) -> Result<String, ramflux_node_core::NodeCoreError> {
    ensure_jwt_crypto_provider_installed();
    let private_key = read_secret_ref(&credential.vapid_private_key_ref)?;
    let aud = format!("https://{}:{}", endpoint.host, endpoint.port);
    let claims = serde_json::json!({
        "aud": aud,
        "exp": ramflux_node_core::now_unix_seconds().saturating_add(12 * 60 * 60),
        "sub": credential.subject
    });
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
        &claims,
        &jsonwebtoken::EncodingKey::from_ec_pem(private_key.as_bytes())
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))?,
    )
    .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()))
}

fn read_optional_secret_ref(
    secret_ref: Option<&str>,
) -> Result<Option<String>, ramflux_node_core::NodeCoreError> {
    secret_ref.map(read_secret_ref).transpose()
}

fn read_secret_ref(secret_ref: &str) -> Result<String, ramflux_node_core::NodeCoreError> {
    if let Some(literal) = secret_ref.strip_prefix("literal:") {
        return Ok(literal.to_owned());
    }
    if let Some(name) = secret_ref.strip_prefix("env:") {
        return std::env::var(name)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()));
    }
    if let Some(path) = secret_ref.strip_prefix("file:") {
        return std::fs::read_to_string(path)
            .map_err(|source| ramflux_node_core::NodeCoreError::ItestHttp(source.to_string()));
    }
    Err(ramflux_node_core::NodeCoreError::ItestHttp(format!(
        "unsupported secret ref scheme: {secret_ref}"
    )))
}

fn apns_push_type(payload: &ramflux_node_core::ProviderPushPayload) -> &'static str {
    match payload.delivery_class {
        ramflux_protocol::NotificationDeliveryClass::CallWakeNotification
        | ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification => "voip",
        _ => "alert",
    }
}

fn fcm_priority(priority: &ramflux_protocol::PushPriority) -> &'static str {
    match priority {
        ramflux_protocol::PushPriority::High => "HIGH",
        ramflux_protocol::PushPriority::Low | ramflux_protocol::PushPriority::Normal => "NORMAL",
    }
}

fn expiration_epoch(prepared: &ramflux_node_core::PreparedProviderPush) -> u64 {
    ramflux_node_core::now_unix_seconds().saturating_add(u64::from(prepared.payload.ttl))
}

fn delivery_class_name(
    delivery_class: &ramflux_protocol::NotificationDeliveryClass,
) -> &'static str {
    match delivery_class {
        ramflux_protocol::NotificationDeliveryClass::SelfDeviceControlNotification => {
            "self_device_control_notification"
        }
        ramflux_protocol::NotificationDeliveryClass::UserContentNotification => {
            "user_content_notification"
        }
        ramflux_protocol::NotificationDeliveryClass::AiTaskNotification => "ai_task_notification",
        ramflux_protocol::NotificationDeliveryClass::A2uiSurfaceNotification => {
            "a2ui_surface_notification"
        }
        ramflux_protocol::NotificationDeliveryClass::CallWakeNotification => {
            "call_wake_notification"
        }
        ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification => {
            "conference_wake_notification"
        }
    }
}

fn is_hard_token_failure(status: u16) -> bool {
    matches!(status, 400 | 404 | 410)
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => {
                let _ = write!(&mut encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

#[derive(Clone, serde::Deserialize)]
struct S13WakeRequest {
    device_delivery_id: String,
    wake: ramflux_protocol::NotificationWake,
    #[serde(default)]
    queued_at: Option<u64>,
    #[serde(default)]
    dnd_active: Option<bool>,
}

#[cfg(feature = "itest-http")]
fn parse_s13_wake_request_body(
    body: &[u8],
) -> Result<S13WakeRequest, ramflux_node_core::NodeCoreError> {
    serde_json::from_slice(body)
        .map_err(|source| ramflux_node_core::NodeCoreError::ItestJson(source.to_string()))
}

#[derive(serde::Serialize)]
struct S13WakeResponse {
    entry: ramflux_node_core::NotifyQueueEntry,
    attempts: Vec<ramflux_node_core::ProviderPushAttempt>,
}

#[derive(serde::Deserialize)]
struct FcmServiceAccount {
    #[serde(default)]
    client_email: Option<String>,
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    token_uri: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "itest-http")]
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};

    const TEST_EC_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwyBphzPT6zP0T3HT\nmUd3y/OXm9uWxWxy8nbR0YWA22ShRANCAAQAIpCYq6Tsdeuzzy1sjb/0VLEcd1+r\nQs8681WYx7uSG+akC/YXdlGjSeyiRGjZYJ1KHqoa2d4mAQwi9XAZuDT5\n-----END PRIVATE KEY-----\n";

    #[test]
    fn s13_dispatch_sends_wake_to_tls_h2_provider() -> Result<(), Box<dyn std::error::Error>> {
        let stub = LocalH2ProviderStub::start()?;
        let store_path = std::env::temp_dir().join(format!(
            "ramflux-notify-s13-dispatch-{}.redb",
            ramflux_node_core::now_unix_seconds()
        ));
        let _ = std::fs::remove_file(&store_path);
        let store = ramflux_node_core::NotifyRedbStore::open(&store_path)?;
        store.update_provider_credential(ramflux_node_core::ProviderCredential::WebPush(
            ramflux_node_core::WebPushProviderCredential {
                credential_id: "credential_webpush".to_owned(),
                vapid_public_key_ref: "literal:test-vapid-public-key".to_owned(),
                vapid_private_key_ref: format!("literal:{TEST_EC_PRIVATE_KEY}"),
                subject: "mailto:ops@ramflux.example".to_owned(),
                provider_ca_pem_ref: Some(stub.ca_pem_secret_ref()),
            },
        ))?;
        let (webpush_p256dh, webpush_auth) = test_webpush_subscription()?;
        store.register_push_route(ramflux_node_core::DevicePushRoute {
            device_delivery_id: "device_dispatch".to_owned(),
            provider: ramflux_node_core::PushProviderKind::WebPush,
            credential_id: Some("credential_webpush".to_owned()),
            token: "raw_token_not_logged".to_owned(),
            endpoint: stub.endpoint("/webpush"),
            webpush_p256dh: Some(webpush_p256dh),
            webpush_auth: Some(webpush_auth),
            registered_at: 1_760_000_000,
            expires_at: 4_102_444_800,
        })?;

        let (entry, pushes) = store.queue_wake_for_push(
            "device_dispatch",
            &test_wake(),
            ramflux_node_core::now_unix_seconds(),
            false,
        )?;
        assert_eq!(entry.queue_id, "wake_dispatch");
        assert_eq!(pushes.len(), 1);
        assert!(send_provider_push(&pushes[0])?);
        let received = stub.recv()?;
        assert_eq!(received.path, "/webpush");
        assert_eq!(
            received.headers.get("ramflux-delivery-class").map(String::as_str),
            Some("user_content_notification")
        );
        assert_eq!(received.headers.get("ttl").map(String::as_str), Some("86400"));
        assert_eq!(received.headers.get("urgency").map(String::as_str), Some("normal"));
        assert!(received.headers.contains_key("ramflux-push-alias-hash"));
        assert!(received.headers.contains_key("ramflux-collapse-key-hash"));
        assert_eq!(received.headers.get("content-encoding").map(String::as_str), Some("aes128gcm"));
        assert!(received.payload.is_none());
        assert!(!received.body.is_empty());
        assert_s13_body_is_opaque(&received.body);
        Ok(())
    }

    #[test]
    fn provider_common_headers_follow_s13_contract() {
        let prepared = test_prepared_push(ramflux_node_core::PushProviderKind::Fcm);
        let headers = generic_provider_headers(&prepared)
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(headers.get("ttl").map(String::as_str), Some("86400"));
        assert_eq!(headers.get("urgency").map(String::as_str), Some("normal"));
        assert_eq!(
            headers.get("ramflux-delivery-class").map(String::as_str),
            Some("user_content_notification")
        );
        assert!(headers.contains_key("ramflux-push-alias-hash"));
        assert!(headers.contains_key("ramflux-collapse-key-hash"));
        assert!(
            headers
                .get("ramflux-collapse-key")
                .map(String::as_str)
                .unwrap_or_default()
                .contains("target:")
        );
    }

    fn test_webpush_subscription() -> Result<(String, String), Box<dyn std::error::Error>> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let secret = p256::SecretKey::from_slice(&[0x07; 32])?;
        let public = secret.public_key();
        let public_key = public.to_encoded_point(false);
        let p256dh = ramflux_protocol::encode_base64url(public_key.as_bytes());
        let auth = ramflux_protocol::encode_base64url([0x11; 16]);
        Ok((p256dh, auth))
    }

    #[cfg(feature = "itest-http")]
    #[ignore = "microbenchmark; set RAMFLUX_NOTIFY_WAL=1 and run explicitly with --ignored --nocapture"]
    #[test]
    fn notify_ingest_throughput_bench() -> Result<(), Box<dyn std::error::Error>> {
        let total = bench_usize_env("RAMFLUX_INGEST_BENCH_TOTAL", 1_000_000);
        let producers = bench_usize_env("RAMFLUX_INGEST_BENCH_PRODUCERS", 16);
        let seed = bench_node_service_signing_seed();
        let key = ramflux_node_core::NodeServiceSigningKey::from_seed(seed);
        let raw_bodies = Arc::new(signed_s13_wake_request_bodies(&key, total)?);
        let temp_root = notify_ingest_bench_temp_root();
        std::fs::create_dir_all(&temp_root)?;
        let store_path = temp_root.join("notify.redb");
        let store = Arc::new(ramflux_node_core::NotifyRedbStore::open(&store_path)?);
        if !store.uses_notify_wal() {
            let _ = std::fs::remove_dir_all(&temp_root);
            return Err("notify ingest bench requires RAMFLUX_NOTIFY_WAL=1".into());
        }
        let store_gate = Arc::new(Mutex::new(()));
        let wake_auth = NotifyWakeAuth { require: true, key: Some(key) };
        let wake_verify_batcher = NotifyWakeVerifyBatcher::from_env(&wake_auth, &store)?;
        let ingress = Arc::new(NotifyIngressState {
            store,
            runtime: Arc::new(NotifyRuntime::Current),
            store_gate,
            async_accept: true,
            wake_auth,
            wake_verify_batcher,
        });
        let next = Arc::new(AtomicUsize::new(0));
        let started = std::time::Instant::now();
        let mut threads = Vec::with_capacity(producers);
        for producer_id in 0..producers {
            let thread_ingress = Arc::clone(&ingress);
            let thread_bodies = Arc::clone(&raw_bodies);
            let thread_next = Arc::clone(&next);
            threads.push(
                std::thread::Builder::new()
                    .name(format!("ramflux-notify-ingest-bench-{producer_id}"))
                    .spawn(move || {
                        notify_ingest_bench_producer(&thread_ingress, &thread_bodies, &thread_next)
                    })?,
            );
        }
        let mut completed = 0_usize;
        for thread in threads {
            let result = thread.join().map_err(|_panic| "notify ingest bench producer panicked")?;
            completed = completed.saturating_add(result.map_err(std::io::Error::other)?);
        }
        let elapsed = started.elapsed();
        let elapsed_secs = elapsed.as_secs_f64();
        let completed_f64 = u32::try_from(completed).map_or(f64::from(u32::MAX), f64::from);
        let ops_per_sec =
            if elapsed_secs > 0.0 { completed_f64 / elapsed_secs } else { f64::INFINITY };
        let batch_verify = if ingress.wake_verify_batcher.is_some() { "on" } else { "off" };
        eprintln!(
            "INGEST_BENCH label=notify_ingest producers={producers} batch_verify={batch_verify} total={completed} elapsed_ms={} ops_per_sec={ops_per_sec:.2}",
            elapsed.as_millis()
        );
        drop(ingress);
        let _ = std::fs::remove_dir_all(&temp_root);
        Ok(())
    }

    #[cfg(feature = "itest-http")]
    fn notify_ingest_bench_producer(
        ingress: &Arc<NotifyIngressState>,
        raw_bodies: &Arc<Vec<Vec<u8>>>,
        next: &Arc<AtomicUsize>,
    ) -> Result<usize, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|source| source.to_string())?;
        let mut completed = 0_usize;
        loop {
            let index = next.fetch_add(1, Ordering::Relaxed);
            let Some(body) = raw_bodies.get(index) else {
                break;
            };
            runtime
                .block_on(ingest_raw_s13_wake_for_async_ingress(ingress, body.clone()))
                .map_err(|source| source.to_string())?;
            completed = completed.saturating_add(1);
        }
        Ok(completed)
    }

    #[cfg(feature = "itest-http")]
    fn signed_s13_wake_request_bodies(
        key: &ramflux_node_core::NodeServiceSigningKey,
        total: usize,
    ) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        let mut bodies = Vec::with_capacity(total);
        for index in 0..total {
            let mut wake = test_signed_wake(index);
            key.sign_notification_wake(&mut wake)?;
            let body = serde_json::json!({
                "device_delivery_id": format!("device_ingest_{}", index % 1024),
                "wake": wake,
                "queued_at": 1_760_000_000_u64.saturating_add(u64::try_from(index).unwrap_or(u64::MAX)),
                "dnd_active": false
            });
            bodies.push(serde_json::to_vec(&body)?);
        }
        Ok(bodies)
    }

    fn test_signed_wake(index: usize) -> ramflux_protocol::NotificationWake {
        ramflux_protocol::NotificationWake {
            schema: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
            version: 1,
            domain: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: ramflux_node_core::NODE_SERVICE_SIGNING_KEY_ID.to_owned(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: String::new(),
            },
            wake_id: format!("wake_ingest_{index}"),
            push_alias: format!("device_ingest_{}", index % 1024),
            delivery_class: ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
            priority: ramflux_protocol::PushPriority::Normal,
            ttl: 86_400,
            collapse_key: Some(format!("target:device_ingest_{}:content", index % 1024)),
            encrypted_hint: Some("encrypted_hint".to_owned()),
        }
    }

    fn bench_node_service_signing_seed() -> [u8; 32] {
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]
    }

    fn notify_ingest_bench_temp_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ramflux-notify-ingest-bench-{}-{}",
            std::process::id(),
            ramflux_node_core::now_unix_seconds()
        ))
    }

    fn bench_usize_env(name: &str, default: usize) -> usize {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(default)
    }

    fn test_wake() -> ramflux_protocol::NotificationWake {
        ramflux_protocol::NotificationWake {
            schema: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
            version: 1,
            domain: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: "test-notify".to_owned(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: "test-signature".to_owned(),
            },
            wake_id: "wake_dispatch".to_owned(),
            push_alias: "device_dispatch".to_owned(),
            delivery_class: ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
            priority: ramflux_protocol::PushPriority::Normal,
            ttl: 86_400,
            collapse_key: Some("target:device_dispatch:content".to_owned()),
            encrypted_hint: Some("encrypted_hint".to_owned()),
        }
    }

    fn test_prepared_push(
        provider: ramflux_node_core::PushProviderKind,
    ) -> ramflux_node_core::PreparedProviderPush {
        ramflux_node_core::PreparedProviderPush {
            route: ramflux_node_core::DevicePushRoute {
                device_delivery_id: "device_dispatch".to_owned(),
                provider: provider.clone(),
                credential_id: Some("credential_dispatch".to_owned()),
                token: "raw_token_not_logged".to_owned(),
                endpoint: "https://localhost:443/push".to_owned(),
                webpush_p256dh: None,
                webpush_auth: None,
                registered_at: 1_760_000_000,
                expires_at: 4_102_444_800,
            },
            credential: ramflux_node_core::ProviderCredential::WebPush(
                ramflux_node_core::WebPushProviderCredential {
                    credential_id: "credential_dispatch".to_owned(),
                    vapid_public_key_ref: "literal:test-public".to_owned(),
                    vapid_private_key_ref: "literal:test-private".to_owned(),
                    subject: "mailto:ops@ramflux.example".to_owned(),
                    provider_ca_pem_ref: None,
                },
            ),
            payload: ramflux_node_core::ProviderPushPayload {
                wake_id: "wake_dispatch".to_owned(),
                provider,
                delivery_class:
                    ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
                priority: ramflux_protocol::PushPriority::Normal,
                ttl: 86_400,
                collapse_key: Some("target:device_dispatch:content".to_owned()),
                encrypted_hint: Some("encrypted_hint".to_owned()),
            },
            push_alias_hash: "push_alias_hash".to_owned(),
            collapse_key_hash: "collapse_key_hash".to_owned(),
            action: ramflux_node_core::NotifyDeliveryAction::Accept,
        }
    }

    fn assert_s13_body_is_opaque(body: &[u8]) {
        for forbidden in [
            b"s13 forbidden plaintext".as_slice(),
            b"conversation_id".as_slice(),
            b"group_id".as_slice(),
            b"SRTP_MEDIA_KEY".as_slice(),
            b"run_shell".as_slice(),
        ] {
            assert!(
                !body.windows(forbidden.len()).any(|window| window == forbidden),
                "push payload leaked forbidden plaintext: {}",
                String::from_utf8_lossy(forbidden)
            );
        }
    }

    struct LocalH2ProviderStub {
        addr: std::net::SocketAddr,
        ca_pem: String,
        receiver: mpsc::Receiver<ReceivedProviderRequest>,
        _thread: std::thread::JoinHandle<()>,
    }

    impl LocalH2ProviderStub {
        fn start() -> Result<Self, Box<dyn std::error::Error>> {
            ensure_ring_crypto_provider_installed();
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            let addr = listener.local_addr()?;
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
            let ca_pem = certified.cert.pem();
            let cert_der = rustls_pki_types::CertificateDer::from(certified.cert.der().to_vec());
            let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
                rustls_pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
            );
            let (sender, receiver) = mpsc::channel();
            let thread = std::thread::spawn(move || {
                run_local_h2_provider(listener, cert_der, key_der, sender);
            });
            Ok(Self { addr, ca_pem, receiver, _thread: thread })
        }

        fn endpoint(&self, path: &str) -> String {
            format!("https://localhost:{}{path}", self.addr.port())
        }

        fn ca_pem_secret_ref(&self) -> String {
            format!("literal:{}", self.ca_pem)
        }

        fn recv(&self) -> Result<ReceivedProviderRequest, Box<dyn std::error::Error>> {
            self.receiver.recv_timeout(Duration::from_secs(5)).map_err(Into::into)
        }
    }

    #[derive(Debug)]
    struct ReceivedProviderRequest {
        path: String,
        headers: std::collections::BTreeMap<String, String>,
        payload: Option<ramflux_node_core::ProviderPushPayload>,
        body: Vec<u8>,
    }

    fn run_local_h2_provider(
        listener: std::net::TcpListener,
        cert_der: rustls_pki_types::CertificateDer<'static>,
        key_der: rustls_pki_types::PrivateKeyDer<'static>,
        sender: mpsc::Sender<ReceivedProviderRequest>,
    ) {
        ensure_ring_crypto_provider_installed();
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
            return;
        };
        runtime.block_on(async move {
            let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
                return;
            };
            let Ok(mut server_config) = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
            else {
                return;
            };
            server_config.alpn_protocols = vec![b"h2".to_vec()];
            let Ok((stream, _peer)) = listener.accept().await else {
                return;
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            let Ok(mut connection) = h2::server::handshake(tls).await else {
                return;
            };
            if let Some(Ok((request, respond))) = connection.accept().await {
                handle_local_h2_provider_request(request, respond, sender).await;
            }
            let _ = tokio::time::timeout(Duration::from_millis(100), connection.accept()).await;
        });
    }

    async fn handle_local_h2_provider_request(
        request: http::Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<bytes::Bytes>,
        sender: mpsc::Sender<ReceivedProviderRequest>,
    ) {
        let path = request.uri().path().to_owned();
        let headers = request
            .headers()
            .iter()
            .filter_map(|(key, value)| {
                Some((key.as_str().to_ascii_lowercase(), value.to_str().ok()?.to_owned()))
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut body_stream = request.into_body();
        let mut body = Vec::new();
        while let Some(Ok(chunk)) = body_stream.data().await {
            body.extend_from_slice(&chunk);
        }
        let payload = local_provider_payload_from_body(&path, &headers, &body).ok();
        let _ = sender.send(ReceivedProviderRequest { path, headers, payload, body });
        let response = http::Response::builder()
            .status(202)
            .header("content-type", "application/json")
            .body(());
        if let Ok(response) = response
            && let Ok(mut send) = respond.send_response(response, false)
        {
            let _ = send.send_data(bytes::Bytes::from_static(b"{}"), true);
        }
    }

    fn local_provider_payload_from_body(
        path: &str,
        headers: &std::collections::BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<ramflux_node_core::ProviderPushPayload, Box<dyn std::error::Error>> {
        if let Ok(payload) = serde_json::from_slice::<ramflux_node_core::ProviderPushPayload>(body)
        {
            return Ok(payload);
        }
        let value: serde_json::Value = serde_json::from_slice(body)?;
        let provider = if path.contains("fcm") {
            ramflux_node_core::PushProviderKind::Fcm
        } else if path.contains("webpush") {
            ramflux_node_core::PushProviderKind::WebPush
        } else {
            ramflux_node_core::PushProviderKind::Apns
        };
        let data = value.get("message").and_then(|message| message.get("data")).unwrap_or(&value);
        let wake_id = data
            .get("wake_id")
            .and_then(serde_json::Value::as_str)
            .ok_or("missing wake_id")?
            .to_owned();
        let delivery_class_value =
            data.get("delivery_class").cloned().ok_or("missing delivery_class")?;
        let delivery_class = serde_json::from_value(delivery_class_value)?;
        let ttl = headers.get("ttl").and_then(|ttl| ttl.parse::<u32>().ok()).unwrap_or(0);
        let priority = match headers.get("urgency").map(String::as_str) {
            Some("high") => ramflux_protocol::PushPriority::High,
            Some("low") => ramflux_protocol::PushPriority::Low,
            _ => ramflux_protocol::PushPriority::Normal,
        };
        Ok(ramflux_node_core::ProviderPushPayload {
            wake_id,
            provider,
            delivery_class,
            priority,
            ttl,
            collapse_key: headers.get("ramflux-collapse-key").cloned(),
            encrypted_hint: data
                .get("encrypted_hint")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
        })
    }
}

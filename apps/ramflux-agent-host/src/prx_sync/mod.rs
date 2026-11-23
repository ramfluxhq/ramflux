// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cold snapshot, then a durable WebSocket, into `<state_file>.prx-mirror`.
//! Live frames are published and not acked. Approval rows are stored and published.
//! `turn.failed` is recorded. This task does not resubmit the turn.

mod apply;
mod publish;
mod store;
mod ws;

use crate::PrxConfig;
use publish::Publisher;
use ramflux_prx_client::{
    ApiCode, ClientConfig, JournalEvent, MirrorOp, PONG_FRAME, PrxClient, PrxError,
    SNAPSHOT_PAGE_LIMIT, SYNC_SNAPSHOT_V1, SYNC_WS_V1, ServerFrame, SnapshotPage, TurnBody,
    ack_frame, decode_server, hello_frame, require,
};
use std::path::{Path, PathBuf};
use std::time::Duration;
use store::{Mirror, MirrorStore, StoreError, mirror_path};
use tokio::sync::watch;
use ws::random_bytes;
use ws::{Incoming, Socket, WsFail};

/// Background mirror of the PRX journal. Drop stops the task.
#[must_use]
pub struct SyncTask {
    stop: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

impl SyncTask {
    /// Starts the sync task. A bad URL or a full mirror does not stop the host.
    pub fn spawn(prx: &PrxConfig, state_file: &Path, socket: &Path, account: &str) -> Self {
        let (stop, rx) = watch::channel(false);
        let prx = prx.clone();
        let state_file = state_file.to_path_buf();
        let socket = socket.to_path_buf();
        let account = account.to_owned();
        let join = tokio::spawn(async move { run(prx, state_file, socket, account, rx).await });
        Self { stop, join }
    }

    /// Sends WebSocket close 1000 and waits up to three seconds.
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        tokio::select! {
            result = &mut self.join => { let _ = result; }
            () = tokio::time::sleep(Duration::from_secs(3)) => self.join.abort(),
        }
    }
}

impl Drop for SyncTask {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.join.abort();
    }
}

enum Flow {
    Live,
    Retry,
    Resync,
    Park,
    Halt,
}

enum PageStep {
    Continue,
    Ready,
    Flow(Flow),
}

async fn run(
    prx: PrxConfig,
    state_file: PathBuf,
    socket: PathBuf,
    account: String,
    mut stop: watch::Receiver<bool>,
) {
    eprintln!("prx sync mirror: {}", mirror_path(&state_file).display());
    let mut attempt = 0_u32;
    loop {
        if halted(&stop) {
            return;
        }
        let flow = cycle(&prx, &state_file, &socket, &account, &mut stop).await;
        if matches!(flow, Flow::Halt) || halted(&stop) {
            return;
        }
        if matches!(flow, Flow::Park) {
            park(&mut stop).await;
            return;
        }
        if matches!(flow, Flow::Live) {
            attempt = 0;
        }
        let delay = backoff_delay(attempt);
        if !matches!(flow, Flow::Live) {
            attempt = attempt.saturating_add(1);
        }
        if wait_stop(&mut stop, delay).await {
            return;
        }
    }
}

async fn cycle(
    prx: &PrxConfig,
    state_file: &Path,
    socket: &Path,
    account: &str,
    stop: &mut watch::Receiver<bool>,
) -> Flow {
    let Ok(client) = open_client(prx) else {
        eprintln!("prx sync requires a loopback PRX URL");
        return Flow::Retry;
    };
    let Ok(store) = MirrorStore::open(state_file) else {
        eprintln!("prx sync mirror is unavailable");
        return Flow::Retry;
    };
    let mut mirror = match store.load() {
        Ok(mirror) => mirror,
        Err(StoreError::Reset) => match reset_mirror(&store) {
            Ok(mirror) => mirror,
            Err(()) => return Flow::Retry,
        },
        Err(_) => {
            eprintln!("prx sync mirror is unavailable");
            return Flow::Retry;
        }
    };
    let mut publisher = Publisher::new(socket, account);
    if !mirror.ready()
        && let Err(flow) = pull_snapshot(&client, &store, &mut mirror, stop, &mut publisher).await
    {
        return flow;
    }
    follow_ws(&client, prx, &store, &mut mirror, stop, &mut publisher).await
}

fn open_client(prx: &PrxConfig) -> Result<PrxClient, ()> {
    let settings = ClientConfig::new(&prx.base_url, &prx.token_file)
        .with_request_timeout(Duration::from_secs(prx.request_timeout_s));
    PrxClient::new(&settings).map_err(|_| ())
}

fn reset_mirror(store: &MirrorStore) -> Result<Mirror, ()> {
    eprintln!("prx sync mirror reset");
    let fresh = Mirror::fresh();
    store.write(&fresh).map_err(|_| ())?;
    Ok(fresh)
}

async fn pull_snapshot(
    client: &PrxClient,
    store: &MirrorStore,
    mirror: &mut Mirror,
    stop: &mut watch::Receiver<bool>,
    publisher: &mut Publisher,
) -> Result<(), Flow> {
    let caps = client.capabilities().await.map_err(|_| Flow::Retry)?;
    if require(&caps, SYNC_SNAPSHOT_V1).is_err() || require(&caps, SYNC_WS_V1).is_err() {
        eprintln!("prx sync capabilities are missing");
        return Err(Flow::Retry);
    }
    let mut pages = 0_u32;
    let mut cuts = 0_u8;
    let mut expired = false;
    loop {
        if halted(stop) {
            return Err(Flow::Halt);
        }
        pages = pages.saturating_add(1);
        if pages > 10_000 {
            return Err(Flow::Retry);
        }
        let token = mirror.page_token().map(str::to_owned);
        match client.sync_snapshot_page(&caps, token.as_deref(), SNAPSHOT_PAGE_LIMIT).await {
            Ok(page) => {
                let outcome = on_page(store, mirror, &page, &mut cuts);
                if matches!(outcome, PageStep::Continue | PageStep::Ready) {
                    publisher.page(&page).await;
                }
                match outcome {
                    PageStep::Continue => expired = false,
                    PageStep::Ready => return Ok(()),
                    PageStep::Flow(flow) => return Err(flow),
                }
            }
            Err(error) => {
                if let Some(flow) = on_snapshot_err(store, mirror, &error, &mut expired) {
                    return Err(flow);
                }
            }
        }
    }
}

fn on_page(
    store: &MirrorStore,
    mirror: &mut Mirror,
    page: &SnapshotPage,
    cuts: &mut u8,
) -> PageStep {
    match mirror.apply_page(store, page) {
        Ok(()) if mirror.ready() => {
            log_ready(mirror);
            PageStep::Ready
        }
        Ok(()) => {
            *cuts = 0;
            PageStep::Continue
        }
        Err(StoreError::Cut) => {
            *cuts = cuts.saturating_add(1);
            if *cuts > 2 || mirror.clear_cut(store).is_err() {
                PageStep::Flow(Flow::Retry)
            } else {
                PageStep::Continue
            }
        }
        Err(StoreError::Full) => {
            eprintln!("prx sync mirror is full; sync stopped");
            PageStep::Flow(Flow::Park)
        }
        Err(_) => PageStep::Flow(Flow::Retry),
    }
}

fn on_snapshot_err(
    store: &MirrorStore,
    mirror: &mut Mirror,
    error: &PrxError,
    expired: &mut bool,
) -> Option<Flow> {
    if let PrxError::Api { code: ApiCode::SnapshotExpired, .. } = error {
        if mirror.clear_cut(store).is_err() {
            return Some(Flow::Retry);
        }
        if *expired {
            return Some(Flow::Retry);
        }
        *expired = true;
        return None;
    }
    Some(Flow::Retry)
}

async fn follow_ws(
    client: &PrxClient,
    prx: &PrxConfig,
    store: &MirrorStore,
    mirror: &mut Mirror,
    stop: &mut watch::Receiver<bool>,
    publisher: &mut Publisher,
) -> Flow {
    let Ok(dial) = client.sync_dial() else {
        eprintln!("prx sync requires a loopback PRX URL");
        return Flow::Retry;
    };
    let Some(cursor) = mirror.cursor().map(str::to_owned) else { return Flow::Retry };
    if !mirror.ready() {
        return Flow::Retry;
    }
    publisher.stored(mirror).await;
    let timeout = Duration::from_secs(prx.request_timeout_s);
    let mut sock = match connect_once(client, &dial, timeout).await {
        Ok(sock) => sock,
        Err(flow) => return flow,
    };
    let Ok(hello) = hello_frame(Some(cursor.as_str())) else {
        return Flow::Retry;
    };
    if sock.send_text(&hello).await.is_err() {
        return Flow::Retry;
    }
    if let Err(flow) = read_welcome(&mut sock, mirror, store, stop).await {
        return flow;
    }
    drive(sock, store, mirror, stop, publisher).await
}

async fn connect_once(
    client: &PrxClient,
    dial: &ramflux_prx_client::SyncDial,
    timeout: Duration,
) -> Result<Socket, Flow> {
    let token = client.bearer().map_err(|_| Flow::Retry)?;
    match Socket::open(dial, &token, timeout).await {
        Ok(sock) => Ok(sock),
        Err(WsFail::Auth) => {
            let token = client.bearer().map_err(|_| Flow::Retry)?;
            Socket::open(dial, &token, timeout).await.map_err(|_| Flow::Retry)
        }
        Err(_) => Err(Flow::Retry),
    }
}

async fn read_welcome(
    sock: &mut Socket,
    mirror: &mut Mirror,
    store: &MirrorStore,
    stop: &mut watch::Receiver<bool>,
) -> Result<(), Flow> {
    loop {
        if halted(stop) {
            sock.close_gracefully().await;
            return Err(Flow::Halt);
        }
        match recv_or_stop(sock, stop).await? {
            Incoming::Close(code) => return Err(on_close(code, mirror, store, false)),
            Incoming::Text(bytes) => {
                if on_welcome_frame(sock, mirror, store, &bytes).await? {
                    return Ok(());
                }
            }
        }
    }
}

async fn on_welcome_frame(
    sock: &mut Socket,
    mirror: &mut Mirror,
    store: &MirrorStore,
    bytes: &[u8],
) -> Result<bool, Flow> {
    match decode_server(bytes) {
        Ok(ServerFrame::Ping) => {
            sock.send_text(PONG_FRAME).await.map_err(|_| Flow::Retry)?;
            Ok(false)
        }
        Ok(ServerFrame::Welcome { epoch, head_seq }) => {
            check_welcome(&epoch, head_seq, mirror, store)?;
            Ok(true)
        }
        Ok(ServerFrame::Resync) => Err(mark_resync(mirror, store)),
        Ok(ServerFrame::Event(_)) => Err(Flow::Retry),
        Ok(ServerFrame::Live(_) | ServerFrame::Ignored) => Ok(false),
        Err(_) => {
            eprintln!("prx sync frame rejected");
            Err(Flow::Retry)
        }
    }
}

fn check_welcome(
    epoch: &str,
    head_seq: i64,
    mirror: &mut Mirror,
    store: &MirrorStore,
) -> Result<(), Flow> {
    let bad = match (mirror.epoch(), mirror.cursor_seq()) {
        (Some(stored), Some(seq)) => epoch != stored || head_seq < seq,
        _ => true,
    };
    if bad { Err(mark_resync(mirror, store)) } else { Ok(()) }
}

async fn drive(
    mut sock: Socket,
    store: &MirrorStore,
    mirror: &mut Mirror,
    stop: &mut watch::Receiver<bool>,
    publisher: &mut Publisher,
) -> Flow {
    loop {
        if halted(stop) {
            sock.close_gracefully().await;
            return Flow::Halt;
        }
        let incoming = match recv_or_stop(&mut sock, stop).await {
            Ok(incoming) => incoming,
            Err(Flow::Halt) => {
                sock.close_gracefully().await;
                return Flow::Halt;
            }
            Err(_) => return Flow::Live,
        };
        match incoming {
            Incoming::Close(code) => return on_close(code, mirror, store, true),
            Incoming::Text(bytes) => {
                if let Some(flow) = on_text(&mut sock, store, mirror, publisher, &bytes).await {
                    return flow;
                }
            }
        }
    }
}

async fn on_text(
    sock: &mut Socket,
    store: &MirrorStore,
    mirror: &mut Mirror,
    publisher: &mut Publisher,
    bytes: &[u8],
) -> Option<Flow> {
    match decode_server(bytes) {
        Ok(ServerFrame::Ping) => sock.send_text(PONG_FRAME).await.err().map(|_| Flow::Live),
        Ok(ServerFrame::Ignored) => None,
        Ok(ServerFrame::Live(notice)) => {
            publisher.progress(&notice).await;
            None
        }
        Ok(ServerFrame::Resync) => Some(mark_resync(mirror, store)),
        Ok(ServerFrame::Welcome { .. }) => Some(Flow::Live),
        Ok(ServerFrame::Event(event)) => on_event(sock, store, mirror, publisher, &event).await,
        Err(_) => {
            eprintln!("prx sync frame rejected");
            Some(Flow::Live)
        }
    }
}

async fn publish_applied(publisher: &mut Publisher, op: &MirrorOp) {
    match op {
        MirrorOp::Approval(copy) => publisher.approval(copy).await,
        MirrorOp::Session { .. } => publisher.mirror_session(op).await,
        MirrorOp::Turn(copy) => {
            if let TurnBody::Text { content, final_reply: true } = &copy.body {
                publisher.final_text(copy, content).await;
            }
        }
        _ => {}
    }
}

async fn on_event(
    sock: &mut Socket,
    store: &MirrorStore,
    mirror: &mut Mirror,
    publisher: &mut Publisher,
    event: &JournalEvent,
) -> Option<Flow> {
    let failed = match mirror.apply_event(store, event) {
        Ok(failed) => failed,
        Err(StoreError::Full) => {
            eprintln!("prx sync mirror is full; sync stopped");
            return Some(Flow::Park);
        }
        Err(_) => return Some(Flow::Live),
    };
    publish_applied(publisher, &event.op).await;
    if let Some(note) = failed {
        eprintln!("prx sync turn.failed reason={} retryable={}", note.reason, note.retryable);
    }
    let Ok(ack) = ack_frame(event.seq) else {
        return Some(Flow::Live);
    };
    sock.send_text(&ack).await.err().map(|_| Flow::Live)
}

fn on_close(code: u16, mirror: &mut Mirror, store: &MirrorStore, welcomed: bool) -> Flow {
    eprintln!("prx sync websocket closed code={code}");
    if code == 4410 {
        return mark_resync(mirror, store);
    }
    if welcomed { Flow::Live } else { Flow::Retry }
}

fn mark_resync(mirror: &mut Mirror, store: &MirrorStore) -> Flow {
    if mirror.begin_resync(store).is_err() {
        return Flow::Retry;
    }
    eprintln!("prx sync resync");
    Flow::Resync
}

fn log_ready(mirror: &Mirror) {
    let cursor = mirror.cursor().unwrap_or("-");
    let counts = mirror.counts();
    eprintln!(
        "prx sync snapshot ready cursor={cursor} sessions={} agents={} turns={}",
        counts.sessions, counts.agents, counts.turns
    );
}

fn halted(stop: &watch::Receiver<bool>) -> bool {
    *stop.borrow()
}

async fn recv_or_stop(
    sock: &mut Socket,
    stop: &mut watch::Receiver<bool>,
) -> Result<Incoming, Flow> {
    tokio::select! {
        biased;
        result = stop.changed() => {
            if result.is_err() || *stop.borrow() { Err(Flow::Halt) } else { Err(Flow::Retry) }
        }
        result = sock.recv() => result.map_err(|_| Flow::Retry),
    }
}

async fn wait_stop(stop: &mut watch::Receiver<bool>, delay: Duration) -> bool {
    tokio::select! {
        biased;
        result = stop.changed() => result.is_err() || *stop.borrow(),
        () = tokio::time::sleep(delay) => false,
    }
}

async fn park(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|flag| *flag).await;
}

fn backoff_delay(attempt: u32) -> Duration {
    let base = match attempt.min(7) {
        0 => 250,
        1 => 500,
        2 => 1_000,
        3 => 2_000,
        4 => 4_000,
        5 => 8_000,
        6 => 16_000,
        _ => 30_000,
    };
    let room = 30_000_u64.saturating_sub(base);
    let jitter = if room == 0 { 0 } else { random_u64() % room.saturating_add(1) };
    Duration::from_millis(base.saturating_add(jitter))
}

fn random_u64() -> u64 {
    let mut buf = [0_u8; 8];
    if random_bytes(&mut buf).is_err() {
        return 0;
    }
    u64::from_le_bytes(buf)
}

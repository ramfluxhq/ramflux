// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The call engine: three threads around one UDP socket.
//!
//! - **send**: takes a captured frame (silence while muted, so the peer's
//!   playout keeps its rhythm and the relay binding stays alive), encodes,
//!   encrypts and sends it to the session's endpoint; with nothing captured
//!   it keeps the relay binding alive.
//! - **receive**: accepts datagrams from the endpoint only (anything else
//!   is dropped unread), opens them and hands the Opus packets to the
//!   jitter buffer. A new SSRC from the peer (it restarted its stream)
//!   starts a fresh buffer. A rebinding challenge from the relay (this
//!   side's address changed, see [`crate::rebind`]) is answered at once
//!   from the same socket; the `SFrame` sender and receiver go on as they
//!   were.
//! - **playout**: every 20 ms takes the jitter buffer's next frame and
//!   plays the decoded audio, a frame rebuilt from forward error correction,
//!   a concealed frame, or silence.
//!
//! [`Capture`] and [`Playback`] are the PCM source and sink. The host
//! implements them (a microphone and speaker, or a file or tone). This
//! crate does not open an audio device. [`Engine::stats`] reports the
//! counters and [`Engine::quality`] what the user is told.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::authorization::{Authorization, GateReason, GateSnapshot};
use crate::codec::{Decoder, FRAME_MS, FRAME_SAMPLES, Frame};
use crate::jitter::{JitterBuffer, JitterStats, Playout};
use crate::pipeline::{Inbound, Outbound, PipelineError, Rebinder};
use crate::relay::MAX_DATAGRAM;
use crate::session::MediaSession;
use crate::video::control::VideoControl;
use crate::video::feedback::Error as FeedbackError;
use crate::video::packet::AccessUnit;
use crate::video::reassembly::Reassembler;
use crate::video::send::{MAX_DATAGRAMS_PER_TURN, Submitted, VideoSender};
use zeroize::{Zeroize, Zeroizing};

/// Where captured audio comes from.
pub trait Capture: Send + 'static {
    /// The next 20 ms frame, waiting at most `timeout`; `None` when none
    /// arrived in time.
    fn next_frame(&mut self, timeout: Duration) -> Option<Frame>;

    /// Discard queued capture after a generation change, on the sender worker.
    fn discard_pending(&mut self) {}
}

/// Where received audio goes.
pub trait Playback: Send + 'static {
    /// Plays one 20 ms frame.
    fn play(&mut self, frame: &Frame);
}

/// Why the engine did not start.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The endpoint does not resolve.
    #[error("media endpoint {0} does not resolve")]
    Endpoint(String),
    /// The socket could not be opened.
    #[error("media socket: {0}")]
    Socket(#[from] std::io::Error),
    /// The session's keys or suite were refused, or the codec did not start.
    #[error(transparent)]
    Pipeline(#[from] PipelineError),
    /// The random source failed (SSRC, initial sequence and timestamp).
    #[error("random source: {0}")]
    Random(String),
}

/// Interval of relay keepalives while nothing is sent.
pub const KEEPALIVE: Duration = Duration::from_secs(5);
/// Silence from the peer after which the connection counts as lost.
pub const NO_AUDIO_AFTER: Duration = Duration::from_secs(3);
/// Captured frames of exact digital silence (two seconds) after which the
/// microphone is taken to be blocked (macOS delivers zeros, not an error,
/// when microphone access is denied; a real microphone never does).
pub const BLOCKED_AFTER_FRAMES: u32 = 100;
/// Frames in the loss window behind [`Engine::quality`].
const QUALITY_WINDOW: usize = 100;

/// How the call sounds, as the in-call bar shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quality {
    /// Nothing received yet.
    Connecting,
    /// Little loss and jitter.
    Good,
    /// Noticeable loss or jitter.
    Fair,
    /// Heavy loss or jitter.
    Poor,
    /// Nothing received for [`NO_AUDIO_AFTER`].
    Lost,
}

/// Counters of a running engine.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct EngineStats {
    /// Packets sent.
    pub sent: u64,
    /// Packets authenticated by the existing replay-protected receiver.
    pub authenticated: u64,
    /// Packets that failed to open (forged, altered, replayed, foreign).
    pub rejected: u64,
    /// Datagrams from another address than the endpoint (dropped unread).
    pub foreign: u64,
    /// The jitter buffer's counters.
    pub jitter: JitterStats,
    /// Frames played from a packet.
    pub played: u64,
    /// Frames rebuilt from the next packet's forward error correction.
    pub recovered: u64,
    /// Frames concealed.
    pub concealed: u64,
    /// Lost frames among the last ones played (per mille).
    pub recent_loss_per_mille: u32,
    /// Milliseconds since the last packet arrived (`None`: none yet).
    pub since_last_packet_ms: Option<u64>,
    /// The microphone delivers only digital silence (access blocked).
    pub microphone_blocked: bool,
    /// A send failed (network down or endpoint refused).
    pub send_errors: u64,
    /// Rebinding challenges from the relay answered.
    pub rebinds_answered: u64,
    /// Video fragments authenticated (before reassembly).
    pub video_authenticated: u64,
    /// Video packets refused (no gate, authentication, replay or framing).
    pub video_rejected: u64,
    /// Video fragments or access units dropped by the bounded reassembly.
    pub video_dropped: u64,
    /// Video feedback reports accepted (PT113).
    pub video_feedback: u64,
    /// The target video bitrate of the rate controller, bits per second (0 without video).
    pub video_target_bps: u32,
    /// The highest keyframe revision the peer asked of this side's video
    /// (increasing; the host answers it with an IDR and [`Engine::keyframe_applied`]).
    pub keyframe_request_revision: u32,
    /// Video datagrams sent.
    pub video_sent: u64,
    /// Video access units dropped before sending (queue full, or waiting for a keyframe).
    pub video_send_dropped: u64,
    /// Video datagrams that failed to send or to seal.
    pub video_send_errors: u64,
    /// Packets refused because their `SFrame` KID belongs to another track
    /// (audio KIDs on PT112/PT113, video KIDs on PT111). Also counted in
    /// `rejected` or `video_rejected`.
    pub kid_mismatch: u64,
}

#[derive(Debug, Default)]
struct Shared {
    stats: EngineStats,
    last_packet: Option<Instant>,
    /// Recent frames: `true` lost.
    window: std::collections::VecDeque<bool>,
}

/// A running call engine. Dropping it stops it.
pub struct Engine {
    authorization: Arc<Authorization>,
    jitter: Arc<Mutex<JitterBuffer>>,
    stop: Arc<AtomicBool>,
    muted: Arc<AtomicBool>,
    shared: Arc<Mutex<Shared>>,
    video: Arc<Mutex<Reassembler>>,
    video_out: Option<Arc<Mutex<VideoSender>>>,
    control: Arc<Mutex<VideoControl>>,
    threads: Vec<JoinHandle<()>>,
    local: SocketAddr,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").field("local", &self.local).finish_non_exhaustive()
    }
}

fn random_u32() -> Result<u32, EngineError> {
    let mut bytes = [0_u8; 4];
    getrandom::fill(&mut bytes).map_err(|error| EngineError::Random(error.to_string()))?;
    Ok(u32::from_be_bytes(bytes))
}

impl Engine {
    /// Starts carrying `session` with `capture` and `playback`. The engine
    /// consumes the session: its keys start here, once, at counter zero,
    /// and are dropped (wiped) with the engine. An engine is never started
    /// again on the same keys; a fresh call brings fresh ones.
    ///
    /// # Errors
    ///
    /// The endpoint does not resolve, the socket does not open, or the
    /// session's suite or keys are refused.
    pub fn start(
        session: MediaSession,
        capture: Box<dyn Capture>,
        playback: Box<dyn Playback>,
    ) -> Result<Self, EngineError> {
        Self::start_inner(session, capture, playback, None)
    }

    /// Start under the SDK fence, initially with audio inactive.
    /// # Errors
    /// Returns the same startup errors as [`Self::start`].
    pub fn start_authorized(
        session: MediaSession,
        capture: Box<dyn Capture>,
        playback: Box<dyn Playback>,
        lease: Duration,
    ) -> Result<Self, EngineError> {
        Self::start_inner(session, capture, playback, Some(lease))
    }

    fn start_inner(
        mut session: MediaSession,
        capture: Box<dyn Capture>,
        playback: Box<dyn Playback>,
        lease: Option<Duration>,
    ) -> Result<Self, EngineError> {
        let endpoint = session
            .endpoint()
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .ok_or_else(|| EngineError::Endpoint(session.endpoint().to_owned()))?;
        let bind: SocketAddr =
            if endpoint.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0_u16; 8], 0).into() };
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(Duration::from_millis(50)))?;
        socket.set_write_timeout(Some(Duration::from_millis(50)))?;
        let local = socket.local_addr()?;
        let ssrc = random_u32()?;
        let initial = random_u32()?;
        let outbound = Outbound::new(&mut session, ssrc, (initial >> 16) as u16, random_u32()?)?;
        let video_ssrc = random_u32()?;
        let video_out = VideoSender::new(&mut session, video_ssrc, (random_u32()? >> 16) as u16)?
            .map(|sender| Arc::new(Mutex::new(sender)));
        let inbound = Inbound::new(&session)?;
        let rebinder = Rebinder::new(&mut session);
        drop(session);
        let decoder = Decoder::new().map_err(PipelineError::from)?;

        let authorization = Arc::new(Authorization::new(lease));
        let stop = Arc::new(AtomicBool::new(false));
        let muted = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Mutex::new(Shared::default()));
        let jitter = Arc::new(Mutex::new(JitterBuffer::new()));
        let video = Arc::new(Mutex::new(Reassembler::new()));
        let control = Arc::new(Mutex::new(VideoControl::new()));
        let started = Instant::now();
        let send_socket = socket.try_clone()?;

        let sender = SendLoop {
            socket: send_socket,
            endpoint,
            outbound,
            capture,
            authorization: authorization.clone(),
            stop: stop.clone(),
            muted: muted.clone(),
            shared: shared.clone(),
            video: video_out.clone(),
            control: control.clone(),
        };
        let receiver = ReceiveLoop {
            socket,
            endpoint,
            inbound,
            rebinder,
            jitter: jitter.clone(),
            video: video.clone(),
            video_out: video_out.clone(),
            control: control.clone(),
            authorization: authorization.clone(),
            stop: stop.clone(),
            shared: shared.clone(),
            started,
        };
        let player = PlayoutLoop {
            decoder,
            playback,
            jitter: jitter.clone(),
            authorization: authorization.clone(),
            stop: stop.clone(),
            shared: shared.clone(),
        };
        let mut engine = Self {
            authorization,
            jitter,
            stop,
            muted,
            shared,
            video,
            video_out,
            control,
            threads: Vec::new(),
            local,
        };
        engine.threads.push(spawn("ramflux-call-send", move || sender.run())?);
        engine.threads.push(spawn("ramflux-call-receive", move || receiver.run())?);
        engine.threads.push(spawn("ramflux-call-playout", move || player.run())?);
        spawn_synthetic_video(&mut engine)?;
        Ok(engine)
    }

    /// Install SDK authority and remaining lease. Never activates host audio.
    pub fn authorize(&self, reason: Option<GateReason>, lease: Duration, renewed: bool) {
        let previous = self.authorization.snapshot().generation;
        self.authorization.update(reason, lease, renewed);
        if self.authorization.snapshot().generation != previous {
            self.flush_playout();
        }
    }

    /// Set host audio readiness after the SDK grant. Closing fences worker output.
    #[must_use]
    pub fn audio_active(&self, active: bool) -> bool {
        let accepted = self.authorization.activate(active);
        if !active {
            self.flush_playout();
        }
        accepted
    }

    /// Current credential-free gate.
    #[must_use]
    pub fn gate(&self) -> GateSnapshot {
        self.authorization.snapshot()
    }

    /// Sets video authority, independent of audio. Turning it off drops the
    /// pending video units. Refused once the gate is closed or retired.
    #[must_use]
    pub fn video_active(&self, active: bool) -> bool {
        let accepted = self.authorization.activate_video(active);
        if !active {
            *lock_video(&self.video) = Reassembler::new();
            self.flush_video();
        }
        accepted
    }

    /// Asks the peer for a keyframe (PT113 request revision, repeated until acknowledged).
    ///
    /// # Errors
    ///
    /// [`FeedbackError::Wrap`] when the revision would wrap.
    pub fn request_keyframe(&self) -> Result<u32, FeedbackError> {
        lock_control(&self.control).request_keyframe()
    }

    /// The host calls this after it produced the IDR for the peer's request
    /// `revision` (the peer then sees the acknowledgement).
    pub fn keyframe_applied(&self, revision: u32) {
        lock_control(&self.control).apply_keyframe(revision);
    }

    /// Queues one encoded access unit on the video track. Refused (counted
    /// as dropped) while the video gate is closed. A full queue flushes to
    /// the next keyframe (see [`VideoSender::submit`]).
    ///
    /// # Errors
    ///
    /// [`PipelineError::VideoNotNegotiated`] without video keys, or
    /// [`PipelineError::Video`] for a malformed access unit.
    pub fn submit_video(&self, au: &AccessUnit) -> Result<Submitted, PipelineError> {
        let out = self.video_out.as_ref().ok_or(PipelineError::VideoNotNegotiated)?;
        submit_video_on(&self.authorization, &self.control, out, &self.shared, au)
    }

    fn flush_video(&self) {
        if let Some(out) = self.video_out.as_ref() {
            lock_sender(out).flush();
        }
        *lock_control(&self.control) = VideoControl::new();
    }

    /// The next complete video access unit, in presentation order (expired
    /// partial units are dropped first).
    #[must_use]
    pub fn take_video_access_unit(&self) -> Option<AccessUnit> {
        lock_video(&self.video).pop_ready(Instant::now())
    }

    fn flush_playout(&self) {
        *self.jitter.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            JitterBuffer::new();
    }

    /// Close admission and fence all in-flight output before returning its retired generation.
    #[must_use]
    pub fn fence(&self, reason: GateReason) -> GateSnapshot {
        self.authorization.retire(reason);
        self.flush_playout();
        *lock_video(&self.video) = Reassembler::new();
        self.flush_video();
        self.authorization.snapshot()
    }

    /// The local socket address (tests, diagnostics).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Mutes or unmutes the microphone (silence is sent while muted).
    pub fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::SeqCst);
    }

    /// Whether the microphone is muted.
    #[must_use]
    pub fn is_muted(&self) -> bool {
        self.muted.load(Ordering::SeqCst)
    }

    /// The counters so far.
    pub fn stats(&self) -> EngineStats {
        let (video_target_bps, keyframe_request_revision) = {
            let control = lock_control(&self.control);
            (control.target_bps(), control.peer_request())
        };
        let shared = self.shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut stats = shared.stats;
        if self.video_out.is_some() {
            stats.video_target_bps = video_target_bps;
        }
        stats.keyframe_request_revision = keyframe_request_revision;
        stats.since_last_packet_ms = shared
            .last_packet
            .map(|at| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX));
        stats
    }

    /// How the call sounds now.
    #[must_use]
    pub fn quality(&self) -> Quality {
        quality_of(&self.stats())
    }

    /// Stops the threads and waits for them.
    pub fn stop(mut self) {
        self.halt();
    }

    /// Stop, join every worker and return the final counters.
    #[must_use]
    pub fn stop_with_stats(mut self) -> EngineStats {
        self.halt();
        self.stats()
    }

    fn halt(&mut self) {
        self.authorization.retire(GateReason::Terminal);
        self.stop.store(true, Ordering::SeqCst);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.halt();
    }
}

/// The quality the counters describe.
#[must_use]
pub fn quality_of(stats: &EngineStats) -> Quality {
    let Some(since) = stats.since_last_packet_ms else { return Quality::Connecting };
    if since >= u64::try_from(NO_AUDIO_AFTER.as_millis()).unwrap_or(u64::MAX) {
        return Quality::Lost;
    }
    let (loss, jitter) = (stats.recent_loss_per_mille, stats.jitter.jitter_ms);
    if loss > 100 || jitter > 80.0 {
        Quality::Poor
    } else if loss > 30 || jitter > 40.0 {
        Quality::Fair
    } else {
        Quality::Good
    }
}

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new().name(name.to_owned()).spawn(f)
}

fn lock(shared: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The submit path shared by [`Engine::submit_video`] and the itest synthetic source.
fn submit_video_on(
    authorization: &Authorization,
    control: &Mutex<VideoControl>,
    out: &Mutex<VideoSender>,
    shared: &Mutex<Shared>,
    au: &AccessUnit,
) -> Result<Submitted, PipelineError> {
    let outcome = if authorization.lock().admitted_video() {
        let paused = {
            let mut control = lock_control(control);
            control.note_outbound_revision(au.track_revision);
            control.paused()
        };
        if paused {
            Submitted { queued: false, dropped: 1 }
        } else {
            lock_sender(out).submit(au, Instant::now())?
        }
    } else {
        Submitted { queued: false, dropped: 1 }
    };
    if outcome.dropped > 0 {
        let dropped = u64::try_from(outcome.dropped).unwrap_or(u64::MAX);
        lock(shared).stats.video_send_dropped += dropped;
    }
    Ok(outcome)
}

/// Starts the synthetic video source on a call with a video track (itest builds only).
#[cfg(feature = "itest-synthetic-video")]
fn spawn_synthetic_video(engine: &mut Engine) -> std::io::Result<()> {
    let Some(out) = engine.video_out.clone() else {
        return Ok(());
    };
    let authorization = engine.authorization.clone();
    let control = engine.control.clone();
    let shared = engine.shared.clone();
    let stop = engine.stop.clone();
    engine.threads.push(spawn("ramflux-call-synthetic-video", move || {
        synthetic_feeder(&authorization, &control, &out, &shared, &stop);
    })?);
    Ok(())
}

#[cfg(not(feature = "itest-synthetic-video"))]
fn spawn_synthetic_video(_engine: &mut Engine) -> std::io::Result<()> {
    Ok(())
}

/// One synthetic access unit per frame interval while the video gate admits. An IDR every
/// `IDR_EVERY` frames, and an IDR answering each new peer keyframe request (then acknowledged).
#[cfg(feature = "itest-synthetic-video")]
fn synthetic_feeder(
    authorization: &Authorization,
    control: &Mutex<VideoControl>,
    out: &Mutex<VideoSender>,
    shared: &Mutex<Shared>,
    stop: &AtomicBool,
) {
    use crate::video::synthetic::{FRAME_INTERVAL, IDR_EVERY, access_unit};
    let mut index = 0_u64;
    let mut applied = lock_control(control).peer_request();
    while !stop.load(Ordering::SeqCst) {
        if authorization.lock().retired {
            break;
        }
        if authorization.lock().admitted_video() {
            let request = lock_control(control).peer_request();
            let answer = request != applied;
            let idr = answer || index % IDR_EVERY == 0;
            let au = access_unit(index, idr);
            let _ = submit_video_on(authorization, control, out, shared, &au);
            if answer {
                lock_control(control).apply_keyframe(request);
                applied = request;
            }
            index = index.saturating_add(1);
        }
        std::thread::sleep(FRAME_INTERVAL);
    }
}

fn lock_video(video: &Mutex<Reassembler>) -> std::sync::MutexGuard<'_, Reassembler> {
    video.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_sender(video: &Mutex<VideoSender>) -> std::sync::MutexGuard<'_, VideoSender> {
    video.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_control(control: &Mutex<VideoControl>) -> std::sync::MutexGuard<'_, VideoControl> {
    control.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct SendLoop {
    socket: UdpSocket,
    endpoint: SocketAddr,
    outbound: Outbound,
    capture: Box<dyn Capture>,
    authorization: Arc<Authorization>,
    stop: Arc<AtomicBool>,
    muted: Arc<AtomicBool>,
    shared: Arc<Mutex<Shared>>,
    video: Option<Arc<Mutex<VideoSender>>>,
    control: Arc<Mutex<VideoControl>>,
}

impl SendLoop {
    fn run(mut self) {
        let mut last_sent = Instant::now();
        let mut silent_frames = 0_u32;
        let mut generation = 0;
        while !self.stop.load(Ordering::SeqCst) {
            let current = {
                let mut gate = self.authorization.lock();
                if gate.retired {
                    break;
                }
                if !gate.admitted() {
                    drop(gate);
                    self.capture.discard_pending();
                    self.video_turn();
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                gate.generation
            };
            if generation != current {
                self.capture.discard_pending();
                generation = current;
                let mut gate = self.authorization.lock();
                if gate.admitted()
                    && gate.generation == current
                    && let Some(keepalive) = self.outbound.keepalive()
                {
                    let _ = self.socket.send_to(&keepalive, self.endpoint);
                    last_sent = Instant::now();
                }
            }
            let captured = self.capture.next_frame(Duration::from_millis(100)).map(Zeroizing::new);
            let mut gate = self.authorization.lock();
            if !gate.admitted() || gate.generation != current {
                continue;
            }
            let Some(frame) = captured else {
                if last_sent.elapsed() >= KEEPALIVE
                    && let Some(keepalive) = self.outbound.keepalive()
                {
                    let _ = self.socket.send_to(&keepalive, self.endpoint);
                    last_sent = Instant::now();
                }
                drop(gate);
                self.video_turn();
                continue;
            };
            let mut frame = frame;
            if self.muted.load(Ordering::SeqCst) {
                frame.zeroize();
                silent_frames = 0;
            } else if frame.iter().all(|s| *s == 0) {
                silent_frames = silent_frames.saturating_add(1);
            } else {
                silent_frames = 0;
            }
            let sent = self.outbound.packet(&frame).ok().and_then(|datagram| {
                gate.admitted().then(|| self.socket.send_to(&datagram, self.endpoint).is_ok())
            });
            drop(gate);
            last_sent = Instant::now();
            let mut shared = lock(&self.shared);
            match sent {
                Some(true) => shared.stats.sent += 1,
                _ => shared.stats.send_errors += 1,
            }
            shared.stats.microphone_blocked = silent_frames >= BLOCKED_AFTER_FRAMES;
            drop(shared);
            self.video_turn();
        }
    }

    /// Sends the video datagrams the pacer allows. It runs after this turn's
    /// audio send, under the video gate, and never holds the gate and the
    /// sender while it waits for anything.
    fn video_turn(&self) {
        let Some(video) = self.video.as_ref() else {
            return;
        };
        let mut gate = self.authorization.lock();
        if !gate.admitted_video() {
            return;
        }
        let now = Instant::now();
        let (report, paused) = {
            let mut control = lock_control(&self.control);
            control.tick(now);
            (control.report_due(now), control.paused())
        };
        let mut sender = lock_sender(video);
        if let Some(report) = report {
            sender.queue_feedback(&report);
        }
        if paused {
            return;
        }
        for _ in 0..MAX_DATAGRAMS_PER_TURN {
            match sender.next_datagram(Instant::now()) {
                Ok(Some(datagram)) => {
                    let sent = self.socket.send_to(&datagram, self.endpoint).is_ok();
                    let mut shared = lock(&self.shared);
                    if sent {
                        shared.stats.video_sent += 1;
                    } else {
                        shared.stats.video_send_errors += 1;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    lock(&self.shared).stats.video_send_errors += 1;
                    break;
                }
            }
        }
    }
}

struct ReceiveLoop {
    socket: UdpSocket,
    endpoint: SocketAddr,
    inbound: Inbound,
    rebinder: Rebinder,
    jitter: Arc<Mutex<JitterBuffer>>,
    video: Arc<Mutex<Reassembler>>,
    video_out: Option<Arc<Mutex<VideoSender>>>,
    control: Arc<Mutex<VideoControl>>,
    authorization: Arc<Authorization>,
    stop: Arc<AtomicBool>,
    shared: Arc<Mutex<Shared>>,
    started: Instant,
}

impl ReceiveLoop {
    fn run(mut self) {
        let mut buffer = vec![0_u8; MAX_DATAGRAM];
        let mut peer_ssrc = None;
        while !self.stop.load(Ordering::SeqCst) {
            if self.authorization.snapshot().retired {
                break;
            }
            let Ok((len, from)) = self.socket.recv_from(&mut buffer) else { continue };
            if from != self.endpoint {
                lock(&self.shared).stats.foreign += 1;
                continue;
            }
            let Some(datagram) = buffer.get(..len).filter(|bytes| !bytes.is_empty()) else {
                continue;
            };
            // Audio (PT111) and video (PT112) share this socket; each track
            // has its own gate, so video authority never depends on audio_active.
            let video = Inbound::is_video(datagram);
            let feedback = !video && Inbound::is_feedback(datagram);
            let mut gate = self.authorization.lock();
            let admitted = if video || feedback { gate.admitted_video() } else { gate.admitted() };
            if !admitted {
                if gate.retired {
                    break;
                }
                continue;
            }
            if video {
                receive_video(
                    &mut self.inbound,
                    &self.video,
                    &self.control,
                    &self.shared,
                    datagram,
                );
                continue;
            }
            if feedback {
                let out = self.video_out.as_deref();
                receive_feedback(&mut self.inbound, out, &self.control, &self.shared, datagram);
                continue;
            }
            if Rebinder::is_challenge(datagram) {
                // From the relay only (checked above): answer from this
                // socket, the address the relay saw change.
                if let Some(answer) = self.rebinder.answer(datagram)
                    && self.socket.send_to(&answer, self.endpoint).is_ok()
                {
                    lock(&self.shared).stats.rebinds_answered += 1;
                }
                continue;
            }
            match self.inbound.open(datagram) {
                Ok(received) => {
                    let arrival = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(0);
                    let mut jitter =
                        self.jitter.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    if peer_ssrc.replace(received.header.ssrc) != Some(received.header.ssrc) {
                        *jitter = JitterBuffer::new();
                    }
                    jitter.push(
                        received.header.sequence,
                        received.header.timestamp,
                        received.opus,
                        arrival,
                    );
                    let mut shared = lock(&self.shared);
                    shared.last_packet = Some(Instant::now());
                    shared.stats.authenticated += 1;
                }
                Err(error) => {
                    let mut shared = lock(&self.shared);
                    shared.stats.rejected += 1;
                    if matches!(error, PipelineError::KidMismatch) {
                        shared.stats.kid_mismatch += 1;
                    }
                }
            }
        }
    }
}

/// Authenticates one video fragment and feeds the bounded reassembly. Runs
/// under the video gate the caller holds.
fn receive_video(
    inbound: &mut Inbound,
    video: &Mutex<Reassembler>,
    control: &Mutex<VideoControl>,
    shared: &Mutex<Shared>,
    datagram: &[u8],
) {
    match inbound.open_video(datagram) {
        Ok(received) => {
            let now = Instant::now();
            lock_control(control).on_fragment(
                &received.fragment,
                received.extended_sequence,
                datagram.len(),
                now,
            );
            let outcome = lock_video(video).push(&received.fragment, &received.payload, now);
            let mut stats = lock(shared);
            match outcome {
                Ok(_) => stats.stats.video_authenticated += 1,
                Err(_) => stats.stats.video_dropped += 1,
            }
        }
        Err(error) => count_video_refusal(shared, &error),
    }
}

/// Authenticates one feedback report (PT113) and feeds the control state.
/// Runs under the video gate the caller holds.
fn receive_feedback(
    inbound: &mut Inbound,
    out: Option<&Mutex<VideoSender>>,
    control: &Mutex<VideoControl>,
    shared: &Mutex<Shared>,
    datagram: &[u8],
) {
    match inbound.open_feedback(datagram) {
        Ok(report) => {
            let now = Instant::now();
            let queue_ms = out.map_or(0, |out| lock_sender(out).queue_age_ms(now));
            let outcome = lock_control(control).on_feedback(report, now, queue_ms);
            let mut stats = lock(shared);
            match outcome {
                Ok(()) => stats.stats.video_feedback += 1,
                Err(_) => stats.stats.video_rejected += 1,
            }
        }
        Err(error) => count_video_refusal(shared, &error),
    }
}

fn count_video_refusal(shared: &Mutex<Shared>, error: &PipelineError) {
    let mut stats = lock(shared);
    stats.stats.video_rejected += 1;
    if matches!(error, PipelineError::KidMismatch) {
        stats.stats.kid_mismatch += 1;
    }
}

struct PlayoutLoop {
    decoder: Decoder,
    playback: Box<dyn Playback>,
    jitter: Arc<Mutex<JitterBuffer>>,
    authorization: Arc<Authorization>,
    stop: Arc<AtomicBool>,
    shared: Arc<Mutex<Shared>>,
}

impl PlayoutLoop {
    fn run(mut self) {
        let frame_time = Duration::from_millis(FRAME_MS);
        let mut deadline = Instant::now() + frame_time;
        let mut generation = 0;
        while !self.stop.load(Ordering::SeqCst) {
            let now = Instant::now();
            if deadline > now {
                std::thread::sleep(deadline - now);
            } else if now - deadline > frame_time * 10 {
                // Far behind (the machine slept): start the rhythm again.
                deadline = now;
            }
            deadline += frame_time;
            let mut gate = self.authorization.lock();
            if !gate.admitted() {
                if gate.retired {
                    break;
                }
                *self.jitter.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                    JitterBuffer::new();
                continue;
            }
            if generation != gate.generation {
                let Ok(decoder) = Decoder::new() else { break };
                self.decoder = decoder;
                generation = gate.generation;
            }
            let (playout, jitter_stats) = {
                let mut jitter =
                    self.jitter.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                (jitter.pop(), jitter.stats())
            };
            let (frame, outcome) = match playout {
                Playout::Wait => ([0; FRAME_SAMPLES], None),
                Playout::Packet(packet) => match self.decoder.decode(&packet) {
                    Ok(frame) => (frame, Some(Outcome::Played)),
                    Err(_) => (
                        self.decoder.conceal().unwrap_or([0; FRAME_SAMPLES]),
                        Some(Outcome::Concealed),
                    ),
                },
                Playout::Lost { next: Some(next) } => match self.decoder.recover(&next) {
                    Ok(frame) => (frame, Some(Outcome::Recovered)),
                    Err(_) => (
                        self.decoder.conceal().unwrap_or([0; FRAME_SAMPLES]),
                        Some(Outcome::Concealed),
                    ),
                },
                Playout::Lost { next: None } => {
                    (self.decoder.conceal().unwrap_or([0; FRAME_SAMPLES]), Some(Outcome::Concealed))
                }
            };
            let frame = Zeroizing::new(frame);
            if !gate.admitted() {
                continue;
            }
            self.playback.play(&frame);
            let mut shared = lock(&self.shared);
            shared.stats.jitter = jitter_stats;
            if let Some(outcome) = outcome {
                match outcome {
                    Outcome::Played => shared.stats.played += 1,
                    Outcome::Recovered => shared.stats.recovered += 1,
                    Outcome::Concealed => shared.stats.concealed += 1,
                }
                shared.window.push_back(outcome != Outcome::Played);
                if shared.window.len() > QUALITY_WINDOW {
                    shared.window.pop_front();
                }
                let lost = shared.window.iter().filter(|lost| **lost).count();
                shared.stats.recent_loss_per_mille =
                    u32::try_from(lost * 1000 / shared.window.len()).unwrap_or(1000);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Played,
    Recovered,
    Concealed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_follows_loss_jitter_and_silence() {
        let mut stats = EngineStats::default();
        assert_eq!(quality_of(&stats), Quality::Connecting);
        stats.since_last_packet_ms = Some(10);
        assert_eq!(quality_of(&stats), Quality::Good);
        stats.recent_loss_per_mille = 50;
        assert_eq!(quality_of(&stats), Quality::Fair);
        stats.jitter.jitter_ms = 120.0;
        assert_eq!(quality_of(&stats), Quality::Poor);
        stats.since_last_packet_ms = Some(3_000);
        assert_eq!(quality_of(&stats), Quality::Lost);
    }
}

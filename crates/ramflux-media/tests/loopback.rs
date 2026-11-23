// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

// Moved tests keep their original numeric casts and assertions.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::similar_names,
    clippy::unwrap_used
)]

//! Synthetic audio through the whole media path: PCM → Opus → RTP + `SFrame`
//! → UDP through a stand-in relay → `SFrame` → jitter buffer → Opus → PCM,
//! in both directions, without audio devices.
//!
//! The stand-in relay does what the product's opaque media relay does: it
//! reads the allocation token in front of each datagram, binds the sender's
//! address to that allocation, and forwards the bare packet to the peer
//! allocation's address. It records every packet it forwards, so the test
//! checks what a relay sees: headers and ciphertext, never the audio.

use std::collections::BTreeMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ramflux_media::codec::{Decoder, Encoder, FRAME_SAMPLES, Frame};
use ramflux_media::jitter::{JitterBuffer, Playout};
use ramflux_media::pipeline::{Inbound, Outbound};
use ramflux_media::sframe::{AES_256_GCM_SHA512_128, Header};
use ramflux_media::{
    BaseKey, Capture, DirectionKey, Engine, MediaSession, Playback, Quality, relay, rtp,
};

/// Frames per tone or pause block.
const BLOCK: usize = 10;

/// Frame `index` of the test signal: blocks of a tone (at `hz`) and of
/// silence, so the envelope shows order and continuity after a lossy codec.
fn synthetic(index: usize, hz: f32) -> Frame {
    let mut frame = [0_i16; FRAME_SAMPLES];
    if (index / BLOCK).is_multiple_of(2) {
        for (i, sample) in frame.iter_mut().enumerate() {
            let t = (index * FRAME_SAMPLES + i) as f32 / 48_000.0;
            *sample = ((2.0 * std::f32::consts::PI * hz * t).sin() * 12_000.0) as i16;
        }
    }
    frame
}

fn rms(frame: &Frame) -> f64 {
    (frame.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / FRAME_SAMPLES as f64).sqrt()
}

fn keys() -> (BaseKey, BaseKey) {
    (BaseKey::new(vec![0x11; 32]), BaseKey::new(vec![0x22; 32]))
}

fn sessions(endpoint: &str, token_a: &[u8], token_b: &[u8]) -> (MediaSession, MediaSession) {
    let (a, b) = keys();
    let a_session = MediaSession::new(
        endpoint,
        token_a.to_vec(),
        AES_256_GCM_SHA512_128,
        DirectionKey::new(0, a.clone()),
        DirectionKey::new(1, b.clone()),
    );
    let b_session = MediaSession::new(
        endpoint,
        token_b.to_vec(),
        AES_256_GCM_SHA512_128,
        DirectionKey::new(1, b),
        DirectionKey::new(0, a),
    );
    (a_session, b_session)
}

#[test]
fn frames_pass_encrypted_and_in_order_without_io() {
    let (mut a, b) = sessions("127.0.0.1:9", b"alloc-a", b"alloc-b");
    let mut outbound = Outbound::new(&mut a, 0x1234_5678, 65_530, 7).unwrap();
    let mut inbound = Inbound::new(&b).unwrap();
    let mut reference = Encoder::new().unwrap();
    let mut jitter = JitterBuffer::new();
    let mut decoder = Decoder::new().unwrap();
    let mut decoded = Vec::new();
    for index in 0..40 {
        let frame = synthetic(index, 440.0);
        let datagram = outbound.packet(&frame).unwrap();
        let (token, packet) = relay::unframe(&datagram).expect("framed for the relay");
        assert_eq!(token, b"alloc-a");
        // What the relay forwards is ciphertext: the Opus packet the same
        // encoder state produces is nowhere in it.
        let opus = reference.encode(&frame).unwrap();
        let header = rtp::RtpHeader::decode(packet).unwrap();
        assert_eq!(header.sequence, 65_530_u16.wrapping_add(index as u16));
        assert_eq!(header.timestamp, 7 + (index * FRAME_SAMPLES) as u32);
        assert_eq!(header.marker, index == 0);
        let body = &packet[rtp::HEADER_LEN..];
        let sframe_header = Header { kid: 0, ctr: index as u64 }.encode();
        assert!(body.starts_with(&sframe_header));
        assert_eq!(body.len(), sframe_header.len() + opus.len() + 16, "header, ciphertext, tag");
        assert!(!body.windows(opus.len()).any(|w| w == opus.as_slice()), "frame {index}");

        let received = inbound.open(packet).unwrap();
        assert_eq!(received.opus, opus, "decrypts to the encoder's packet");
        // A replayed packet and one with an altered header are refused.
        assert!(inbound.open(packet).is_err());
        let mut altered = packet.to_vec();
        altered[3] ^= 1;
        assert!(inbound.open(&altered).is_err());
        jitter.push(header.sequence, header.timestamp, received.opus, index as u64 * 20);
        if let Playout::Packet(packet) = jitter.pop() {
            decoded.push(decoder.decode(&packet).unwrap());
        }
    }
    assert!(decoded.len() >= 38, "played in turn across the sequence wrap: {}", decoded.len());
    assert_eq!(jitter.stats().lost, 0);
    // The other direction's key does not open these packets.
    let mut wrong = Inbound::new(&a).unwrap();
    let datagram = outbound.packet(&synthetic(0, 440.0)).unwrap();
    assert!(wrong.open(relay::unframe(&datagram).unwrap().1).is_err());
}

/// What the stand-in relay saw.
#[derive(Default)]
struct Seen {
    packets: Vec<Vec<u8>>,
}

/// A relay that binds each token's sender and forwards to the peer token.
fn stand_in_relay(stop: Arc<AtomicBool>, seen: Arc<Mutex<Seen>>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let addr = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut bound: BTreeMap<Vec<u8>, SocketAddr> = BTreeMap::new();
        let mut buffer = vec![0_u8; relay::MAX_DATAGRAM];
        while !stop.load(Ordering::SeqCst) {
            let Ok((len, from)) = socket.recv_from(&mut buffer) else { continue };
            let Some((token, packet)) = relay::unframe(&buffer[..len]) else { continue };
            bound.insert(token.to_vec(), from);
            let peer: &[u8] = if token == b"alloc-a" { b"alloc-b" } else { b"alloc-a" };
            if let Some(target) = bound.get(peer) {
                seen.lock().unwrap().packets.push(packet.to_vec());
                let _ = socket.send_to(packet, target);
            }
        }
    });
    addr
}

/// Paced synthetic capture: one frame per 20 ms, then nothing.
struct Synthetic {
    hz: f32,
    index: usize,
    frames: usize,
    next: Instant,
}

impl Capture for Synthetic {
    fn next_frame(&mut self, timeout: Duration) -> Option<Frame> {
        if self.index >= self.frames {
            std::thread::sleep(timeout);
            return None;
        }
        let now = Instant::now();
        if self.next > now {
            std::thread::sleep(self.next - now);
        }
        self.next += Duration::from_millis(20);
        let frame = synthetic(self.index, self.hz);
        self.index += 1;
        Some(frame)
    }
}

/// Records what is played.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Frame>>>);

impl Playback for Recorder {
    fn play(&mut self, frame: &Frame) {
        self.0.lock().unwrap().push(*frame);
    }
}

/// Tone and pause blocks heard in order: the loud frames form runs of
/// about `BLOCK`, separated by quiet runs of about `BLOCK`.
fn assert_blocks(heard: &[Frame], expected_tone_blocks: usize, what: &str) {
    let loud: Vec<bool> = heard.iter().map(|f| rms(f) > 2_000.0).collect();
    let mut runs: Vec<(bool, usize)> = Vec::new();
    for l in loud {
        match runs.last_mut() {
            Some((state, n)) if *state == l => *n += 1,
            _ => runs.push((l, 1)),
        }
    }
    let tone_runs: Vec<usize> = runs.iter().filter(|(l, _)| *l).map(|(_, n)| *n).collect();
    assert_eq!(tone_runs.len(), expected_tone_blocks, "{what}: runs {runs:?}");
    for n in &tone_runs {
        assert!((BLOCK - 3..=BLOCK + 3).contains(n), "{what}: tone run of {n}: {runs:?}");
    }
}

#[test]
fn two_engines_talk_through_a_relay() {
    const FRAMES: usize = 80;
    let stop = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(Mutex::new(Seen::default()));
    let relay_addr = stand_in_relay(stop.clone(), seen.clone());
    let (a, b) = sessions(&relay_addr.to_string(), b"alloc-a", b"alloc-b");
    let (heard_by_a, heard_by_b) = (Recorder::default(), Recorder::default());
    let start = Instant::now() + Duration::from_millis(200);
    let capture = |hz| Box::new(Synthetic { hz, index: 0, frames: FRAMES, next: start });
    let engine_b = Engine::start(b, capture(660.0), Box::new(heard_by_b.clone())).unwrap();
    let engine_a = Engine::start(a, capture(440.0), Box::new(heard_by_a.clone())).unwrap();
    assert_eq!(engine_a.quality(), Quality::Connecting);

    let deadline = Instant::now() + Duration::from_secs(30);
    while engine_b.stats().played < (FRAMES - 4) as u64
        || engine_a.stats().played < (FRAMES - 4) as u64
    {
        assert!(Instant::now() < deadline, "a {:?}\nb {:?}", engine_a.stats(), engine_b.stats());
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_ne!(engine_b.quality(), Quality::Connecting);
    let (stats_a, stats_b) = (engine_a.stats(), engine_b.stats());
    engine_a.set_muted(true);
    assert!(engine_a.is_muted());
    engine_a.stop();
    engine_b.stop();
    stop.store(true, Ordering::SeqCst);

    for (stats, what) in [(stats_a, "a"), (stats_b, "b")] {
        assert_eq!(stats.rejected, 0, "{what}: {stats:?}");
        assert_eq!(stats.foreign, 0, "{what}: {stats:?}");
        assert!(stats.jitter.received >= (FRAMES - 4) as u64, "{what}: {stats:?}");
        // A loaded machine may play a frame late now and then.
        assert!(
            stats.jitter.late + stats.jitter.duplicates <= (FRAMES / 10) as u64,
            "{what}: {stats:?}"
        );
    }
    // Continuity and order, after the lossy codec: four tone blocks of
    // about ten frames each, in turn with the pauses.
    let expected = FRAMES / BLOCK / 2;
    assert_blocks(&heard_by_b.0.lock().unwrap(), expected, "b hears a");
    assert_blocks(&heard_by_a.0.lock().unwrap(), expected, "a hears b");

    // The relay saw RTP headers and SFrame ciphertext only.
    let seen = seen.lock().unwrap();
    assert!(seen.packets.len() >= 2 * (FRAMES - 4));
    for packet in seen.packets.iter().filter(|p| !p.is_empty()) {
        let header = rtp::RtpHeader::decode(packet).expect("rtp");
        assert_eq!(header.payload_type, rtp::OPUS_PAYLOAD_TYPE);
        let (sframe, _) = Header::decode(&packet[rtp::HEADER_LEN..]).unwrap();
        assert!(sframe.kid == 0 || sframe.kid == 1);
    }
}

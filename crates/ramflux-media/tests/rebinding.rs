// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

// Moved tests keep their original numeric casts and assertions.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::format_collect,
    clippy::indexing_slicing,
    clippy::similar_names,
    clippy::unwrap_used
)]

//! Relay rebinding (CALL-01 r2) and the once-only `SFrame` keys.
//!
//! - The answer to a rebinding challenge matches the product's published
//!   known-answer vectors and the product's own helper
//!   (`ramflux_crypto::voice_rebind_response`, the code the relay checks
//!   answers with) on many inputs.
//! - A session's sending key starts once, at counter zero: a second sender
//!   on it is refused.
//! - Two engines talk through a stand-in of the product relay that pins
//!   each side's source address, and through a NAT in front of one engine
//!   whose public port changes mid-call: the relay challenges the new
//!   address, the engine answers from it, the relay verifies the answer
//!   with `ramflux_crypto::verify_voice_rebind_tag` and moves the pin, and
//!   audio goes on both ways with the `SFrame` counters running on (no key
//!   is set up again). A token thief at another address gets a challenge
//!   it cannot answer, and the pin stays.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ramflux_media::codec::{FRAME_SAMPLES, Frame};
use ramflux_media::pipeline::{Outbound, PipelineError, Rebinder};
use ramflux_media::rebind::{self, Rebind};
use ramflux_media::sframe::{AES_256_GCM_SHA512_128, Header};
use ramflux_media::{BaseKey, Capture, DirectionKey, Engine, MediaSession, Playback, relay, rtp};

fn counting<const N: usize>(from: u8) -> [u8; N] {
    std::array::from_fn(|i| from.wrapping_add(i as u8))
}

fn challenge_for(cookie: &[u8; 32], address: SocketAddr) -> Vec<u8> {
    let mut out = rebind::CHALLENGE_MAGIC.to_vec();
    out.extend_from_slice(cookie);
    match address {
        SocketAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out.extend_from_slice(&address.port().to_be_bytes());
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn answers_match_the_products_known_answer_vectors() {
    // docs/voice-calls.md (product) and docs/contract.md: key 0..31, lease
    // 0..15, side 1, cookie 32..63.
    let rebind = Rebind::new(counting(0), 1, &counting(0)).unwrap();
    let cookie = counting::<32>(32);
    for (address, tag, len) in [
        ("203.0.113.7:54321", "5a2ff8f9d9c805d3a158c94d51bb0bbe", rebind::CHALLENGE_V4_LEN),
        ("[2001:db8::1234]:54321", "07d911fa05814f8c69af12f9420b5aee", rebind::CHALLENGE_V6_LEN),
    ] {
        let challenge = challenge_for(&cookie, address.parse().unwrap());
        assert_eq!(challenge.len(), len);
        let read = rebind::challenge(&challenge).expect("a challenge");
        let response = rebind.response(&read);
        assert_eq!(&response[..4], b"RFVE");
        assert_eq!(&response[4..36], &cookie);
        assert_eq!(hex(&response[36..]), tag, "{address}");
    }
}

#[test]
fn answers_match_the_products_helper() {
    let mut seed = 0x9e37_79b9_u32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };
    for round in 0..64 {
        let key: [u8; 32] = std::array::from_fn(|_| next() as u8);
        let lease: [u8; 16] = std::array::from_fn(|_| next() as u8);
        let cookie: [u8; 32] = std::array::from_fn(|_| next() as u8);
        let side = (round % 2) as u8;
        let port = (next() % 65_535 + 1) as u16;
        let address: SocketAddr = if round % 3 == 0 {
            let ip: [u8; 16] = std::array::from_fn(|_| next() as u8);
            (std::net::Ipv6Addr::from(ip), port).into()
        } else {
            let ip: [u8; 4] = std::array::from_fn(|_| next() as u8);
            (std::net::Ipv4Addr::from(ip), port).into()
        };
        let challenge = challenge_for(&cookie, address);
        let lease_b64 = ramflux_protocol::encode_base64url(lease);
        let product =
            ramflux_crypto::voice_rebind_response(&key, &lease_b64, side, &challenge).unwrap();
        let ours = Rebind::new(lease, side, &key)
            .unwrap()
            .response(&rebind::challenge(&challenge).unwrap());
        assert_eq!(ours.as_slice(), product.as_slice(), "round {round} {address}");
        // A credential of the other side or another lease does not verify.
        let other_side = Rebind::new(lease, side ^ 1, &key).unwrap();
        let wrong = other_side.tag(&cookie, &challenge[36..]);
        assert!(
            ramflux_crypto::verify_voice_rebind_tag(
                &key, &lease_b64, side, &cookie, address, &wrong
            )
            .is_err()
        );
    }
}

fn session(endpoint: &str, token: &[u8], send: u64, keys: (u8, u8)) -> MediaSession {
    MediaSession::new(
        endpoint,
        token.to_vec(),
        AES_256_GCM_SHA512_128,
        DirectionKey::new(send, BaseKey::new(vec![keys.0; 32])),
        DirectionKey::new(send ^ 1, BaseKey::new(vec![keys.1; 32])),
    )
}

#[test]
fn a_sending_key_starts_once_at_counter_zero() {
    let mut session = session("127.0.0.1:9", b"token", 0, (0x11, 0x22));
    let mut first = Outbound::new(&mut session, 1, 0, 0).unwrap();
    // No second sender on the same key, so no counter (nonce) repeats.
    assert!(matches!(Outbound::new(&mut session, 2, 0, 0), Err(PipelineError::SendKeyUsed)));
    let datagram = first.packet(&[0; FRAME_SAMPLES]).unwrap();
    let (_, packet) = relay::unframe(&datagram).unwrap();
    let (header, _) = Header::decode(&packet[rtp::HEADER_LEN..]).unwrap();
    assert_eq!(header, Header { kid: 0, ctr: 0 });
    let datagram = first.packet(&[0; FRAME_SAMPLES]).unwrap();
    let (_, packet) = relay::unframe(&datagram).unwrap();
    assert_eq!(Header::decode(&packet[rtp::HEADER_LEN..]).unwrap().0.ctr, 1);
}

#[test]
fn without_a_credential_or_a_relay_nothing_is_answered() {
    let cookie = counting::<32>(1);
    let challenge = challenge_for(&cookie, "198.51.100.1:4000".parse().unwrap());
    let mut plain = session("127.0.0.1:9", b"token", 0, (1, 2));
    assert_eq!(Rebinder::new(&mut plain).answer(&challenge), None);
    let mut direct = session("127.0.0.1:9", b"", 0, (1, 2))
        .with_rebind(Rebind::new([0; 16], 0, &[9; 32]).unwrap());
    assert_eq!(Rebinder::new(&mut direct).answer(&challenge), None);
    let mut relayed = session("127.0.0.1:9", b"token", 0, (1, 2))
        .with_rebind(Rebind::new([0; 16], 0, &[9; 32]).unwrap());
    let answer = Rebinder::new(&mut relayed).answer(&challenge).unwrap();
    let (token, payload) = relay::unframe(&answer).unwrap();
    assert_eq!((token, payload.len()), (&b"token"[..], rebind::RESPONSE_LEN));
    assert!(Rebinder::new(&mut relayed).answer(&[0x80, 111, 0, 0]).is_none());
}

const LEASE: [u8; 16] = [0x4c; 16];
const TOKENS: [&[u8]; 2] = [b"caller-token", b"callee-token"];
const KEYS: [[u8; 32]; 2] = [[0xa0; 32], [0xb1; 32]];

/// One side of the stand-in relay's lease.
#[derive(Default)]
struct Side {
    source: Option<SocketAddr>,
    challenge: Option<(SocketAddr, [u8; 32], Instant)>,
}

/// What the stand-in relay saw.
#[derive(Default)]
struct Relayed {
    sides: [Side; 2],
    /// `SFrame` (kid, ctr) of every media packet admitted, in order.
    admitted: Vec<(u64, u64)>,
    challenges: Vec<SocketAddr>,
    rebound: Vec<SocketAddr>,
    refused: u64,
}

/// The product relay's admission, as `ramflux-node-core` `voice_rebinding`
/// does it: pin on the first token-framed datagram; from another source,
/// a pending challenge's answer (verified by the product's helper) moves
/// the pin, anything else gets a fresh challenge and is dropped.
fn stand_in_relay(stop: Arc<AtomicBool>, seen: Arc<Mutex<Relayed>>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
    let addr = socket.local_addr().unwrap();
    let lease = ramflux_protocol::encode_base64url(LEASE);
    std::thread::spawn(move || {
        let mut buffer = vec![0_u8; relay::MAX_DATAGRAM];
        while !stop.load(Ordering::SeqCst) {
            let Ok((len, from)) = socket.recv_from(&mut buffer) else { continue };
            let Some((token, payload)) = relay::unframe(&buffer[..len]) else { continue };
            let Some(index) = TOKENS.iter().position(|t| *t == token) else { continue };
            let mut seen = seen.lock().unwrap();
            let side = &mut seen.sides[index];
            let response = payload.starts_with(rebind::RESPONSE_MAGIC);
            if side.source.is_none() && !response {
                side.source = Some(from);
            }
            if side.source != Some(from) {
                match side.challenge {
                    Some((at, cookie, expires)) if Instant::now() < expires => {
                        let valid = from == at
                            && payload.len() == rebind::RESPONSE_LEN
                            && response
                            && payload[4..36] == cookie
                            && ramflux_crypto::verify_voice_rebind_tag(
                                &KEYS[index],
                                &lease,
                                index as u8,
                                &cookie,
                                from,
                                &payload[36..],
                            )
                            .is_ok();
                        if valid {
                            side.source = Some(from);
                            side.challenge = None;
                            seen.rebound.push(from);
                        } else if response {
                            seen.refused += 1;
                        }
                    }
                    _ => {
                        let cookie = counting::<32>(seen.challenges.len() as u8);
                        let packet = challenge_for(&cookie, from);
                        seen.sides[index].challenge =
                            Some((from, cookie, Instant::now() + Duration::from_secs(5)));
                        seen.challenges.push(from);
                        let _ = socket.send_to(&packet, from);
                    }
                }
                continue;
            }
            if payload.is_empty() || response {
                continue;
            }
            // Every media packet admitted from the pinned source, whether
            // or not the peer is pinned yet to receive it.
            if let Some(body) = payload.get(rtp::HEADER_LEN..)
                && let Ok((header, _)) = Header::decode(body)
            {
                seen.admitted.push((header.kid, header.ctr));
            }
            let Some(target) = seen.sides[index ^ 1].source else { continue };
            let _ = socket.send_to(payload, target);
        }
    });
    addr
}

/// A NAT in front of one engine: the engine talks to its inside address,
/// the relay sees its outside one; [`Nat::remap`] gives it a new outside
/// port (the old mapping is gone).
struct Nat {
    inside: SocketAddr,
    remaps: Arc<AtomicU64>,
}

impl Nat {
    fn start(relay: SocketAddr, stop: Arc<AtomicBool>) -> Self {
        let inside = UdpSocket::bind("127.0.0.1:0").unwrap();
        inside.set_read_timeout(Some(Duration::from_millis(2))).unwrap();
        let inside_addr = inside.local_addr().unwrap();
        let remaps = Arc::new(AtomicU64::new(0));
        let wanted = remaps.clone();
        std::thread::spawn(move || {
            let outside = || {
                let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                s.set_read_timeout(Some(Duration::from_millis(2))).unwrap();
                s
            };
            let (mut out, mut mapped) = (outside(), 0);
            let mut engine = None;
            let mut buffer = vec![0_u8; relay::MAX_DATAGRAM];
            while !stop.load(Ordering::SeqCst) {
                if wanted.load(Ordering::SeqCst) != mapped {
                    out = outside();
                    mapped = wanted.load(Ordering::SeqCst);
                }
                if let Ok((len, from)) = inside.recv_from(&mut buffer) {
                    engine = Some(from);
                    let _ = out.send_to(&buffer[..len], relay);
                }
                if let Ok((len, from)) = out.recv_from(&mut buffer)
                    && from == relay
                    && let Some(engine) = engine
                {
                    let _ = inside.send_to(&buffer[..len], engine);
                }
            }
        });
        Self { inside: inside_addr, remaps }
    }

    fn remap(&self) {
        self.remaps.fetch_add(1, Ordering::SeqCst);
    }
}

/// A tone, paced at one frame per 20 ms, for as long as the test runs.
struct Tone {
    hz: f32,
    index: usize,
    next: Instant,
}

impl Capture for Tone {
    fn next_frame(&mut self, _timeout: Duration) -> Option<Frame> {
        let now = Instant::now();
        if self.next > now {
            std::thread::sleep(self.next - now);
        }
        self.next += Duration::from_millis(20);
        let mut frame = [0_i16; FRAME_SAMPLES];
        for (i, sample) in frame.iter_mut().enumerate() {
            let t = (self.index * FRAME_SAMPLES + i) as f32 / 48_000.0;
            *sample = ((2.0 * std::f32::consts::PI * self.hz * t).sin() * 12_000.0) as i16;
        }
        self.index += 1;
        Some(frame)
    }
}

/// Counts frames played loud (the tone, decoded).
#[derive(Clone, Default)]
struct Loud(Arc<AtomicU64>);

impl Playback for Loud {
    fn play(&mut self, frame: &Frame) {
        let rms = (frame.iter().map(|s| f64::from(*s).powi(2)).sum::<f64>() / FRAME_SAMPLES as f64)
            .sqrt();
        if rms > 2_000.0 {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn wait(what: &str, deadline: Duration, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + deadline;
    while !done() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_nat_rebinding_mid_call_is_answered_and_audio_goes_on() {
    let stop = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(Mutex::new(Relayed::default()));
    let relay_addr = stand_in_relay(stop.clone(), seen.clone());
    let nat = Nat::start(relay_addr, stop.clone());
    let rebind = |side: usize| Rebind::new(LEASE, side as u8, &KEYS[side]).unwrap();
    let caller =
        session(&nat.inside.to_string(), TOKENS[0], 0, (0x11, 0x22)).with_rebind(rebind(0));
    let callee =
        session(&relay_addr.to_string(), TOKENS[1], 1, (0x22, 0x11)).with_rebind(rebind(1));
    let (heard_by_caller, heard_by_callee) = (Loud::default(), Loud::default());
    let start = Instant::now();
    let tone = |hz| Box::new(Tone { hz, index: 0, next: start });
    let callee = Engine::start(callee, tone(660.0), Box::new(heard_by_callee.clone())).unwrap();
    let caller = Engine::start(caller, tone(440.0), Box::new(heard_by_caller.clone())).unwrap();
    let loud = |l: &Loud| l.0.load(Ordering::SeqCst);

    wait("audio both ways", Duration::from_secs(20), || {
        loud(&heard_by_callee) >= 25 && loud(&heard_by_caller) >= 25
    });
    let pinned = seen.lock().unwrap().sides[0].source.unwrap();

    // The caller's NAT maps it to a new public port.
    nat.remap();
    wait("the relay to move the caller's pin", Duration::from_secs(10), || {
        !seen.lock().unwrap().rebound.is_empty()
    });
    let moved = seen.lock().unwrap().sides[0].source.unwrap();
    assert_ne!(moved, pinned);
    assert_eq!(seen.lock().unwrap().challenges, [moved], "one challenge, to the new address");
    assert!(caller.stats().rebinds_answered >= 1);
    let (before_callee, before_caller) = (loud(&heard_by_callee), loud(&heard_by_caller));
    wait("audio both ways after the rebinding", Duration::from_secs(20), || {
        loud(&heard_by_callee) >= before_callee + 25 && loud(&heard_by_caller) >= before_caller + 25
    });

    // A thief with the caller's token (and any cookie it sees) at another
    // address cannot move the pin.
    let thief = UdpSocket::bind("127.0.0.1:0").unwrap();
    thief.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    thief.send_to(&relay::frame(TOKENS[0], b"spoofed"), relay_addr).unwrap();
    let mut buffer = [0_u8; 128];
    let (len, _) = thief.recv_from(&mut buffer).expect("the relay challenges the thief");
    let challenge = rebind::challenge(&buffer[..len]).expect("a challenge");
    let guessed = Rebind::new(LEASE, 0, &[0x77; 32]).unwrap().response(&challenge);
    thief.send_to(&relay::frame(TOKENS[0], &guessed), relay_addr).unwrap();
    wait("the relay to refuse the thief", Duration::from_secs(5), || {
        seen.lock().unwrap().refused >= 1
    });
    assert_eq!(seen.lock().unwrap().sides[0].source, Some(moved));
    let after_thief = loud(&heard_by_callee);
    wait("the callee to still hear the caller", Duration::from_secs(10), || {
        loud(&heard_by_callee) >= after_thief + 10
    });

    let (caller_stats, callee_stats) = (caller.stats(), callee.stats());
    caller.stop();
    callee.stop();
    stop.store(true, Ordering::SeqCst);
    assert_eq!((caller_stats.rejected, callee_stats.rejected), (0, 0));

    // Each direction's counter started at zero and ran on through the
    // rebinding: no key was set up again, no counter repeated.
    let seen = seen.lock().unwrap();
    for kid in [0, 1] {
        let ctrs: Vec<u64> =
            seen.admitted.iter().filter(|(k, _)| *k == kid).map(|(_, c)| *c).collect();
        assert!(ctrs.len() > 60, "kid {kid}: {} packets", ctrs.len());
        assert_eq!(ctrs[0], 0, "kid {kid} starts at zero");
        assert!(ctrs.windows(2).all(|w| w[0] < w[1]), "kid {kid} counters rise: {ctrs:?}");
    }
}

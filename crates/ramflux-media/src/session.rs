// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! What the engine needs to carry one call: where to send (the relay
//! allocation), how to present itself there (this side's opaque allocation
//! token), how to move its binding when its address changes (this side's
//! rebind credential, see [`crate::rebind`]), and the `SFrame` keys of both
//! directions.
//!
//! The daemon hands this out once per call (`call.media.session`): keys
//! never leave the end-to-end encrypted channel the daemon received them
//! on and the engine's memory; they are wiped when dropped and never
//! printed.
//!
//! Each `SFrame` base key starts exactly once, at counter zero (RFC 9605
//! §4.4.3: a nonce is the salt XOR the counter, so a second sender on the
//! same key would repeat nonces). So a session is not `Clone`, the engine
//! consumes it, and its sending key can be taken once
//! ([`MediaSession::take_send_key`]): there is no way to start a second
//! sender on it. An engine that stops (or fails) is not restarted with the
//! same session; a fresh call brings fresh keys.

use zeroize::Zeroizing;

use crate::rebind::Rebind;
use crate::sframe::BaseKey;

/// One direction's `SFrame` key: its KID and base key (RFC 9605 §4.4.1).
#[derive(Clone, PartialEq, Eq)]
pub struct DirectionKey {
    kid: u64,
    base_key: BaseKey,
}

impl DirectionKey {
    /// A key for `kid`.
    #[must_use]
    pub fn new(kid: u64, base_key: BaseKey) -> Self {
        Self { kid, base_key }
    }

    /// The key id.
    #[must_use]
    pub fn kid(&self) -> u64 {
        self.kid
    }

    /// The base key.
    #[must_use]
    pub fn base_key(&self) -> &BaseKey {
        &self.base_key
    }
}

impl std::fmt::Debug for DirectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectionKey").field("kid", &self.kid).finish_non_exhaustive()
    }
}

/// The media session of one call. Not `Clone`: see the module.
pub struct MediaSession {
    endpoint: String,
    token: Zeroizing<Vec<u8>>,
    rebind: Option<Rebind>,
    suite: u16,
    send: Option<DirectionKey>,
    send_kid: u64,
    receive: DirectionKey,
    video_send: Option<DirectionKey>,
    video_receive: Option<DirectionKey>,
}

impl MediaSession {
    /// A session sending to `endpoint` (`host:port` of the relay
    /// allocation), presenting `token` (empty: talk to the endpoint
    /// directly, without relay framing), with `SFrame` `suite` and the keys
    /// of both directions.
    pub fn new(
        endpoint: impl Into<String>,
        token: Vec<u8>,
        suite: u16,
        send: DirectionKey,
        receive: DirectionKey,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            token: Zeroizing::new(token),
            rebind: None,
            suite,
            send_kid: send.kid,
            send: Some(send),
            receive,
            video_send: None,
            video_receive: None,
        }
    }

    /// The same session with the video keys of both directions (V2.1, KIDs
    /// 2 and 3 by the card). Video shares the audio suite and socket, never
    /// the audio keys or counters.
    #[must_use]
    pub fn with_video(mut self, send: DirectionKey, receive: DirectionKey) -> Self {
        self.video_send = Some(send);
        self.video_receive = Some(receive);
        self
    }

    /// Takes this side's video sending key, once (no video sender exists
    /// before V2.2). `None` without video keys or once taken.
    pub fn take_video_send_key(&mut self) -> Option<DirectionKey> {
        self.video_send.take()
    }

    /// The peer's video sending key, when the session negotiated video.
    #[must_use]
    pub fn video_receive_key(&self) -> Option<&DirectionKey> {
        self.video_receive.as_ref()
    }

    /// The same session, able to answer the relay's rebinding challenges
    /// with `rebind` (this side's credential).
    #[must_use]
    pub fn with_rebind(mut self, rebind: Rebind) -> Self {
        self.rebind = Some(rebind);
        self
    }

    /// Where media is sent.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The opaque allocation token presented to the relay.
    #[must_use]
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// The `SFrame` cipher suite id.
    #[must_use]
    pub fn suite(&self) -> u16 {
        self.suite
    }

    /// This side's rebinding credential, when the relay may challenge it.
    #[must_use]
    pub fn rebind(&self) -> Option<&Rebind> {
        self.rebind.as_ref()
    }

    /// Takes the rebinding credential, for the one socket that answers
    /// the relay's challenges.
    pub fn take_rebind(&mut self) -> Option<Rebind> {
        self.rebind.take()
    }

    /// The key id this side sends with.
    #[must_use]
    pub fn send_kid(&self) -> u64 {
        self.send_kid
    }

    /// Takes this side's sending key, for the one sender that ever uses it
    /// (starting at counter zero). `None` once taken.
    pub fn take_send_key(&mut self) -> Option<DirectionKey> {
        self.send.take()
    }

    /// The peer's sending key (this side decrypts with it).
    #[must_use]
    pub fn receive_key(&self) -> &DirectionKey {
        &self.receive
    }
}

impl std::fmt::Debug for MediaSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaSession")
            .field("endpoint", &self.endpoint)
            .field("suite", &self.suite)
            .field("send_kid", &self.send_kid)
            .field("rebind", &self.rebind)
            .field("receive_kid", &self.receive.kid)
            .finish_non_exhaustive()
    }
}

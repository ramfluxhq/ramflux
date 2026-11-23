# ramflux-media

Platform-independent engine for one one-to-one voice call. A host supplies
PCM and receives PCM. This crate does not open a microphone or a speaker.

`Capture::next_frame` yields one 20 ms mono frame (`[i16; 960]` at 48 kHz),
or nothing if that wait expires. `Playback::play` takes one such frame.
`Engine::start` consumes a `MediaSession` (relay endpoint, allocation token,
rebind credential, SFrame suite and the two directional base keys) and runs
the send, receive and playout threads.

The path is PCM, Opus, a 12-byte RTP header, SFrame (the RTP header is
authenticated metadata), then the relay's length-prefixed token framing.
The receive replay window is `ramflux_crypto::SFRAME_REPLAY_WINDOW`.

Platform audio I/O stays in each client. A client implements `Capture` and
`Playback` and keeps the device streams alive for the life of the engine.

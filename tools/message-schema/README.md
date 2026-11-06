# Message schema generator

The authoritative proto3 source is
`crates/ramflux-protocol/src/message/schema/message.proto`, extracted from the
approved message schema design. It is dormant until the separately owned profile
activation. Generated types grant no native authority and are not wire validators.

Run `cargo run --locked --offline -p ramflux-message-schema` to regenerate, or
append `-- --check` to check freshness. Provision the locked Cargo dependencies
before working offline. Ordinary product builds read checked-in artifacts and
never invoke this tool, protoc, a build script or a network client.

The pinned protox compiler emits one descriptor consumed by both prost-build and
pbjson-build. The tool partitions their syntax trees by the real message/type
responsibility, under common, content, controls, state and API modules; it does
not maintain a second Rust model. A deterministic visitor transformation tracks
field discriminants independently of values, rejecting repeated fields and
aliases even after null while preserving arbitrary protobuf map keys. Enum
fields use a shared adapter that keeps known names and unknown i32 numbers. Every output has deterministic SPDX headers.
Rustfmt comes from the repository's pinned toolchain and explicitly uses
its `rustfmt.toml`, including for staged files outside the repository. All schema imports are
local; no host protoc is used. The descriptor is also available as
`ramflux_protocol::message::FILE_DESCRIPTOR_SET`.

Rust consumers use `ramflux_protocol::message` or `ramflux_sdk::message`.
`MessageRequest` and `MessageUpdate` are also re-exported from the SDK root.
Future local JSON command adapters use `message::from_protojson` for strict duplicate/alias
handling. Peer binary admission and native proof validation belong to subsequent
schema parts (starting with P03 registry/validation) and must precede execution
of these generated values. No producer, receiver or local-bus command is wired
to these types by this foundation.

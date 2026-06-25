// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use crate::domain;

pub const FIXTURE_OBJECTS: [FixtureObject; 25] = [
    FixtureObject { dir: "envelope", domain: domain::ENVELOPE, signed: true },
    FixtureObject { dir: "signed_request", domain: domain::SIGNED_REQUEST, signed: true },
    FixtureObject { dir: "device_proof", domain: domain::DEVICE_PROOF, signed: true },
    FixtureObject { dir: "branch_proof", domain: domain::BRANCH_PROOF, signed: true },
    FixtureObject {
        dir: "home_node_migration_proof",
        domain: domain::HOME_NODE_MIGRATION_PROOF,
        signed: true,
    },
    FixtureObject {
        dir: "identity_deletion_proof",
        domain: domain::IDENTITY_DELETION_PROOF,
        signed: true,
    },
    FixtureObject { dir: "ack", domain: domain::ACK, signed: true },
    FixtureObject { dir: "nack", domain: domain::NACK, signed: true },
    FixtureObject { dir: "cursor", domain: domain::CURSOR, signed: true },
    FixtureObject { dir: "event_id", domain: domain::EVENT, signed: false },
    FixtureObject { dir: "identity_event", domain: domain::IDENTITY_EVENT, signed: true },
    FixtureObject { dir: "friend_event", domain: domain::FRIEND_EVENT, signed: true },
    FixtureObject { dir: "group_event", domain: domain::GROUP_EVENT, signed: true },
    FixtureObject { dir: "conversation_event", domain: domain::CONVERSATION_EVENT, signed: true },
    FixtureObject { dir: "message_event", domain: domain::MESSAGE_EVENT, signed: true },
    FixtureObject { dir: "object_manifest", domain: domain::OBJECT_MANIFEST, signed: true },
    FixtureObject {
        dir: "object_chunk_request",
        domain: domain::OBJECT_CHUNK_REQUEST,
        signed: true,
    },
    FixtureObject { dir: "a2i_control", domain: domain::A2I_CONTROL, signed: true },
    FixtureObject { dir: "a2ui_surface", domain: domain::A2UI_SURFACE, signed: true },
    FixtureObject { dir: "mcp_grant", domain: domain::MCP_GRANT, signed: true },
    FixtureObject { dir: "bot_manifest", domain: domain::BOT_MANIFEST, signed: true },
    FixtureObject { dir: "bot_event", domain: domain::BOT_EVENT, signed: true },
    FixtureObject { dir: "bot_install_grant", domain: domain::BOT_INSTALL_GRANT, signed: true },
    FixtureObject { dir: "notification_wake", domain: domain::NOTIFICATION_WAKE, signed: true },
    FixtureObject {
        dir: "federation_handshake",
        domain: domain::FEDERATION_HANDSHAKE,
        signed: true,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixtureObject {
    pub dir: &'static str,
    pub domain: &'static str,
    pub signed: bool,
}

#[must_use]
pub fn fixture_json_path(object: FixtureObject) -> String {
    format!("fixtures/protocol/v1/{}/fixture.json", object.dir)
}

#[must_use]
pub fn fixture_canonical_path(object: FixtureObject) -> String {
    format!("fixtures/protocol/v1/{}/fixture.canonical", object.dir)
}

#[must_use]
pub fn fixture_hash_path(object: FixtureObject) -> String {
    format!("fixtures/protocol/v1/{}/fixture.hash", object.dir)
}

#[must_use]
pub fn fixture_sig_path(object: FixtureObject) -> String {
    format!("fixtures/protocol/v1/{}/fixture.sig", object.dir)
}

#[must_use]
pub fn fixture_invalid_signature_path(object: FixtureObject) -> String {
    format!("fixtures/protocol/v1/{}/negative.invalid_signature.json", object.dir)
}

#[must_use]
pub fn fixture_replay_path(object: FixtureObject) -> String {
    format!("fixtures/protocol/v1/{}/negative.replay.json", object.dir)
}

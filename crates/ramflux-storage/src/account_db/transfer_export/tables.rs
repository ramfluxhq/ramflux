// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The compiled export list. A table that is not listed here is never read for a transfer.
//! Every other account table is named in `classification::EXCLUDED_TABLES` with a reason,
//! and every live column of a listed table that is not declared here is named in
//! `classification::EXCLUDED_COLUMNS`. `scripts/check-transfer-export.py` keeps all three
//! complete against the storage schema.
use super::bodies::BodyCodec;
use super::contract::{Cell, Class, Column, RowFilter, Table};

const fn plain(name: &'static str, class: Class) -> Column {
    Column { name, cell: Cell::Plain(class), nullable: false }
}
const fn optional(name: &'static str, class: Class) -> Column {
    Column { name, cell: Cell::Plain(class), nullable: true }
}
const fn content(name: &'static str, class: Class) -> Column {
    Column { name, cell: Cell::UserContent(class), nullable: false }
}
const fn body(name: &'static str, codec: BodyCodec) -> Column {
    Column { name, cell: Cell::Body(codec), nullable: false }
}
const fn table(
    name: &'static str,
    key: &'static [&'static str],
    columns: &'static [Column],
) -> Table {
    Table { name, key, columns, filter: RowFilter::All, transformed: false }
}

use Class::{Integer, Text};

/// The account root the file belongs to (M4). Read only for the root check and never merged.
const ACCOUNT_IDENTITY: Table = table(
    "runtime_account_identity",
    &["singleton"],
    &[plain("singleton", Integer), plain("principal_commitment", Text)],
);
const FRIEND_LINKS: Table = table(
    "friend_link_projection",
    &["link_id"],
    &[
        plain("link_id", Text),
        plain("requester_id", Text),
        plain("target_id", Text),
        plain("state", Text),
        optional("remove_scope", Text),
        plain("blocked", Integer),
        optional("capability_revoked_at", Integer),
        plain("updated_at", Integer),
    ],
);
const DIRECT_MESSAGES: Table = table(
    "direct_message_projection",
    &["message_id"],
    &[
        plain("conversation_id", Text),
        plain("message_id", Text),
        plain("sender_id", Text),
        body("metadata_json", BodyCodec::MessageMetadata),
        plain("deleted", Integer),
        plain("is_own", Integer),
        plain("scrub_version", Integer),
        plain("created_at", Integer),
    ],
);
const MESSAGE_CONTENT: Table = table(
    "runtime_message_content",
    &["message_id"],
    &[plain("message_id", Text), plain("conversation_id", Text), content("body", Class::Blob)],
);
const MESSAGE_SEQUENCE: Table = table(
    "runtime_message_sequence",
    &["message_id"],
    &[plain("message_id", Text), plain("seq", Integer)],
);
const CONVERSATION_LIST: Table = table(
    "conversation_list_state",
    &["conversation_id"],
    &[
        plain("conversation_id", Text),
        plain("archived", Integer),
        optional("pin_order", Integer),
        optional("mute_until", Integer),
        optional("hidden_at", Integer),
        optional("cleared_at", Integer),
        plain("updated_at", Integer),
    ],
);
const READ_STATE: Table = table(
    "conversation_read_state",
    &["conversation_id", "reader_id"],
    &[
        plain("conversation_id", Text),
        plain("reader_id", Text),
        plain("read_through_message_id", Text),
        plain("read_at", Integer),
    ],
);
const DELIVERY_STATE: Table = table(
    "conversation_delivery_state",
    &["conversation_id", "receiver_device_id"],
    &[
        plain("conversation_id", Text),
        plain("receiver_device_id", Text),
        plain("delivered_through_message_id", Text),
        plain("delivered_at", Integer),
        plain("ttl_seconds", Integer),
    ],
);
const UNREAD_MARKER: Table = table(
    "conversation_unread_marker",
    &["conversation_id", "marker_owner"],
    &[
        plain("conversation_id", Text),
        plain("marker_owner", Text),
        plain("message_id", Text),
        plain("marker_epoch", Integer),
        plain("active", Integer),
        plain("updated_at", Integer),
    ],
);
const DISAPPEARING_POLICY: Table = table(
    "conversation_disappearing_policy",
    &["conversation_id"],
    &[
        plain("conversation_id", Text),
        plain("timer_seconds", Integer),
        plain("countdown_mode", Text),
        plain("scope", Text),
        plain("updated_at", Integer),
    ],
);
const MESSAGE_TOMBSTONES: Table = table(
    "message_tombstone_projection",
    &["tombstone_id"],
    &[
        plain("tombstone_id", Text),
        plain("conversation_id", Text),
        plain("message_id", Text),
        plain("delete_scope", Text),
        plain("created_at", Integer),
    ],
);
const GROUPS: Table = table(
    "group_projection",
    &["group_id"],
    &[
        plain("group_id", Text),
        plain("group_epoch", Integer),
        optional("role", Text),
        optional("notification_state", Text),
        plain("max_members", Integer),
        plain("new_member_history", Text),
        optional("deleted_at", Integer),
        plain("created_at", Integer),
        plain("updated_at", Integer),
    ],
);
const GROUP_MEMBERS: Table = table(
    "group_member_projection",
    &["group_id", "member_principal_id"],
    &[
        plain("group_id", Text),
        plain("member_principal_id", Text),
        optional("member_id", Text),
        plain("role", Text),
        plain("joined_epoch", Integer),
        optional("removed_epoch", Integer),
        plain("active", Integer),
        plain("updated_at", Integer),
        optional("principal_commitment", Text),
    ],
);
const GROUP_TOMBSTONES: Table = table(
    "group_message_tombstone_projection",
    &["group_id", "message_id"],
    &[
        plain("group_id", Text),
        plain("message_id", Text),
        plain("tombstone_id", Text),
        plain("actor_device_id", Text),
        plain("delete_scope", Text),
        plain("deleted_epoch", Integer),
        plain("reason", Text),
        plain("deleted_at", Integer),
    ],
);
const ACTOR_STATE: Table = Table {
    name: "runtime_actor_state",
    key: &["state_kind"],
    columns: &[plain("state_kind", Text), body("state_json", BodyCodec::ActorNamespace)],
    filter: RowFilter::ActorNamespaces,
    transformed: false,
};

/// Creation order of the canonical export file.
pub(crate) const EXPORT_TABLES: &[Table] = &[
    ACCOUNT_IDENTITY,
    FRIEND_LINKS,
    DIRECT_MESSAGES,
    MESSAGE_CONTENT,
    MESSAGE_SEQUENCE,
    CONVERSATION_LIST,
    READ_STATE,
    DELIVERY_STATE,
    UNREAD_MARKER,
    DISAPPEARING_POLICY,
    MESSAGE_TOMBSTONES,
    GROUPS,
    GROUP_MEMBERS,
    GROUP_TOMBSTONES,
    ACTOR_STATE,
];

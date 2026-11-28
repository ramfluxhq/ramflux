// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Wire of the group host's direct sessions (MLS-SPEC r1.2 2.1, 5): the gateway call to the
//! router, the session/op split and the bounds the gateway applies before it calls.
//!
//! A group session is anonymous. Nothing here names an account, a device, a session id or a
//! source address; the gateway keeps the per-source counters in its own memory and never puts
//! them into a call.
//!
//! Op bodies are raw bytes (`LgWriter` encoding) carried as base64url in `body`; replies carry
//! the matching encoding. Table (`||` = concatenation, `var` = u32 length prefix):
//!
//! | op | session | request body | reply body |
//! |---|---|---|---|
//! | `open` (gateway only, from `GroupOpen`) | member | `nonce[32] || token[68]` | empty |
//! | `status` | member | empty | `epoch u64, log_seq u64, te u32, floor_seq u64, head[32]` |
//! | `read` | member | `from_seq u64, limit u32` | `ReadReply` |
//! | `blob.get` | member | `blob_ref[32], idx u32` | chunk bytes |
//! | `submit` | member | `Envelope` (token auth) | `log_seq u64, appended_at u64, head[32], sig[64]` |
//! | `blob.put` | member | `blob_ref[32], idx u32, total u32, total_bytes u64, var auth, var chunk` | `received u32, complete u8` |
//! | `attach.put` | member | `blob_ref[32], idx u32, total u32, total_bytes u64, var del_hash (idx 0: 32 bytes, else empty), var auth (idx 0), var chunk` | `received u32, complete u8` |
//! | `attach.get` | member | `blob_ref[32], idx u32` | chunk bytes |
//! | `attach.delete` | member | `blob_ref[32], del_secret[32]` | empty |
//! | `route.register` | member | `rt[16], var sealed, mention_key[32], mode u8, del_hash[32]` | empty |
//! | `join` | both | `JoinRequest` (kind decides the session) | queue `u8` |
//! | `route.delete` | ident | `rt[16], var del_secret` | empty |
//! | `create.prepare` | ident (zero group) | empty | `prep_id[16], host_head_pk[32], token_root_pk[32]` |
//! | `create` | ident (zero group) | `prep_id[16], var genesis, owner_sig[64]` | `group_id[32]` |
//! | `tokens` | ident | `SignedReq` | `TokenReply` |
//! | `welcome.get` | ident | `SignedReq` (empty inner body) | `commit_seq u64, blob_ref[32], total u32, bytes u64` |
//! | `submit`, `leave`, `void` | ident | `Envelope` (admin or P signature) | as member `submit` |
//! | `admin` | ident | `SignedReq` | empty |
//! | `join.pending` | ident | `SignedReq` | `count u32` then per row `p[32], queue u8, kind u8, join_pk_id[32], var key_package, var sealed` |
//! | `invite.put` | ident | `SignedReq` (body = invite spec) | empty |
//! | `invite.revoke` | ident | `SignedReq` (body = invite id) | empty |

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Gateway to router: one operation of a group session.
pub const GROUP_HOST_ROUTER_PATH: &str = "/mvp1/group-host";
/// Largest decoded op body (spec 2.7: frame body at most 768 KiB).
pub const GROUP_BODY_MAX_BYTES: usize = 768 * 1024;
/// Longest base64url text of a body (768 KiB in 4/3 form, exactly the 1 MiB frame budget).
pub const GROUP_BODY_B64_MAX: usize = GROUP_BODY_MAX_BYTES / 3 * 4;
/// Pending upload bytes one session may reserve (spec 2.2, 2.7).
pub const SESSION_UPLOAD_CAP_BYTES: u64 = 32 * 1024 * 1024;
/// Uploads one session may have pending at once.
pub const SESSION_UPLOADS_MAX: usize = 64;
/// The scope of `create.prepare` and `create`: the group does not exist yet.
pub const CREATE_SCOPE: [u8; 32] = [0; 32];

const MEMBER_OPS: &[&str] = &[
    "status",
    "read",
    "subscribe",
    "blob.get",
    "submit",
    "blob.put",
    "attach.put",
    "attach.get",
    "attach.delete",
    "route.register",
    "join",
];
const IDENT_OPS: &[&str] = &[
    "route.delete",
    "create.prepare",
    "create",
    "tokens",
    "welcome.get",
    "submit",
    "leave",
    "void",
    "admin",
    "join",
    "join.pending",
    "invite.put",
    "invite.revoke",
];

/// The two kinds of group session (spec 2.1).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupDirectKind {
    /// Opened by an `open` token; reads, posts and uploads. Never carries a pseudonym signature.
    Member,
    /// One signed or invite-authorised op, or one route delete. Never spends a token.
    Ident,
}

/// Whether a client `Group` frame may carry `op` on a session of `kind`.
#[must_use]
pub fn frame_op_allowed(kind: GroupDirectKind, op: &str) -> bool {
    match kind {
        GroupDirectKind::Member => MEMBER_OPS.contains(&op),
        GroupDirectKind::Ident => IDENT_OPS.contains(&op),
    }
}

/// Whether the router runs `op` for `kind`: the frame ops except the gateway-local `subscribe`,
/// plus the gateway's `open`.
#[must_use]
pub fn router_op_allowed(kind: GroupDirectKind, op: &str) -> bool {
    match kind {
        GroupDirectKind::Member => {
            op == "open" || (op != "subscribe" && frame_op_allowed(kind, op))
        }
        GroupDirectKind::Ident => frame_op_allowed(kind, op),
    }
}

/// Gateway to router: one op. Holds no source key, session id or account.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupHostCall {
    /// Session kind the gateway holds.
    pub session: GroupDirectKind,
    /// The session's group, base64url of 32 bytes ([`CREATE_SCOPE`] for `create*`).
    pub group_id: String,
    /// Op name.
    pub op: String,
    /// Op body, base64url.
    #[serde(default)]
    pub body: String,
}

/// Router to gateway to client: the status token and what goes with it.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupHostReply {
    /// `ok` or a refusal code (`LgRefusal::code`).
    pub status: String,
    /// Head epoch (`stale`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    /// Earliest host time a commit is accepted again (`paced`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_at_ms: Option<u64>,
    /// First retained entry (`pruned`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor_seq: Option<u64>,
    /// Current join key, base64url of 32 bytes (`join_key_stale`; the code stays the same).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_pk: Option<String>,
    /// Reply body, base64url (empty when the op has none).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body: String,
}

impl GroupHostReply {
    /// A status with no data.
    #[must_use]
    pub fn status(status: &str) -> Self {
        Self { status: status.to_owned(), ..Self::default() }
    }

    /// `ok` with a body.
    #[must_use]
    pub fn ok(body: &[u8]) -> Self {
        Self {
            status: "ok".to_owned(),
            body: ramflux_protocol::encode_base64url(body),
            ..Self::default()
        }
    }
}

/// `N` bytes from base64url text, or `None` for any other length or alphabet.
#[must_use]
pub fn decode_b64<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() > N.div_ceil(3).saturating_mul(4) {
        return None;
    }
    let bytes = ramflux_protocol::decode_base64url(text).ok()?;
    bytes.try_into().ok()
}

/// An op body from base64url text: at most [`GROUP_BODY_B64_MAX`] characters and
/// [`GROUP_BODY_MAX_BYTES`] bytes (checked before the decode allocates).
#[must_use]
pub fn decode_body(text: &str) -> Option<Vec<u8>> {
    if text.len() > GROUP_BODY_B64_MAX {
        return None;
    }
    let bytes = ramflux_protocol::decode_base64url(text).ok()?;
    (bytes.len() <= GROUP_BODY_MAX_BYTES).then_some(bytes)
}

/// The fixed prefix of a `blob.put` body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPutHead {
    /// Content address of the whole blob.
    pub blob_ref: [u8; 32],
    /// Chunk position.
    pub idx: u32,
    /// Bytes the whole upload declares.
    pub total_bytes: u64,
}

/// Reads the prefix `blob_ref[32], idx u32, total u32, total_bytes u64` of a `blob.put` body.
#[must_use]
pub fn blob_put_head(body: &[u8]) -> Option<BlobPutHead> {
    let blob_ref: [u8; 32] = body.get(..32)?.try_into().ok()?;
    let idx = u32::from_be_bytes(body.get(32..36)?.try_into().ok()?);
    let total_bytes = u64::from_be_bytes(body.get(40..48)?.try_into().ok()?);
    Some(BlobPutHead { blob_ref, idx, total_bytes })
}

/// Which store an upload goes to; the same `blob_ref` may be pending in both.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum UploadClass {
    /// `blob.put` (group blobs: welcomes, media of the log).
    Blob,
    /// `attach.put` (attachment class).
    Attach,
}

/// The pending uploads of one session against the 32 MiB cap, `blob.put` and `attach.put`
/// together. Lives in the session task only.
#[derive(Debug, Default)]
pub struct UploadCap {
    pending: BTreeMap<(UploadClass, [u8; 32]), u64>,
    reserved: u64,
}

impl UploadCap {
    /// Reserves `total_bytes` for a new upload at chunk 0; `false` when it does not fit or the
    /// upload is already pending.
    pub fn begin(&mut self, class: UploadClass, blob_ref: [u8; 32], total_bytes: u64) -> bool {
        let next = self.reserved.saturating_add(total_bytes);
        if next > SESSION_UPLOAD_CAP_BYTES
            || self.pending.len() >= SESSION_UPLOADS_MAX
            || self.pending.contains_key(&(class, blob_ref))
        {
            return false;
        }
        self.pending.insert((class, blob_ref), total_bytes);
        self.reserved = next;
        true
    }

    /// Releases an upload that completed or was refused.
    pub fn finish(&mut self, class: UploadClass, blob_ref: &[u8; 32]) {
        if let Some(bytes) = self.pending.remove(&(class, *blob_ref)) {
            self.reserved = self.reserved.saturating_sub(bytes);
        }
    }

    /// Whether `blob_ref` is pending in this session in `class`.
    #[must_use]
    pub fn holds(&self, class: UploadClass, blob_ref: &[u8; 32]) -> bool {
        self.pending.contains_key(&(class, *blob_ref))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_split_keeps_tokens_and_signatures_apart() {
        for op in [
            "status",
            "read",
            "blob.get",
            "submit",
            "blob.put",
            "attach.put",
            "attach.get",
            "attach.delete",
            "route.register",
            "join",
        ] {
            assert!(frame_op_allowed(GroupDirectKind::Member, op), "member {op}");
        }
        for op in ["tokens", "welcome.get", "create", "route.delete", "invite.put", "join.pending"]
        {
            assert!(!frame_op_allowed(GroupDirectKind::Member, op), "member {op}");
            assert!(frame_op_allowed(GroupDirectKind::Ident, op), "ident {op}");
        }
        assert!(!frame_op_allowed(GroupDirectKind::Ident, "read"));
        assert!(!frame_op_allowed(GroupDirectKind::Ident, "blob.put"));
        assert!(!frame_op_allowed(GroupDirectKind::Ident, "attach.put"));
        assert!(!frame_op_allowed(GroupDirectKind::Ident, "attach.delete"));
        assert!(!frame_op_allowed(GroupDirectKind::Member, "open"));
        assert!(router_op_allowed(GroupDirectKind::Member, "open"));
        assert!(!router_op_allowed(GroupDirectKind::Ident, "open"));
        assert!(!router_op_allowed(GroupDirectKind::Member, "subscribe"));
    }

    #[test]
    fn bodies_are_bounded_before_decoding() {
        assert_eq!(decode_body(""), Some(Vec::new()));
        assert_eq!(decode_body("AQID"), Some(vec![1, 2, 3]));
        assert_eq!(decode_body(&"A".repeat(GROUP_BODY_B64_MAX + 1)), None);
        assert_eq!(decode_body("not base64 !"), None);
        let full = ramflux_protocol::encode_base64url(vec![7; GROUP_BODY_MAX_BYTES]);
        assert_eq!(decode_body(&full).map(|bytes| bytes.len()), Some(GROUP_BODY_MAX_BYTES));
        let over = ramflux_protocol::encode_base64url(vec![7; GROUP_BODY_MAX_BYTES + 1]);
        assert_eq!(decode_body(&over), None);
        let id = ramflux_protocol::encode_base64url([9_u8; 32]);
        assert_eq!(decode_b64::<32>(&id), Some([9; 32]));
        assert_eq!(decode_b64::<16>(&id), None);
        assert_eq!(decode_b64::<32>(&"A".repeat(100)), None);
    }

    #[test]
    fn blob_put_prefix_is_read_without_the_chunk() {
        let mut body = vec![5_u8; 32];
        body.extend(3_u32.to_be_bytes());
        body.extend(4_u32.to_be_bytes());
        body.extend(2_048_u64.to_be_bytes());
        let head = blob_put_head(&body).expect("test: prefix parses");
        assert_eq!((head.blob_ref, head.idx, head.total_bytes), ([5; 32], 3, 2_048));
        assert_eq!(blob_put_head(&body[..47]), None);
    }

    #[test]
    fn upload_cap_reserves_declared_bytes_and_releases_them() {
        let mut cap = UploadCap::default();
        let half = SESSION_UPLOAD_CAP_BYTES / 2;
        assert!(cap.begin(UploadClass::Blob, [1; 32], half));
        assert!(!cap.begin(UploadClass::Blob, [1; 32], 1), "same upload twice");
        assert!(cap.begin(UploadClass::Blob, [2; 32], half));
        assert!(!cap.begin(UploadClass::Blob, [3; 32], 1), "cap reached");
        cap.finish(UploadClass::Blob, &[1; 32]);
        assert!(cap.begin(UploadClass::Blob, [3; 32], half));
        assert!(cap.holds(UploadClass::Blob, &[3; 32]) && !cap.holds(UploadClass::Blob, &[1; 32]));
        let mut many = UploadCap::default();
        for index in 0..SESSION_UPLOADS_MAX {
            let mut blob_ref = [0_u8; 32];
            blob_ref[0] = u8::try_from(index).expect("test: index fits");
            assert!(many.begin(UploadClass::Blob, blob_ref, 1));
        }
        assert!(!many.begin(UploadClass::Blob, [200; 32], 1), "too many pending uploads");
    }

    #[test]
    fn attach_and_blob_uploads_share_one_cap_but_not_one_key() {
        let mut cap = UploadCap::default();
        let half = SESSION_UPLOAD_CAP_BYTES / 2;
        assert!(cap.begin(UploadClass::Blob, [4; 32], half));
        assert!(cap.begin(UploadClass::Attach, [4; 32], half), "same ref, other class");
        assert!(!cap.begin(UploadClass::Attach, [5; 32], 1), "declared bytes of both count");
        assert!(cap.holds(UploadClass::Attach, &[4; 32]));
        cap.finish(UploadClass::Attach, &[4; 32]);
        assert!(
            !cap.holds(UploadClass::Attach, &[4; 32]) && cap.holds(UploadClass::Blob, &[4; 32])
        );
        assert!(cap.begin(UploadClass::Attach, [5; 32], half));
    }
}

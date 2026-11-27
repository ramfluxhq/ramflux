// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Large-group (LARGE-GROUP-01 P1) cryptographic core: genesis and `group_id`, POPRF posting tokens,
//! the epoch key schedule, authenticated key slots, the host-signed head chain, content encryption
//! and the pure client rules of design v7 sections 2.3 to 2.7.

mod codec;
mod content;
mod error;
mod group_key;
mod head;
mod ids;
mod kat;
mod keys;
mod merkle;
mod poprf_host;
mod rng;
mod rules;
mod slots;
mod token;

pub use content::{
    EntryHeader, EntryKind, MAX_BUCKET, OpenedEntry, SIZE_BUCKETS, SealedEntry, TAG_SLOTS,
    bucket_for, entry_bind_hash, entry_chain_hash, header_hash, open_entry, seal_entry,
};
pub use error::LgError;
pub use group_key::LgGroupKey;
pub use head::{Seen, SeenVerdict, classify_seen, host_head_sign, host_head_verify, next_head};
pub use ids::{
    BATCH_SIZE, Genesis, JoinPolicy, MEMBER_CAP, TOKEN_INFO_LEN, group_id_of, token_info,
};
pub use kat::{KatReport, kat_poprf};
pub use keys::{
    EpochKey, MAX_JOINERS_PER_ENTRY, derive_k_content, derive_kc, ratchet_epoch_key, w_body_hash,
};
pub use merkle::{audit_path, leaf_hash, merkle_root, verify_audit_path};
pub use poprf_host::{IssuedBatch, LgTokenRootKey};
pub use rng::random_array;
pub use rules::{
    ProvisionalKey, ProvisionalState, ROLL_U_MAX_MS, RedeliveryDecision, RedeliveryLedger,
    RollKind, RollRecord, RollRefusal, RollWindow, SETTLE_REPLY_DELAY_MS, SETTLE_ROLL_DELAY_MS,
    SKEW_MS, appended_at_ok, late_reply, late_roll, settle_at_ms,
};
pub use slots::{
    SignedKeyBody, SlotOpened, generate_recv_keypair, open_slot, seal_slot, slot_info,
};
pub use token::{
    SPENT_KEY_LEN, TOKEN_LEN, Token, TokenBatchRequest, TokenSecret, begin_token_batch,
    finish_token_batch, spent_key, verify_token_binding,
};

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Group-host cryptographic core (MLS-SPEC r1.1 section 2; reused from LARGE-GROUP-01 P1): genesis
//! v2 and `group_id`, POPRF posting tokens in four buckets, the host-signed head chain, the
//! `rf-lg-env-v1` envelope, join kinds, the commit election order and the pure host and client
//! rules. MLS itself lives in `ramflux-mls`; this module holds only what the host may see.

mod codec;
mod error;
mod head;
mod ids;
mod kat;
mod poprf_host;
mod rng;
mod rules;
mod token;
mod wire;

pub use codec::{Dec as LgReader, Enc as LgWriter};
pub use error::LgError;
pub use head::{Seen, SeenVerdict, classify_seen, host_head_sign, host_head_verify, next_head};
pub use ids::{BATCH_SIZE, Genesis, LEAF_CAP, TIER_1000, TOKEN_INFO_LEN, group_id_of, token_info};
pub use kat::{KatReport, kat_poprf};
pub use poprf_host::{IssuedBatch, LgTokenRootKey};
pub use rng::random_array;
pub use rules::{
    ADMIN_COMMIT_GAP_MS, ATTACH_MAX_BYTES, ATTACH_PAD, ATTACH_PER_POST_MAX, ATTACH_THUMB_MAX,
    CARD_JSON_MAX, ELECT_WINDOW_MS, ELECT_WINDOW_SIZE, ElectCandidate, MAX_ADDS_PER_COMMIT,
    MEMBER_COMMIT_GAP_MS, POST_PAD_CLASSES, PRIVACY_DELAY_MIN_LEAVES, REVOKE_ROLL_GAP_MS,
    ROLL_U_MAX_MS, RollKind, RollRecord, RollRefusal, RollWindow, SETTLE_REPLY_DELAY_MS,
    SETTLE_ROLL_DELAY_MS, SKEW_MS, appended_at_ok, attach_size_ok, election_delay_ms,
    election_order, election_rank, late_reply, late_roll, post_padded_len, privacy_delay_applies,
    settle_at_ms,
};
pub use token::{
    BucketQuota, COMMIT_TOKEN_COST, SPENT_KEY_LEN, TOKEN_LEN, Token, TokenBatchRequest,
    TokenBucket, TokenSecret, begin_token_batch, begin_token_batch_sized, finish_token_batch,
    spent_key, verify_token_binding,
};
pub use wire::{
    ENV_DOMAIN, EnvAuth, EnvHeader, EnvKind, Envelope, JoinKind, JoinRequest, JoinSession, LogView,
    MAX_ENVELOPE_BYTES, MAX_INLINE_MLS, MAX_REMOVED, MlsContent, ReadReply, ReadRequest, Removal,
    RemoveGround, RollPayload, SignedReq, TAG_SLOTS, admin_chain_head, attach_put_body,
    blob_put_body, invite_proof_message, join_bind, join_proof_sign, join_proof_verify,
    key_ack_message, key_ack_sign, key_ack_verify, op_bind, parse_void_payload, sign_envelope,
    verify_envelope_sig, void_payload,
};

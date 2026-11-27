// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! MLS (RFC 9420) foundation for ramflux.
//!
//! The crate wraps `openmls` (`RustCrypto` provider only) behind one facade and one gate:
//!
//! * `provider`: [`CryptoHandle`] (the single process-wide crypto construction, probed first) and
//!   [`RfMlsProvider`] (crypto plus the overlay storage).
//! * `storage`: the 74-method storage surface over a caller-supplied [`MlsKv`], with an in-memory
//!   overlay that reaches the database only through [`Staged::commit`] (one transaction).
//! * `credential`: the two private-use credential types (`0xF0D1` device v2 with its pure V1
//!   device chain, `0xF0D2` pseudonym), the (credential, leaf signature key) pair verification
//!   and the directory-path [`DeviceAuthority`] (`credential::authority`).
//! * `group`: group configuration, the facade and the single gate that owns every merge.
//!
//! Suite: only `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001). The provider also accepts
//! 0x0002 and 0x0003, so the pin is enforced by the gate, not by the provider.
//!
//! Past epochs: groups keep the receive secrets of the last [`MAX_PAST_EPOCHS`] (3) epochs so that
//! delayed application messages still decrypt. The cost is that a compromise of the device exposes
//! the not-yet-used message keys of up to three epochs (RFC 9420 sections 15.3 and 16.6). Higher
//! layers may lower the number.
//!
//! Leaf lifetime (rule V, no clock in commit validity): received commits and Welcomes are
//! processed with the openmls leaf-node lifetime validation skipped; only the device that adds a
//! `KeyPackage` checks its 30 day lifetime, locally, when it fetches or uses it.

pub mod credential;
mod error;
pub mod group;
pub mod kat;
pub mod provider;
pub mod signer;
pub mod storage;

#[cfg(feature = "itest-mls-debug")]
pub mod debug;

pub use credential::authority::{DeviceAuthority, NoAuthority, VerifiedRecord};
pub use credential::{DeviceCertSigner, DeviceIdentity, GroupKind, MemberIdentity, VerifiedMember};
pub use error::MlsError;
pub use group::context::{CommitCtx, CommitMeta, WelcomeCtx};
pub use group::conversation::{ConversationRole, ExpectedPrincipals, RfConversation};
pub use group::policy::{CommitPolicy, DenyAllRoster, PermissiveCommitPolicy, RosterPolicy};
pub use group::{
    AddOutput, CommitOutput, CreateOutput, JoinOutput, KeyPackageOutput, MemberSummary, Mls,
    ReceivedMessage, SendOutput, StatusOutput, Tier,
};
pub use provider::{CryptoHandle, RfMlsProvider};
pub use storage::kv::{MlsKv, MlsKvError, RowStats, Staged, WriteBatch, WriteOp};

use openmls::prelude::Ciphersuite;

/// The only accepted ciphersuite, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (RFC 9420 17.1).
pub const MLS_SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// Wire code point of [`MLS_SUITE`].
pub const MLS_SUITE_CODE: u16 = 0x0001;
/// Credential type of a device credential (direct-message groups).
pub const CREDENTIAL_TYPE_DEVICE: u16 = 0xF0D1;
/// Credential type of a pseudonym credential (groups).
pub const CREDENTIAL_TYPE_PSEUDONYM: u16 = 0xF0D2;
/// Format version of the device credential `0xF0D1` (v2: it no longer embeds the device record).
pub const CREDENTIAL_VERSION: u8 = 2;
/// Largest accepted credential.
pub const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
/// Largest accepted `KeyPackage` message.
pub const MAX_KEY_PACKAGE_BYTES: usize = 64 * 1024;
/// Largest accepted Welcome, commit, proposal or application message.
pub const MAX_MLS_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
/// Largest value the storage codec decodes.
pub const MAX_STORED_VALUE_BYTES: usize = 64 * 1024 * 1024;
/// Lifetime of an own `KeyPackage` in seconds (30 days).
pub const KEY_PACKAGE_LIFETIME_SECS: u64 = 30 * 86_400;
/// Number of past epochs whose receive secrets are kept.
pub const MAX_PAST_EPOCHS: usize = 3;
/// Padding block size of private messages.
pub const PADDING_SIZE: usize = 32;
/// Leaf cap of the 1 000 member tier.
pub const LEAF_CAP_TIER_1000: usize = 3_000;
/// Leaf cap of the 5 000 member tier.
pub const LEAF_CAP_TIER_5000: usize = 15_000;
/// Absolute leaf cap applied to every received commit and Welcome.
pub const ABSOLUTE_LEAF_CAP: usize = LEAF_CAP_TIER_5000;
/// Largest number of distinct principals in a direct-message group.
pub const DM_MAX_PRINCIPALS: usize = 2;
/// Largest number of principals in a `self` group.
pub const SELF_MAX_PRINCIPALS: usize = 1;
/// Group context extension type carrying the conversation binding (`rf_conversation`).
pub const EXTENSION_TYPE_RF_CONVERSATION: u16 = 0xF0C1;
/// Length of a generated group id in bytes.
pub const GROUP_ID_BYTES: usize = 32;

/// Label prefix of every own (non-openmls) row in `mls_kv`.
pub const RF_LABEL_PREFIX: &str = "rf/";
/// Index of own `KeyPackages` with their expiry.
pub const RF_LABEL_OWN_KP: &str = "rf/own_kp";
/// Group kind per group id.
pub const RF_LABEL_GROUP_KIND: &str = "rf/group_kind";
/// Group tier per group id.
pub const RF_LABEL_GROUP_TIER: &str = "rf/group_tier";
/// Leaf signature secret keys, keyed by the public key.
pub const RF_LABEL_LEAF_SIG: &str = "rf/leaf_sig";

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared host/client wire layouts of the group host (MLS-SPEC r1.1 sections 2 and 5): the
//! `rf-lg-env-v1` envelope header, the P-signed request, the log view of a read, the join request
//! and the plaintext payloads of void and token-epoch roll entries. Deterministic, length-prefixed,
//! every variable field bounded.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ramflux_protocol::domain::{LG_AAD_V1, LG_JOIN_V1};

use super::LgError;
use super::codec::{Dec, Enc};
use super::rules::{MAX_ADDS_PER_COMMIT, RollKind};
use super::token::{TOKEN_LEN, Token, TokenBucket};

/// Canonical envelope header format name.
pub const ENV_DOMAIN: &[u8] = b"rf-lg-env-v1";
/// Mention tag slots per post header (spec 2.7).
pub const TAG_SLOTS: usize = 8;
/// Largest MLS payload carried inline; larger entries travel as blobs (spec 2.7).
pub const MAX_INLINE_MLS: usize = 512 * 1024;
/// Removals one commit header may list.
pub const MAX_REMOVED: usize = 100;
/// Largest encoded envelope (header plus inline payload).
pub const MAX_ENVELOPE_BYTES: usize = MAX_INLINE_MLS + 16 * 1024;

const REQ_DOMAIN: &[u8] = b"rf-lg-req-v1";
const SIG_DOMAIN: &[u8] = b"rf-lg-env-sig-v1";
const BIND_DOMAIN: &[u8] = b"rf-lg-entry-v1";
const CHAIN_DOMAIN: &[u8] = b"rf-lg-entry-chain-v1";
const MAX_BODY: usize = 16 * 1024;
const MAX_ENTRIES_PER_READ: usize = 64;
const MAX_ADMIN_CHAIN: usize = 64;
const MAX_KEY_PACKAGE: usize = 16 * 1024;
const MAX_JOIN_SEALED: usize = 16 * 1024;
const MAX_JOIN_AUTH: usize = 256;
const MAX_ROLL_REFS: usize = 64;

/// What an envelope is. The MLS content type is checked against it by the host (spec 2.3 check 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvKind {
    Post,
    Commit,
    Proposal,
    State,
    Tombstone,
    /// `leave{P, sig_P}` stored in the log prefix.
    Leave,
    /// Admin void of the head commit; payload [`void_payload`].
    Void,
    /// Host-written token epoch roll; payload [`RollPayload`].
    Roll,
}

/// MLS content type an envelope kind must carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsContent {
    Commit,
    Proposal,
    Application,
}

impl EnvKind {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Post => 1,
            Self::Commit => 2,
            Self::Proposal => 3,
            Self::State => 4,
            Self::Tombstone => 5,
            Self::Leave => 6,
            Self::Void => 7,
            Self::Roll => 8,
        }
    }

    /// # Errors
    /// Refuses an unknown code.
    pub fn from_code(code: u8) -> Result<Self, LgError> {
        match code {
            1 => Ok(Self::Post),
            2 => Ok(Self::Commit),
            3 => Ok(Self::Proposal),
            4 => Ok(Self::State),
            5 => Ok(Self::Tombstone),
            6 => Ok(Self::Leave),
            7 => Ok(Self::Void),
            8 => Ok(Self::Roll),
            _ => Err(LgError::Format("envelope kind")),
        }
    }

    /// The MLS content type of the payload; `None` for entries that carry no MLS message.
    #[must_use]
    pub const fn mls_content(self) -> Option<MlsContent> {
        match self {
            Self::Commit => Some(MlsContent::Commit),
            Self::Proposal => Some(MlsContent::Proposal),
            Self::Post | Self::State | Self::Tombstone => Some(MlsContent::Application),
            Self::Leave | Self::Void | Self::Roll => None,
        }
    }

    /// The token bucket this kind is paid from (`None`: not token-authorised).
    #[must_use]
    pub const fn token_bucket(self) -> Option<TokenBucket> {
        match self {
            Self::Post | Self::Tombstone => Some(TokenBucket::Post),
            Self::Commit | Self::Proposal | Self::State => Some(TokenBucket::Commit),
            Self::Leave | Self::Void | Self::Roll => None,
        }
    }
}

/// Ground of one removal in a commit header (spec 2.4 rights).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveGround {
    Admin,
    Leave,
    OwnSibling,
    Rejoin,
}

impl RemoveGround {
    const fn code(self) -> u8 {
        match self {
            Self::Admin => 1,
            Self::Leave => 2,
            Self::OwnSibling => 3,
            Self::Rejoin => 4,
        }
    }

    fn from_code(code: u8) -> Result<Self, LgError> {
        match code {
            1 => Ok(Self::Admin),
            2 => Ok(Self::Leave),
            3 => Ok(Self::OwnSibling),
            4 => Ok(Self::Rejoin),
            _ => Err(LgError::Format("removal ground")),
        }
    }
}

/// One removed leaf pseudonym and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Removal {
    pub p: [u8; 32],
    pub ground: RemoveGround,
}

/// Who authorises the entry: a posting token, an admin or member pseudonym signature, or the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvAuth {
    Token(Token),
    AdminSig([u8; 64]),
    PSig([u8; 64]),
    /// Written by the host itself (token epoch roll); covered by the head chain.
    Host,
}

/// The `rf-lg-env-v1` header: everything the host may read and the clients bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvHeader {
    pub group_id: [u8; 32],
    pub kind: EnvKind,
    /// MLS epoch the entry was made in.
    pub epoch: u64,
    pub post_id: [u8; 16],
    /// Token bucket; `Some` exactly when `auth` is a token.
    pub bucket: Option<TokenBucket>,
    pub tags: [[u8; 16]; TAG_SLOTS],
    pub del_hash: Option<[u8; 32]>,
    pub blob_ref: Option<[u8; 32]>,
    pub added_p: Vec<[u8; 32]>,
    pub removed: Vec<Removal>,
    pub join_pk_new: Option<[u8; 32]>,
    pub auth: EnvAuth,
}

fn put_opt32(enc: &mut Enc, value: Option<&[u8; 32]>) {
    match value {
        Some(bytes) => enc.u8(1).fixed(bytes),
        None => enc.u8(0),
    };
}

fn get_opt32(dec: &mut Dec<'_>) -> Result<Option<[u8; 32]>, LgError> {
    match dec.u8()? {
        0 => Ok(None),
        1 => Ok(Some(dec.fixed()?)),
        _ => Err(LgError::Format("optional flag")),
    }
}

fn put_count(enc: &mut Enc, len: usize) {
    enc.u32(u32::try_from(len).unwrap_or(u32::MAX));
}

fn get_count(dec: &mut Dec<'_>, max: usize, what: &'static str) -> Result<usize, LgError> {
    let count = usize::try_from(dec.u32()?).map_err(|_| LgError::Format(what))?;
    if count > max { Err(LgError::Format(what)) } else { Ok(count) }
}

impl EnvHeader {
    /// Structural rules: kind, bucket and authorisation agree; only commits list adds, removals
    /// and a new join key; a removal comes with the next join key.
    ///
    /// # Errors
    /// Returns the first violated rule.
    pub fn check(&self) -> Result<(), LgError> {
        match (&self.auth, self.bucket, self.kind.token_bucket()) {
            (EnvAuth::Token(_), Some(got), Some(want)) if got == want => {}
            (EnvAuth::Token(_), ..) => return Err(LgError::Format("token bucket mismatch")),
            (_, None, _) => {}
            _ => return Err(LgError::Format("bucket without token")),
        }
        let auth_ok = match self.kind {
            EnvKind::Post | EnvKind::Tombstone => matches!(self.auth, EnvAuth::Token(_)),
            EnvKind::Commit | EnvKind::Proposal | EnvKind::State => {
                !matches!(self.auth, EnvAuth::Host)
            }
            EnvKind::Leave => matches!(self.auth, EnvAuth::PSig(_)),
            EnvKind::Void => matches!(self.auth, EnvAuth::AdminSig(_)),
            EnvKind::Roll => matches!(self.auth, EnvAuth::Host),
        };
        if !auth_ok {
            return Err(LgError::Format("authorisation for kind"));
        }
        let commit = self.kind == EnvKind::Commit;
        if !commit
            && (!self.added_p.is_empty() || !self.removed.is_empty() || self.join_pk_new.is_some())
        {
            return Err(LgError::Format("commit-only field"));
        }
        if self.added_p.len() > MAX_ADDS_PER_COMMIT || self.removed.len() > MAX_REMOVED {
            return Err(LgError::Format("commit list too long"));
        }
        if !self.removed.is_empty() && self.join_pk_new.is_none() {
            return Err(LgError::Format("removal without join key"));
        }
        if self.del_hash.is_some() && self.kind != EnvKind::Post {
            return Err(LgError::Format("delete hash on non-post"));
        }
        Ok(())
    }

    fn write_fields(&self, enc: &mut Enc, with_blob_ref: bool) {
        enc.fixed(&self.group_id)
            .u8(self.kind.code())
            .u64(self.epoch)
            .fixed(&self.post_id)
            .u8(self.bucket.map_or(0, TokenBucket::code));
        for tag in &self.tags {
            enc.fixed(tag);
        }
        put_opt32(enc, self.del_hash.as_ref());
        if with_blob_ref {
            put_opt32(enc, self.blob_ref.as_ref());
        }
        put_count(enc, self.added_p.len());
        for p in &self.added_p {
            enc.fixed(p);
        }
        put_count(enc, self.removed.len());
        for removal in &self.removed {
            enc.fixed(&removal.p).u8(removal.ground.code());
        }
        put_opt32(enc, self.join_pk_new.as_ref());
    }

    fn write_auth(&self, enc: &mut Enc) {
        match &self.auth {
            EnvAuth::Token(token) => enc.u8(1).fixed(&token.to_bytes()),
            EnvAuth::AdminSig(sig) => enc.u8(2).fixed(sig),
            EnvAuth::PSig(sig) => enc.u8(3).fixed(sig),
            EnvAuth::Host => enc.u8(4),
        };
    }

    /// Commit authenticated data: `rf-lg-aad-v1 ‖ canonical header without token and blob_ref`.
    #[must_use]
    pub fn aad_bytes(&self) -> Vec<u8> {
        let mut enc = Enc::new(LG_AAD_V1.as_bytes());
        self.write_fields(&mut enc, false);
        enc.finish()
    }

    fn canonical_without_auth(&self) -> Vec<u8> {
        let mut enc = Enc::new(ENV_DOMAIN);
        self.write_fields(&mut enc, true);
        enc.finish()
    }

    /// `H(header without token ‖ mls bytes)`: what a token tag and a signature bind.
    #[must_use]
    pub fn bind_hash(&self, payload: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BIND_DOMAIN);
        hasher.update(&self.canonical_without_auth());
        hasher.update(blake3::hash(payload).as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// The entry hash the head chain covers: the bind hash plus the authorisation, `appended_at`
    /// and `log_seq` (the last two are host-written, outside the bind hash).
    #[must_use]
    pub fn chain_hash(&self, payload: &[u8], appended_at_ms: u64, log_seq: u64) -> [u8; 32] {
        let mut auth = Enc::default();
        self.write_auth(&mut auth);
        let mut enc = Enc::new(CHAIN_DOMAIN);
        enc.fixed(&self.bind_hash(payload)).var(&auth.finish()).u64(appended_at_ms).u64(log_seq);
        *blake3::hash(&enc.finish()).as_bytes()
    }

    fn encode_into(&self, enc: &mut Enc) {
        self.write_fields(enc, true);
        self.write_auth(enc);
    }

    fn decode_from(dec: &mut Dec<'_>) -> Result<Self, LgError> {
        let group_id = dec.fixed()?;
        let kind = EnvKind::from_code(dec.u8()?)?;
        let epoch = dec.u64()?;
        let post_id = dec.fixed()?;
        let bucket = match dec.u8()? {
            0 => None,
            code => Some(TokenBucket::from_code(code)?),
        };
        let mut tags = [[0_u8; 16]; TAG_SLOTS];
        for tag in &mut tags {
            *tag = dec.fixed()?;
        }
        let del_hash = get_opt32(dec)?;
        let blob_ref = get_opt32(dec)?;
        let adds = get_count(dec, MAX_ADDS_PER_COMMIT, "added count")?;
        let mut added_p = Vec::with_capacity(adds);
        for _ in 0..adds {
            added_p.push(dec.fixed()?);
        }
        let removals = get_count(dec, MAX_REMOVED, "removed count")?;
        let mut removed = Vec::with_capacity(removals);
        for _ in 0..removals {
            removed.push(Removal { p: dec.fixed()?, ground: RemoveGround::from_code(dec.u8()?)? });
        }
        let join_pk_new = get_opt32(dec)?;
        let auth = match dec.u8()? {
            1 => EnvAuth::Token(Token::from_bytes(&dec.fixed::<TOKEN_LEN>()?)?),
            2 => EnvAuth::AdminSig(dec.fixed()?),
            3 => EnvAuth::PSig(dec.fixed()?),
            4 => EnvAuth::Host,
            _ => return Err(LgError::Format("authorisation tag")),
        };
        Ok(Self {
            group_id,
            kind,
            epoch,
            post_id,
            bucket,
            tags,
            del_hash,
            blob_ref,
            added_p,
            removed,
            join_pk_new,
            auth,
        })
    }
}

/// Signs an envelope as pseudonym `seed` (admin `P` or member `P`).
#[must_use]
pub fn sign_envelope(seed: &[u8; 32], header: &EnvHeader, payload: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(&sig_message(header, payload)).to_bytes()
}

/// # Errors
/// Returns an error when `signature` is not `p_pub`'s signature over the envelope.
pub fn verify_envelope_sig(
    p_pub: &[u8; 32],
    header: &EnvHeader,
    payload: &[u8],
    signature: &[u8; 64],
) -> Result<(), LgError> {
    let key = VerifyingKey::from_bytes(p_pub).map_err(|_| LgError::Verify("pseudonym"))?;
    key.verify(&sig_message(header, payload), &Signature::from_bytes(signature))
        .map_err(|_| LgError::Verify("envelope signature"))
}

fn sig_message(header: &EnvHeader, payload: &[u8]) -> Vec<u8> {
    let mut enc = Enc::new(SIG_DOMAIN);
    enc.fixed(&header.bind_hash(payload));
    enc.finish()
}

/// A header and its inline payload (MLS bytes, or the plaintext of leave, void and roll entries;
/// empty when `blob_ref` names the payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub header: EnvHeader,
    pub payload: Vec<u8>,
}

impl Envelope {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::new(ENV_DOMAIN);
        self.header.encode_into(&mut enc);
        enc.var(&self.payload);
        enc.finish()
    }

    /// # Errors
    /// Returns an error for a malformed or structurally invalid envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self, LgError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(LgError::Format("envelope too large"));
        }
        let mut dec = Dec::new(bytes);
        if dec.var(ENV_DOMAIN.len())? != ENV_DOMAIN {
            return Err(LgError::Format("envelope domain"));
        }
        let header = EnvHeader::decode_from(&mut dec)?;
        let payload = dec.var(MAX_INLINE_MLS)?.to_vec();
        dec.finish()?;
        header.check()?;
        Ok(Self { header, payload })
    }

    /// `H(header without token ‖ payload)` of this envelope.
    #[must_use]
    pub fn bind_hash(&self) -> [u8; 32] {
        self.header.bind_hash(&self.payload)
    }

    /// Head-chain entry hash once the host has written `appended_at` and `log_seq`.
    #[must_use]
    pub fn chain_hash(&self, appended_at_ms: u64, log_seq: u64) -> [u8; 32] {
        self.header.chain_hash(&self.payload, appended_at_ms, log_seq)
    }
}

/// A request signed by one pseudonym over `(op, group_id, body)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReq {
    pub gid: [u8; 32],
    pub p: [u8; 32],
    pub body: Vec<u8>,
    pub sig: [u8; 64],
}

fn req_message(op: &str, gid: &[u8; 32], body: &[u8]) -> Vec<u8> {
    let mut enc = Enc::new(REQ_DOMAIN);
    enc.var(op.as_bytes()).fixed(gid).var(body);
    enc.finish()
}

impl SignedReq {
    /// Signs `body` as pseudonym `seed` for operation `op`.
    #[must_use]
    pub fn sign(op: &str, gid: &[u8; 32], seed: &[u8; 32], body: Vec<u8>) -> Self {
        let key = SigningKey::from_bytes(seed);
        let sig = key.sign(&req_message(op, gid, &body)).to_bytes();
        Self { gid: *gid, p: key.verifying_key().to_bytes(), body, sig }
    }

    /// # Errors
    /// Returns an error when the signature does not verify for `op`.
    pub fn verify(&self, op: &str) -> Result<(), LgError> {
        let key = VerifyingKey::from_bytes(&self.p).map_err(|_| LgError::Verify("pseudonym"))?;
        key.verify(&req_message(op, &self.gid, &self.body), &Signature::from_bytes(&self.sig))
            .map_err(|_| LgError::Verify("request signature"))
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.fixed(&self.gid).fixed(&self.p).var(&self.body).fixed(&self.sig);
        enc.finish()
    }

    /// # Errors
    /// Returns an error for a malformed request.
    pub fn decode(bytes: &[u8]) -> Result<Self, LgError> {
        let mut dec = Dec::new(bytes);
        let req = Self {
            gid: dec.fixed()?,
            p: dec.fixed()?,
            body: dec.var(MAX_BODY)?.to_vec(),
            sig: dec.fixed()?,
        };
        dec.finish()?;
        Ok(req)
    }
}

/// One log entry as delivered to a reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogView {
    pub seq: u64,
    pub appended_at_ms: u64,
    pub head: [u8; 32],
    pub host_sig: [u8; 64],
    pub envelope: Envelope,
}

impl LogView {
    fn encode_into(&self, enc: &mut Enc) {
        enc.u64(self.seq)
            .u64(self.appended_at_ms)
            .fixed(&self.head)
            .fixed(&self.host_sig)
            .var(&self.envelope.encode());
    }

    fn decode_from(dec: &mut Dec<'_>) -> Result<Self, LgError> {
        Ok(Self {
            seq: dec.u64()?,
            appended_at_ms: dec.u64()?,
            head: dec.fixed()?,
            host_sig: dec.fixed()?,
            envelope: Envelope::decode(dec.var(MAX_ENVELOPE_BYTES)?)?,
        })
    }
}

/// Body of the signed read request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadRequest {
    pub from_seq: u64,
    pub limit: u32,
}

impl ReadRequest {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.u64(self.from_seq).u32(self.limit);
        enc.finish()
    }

    /// # Errors
    /// Returns an error for a malformed body.
    pub fn decode(bytes: &[u8]) -> Result<Self, LgError> {
        let mut dec = Dec::new(bytes);
        let req = Self { from_seq: dec.u64()?, limit: dec.u32()? };
        dec.finish()?;
        Ok(req)
    }
}

/// Host answer to a read: group counters, the genesis, the admin chain and a page of entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadReply {
    pub genesis: Vec<u8>,
    /// Current token epoch.
    pub te: u32,
    /// Current MLS epoch.
    pub epoch: u64,
    pub last_seq: u64,
    pub now_ms: u64,
    pub admin_chain: Vec<Vec<u8>>,
    pub entries: Vec<LogView>,
}

impl ReadReply {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.var(&self.genesis).u32(self.te).u64(self.epoch).u64(self.last_seq).u64(self.now_ms);
        put_count(&mut enc, self.admin_chain.len());
        for item in &self.admin_chain {
            enc.var(item);
        }
        put_count(&mut enc, self.entries.len());
        for entry in &self.entries {
            entry.encode_into(&mut enc);
        }
        enc.finish()
    }

    /// # Errors
    /// Returns an error for a malformed reply.
    pub fn decode(bytes: &[u8]) -> Result<Self, LgError> {
        let mut dec = Dec::new(bytes);
        let genesis = dec.var(MAX_BODY)?.to_vec();
        let te = dec.u32()?;
        let epoch = dec.u64()?;
        let last_seq = dec.u64()?;
        let now_ms = dec.u64()?;
        let chain = get_count(&mut dec, MAX_ADMIN_CHAIN, "admin chain length")?;
        let mut admin_chain = Vec::with_capacity(chain);
        for _ in 0..chain {
            admin_chain.push(dec.var(MAX_BODY)?.to_vec());
        }
        let count = get_count(&mut dec, MAX_ENTRIES_PER_READ, "entry count")?;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(LogView::decode_from(&mut dec)?);
        }
        dec.finish()?;
        Ok(Self { genesis, te, epoch, last_seq, now_ms, admin_chain, entries })
    }
}

/// Admin chain head: hash of the latest chain entry, or the group id (hash of the genesis) when the
/// chain is empty.
#[must_use]
pub fn admin_chain_head(gid: &[u8; 32], chain: &[Vec<u8>]) -> [u8; 32] {
    chain.last().map_or(*gid, |entry| *blake3::hash(entry).as_bytes())
}

/// How a join request is admitted (spec 2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinKind {
    /// Invite proof on an ident session; the outsider queue.
    Invite,
    /// A current own leaf adds a new device of the same anchor; member session plus commit token.
    OwnDevice,
    /// A returning member replaces its old leaf; member session plus commit token.
    Rejoin,
}

/// The session a join request travels on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinSession {
    Ident,
    Member,
}

impl JoinKind {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Invite => 1,
            Self::OwnDevice => 2,
            Self::Rejoin => 3,
        }
    }

    /// # Errors
    /// Refuses an unknown code.
    pub fn from_code(code: u8) -> Result<Self, LgError> {
        match code {
            1 => Ok(Self::Invite),
            2 => Ok(Self::OwnDevice),
            3 => Ok(Self::Rejoin),
            _ => Err(LgError::Format("join kind")),
        }
    }

    #[must_use]
    pub const fn session(self) -> JoinSession {
        match self {
            Self::Invite => JoinSession::Ident,
            Self::OwnDevice | Self::Rejoin => JoinSession::Member,
        }
    }

    /// Own-device and rejoin requests spend a commit-bucket token; an invite spends none.
    #[must_use]
    pub const fn token_bucket(self) -> Option<TokenBucket> {
        match self {
            Self::Invite => None,
            Self::OwnDevice | Self::Rejoin => Some(TokenBucket::Commit),
        }
    }

    /// Whether the join goes to the member queue (`own_device`, `rejoin`) or the outsider queue.
    #[must_use]
    pub const fn member_queue(self) -> bool {
        !matches!(self, Self::Invite)
    }
}

/// `join{kind, KeyPackage(P), auth, join_pk_id, HPKE(join_pk, "rf-lg-join-v1", roster entry ‖
/// proof?)}`. The HPKE blob stays opaque here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    pub kind: JoinKind,
    pub key_package: Vec<u8>,
    /// Invite proof (invite) or the 68-byte commit token (`own_device`, `rejoin`).
    pub auth: Vec<u8>,
    pub join_pk_id: [u8; 32],
    pub sealed: Vec<u8>,
}

impl JoinRequest {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::new(LG_JOIN_V1.as_bytes());
        enc.u8(self.kind.code())
            .var(&self.key_package)
            .var(&self.auth)
            .fixed(&self.join_pk_id)
            .var(&self.sealed);
        enc.finish()
    }

    /// # Errors
    /// Returns an error for a malformed request, or a token kind without a well-formed token.
    pub fn decode(bytes: &[u8]) -> Result<Self, LgError> {
        let mut dec = Dec::new(bytes);
        if dec.var(LG_JOIN_V1.len())? != LG_JOIN_V1.as_bytes() {
            return Err(LgError::Format("join domain"));
        }
        let req = Self {
            kind: JoinKind::from_code(dec.u8()?)?,
            key_package: dec.var(MAX_KEY_PACKAGE)?.to_vec(),
            auth: dec.var(MAX_JOIN_AUTH)?.to_vec(),
            join_pk_id: dec.fixed()?,
            sealed: dec.var(MAX_JOIN_SEALED)?.to_vec(),
        };
        dec.finish()?;
        if req.kind.token_bucket().is_some() {
            Token::from_bytes(&req.auth)?;
        }
        Ok(req)
    }
}

/// Proof inside the join blob: the signature of an existing own pseudonym (`P_s` for `own_device`,
/// `P_old` for `rejoin`) over the new pseudonym.
#[must_use]
pub fn join_proof_sign(seed: &[u8; 32], new_p: &[u8; 32]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(&join_proof_message(new_p)).to_bytes()
}

/// # Errors
/// Returns an error when `signature` is not `old_p`'s signature over `new_p`.
pub fn join_proof_verify(
    old_p: &[u8; 32],
    new_p: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), LgError> {
    let key = VerifyingKey::from_bytes(old_p).map_err(|_| LgError::Verify("pseudonym"))?;
    key.verify(&join_proof_message(new_p), &Signature::from_bytes(signature))
        .map_err(|_| LgError::Verify("join proof"))
}

fn join_proof_message(new_p: &[u8; 32]) -> Vec<u8> {
    let mut enc = Enc::new(LG_JOIN_V1.as_bytes());
    enc.fixed(new_p);
    enc.finish()
}

/// Void payload: the log sequence of the voided head commit.
#[must_use]
pub fn void_payload(target_seq: u64) -> Vec<u8> {
    target_seq.to_be_bytes().to_vec()
}

/// # Errors
/// Refuses any payload that is not exactly one big-endian `u64`.
pub fn parse_void_payload(payload: &[u8]) -> Result<u64, LgError> {
    let bytes: [u8; 8] = payload.try_into().map_err(|_| LgError::Format("void payload"))?;
    Ok(u64::from_be_bytes(bytes))
}

/// Plaintext payload of a host-written token epoch roll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollPayload {
    pub kind: RollKind,
    /// The new token epoch.
    pub te: u32,
    /// Log sequences of the removals, bans or leaves that justify a revoke roll.
    pub ref_seqs: Vec<u64>,
}

impl RollPayload {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc::default();
        enc.u8(self.kind.code()).u32(self.te);
        put_count(&mut enc, self.ref_seqs.len());
        for seq in &self.ref_seqs {
            enc.u64(*seq);
        }
        enc.finish()
    }

    /// # Errors
    /// Returns an error for a malformed payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, LgError> {
        let mut dec = Dec::new(bytes);
        let kind = RollKind::from_code(dec.u8()?)?;
        let te = dec.u32()?;
        let count = get_count(&mut dec, MAX_ROLL_REFS, "roll references")?;
        let mut ref_seqs = Vec::with_capacity(count);
        for _ in 0..count {
            ref_seqs.push(dec.u64()?);
        }
        dec.finish()?;
        Ok(Self { kind, te, ref_seqs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post_header(token: Token) -> EnvHeader {
        EnvHeader {
            group_id: [1; 32],
            kind: EnvKind::Post,
            epoch: 3,
            post_id: [2; 16],
            bucket: Some(TokenBucket::Post),
            tags: [[0; 16]; TAG_SLOTS],
            del_hash: Some([4; 32]),
            blob_ref: None,
            added_p: Vec::new(),
            removed: Vec::new(),
            join_pk_new: None,
            auth: EnvAuth::Token(token),
        }
    }

    #[test]
    fn envelope_round_trips_and_binds_the_payload() {
        let token = Token { te: 1, input: [5; 32], tag: [6; 32] };
        let envelope = Envelope { header: post_header(token), payload: vec![9; 40] };
        let decoded = Envelope::decode(&envelope.encode()).expect("test: envelope decodes");
        assert_eq!(decoded, envelope, "envelope must round trip");
        let mut other = envelope.clone();
        other.payload.push(1);
        assert_ne!(envelope.bind_hash(), other.bind_hash(), "bind hash must cover the payload");
    }

    #[test]
    fn header_check_refuses_inconsistent_headers() {
        let token = Token { te: 1, input: [5; 32], tag: [6; 32] };
        let mut header = post_header(token);
        header.bucket = Some(TokenBucket::Commit);
        assert!(header.check().is_err(), "a post token in the commit bucket must be refused");
        let mut header = post_header(Token { te: 1, input: [5; 32], tag: [6; 32] });
        header.removed.push(Removal { p: [7; 32], ground: RemoveGround::Admin });
        assert!(header.check().is_err(), "removals are commit-only");
    }

    #[test]
    fn aad_ignores_blob_ref_and_auth() {
        let token = Token { te: 1, input: [5; 32], tag: [6; 32] };
        let mut a = post_header(token);
        let before = a.aad_bytes();
        a.blob_ref = Some([8; 32]);
        a.auth = EnvAuth::PSig([0; 64]);
        assert_eq!(before, a.aad_bytes(), "aad excludes token and blob_ref");
    }

    #[test]
    fn join_proof_and_request_round_trip() {
        let seed = [3_u8; 32];
        let old_p = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let sig = join_proof_sign(&seed, &[8; 32]);
        join_proof_verify(&old_p, &[8; 32], &sig).expect("test: proof verifies");
        assert!(join_proof_verify(&old_p, &[9; 32], &sig).is_err(), "proof binds the new P");
        let request = JoinRequest {
            kind: JoinKind::Invite,
            key_package: vec![1; 10],
            auth: vec![2; 20],
            join_pk_id: [3; 32],
            sealed: vec![4; 30],
        };
        let decoded = JoinRequest::decode(&request.encode()).expect("test: join decodes");
        assert_eq!(decoded, request, "join request must round trip");
    }
}

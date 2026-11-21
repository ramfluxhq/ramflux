// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-use, expiring phrase display and backup confirmation; no durable secret state.
use super::{BornAccount, PrimaryVault, account_exists, invalid, random, valid_id};
use crate::SdkError;
use ramflux_crypto::custody::{
    GenesisInput, MasterKey, RecoveryPhrase, SelfSigningKey, create_genesis,
};
use ramflux_protocol::{PrincipalKind, encode_base64url};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Public setup intent. No caller-supplied phrase, master seed or root seed is accepted.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInput {
    pub local_account_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub display_name: String,
    pub principal_kind: PrincipalKind,
    pub custodian_account_id: Option<String>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Unshown,
    Shown,
    Hidden,
}
/// Not cloneable or serializable. Drop erases the phrase, including on disconnect/cancel.
pub struct CreationCeremony {
    ceremony_id: String,
    expired: bool,
    root: PathBuf,
    lease: std::sync::Arc<crate::bus::data_root_lock::DataRootLock>,
    input: CreateInput,
    phrase: Option<RecoveryPhrase>,
    anchor: String,
    phase: Phase,
    positions: Option<[u8; 3]>,
    deadline: Instant,
    commit_gate: Option<std::sync::Arc<super::CommitGate>>,
    home_node_id: Option<String>,
}
impl std::fmt::Debug for CreationCeremony {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CreationCeremony(<redacted>)")
    }
}
impl CreationCeremony {
    /// Prepare a native human account without persisting recovery material. An agent
    /// (`headless_ai`) account is never created by this ceremony: it comes from the
    /// primary-approved agent creation flow (AGENT-IDENTITY-01 decision D6).
    /// # Errors
    /// Rejects existing account ids, invalid names, a non-human kind and any custodian.
    pub fn begin(root: &Path, input: CreateInput, now: u64) -> Result<Self, SdkError> {
        let lease = crate::bus::data_root_lock::DataRootLock::acquire(root)?;
        Self::begin_with_lease(root, input, now, lease)
    }
    pub(crate) fn begin_with_lease(
        root: &Path,
        input: CreateInput,
        now: u64,
        lease: std::sync::Arc<crate::bus::data_root_lock::DataRootLock>,
    ) -> Result<Self, SdkError> {
        Self::prepare(root, input, false, None, now, lease)
    }
    pub(crate) fn begin_account(
        context: (&Path, Option<std::sync::Arc<crate::bus::data_root_lock::DataRootLock>>),
        display_name: String,
        home_node_id: Option<String>,
        now: u64,
    ) -> Result<Self, SdkError> {
        let (root, lease) = context;
        let lease = match lease {
            Some(lease) => lease,
            None => crate::bus::data_root_lock::DataRootLock::acquire(root)?,
        };
        let input = CreateInput {
            local_account_id: format!("account-{}", encode_base64url(*random()?)),
            principal_id: String::new(),
            device_id: format!("device-{}", encode_base64url(*random()?)),
            display_name,
            principal_kind: PrincipalKind::Human,
            custodian_account_id: None,
        };
        Self::prepare(root, input, true, home_node_id, now, lease)
    }
    fn prepare(
        root: &Path,
        mut input: CreateInput,
        allocate_principal: bool,
        home_node_id: Option<String>,
        // A human ceremony needs no authority lookup; callers still pass the creation clock.
        _now: u64,
        lease: std::sync::Arc<crate::bus::data_root_lock::DataRootLock>,
    ) -> Result<Self, SdkError> {
        valid_id(&input.local_account_id)?;
        ramflux_protocol::validate_device_name(&input.device_id)?;
        if !allocate_principal
            && (input.principal_id.is_empty()
                || input.principal_id.len() > 256
                || input.principal_id.chars().any(char::is_control))
        {
            return Err(invalid());
        }
        let normalized = ramflux_protocol::normalize_profile_display_name(&input.display_name)
            .map_err(|_| rejected(crate::CustodyConfirmReason::DisplayName))?;
        if normalized != input.display_name {
            return Err(rejected(crate::CustodyConfirmReason::DisplayName));
        }
        if account_exists(root, &input.local_account_id)? {
            return Err(invalid());
        }
        // The phrase ceremony creates humans only. An agent account is created by the approved
        // agent creation flow, so a custodian or any other kind is refused here (decision D6).
        if input.principal_kind != PrincipalKind::Human || input.custodian_account_id.is_some() {
            return Err(invalid());
        }
        let phrase = RecoveryPhrase::generate()?;
        let master = MasterKey::from_phrase(&phrase)?;
        let public = ramflux_crypto::verifying_key_from_base64url(&master.public_key())?;
        let anchor = ramflux_crypto::identity_root_commitment(&public);
        if allocate_principal {
            input.principal_id = format!("principal-{anchor}");
        }
        Ok(Self {
            ceremony_id: format!("ceremony-{}", encode_base64url(*random()?)),
            expired: false,
            commit_gate: None,
            root: root.into(),
            lease,
            input,
            phrase: Some(phrase),
            anchor,
            phase: Phase::Unshown,
            positions: None,
            deadline: Instant::now() + Duration::from_secs(300),
            home_node_id,
        })
    }
    #[must_use]
    pub fn account_anchor(&self) -> &str {
        &self.anchor
    }
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn ceremony_id(&self) -> &str {
        &self.ceremony_id
    }
    pub(crate) fn principal_kind(&self) -> PrincipalKind {
        self.input.principal_kind
    }
    pub(crate) fn expires_in_ms(&self) -> u64 {
        u64::try_from(self.deadline.saturating_duration_since(Instant::now()).as_millis())
            .unwrap_or(u64::MAX)
    }
    pub(crate) const fn is_expired(&self) -> bool {
        self.expired
    }
    pub(crate) fn home_node_id(&self) -> Option<&str> {
        self.home_node_id.as_deref()
    }
    pub(crate) fn expire(&mut self) {
        self.phrase = None;
        self.expired = true;
    }
    fn live(&mut self) -> Result<(), SdkError> {
        if self.expired || Instant::now() >= self.deadline {
            self.expire();
            return Err(SdkError::CustodyExpired);
        }
        if self.phrase.is_none() {
            return Err(invalid());
        }
        Ok(())
    }
    /// Return the only display copy; the trusted frontend must erase it before requesting words.
    /// # Errors
    /// Rejects repeat display or expiration and destroys the pending phrase on error.
    pub fn show_once(&mut self) -> Result<Zeroizing<String>, SdkError> {
        self.live()?;
        if self.phase != Phase::Unshown {
            self.phrase = None;
            return Err(invalid());
        }
        self.phase = Phase::Shown;
        Ok(self.phrase.as_ref().ok_or_else(invalid)?.display_words())
    }
    /// Call only after hiding/erasing the display; choose distinct uniform positions now.
    /// # Errors
    /// Rejects incorrect ordering, replay, expiry or randomness failure; clears secrets on error.
    pub fn hidden_challenge(&mut self) -> Result<[u8; 3], SdkError> {
        self.live()?;
        if self.phase != Phase::Shown {
            self.phrase = None;
            return Err(invalid());
        }
        let result = positions();
        match result {
            Ok(positions) => {
                self.phase = Phase::Hidden;
                self.positions = Some(positions);
                Ok(positions)
            }
            Err(error) => {
                self.phrase = None;
                Err(error)
            }
        }
    }
    /// Consume the ceremony on every attempt, with no per-word feedback or retries.
    /// # Errors
    /// Rejects bad confirmation/expiry, unavailable vaults and incomplete durable creation.
    pub fn confirm(
        self,
        words: &[Zeroizing<String>; 3],
        vault: &dyn PrimaryVault,
        now: u64,
    ) -> Result<BornAccount, SdkError> {
        self.complete(words, vault, now, None)
    }
    pub(crate) fn guard_commit(&mut self, gate: std::sync::Arc<super::CommitGate>) {
        self.commit_gate = Some(gate);
    }
    /// Complete attended creation and seal this device's data with its own local password.
    /// The password is borrowed only for this call and never enters a pairing DTO or native publication.
    /// # Errors
    /// Rejects empty, non-UTF-8, overlong, too-short and blocklisted passwords,
    /// plus bad confirmation, expiry or vault/storage failure.
    pub fn confirm_with_passphrase(
        self,
        words: &[Zeroizing<String>; 3],
        vault: &dyn PrimaryVault,
        now: u64,
        passphrase: &[u8],
    ) -> Result<BornAccount, SdkError> {
        if passphrase.is_empty() {
            return Err(rejected(crate::CustodyConfirmReason::PassphraseEmpty));
        }
        if passphrase.len() > 1024 {
            return Err(rejected(crate::CustodyConfirmReason::PassphraseTooLong));
        }
        let text = std::str::from_utf8(passphrase)
            .map_err(|_| rejected(crate::CustodyConfirmReason::PassphraseNotUtf8))?;
        if let Err(error) = crate::check_new_passphrase(text) {
            let reason = match error {
                crate::PassphrasePolicyError::TooShort { .. } => {
                    crate::CustodyConfirmReason::PassphraseTooShort
                }
                crate::PassphrasePolicyError::TooCommon => {
                    crate::CustodyConfirmReason::PassphraseTooCommon
                }
            };
            return Err(rejected(reason));
        }
        self.complete(words, vault, now, Some(passphrase))
    }
    fn complete(
        mut self,
        words: &[Zeroizing<String>; 3],
        vault: &dyn PrimaryVault,
        now: u64,
        data_secret: Option<&[u8]>,
    ) -> Result<BornAccount, SdkError> {
        let _lease = std::sync::Arc::clone(&self.lease);
        self.live()?;
        let phrase = self.phrase.take().ok_or_else(invalid)?;
        let positions =
            self.positions.filter(|_| self.phase == Phase::Hidden).ok_or_else(invalid)?;
        for (position, word) in positions.into_iter().zip(words) {
            if !phrase.matches_word(usize::from(position), word).unwrap_or(false) {
                return Err(rejected(crate::CustodyConfirmReason::WordMismatch { position }));
            }
        }
        let master = MasterKey::from_phrase(&phrase)?;
        drop(phrase);
        let primary = SelfSigningKey::generate()?;
        let signing = random()?;
        let agreement = random()?;
        let branch = ramflux_crypto::create_device_branch_from_seed(
            &self.input.principal_id,
            &self.input.device_id,
            1,
            &signing,
        );
        let agreement_key = ramflux_crypto::X25519KeyPair::from_seed_ref(&agreement);
        let record = create_genesis(
            &master,
            &primary,
            &branch,
            &agreement_key,
            GenesisInput {
                principal_kind: self.input.principal_kind,
                display_name: self.input.display_name.clone(),
                issued_at: now,
                master_cert_id: encode_base64url(*random()?),
                branch_cert_id: encode_base64url(*random()?),
                external_human_primary: None,
            },
        )?;
        drop(master);
        let mut branch_seeds = Zeroizing::new([0; 64]);
        branch_seeds[..32].copy_from_slice(&*signing);
        branch_seeds[32..].copy_from_slice(&*agreement);
        super::store::persist(
            &self.root,
            &self.input,
            super::store::GenesisMaterial {
                record,
                primary: &primary,
                branch: Some(&branch_seeds),
                now,
                data_secret,
                commit_gate: self.commit_gate.as_deref(),
                pre_staged: false,
            },
            vault,
        )
    }
}
fn rejected(reason: crate::CustodyConfirmReason) -> SdkError {
    SdkError::CustodyConfirmRejected(reason)
}
fn positions() -> Result<[u8; 3], SdkError> {
    let mut positions = [0; 3];
    for i in 0..3 {
        loop {
            let mut byte = Zeroizing::new([0_u8; 1]);
            getrandom::fill(&mut *byte).map_err(|_| SdkError::CustodyRandomUnavailable)?;
            if byte[0] >= 240 {
                continue;
            }
            let candidate = 1 + byte[0] % 24;
            if !positions[..i].contains(&candidate) {
                positions[i] = candidate;
                break;
            }
        }
    }
    Ok(positions)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reject_passphrase(
        password: &[u8],
        reason: crate::CustodyConfirmReason,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let vault = crate::custody::tests::TestVault::default();
        let mut ceremony = CreationCeremony::begin(
            root.path(),
            crate::custody::tests::input("invalid-data-password"),
            100,
        )?;
        let phrase = ceremony.show_once()?;
        let positions = ceremony.hidden_challenge()?;
        let answers = crate::custody::tests::words(&phrase, positions)?;
        let reference = super::super::custody_vault_reference(
            root.path(),
            "invalid-data-password",
            &ceremony.anchor,
        )?;
        let error = ceremony
            .confirm_with_passphrase(&answers, &vault, 100, password)
            .expect_err("test: invalid data password was accepted");
        assert!(matches!(error, SdkError::CustodyConfirmRejected(got) if got == reason), "{error}");
        let body = crate::bus::io::local_bus_error_body(&error);
        assert_eq!(
            body.code, "CustodySetupInvalid",
            "test: passphrase refusal changed the custody error family"
        );
        assert_eq!(
            body.reason_code.as_deref(),
            Some(reason.token()),
            "test: passphrase refusal dropped its reason token"
        );
        assert!(!body.message.contains(reason.token()), "bus message echoes the check token");
        assert!(
            super::super::load_account(root.path(), "invalid-data-password", 100).is_err(),
            "test: invalid data password left durable native authority"
        );
        assert!(
            vault.load_primary(&reference).is_err(),
            "test: invalid data password created a management vault item"
        );
        Ok(())
    }
    #[test]
    fn empty_passphrase_names_its_rule_and_writes_nothing() -> Result<(), Box<dyn std::error::Error>>
    {
        reject_passphrase(&[], crate::CustodyConfirmReason::PassphraseEmpty)
    }
    #[test]
    fn overlong_passphrase_names_its_rule_and_writes_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        reject_passphrase(&[b'x'; 1025], crate::CustodyConfirmReason::PassphraseTooLong)
    }
    #[test]
    fn non_utf8_passphrase_names_its_rule_and_writes_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        reject_passphrase(&[255], crate::CustodyConfirmReason::PassphraseNotUtf8)
    }
    #[test]
    fn fourteen_scalar_passphrase_names_its_rule_and_writes_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        reject_passphrase(&[b'a'; 14], crate::CustodyConfirmReason::PassphraseTooShort)
    }
    #[test]
    fn blocklisted_passphrase_names_its_rule_and_writes_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        reject_passphrase(b"films+pic+galeries", crate::CustodyConfirmReason::PassphraseTooCommon)
    }

    #[test]
    fn custody_expiration_destroys_pending_phrase() -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::custody::tests::Root::new()?;
        let mut ceremony =
            CreationCeremony::begin(&root.0, crate::custody::tests::input("expired"), 100)?;
        ceremony.deadline = Instant::now();
        let error = ceremony.show_once().expect_err("expired ceremony");
        assert!(matches!(error, SdkError::CustodyExpired), "{error}");
        let body = crate::bus::io::local_bus_error_body(&error);
        assert_eq!(body.code, "CustodyExpired");
        assert_eq!(body.reason_code.as_deref(), Some("deadline"));
        assert!(ceremony.phrase.is_none());
        assert!(!format!("{ceremony:?}").contains("abandon"));
        Ok(())
    }
    #[test]
    fn ordinary_creation_allocates_ids_and_seals_passphrase_before_publishing_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::custody::tests::Root::new()?;
        let vault = crate::custody::tests::TestVault::default();
        let now = crate::custody::network_now()?;
        let mut pending =
            CreationCeremony::begin_account((&root.0, None), "Ordinary Human".into(), None, now)?;
        let id = pending.input.local_account_id.clone();
        assert_eq!(pending.input.principal_id, format!("principal-{}", pending.account_anchor()));
        assert!(pending.input.device_id.starts_with("device-"));
        assert!(pending.ceremony_id().starts_with("ceremony-"));
        assert!((1..=300_000).contains(&pending.expires_in_ms()));
        let phrase = pending.show_once()?;
        let positions = pending.hidden_challenge()?;
        let answers = crate::custody::tests::words(&phrase, positions)?;
        let passphrase = Zeroizing::new("creation data passphrase".to_owned());
        let account =
            pending.confirm_with_passphrase(&answers, &vault, now, passphrase.as_bytes())?;
        assert!(ramflux_storage::AccountIndex::open(&root.0)?.load_wrapped_db_key(&id)?.is_some());
        vault.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut client = crate::RamfluxClient::new();
        client.open_account_index(&root.0)?;
        client.unlock_account(&id, passphrase.as_bytes())?;
        assert!(client.device_branch.is_none());
        assert!(client.identity_root.is_none());
        assert_eq!(client.own_account_anchor()?, account.record().body.account_anchor);
        drop(client);
        let mut restarted = crate::RamfluxClient::new();
        restarted.open_account_index(&root.0)?;
        assert!(restarted.unlock_account(&id, b"wrong passphrase").is_err());
        restarted.unlock_account(&id, passphrase.as_bytes())?;
        Ok(())
    }

    #[test]
    fn ordinary_creation_wrong_words_leave_no_account_or_data_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::custody::tests::Root::new()?;
        let vault = crate::custody::tests::TestVault::default();
        let mut pending =
            CreationCeremony::begin_account((&root.0, None), "Ordinary Human".into(), None, 100)?;
        let id = pending.input.local_account_id.clone();
        let phrase = pending.show_once()?;
        let positions = pending.hidden_challenge()?;
        let mut answers = crate::custody::tests::words(&phrase, positions)?;
        let expected = answers[1].clone();
        answers[1] = Zeroizing::new("quartz".to_owned());
        let error = pending
            .confirm_with_passphrase(&answers, &vault, 100, b"discarded secret")
            .expect_err("second challenge word");
        assert!(
            matches!(
                error,
                SdkError::CustodyConfirmRejected(crate::CustodyConfirmReason::WordMismatch {
                    position,
                }) if position == positions[1]
            ),
            "{error}"
        );
        let body = crate::bus::io::local_bus_error_body(&error);
        assert_eq!(body.code, "CustodyConfirmationFailed");
        assert_eq!(
            body.reason_code.as_deref(),
            Some(crate::CustodyConfirmReason::WordMismatch { position: positions[1] }.token())
        );
        assert!(!body.message.contains(expected.as_str()), "reason reveals the expected word");
        assert!(!body.message.contains("quartz"), "reason reveals the submitted word");
        assert!(!error.to_string().contains(expected.as_str()));
        assert!(!root.0.join(ramflux_storage::ACCOUNT_INDEX_FILE).exists());
        assert!(!root.0.join("custody_accounts").join(id).exists());
        Ok(())
    }

    /// AGENT-IDENTITY-01 decision D6: the phrase ceremony never creates an agent account, with or
    /// without a custodian, and refuses before it writes anything.
    #[test]
    fn phrase_ceremony_refuses_an_agent_account_with_or_without_a_custodian()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::custody::tests::Root::new()?;
        for custodian in [None, Some("human".to_owned())] {
            let mut input = crate::custody::tests::input("machine");
            input.principal_kind = PrincipalKind::HeadlessAi;
            input.custodian_account_id = custodian;
            assert!(
                matches!(
                    CreationCeremony::begin(&root.0, input, 100),
                    Err(SdkError::CustodySetupInvalid)
                ),
                "an agent kind must be refused by the phrase ceremony"
            );
        }
        let mut human = crate::custody::tests::input("human-with-custodian");
        human.custodian_account_id = Some("human".into());
        assert!(
            matches!(
                CreationCeremony::begin(&root.0, human, 100),
                Err(SdkError::CustodySetupInvalid)
            ),
            "a human never has a custodian"
        );
        assert!(!root.0.join("custody_accounts").exists(), "nothing was written");
        Ok(())
    }

    #[test]
    fn padded_display_name_names_the_check_and_writes_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::custody::tests::Root::new()?;
        let mut input = crate::custody::tests::input("named");
        input.display_name = "  Ada".into();
        let error = CreationCeremony::begin(&root.0, input, 100).expect_err("padded display name");
        assert!(
            matches!(
                error,
                SdkError::CustodyConfirmRejected(crate::CustodyConfirmReason::DisplayName)
            ),
            "{error}"
        );
        let body = crate::bus::io::local_bus_error_body(&error);
        assert_eq!(body.reason_code.as_deref(), Some("display_name"));
        assert!(!body.message.contains("Ada"), "reason reveals the display name");
        assert!(!root.0.join("custody_accounts").exists());
        Ok(())
    }

    #[test]
    fn word_position_tokens_roundtrip_without_a_word() {
        for position in 1..=24 {
            let reason = crate::CustodyConfirmReason::WordMismatch { position };
            assert_eq!(reason.token(), format!("word_{position}"));
            assert_eq!(crate::CustodyConfirmReason::from_token(reason.token()), Some(reason));
            assert_eq!(reason.family(), "CustodyConfirmationFailed");
        }
        assert_eq!(
            crate::CustodyConfirmReason::WordMismatch { position: 0 }.token(),
            "word_rejected"
        );
        assert_eq!(
            crate::CustodyConfirmReason::WordMismatch { position: 25 }.token(),
            "word_rejected"
        );
        assert!(crate::CustodyConfirmReason::from_token("word_rejected").is_none());
        assert!(crate::CustodyConfirmReason::from_token("word_01").is_none());
        assert!(crate::CustodyConfirmReason::from_token("harbor").is_none());
    }
}

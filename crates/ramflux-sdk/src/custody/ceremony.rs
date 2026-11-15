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
    /// Prepare a native account without persisting recovery material.
    /// # Errors
    /// Rejects existing account ids, invalid names and unsupported custodians.
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
        kind: PrincipalKind,
        custodian_account_id: Option<String>,
        home_node_id: Option<String>,
        now: u64,
    ) -> Result<Self, SdkError> {
        let (root, lease) = context;
        let lease = match lease {
            Some(lease) => lease,
            None => crate::bus::data_root_lock::DataRootLock::acquire(root)?,
        };
        if !matches!(kind, PrincipalKind::Human | PrincipalKind::HeadlessAi) {
            return Err(invalid());
        }
        let input = CreateInput {
            local_account_id: format!("account-{}", encode_base64url(*random()?)),
            principal_id: String::new(),
            device_id: format!("device-{}", encode_base64url(*random()?)),
            display_name,
            principal_kind: kind,
            custodian_account_id,
        };
        Self::prepare(root, input, true, home_node_id, now, lease)
    }
    fn prepare(
        root: &Path,
        mut input: CreateInput,
        allocate_principal: bool,
        home_node_id: Option<String>,
        now: u64,
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
        if ramflux_protocol::normalize_profile_display_name(&input.display_name)?
            != input.display_name
        {
            return Err(invalid());
        }
        if account_exists(root, &input.local_account_id)? {
            return Err(invalid());
        }
        if input.principal_kind == PrincipalKind::Human {
            if input.custodian_account_id.is_some() {
                return Err(invalid());
            }
        } else {
            let id = input.custodian_account_id.as_ref().ok_or_else(invalid)?;
            let human = super::load_account(root, id, now)?;
            if human.record().body.principal_kind != PrincipalKind::Human {
                return Err(invalid());
            }
            human.require_networking()?;
            human.verified().authorize(
                &human.record().body.master_certificate.body.primary_device_ref,
                "register",
                now,
            )?;
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
    /// Rejects empty/non-UTF-8/overlong passwords, bad confirmation, expiry or vault/storage failure.
    pub fn confirm_with_passphrase(
        self,
        words: &[Zeroizing<String>; 3],
        vault: &dyn PrimaryVault,
        now: u64,
        passphrase: &[u8],
    ) -> Result<BornAccount, SdkError> {
        if passphrase.is_empty()
            || passphrase.len() > 1024
            || std::str::from_utf8(passphrase).is_err()
        {
            return Err(invalid());
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
        let mut matches = true;
        for (position, word) in positions.into_iter().zip(words) {
            matches &= phrase.matches_word(usize::from(position), word).unwrap_or(false);
        }
        if !matches {
            return Err(SdkError::CustodyConfirmationFailed);
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
        let human = self
            .input
            .custodian_account_id
            .as_ref()
            .map(|id| super::load_account(&self.root, id, now))
            .transpose()?;
        let external = human.as_ref().map(|account| {
            account.record().body.master_certificate.body.primary_device_ref.clone()
        });
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
                external_human_primary: external,
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
                branch: &branch_seeds,
                now,
                data_secret,
                commit_gate: self.commit_gate.as_deref(),
            },
            vault,
        )
    }
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
    #[test]
    fn custody_attended_sdk_creation_refuses_invalid_data_password_before_persistence()
    -> Result<(), Box<dyn std::error::Error>> {
        const OVERLONG_BYTES: usize = 1025;
        for password in [Vec::new(), vec![b'x'; OVERLONG_BYTES], vec![255]] {
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
            assert!(
                ceremony.confirm_with_passphrase(&answers, &vault, 100, &password).is_err(),
                "test: attended SDK creation accepted an invalid original data password"
            );
            assert!(
                super::super::load_account(root.path(), "invalid-data-password", 100).is_err(),
                "test: invalid data password left durable native authority"
            );
            assert!(
                vault.load_primary(&reference).is_err(),
                "test: invalid data password created a management vault item"
            );
        }
        Ok(())
    }

    #[test]
    fn custody_expiration_destroys_pending_phrase() -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::custody::tests::Root::new()?;
        let mut ceremony =
            CreationCeremony::begin(&root.0, crate::custody::tests::input("expired"), 100)?;
        ceremony.deadline = Instant::now();
        assert!(matches!(ceremony.show_once(), Err(SdkError::CustodyExpired)));
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
        let mut pending = CreationCeremony::begin_account(
            (&root.0, None),
            "Ordinary Human".into(),
            PrincipalKind::Human,
            None,
            None,
            now,
        )?;
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
        let mut pending = CreationCeremony::begin_account(
            (&root.0, None),
            "Ordinary Human".into(),
            PrincipalKind::Human,
            None,
            None,
            100,
        )?;
        let id = pending.input.local_account_id.clone();
        drop(pending.show_once()?);
        pending.hidden_challenge()?;
        let wrong = std::array::from_fn(|_| Zeroizing::new("wrong".to_owned()));
        assert!(matches!(
            pending.confirm_with_passphrase(&wrong, &vault, 100, b"discarded secret"),
            Err(SdkError::CustodyConfirmationFailed)
        ));
        assert!(!root.0.join(ramflux_storage::ACCOUNT_INDEX_FILE).exists());
        assert!(!root.0.join("custody_accounts").join(id).exists());
        assert!(matches!(
            CreationCeremony::begin_account(
                (&root.0, None),
                "Machine".into(),
                PrincipalKind::HeadlessAi,
                None,
                None,
                100
            ),
            Err(SdkError::CustodySetupInvalid)
        ));
        Ok(())
    }
}

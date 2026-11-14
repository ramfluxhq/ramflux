// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Actual selected DB/preflight ownership only. No native issuance or vault signer proof.
use super::super::super::{
    CredentialOutcome, LocalCredentialProvider, NodeHeadPersist, PairingAuthorityQuery,
};
use super::*;
use ramflux_protocol::custody::pairing::local_dto::CredentialRequest;
use ramflux_protocol::custody::{CustodyAuthority, Publication};
use ramflux_storage::AccountDbKey;
use std::sync::{Arc, Mutex};
type ResultOf<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct NoExternal;
impl LocalCredentialProvider for NoExternal {
    fn provide(&self, _: &CredentialRequest) -> Result<CredentialOutcome, SdkError> {
        Err(wrong())
    }
}
impl NodeHeadPersist for NoExternal {
    fn persist_head(&self, _: &Publication, _: u64) -> Result<String, SdkError> {
        Err(wrong())
    }
}
impl PairingAuthorityQuery for NoExternal {
    fn current_authority(&self, _: &str) -> Result<CustodyAuthority, SdkError> {
        Err(wrong())
    }
}
fn participant(root: &std::path::Path) -> ResultOf<LocalPairingParticipant> {
    let index = AccountIndex::open(root)?;
    index.create_account("acct", &encode_base64url([2; 32]))?;
    let db =
        AccountDb::open(&index, "acct", &AccountDbKey::derive("acct", b"full-preflight-test"))?;
    Ok(LocalPairingParticipant {
        root: root.to_path_buf(),
        account_id: "acct".into(),
        vault: Arc::new(custody::NativePrimaryVault),
        provider: Arc::new(NoExternal),
        db: Mutex::new(Some(db)),
        persist: Arc::new(NoExternal),
        query: Arc::new(NoExternal),
    })
}
#[test]
fn pairing_full_participant_preflight_returns_opaque_cancelled_data_without_network_or_signer()
-> ResultOf {
    let root = tempfile::tempdir()?;
    let owner = participant(root.path())?;
    let (prepared, cancel) = owner.prepare_full_source()?;
    assert_eq!(prepared.local_account_id(), "acct");
    assert!(
        prepared.encoding().total_bytes > 0,
        "preflight omitted actual portable MAC/counter rows"
    );
    assert!(!prepared.is_cancelled());
    cancel.cancel();
    assert!(prepared.is_cancelled());
    owner.db.lock().map_err(|_| "slot")?.take();
    assert!(matches!(owner.prepare_full_source(), Err(SdkError::AccountDbNotUnlocked)));
    Ok(())
}
#[test]
fn pairing_full_participant_preflight_refuses_foreign_selected_database_and_root() -> ResultOf {
    let root = tempfile::tempdir()?;
    let other = tempfile::tempdir()?;
    let owner = participant(root.path())?;
    let foreign = participant(other.path())?;
    let db = foreign.db.lock().map_err(|_| "foreign slot")?.take();
    *owner.db.lock().map_err(|_| "slot")? = db;
    assert!(
        owner.prepare_full_source().is_err(),
        "another store's same account id passed preflight"
    );
    assert!(
        owner
            .with_full_branch(
                &DeviceRef {
                    account_anchor: encode_base64url([2; 32]),
                    device_id: "A".into(),
                    device_epoch: 1
                },
                "unused",
                |_| Ok(())
            )
            .is_err()
    );
    Ok(())
}

impl LocalPairingParticipant {
    pub(in crate::custody::pairing) fn full_test_participant(
        root: &std::path::Path,
    ) -> ResultOf<Self> {
        participant(root)
    }
}

#[test]
fn pairing_full_candidate_requires_the_adopted_day_of_tail_margin() {
    for remaining in [0, 1, 23 * 3600, 86_399] {
        assert!(matches!(
            require_candidate_lease(1000 + remaining, 1000),
            Err(SdkError::PairingCode("LeaseExpired"))
        ));
    }
    assert!(require_candidate_lease(1000, 1001).is_err());
    for remaining in [86_400, 25 * 3600, 604_800] {
        assert!(require_candidate_lease(1000 + remaining, 1000).is_ok());
    }
}

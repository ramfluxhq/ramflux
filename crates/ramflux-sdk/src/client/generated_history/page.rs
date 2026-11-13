// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Native own-root history transport, exact-item digest chain and atomic item imports.
use crate::client::identity_authority::{HeadUse, NativeOperation};
use crate::{GatewayInboxEntry, RamfluxClient, SdkError};
use ramflux_protocol::message as g;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Default, Deserialize, Serialize)]
struct Transfer {
    id: Vec<u8>,
    last_page: u64,
    last_digest: Vec<u8>,
    accepted_at: i64,
    pages: BTreeMap<u64, Vec<u8>>,
    #[serde(default)]
    retired: Vec<Retired>,
    #[serde(default)]
    refusals: VecDeque<ItemRefusal>,
}

#[derive(Clone, Deserialize, Serialize)]
struct ItemRefusal {
    transfer: Vec<u8>,
    page: u64,
    item: usize,
    code: crate::error::GeneratedRefusalCode,
}

// The wire TTL is u32 seconds. Keep every retired id for that entire maximum
// lifetime; refuse a replacement at capacity instead of weakening its replay fence.
const RETIRED_CAPACITY: usize = 256;
#[derive(Clone, Deserialize, Serialize)]
struct Retired {
    id: Vec<u8>,
    until: i64,
}

fn refused(reason: &str) -> SdkError {
    SdkError::GeneratedRefused {
        code: crate::error::GeneratedRefusalCode::Content,
        reason: reason.into(),
    }
}

impl Transfer {
    // Only a newly accepted page refreshes the inactivity deadline. Retransmits cannot
    // hold the source's single transfer open forever or switch its active transfer id.
    fn advance(&mut self, page: &g::HistoryPage, now: i64) -> Result<bool, SdkError> {
        self.retired.retain(|row| row.until > now);
        if self.retired.iter().any(|row| row.id == page.transfer_id) {
            return Err(refused("retired history transfer"));
        }
        if !self.id.is_empty() && self.id != page.transfer_id {
            if now.saturating_sub(self.accepted_at) < 60
                || page.page != 0
                || page.previous_page_digest != [0; 32]
            {
                return Err(refused("interleaved history transfer"));
            }
            if self.retired.len() >= RETIRED_CAPACITY {
                return Err(refused("history retired-transfer capacity"));
            }
            self.retired.push(Retired {
                id: self.id.clone(),
                until: now.saturating_add(i64::from(u32::MAX)),
            });
            self.id.clear();
            self.pages.clear();
        }
        if self.id.is_empty() {
            if page.page != 0 || page.previous_page_digest != [0; 32] {
                return Err(refused("history transfer must start at page zero"));
            }
            self.id.clone_from(&page.transfer_id);
        } else {
            if self.id != page.transfer_id {
                return Err(refused("interleaved history transfer"));
            }
            if let Some(digest) = self.pages.get(&page.page) {
                return if digest == &page.page_digest {
                    Ok(false)
                } else {
                    Err(SdkError::ReplayMismatch)
                };
            }
            if self.last_page.checked_add(1) != Some(page.page)
                || self.last_digest != page.previous_page_digest
            {
                return Err(refused("history page chain gap or mismatch"));
            }
        }
        self.last_page = page.page;
        self.last_digest.clone_from(&page.page_digest);
        self.accepted_at = now;
        self.pages.insert(page.page, page.page_digest.clone());
        Ok(true)
    }
}

fn edited(item: &g::HistoryItem) -> Result<bool, SdkError> {
    let inner = g::validation::scan_inner(&item.exact_inner)
        .map_err(|_| refused("history item Inner malformed"))?;
    Ok(inner.kind == 3
        || item.original_metadata_evidence.is_some()
        || !item.exact_original_identity.is_empty())
}

// A refusal can deny dependent items but never supplies origin authority for them.
fn claimed_edit_target(item: &g::HistoryItem) -> Option<Vec<u8>> {
    let inner = g::validation::scan_inner(&item.exact_inner).ok()?;
    if inner.kind != 3 || inner.outcome != g::validation::ScanOutcome::Supported {
        return None;
    }
    let content = g::registry::decode_body(inner.kind, inner.body, inner.layer).ok()?;
    let Some(g::content::Value::Edit(edit)) = content.value else {
        return None;
    };
    Some(edit.target?.id)
}

fn item_refusal(error: SdkError) -> Result<crate::error::GeneratedRefusalCode, SdkError> {
    use crate::error::GeneratedRefusalCode as Code;
    use g::original_header::EvidenceError;
    match error {
        SdkError::GeneratedRefused { code, .. } => Ok(code),
        SdkError::HistoryEvidence(EvidenceError::OriginEvidenceMissing) => {
            Ok(Code::OriginEvidenceMissing)
        }
        SdkError::HistoryEvidence(_) => Ok(Code::OriginCommitmentMismatch),
        SdkError::InboundRejected(_) | SdkError::ReplayMismatch => Ok(Code::Content),
        // Storage and transient authority failures propagate to the enclosing transaction.
        error => Err(error),
    }
}

impl RamfluxClient {
    fn import_history_page_item(
        &self,
        entry: &GatewayInboxEntry,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        item: &g::HistoryItem,
    ) -> Result<(), SdkError> {
        let identity = if edited(item)? {
            self.verify_generated_edited_history_item(item)?
        } else {
            Self::verify_history_message_origin(item)?.0
        };
        self.authorize_history_message_scope(&identity)?;
        if edited(item)? {
            self.apply_generated_history_edit(entry, item)?;
        } else {
            self.import_generated_history_message(source, item)?;
        }
        Ok(())
    }

    pub(crate) fn authorize_generated_history_page(
        &self,
        source: &ramflux_crypto::RootQualifiedDeviceRef,
        exact_control: &[u8],
    ) -> Result<g::HistoryPage, SdkError> {
        let local = self.owned_device_identity()?;
        if source == &local || source.root_commitment() != local.root_commitment() {
            return Err(refused("history transport requires an own-root sibling"));
        }
        self.require_native_operation(source, NativeOperation::Sync)?;
        self.require_native_operation(&local, NativeOperation::Sync)?;
        // Hash the exact wire items before decoding/authorizing any nested item.
        let page = g::history_chain::verify_control(exact_control)
            .map_err(|_| refused("history page exact-item digest mismatch"))?;
        let key = format!("routed/history-transfer/{}", source.storage_key());
        let mut state = self.account_db()?.load_actor_state::<Transfer>(&key)?.unwrap_or_default();
        state.advance(&page, crate::time::now_unix_timestamp())?;
        Ok(page)
    }

    pub(crate) fn receive_generated_history_page(
        &self,
        entry: &GatewayInboxEntry,
        exact_control: &[u8],
    ) -> Result<(), SdkError> {
        let source = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let db = self.account_db()?;
        db.write_transaction(|| {
            let page = self.authorize_generated_history_page(&source, exact_control)?;
            let key = format!("routed/history-transfer/{}", source.storage_key());
            let mut state = db.load_actor_state::<Transfer>(&key)?.unwrap_or_default();
            if !state.advance(&page, crate::time::now_unix_timestamp())? {
                return Ok(());
            }
            let mut refused_targets = std::collections::BTreeSet::new();
            for (index, item) in page.items.iter().enumerate() {
                let target = claimed_edit_target(item);
                let imported = if target.as_ref().is_some_and(|id| refused_targets.contains(id)) {
                    Err(SdkError::GeneratedRefused {
                        code: crate::error::GeneratedRefusalCode::OriginCommitmentMismatch,
                        reason: "history item depends on a refused item".into(),
                    })
                } else {
                    db.write_transaction(|| self.import_history_page_item(entry, &source, item))
                };
                let code = match imported {
                    Ok(()) => continue,
                    Err(error) => item_refusal(error)?,
                };
                if let Some(target) = target {
                    refused_targets.insert(target);
                }
                if state.refusals.len() >= RETIRED_CAPACITY {
                    state.refusals.pop_front();
                }
                state.refusals.push_back(ItemRefusal {
                    transfer: page.transfer_id.clone(),
                    page: page.page,
                    item: index,
                    code,
                });
            }
            db.persist_actor_state(&key, &state)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn outgoing_history_requires_a_native_bound_peer_scope()
    -> crate::client::native_test_support::TestResult {
        let own =
            crate::client::native_test_support::Fixture::new("outgoing-history-scope").await?;
        let peer =
            crate::client::native_test_support::Fixture::new("outgoing-history-peer").await?;
        let own_root = own.client.own_account_anchor()?;
        let peer_root = peer.client.own_account_anchor()?;
        let conversation = g::dm_scope::derive(&own_root, &peer_root)?;
        let identity = own.client.allocate_generated_identity(&conversation, 1000, false)?;
        assert!(
            own.client.authorize_history_message_scope(&identity).is_err(),
            "an outgoing history item cannot establish its own peer relationship"
        );
        let db = own.client.account_db()?;
        db.persist_client_record(
            "conversation",
            &conversation,
            &serde_json::json!({
                "kind":"direct", "group_id":null, "participant_roots":[own_root,peer_root],
            }),
        )?;
        own.client.authorize_history_message_scope(&identity)?;
        db.persist_client_record(
            "conversation",
            &conversation,
            &serde_json::json!({
                "kind":"direct", "group_id":null, "participant_roots":[own_root,own_root],
            }),
        )?;
        assert!(own.client.authorize_history_message_scope(&identity).is_err());
        assert!(
            own.client.friend_links()?.is_empty(),
            "history scope checks grant no contact authority"
        );
        Ok(())
    }

    #[test]
    fn history_retired_transfer_fences_refuse_at_capacity_without_eviction() -> Result<(), SdkError>
    {
        let first = g::HistoryPage {
            transfer_id: vec![1; 32],
            previous_page_digest: vec![0; 32],
            page_digest: vec![2; 32],
            ..Default::default()
        };
        let mut state = Transfer::default();
        assert!(state.advance(&first, 100)?);
        state.retired = (0..RETIRED_CAPACITY)
            .map(|index| Retired { id: index.to_be_bytes().to_vec(), until: 1_000 })
            .collect();
        let replacement = g::HistoryPage { transfer_id: vec![3; 32], ..first.clone() };
        assert!(state.advance(&replacement, 160).is_err());
        assert_eq!(state.id, first.transfer_id);
        assert_eq!(state.retired.len(), RETIRED_CAPACITY);
        assert!(state.advance(&replacement, 1_000)?);
        assert!(
            state.advance(&first, 1_060).is_err(),
            "a retired id never replaces the current chain"
        );
        assert_eq!(state.retired.len(), 1);
        Ok(())
    }

    #[test]
    fn history_chain_replays_do_not_refresh_and_gaps_forks_interleaving_refuse()
    -> Result<(), SdkError> {
        let mut state = Transfer::default();
        let mut first = g::HistoryPage {
            transfer_id: vec![1; 32],
            previous_page_digest: vec![0; 32],
            page_digest: vec![2; 32],
            ..Default::default()
        };
        assert!(state.advance(&first, 100)?);
        assert!(!state.advance(&first, 120)?);
        assert_eq!(state.accepted_at, 100);
        first.page_digest[0] ^= 1;
        assert!(matches!(state.advance(&first, 121), Err(SdkError::ReplayMismatch)));
        first.page_digest[0] ^= 1;
        let mut second = g::HistoryPage {
            page: 1,
            previous_page_digest: first.page_digest.clone(),
            page_digest: vec![3; 32],
            ..first.clone()
        };
        second.transfer_id[0] ^= 1;
        assert!(state.advance(&second, 122).is_err());
        second.transfer_id[0] ^= 1;
        second.page = 2;
        assert!(state.advance(&second, 123).is_err());
        second.page = 1;
        second.previous_page_digest[0] ^= 1;
        assert!(state.advance(&second, 124).is_err());
        second.previous_page_digest[0] ^= 1;
        assert!(state.advance(&second, 125)?);
        assert!(!state.advance(&first, 130)?, "an earlier exact replay settles");
        assert_eq!(state.accepted_at, 125);
        assert!(!state.advance(&second, 185)?, "idle exact replay still settles");
        let third = g::HistoryPage {
            page: 2,
            previous_page_digest: second.page_digest.clone(),
            page_digest: vec![4; 32],
            ..second.clone()
        };
        assert!(state.advance(&third, 186)?, "delayed continuation retains the active chain");
        first.transfer_id[0] ^= 1;
        assert!(state.advance(&first, 246)?);
        assert!(state.advance(&second, 247).is_err(), "retired id cannot replace the new chain");
        Ok(())
    }
}

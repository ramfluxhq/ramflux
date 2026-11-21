// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Agent custody operations for fixture vaults (AGENT-IDENTITY-01 stage F4). A test vault that
//! implements [`super::PrimaryVault`] by itself delegates the four agent operations to one
//! [`AgentVaultParts`]: it holds the agent master items under the shared write-once rules, and it
//! signs a registration decision only after a one-shot approval armed for exactly that plan hash.
//! It is compiled for the `test-support` feature only (the shared consumer-test accounts); no production vault uses it.
use super::vault::agent_master_item::{self, AgentMasterCells};
use super::{AgentDecisionSigning, PrimaryVault};
use crate::SdkError;
use ramflux_crypto::custody::{AgentMasterRequest, MasterKey};
use ramflux_protocol::custody::{
    Envelope, MasterCertificate, RegisterDecision, register_decision_body,
};
use std::{collections::BTreeMap, sync::Mutex};
use zeroize::Zeroizing;

/// Upper bound on the items one fixture vault keeps for agent masters.
const MAX_ITEMS: usize = 16;

#[derive(Default)]
pub(crate) struct AgentVaultParts {
    items: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
    approval: Mutex<Option<String>>,
}

impl AgentMasterCells for AgentVaultParts {
    fn read_item(&self, reference: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SdkError> {
        let items = self.items.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        Ok(items.get(reference).cloned())
    }
    fn insert_item(&self, reference: &str, value: &[u8]) -> Result<(), SdkError> {
        let mut items = self.items.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if items.contains_key(reference) || items.len() >= MAX_ITEMS {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        items.insert(reference.into(), Zeroizing::new(value.to_vec()));
        Ok(())
    }
    fn remove_item(&self, reference: &str) -> Result<(), SdkError> {
        self.items.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?.remove(reference);
        Ok(())
    }
}

impl AgentVaultParts {
    /// Arms the one-shot presence approval for one plan hash.
    ///
    /// # Errors
    /// `CustodyVaultUnavailable` when the lock is poisoned.
    pub(crate) fn arm(&self, plan_hash: &str) -> Result<(), SdkError> {
        *self.approval.lock().map_err(|_| SdkError::CustodyVaultUnavailable)? =
            Some(plan_hash.into());
        Ok(())
    }

    /// # Errors
    /// The shared rules' refusals.
    pub(crate) fn store_master(&self, reference: &str, master: &MasterKey) -> Result<(), SdkError> {
        agent_master_item::store(self, reference, master)
    }

    /// # Errors
    /// The shared rules' refusals.
    pub(crate) fn certify(
        &self,
        reference: &str,
        request: AgentMasterRequest,
    ) -> Result<Envelope<MasterCertificate>, SdkError> {
        agent_master_item::certify(self, reference, request)
    }

    /// # Errors
    /// The shared rules' refusals.
    pub(crate) fn delete_master(&self, reference: &str, last_range: u64) -> Result<(), SdkError> {
        agent_master_item::delete(self, reference, last_range)
    }

    /// Signs the decision of `request` with the primary branch held by `vault`, after the plan is
    /// bound, the primary key matches and the armed approval for this plan hash is consumed.
    ///
    /// # Errors
    /// `custody_key_unavailable` without a matching armed approval or key.
    pub(crate) fn sign(
        &self,
        vault: &dyn PrimaryVault,
        request: &AgentDecisionSigning<'_>,
    ) -> Result<RegisterDecision, SdkError> {
        let body =
            register_decision_body(request.request).map_err(|_| SdkError::CustodySetupInvalid)?;
        let primary = vault.load_primary(request.primary_reference)?;
        if primary.public_key() != request.expected_primary_public_key {
            return Err(super::vault::agent_key_unavailable());
        }
        {
            let mut armed = self.approval.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
            if armed.as_deref() != Some(request.request.plan_hash.as_str()) {
                return Err(super::vault::agent_key_unavailable());
            }
            *armed = None;
        }
        let branch = vault.load_branch(
            request.branch_reference,
            request.principal_id,
            &request.request.signer,
        )?;
        ramflux_crypto::custody::sign_register_decision(&branch.signing, body)
            .map_err(|_| super::vault::agent_key_unavailable())
    }
}

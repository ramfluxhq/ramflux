// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Integration fixture. `Default` is process-local. `persist_at` keeps wrapping
//! keys across a test process restart. Not a production vault or production file fallback.
use super::vault::agent_master_item::{decode as decode_item, encode as encode_item};
use super::vault::{AGENT_MASTER_PREFIX, agent_key_unavailable};
use super::{AgentDecisionSigning, BranchCredentials, PrimaryVault, require_vault_reference};
use crate::SdkError;
use ramflux_crypto::custody::{
    AgentMasterRequest, MasterKey, SelfSigningKey, certify_agent_master, sign_register_decision,
};
use ramflux_protocol::custody::{
    Envelope, MasterCertificate, RegisterDecision, register_decision_body,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Mutex,
};
use zeroize::Zeroizing;
struct MigrationApproval {
    account: String,
    request_id: String,
}
#[derive(Default)]
struct MigrationApprovals {
    pending: Option<MigrationApproval>,
    consumed: BTreeSet<(String, String)>,
}
/// One armed registration decision, keyed by the plan hash it may sign. Consumed on use.
#[derive(Default)]
struct AgentDecisionApprovals {
    pending: Option<String>,
    consumed: BTreeSet<String>,
}
#[derive(Default)]
pub struct MemoryPrimaryVault {
    entries: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
    migration_approval: Mutex<MigrationApprovals>,
    agent_decision_approval: Mutex<AgentDecisionApprovals>,
    persist: Option<PathBuf>,
}
impl MemoryPrimaryVault {
    /// Reload wrapping keys from `path` so a later fixture process can unlock.
    /// `Default` stays process-local. Production vaults never use this file.
    ///
    /// # Errors
    /// `CustodyVaultUnavailable` when an existing file cannot be read or decoded.
    pub fn persist_at(path: impl Into<PathBuf>) -> Result<Self, SdkError> {
        let path = path.into();
        Ok(Self {
            entries: Mutex::new(load_persisted(&path)?),
            migration_approval: Mutex::new(MigrationApprovals::default()),
            agent_decision_approval: Mutex::new(AgentDecisionApprovals::default()),
            persist: Some(path),
        })
    }
    /// Grant one exact migration signature in the default-off integration fixture only.
    /// # Errors
    /// Refuses a pending approval or any already-consumed account/request pair.
    pub fn approve_migration_once_for_test(
        &self,
        account: &str,
        request_id: &str,
    ) -> Result<(), SdkError> {
        let mut approval =
            self.migration_approval.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if approval.consumed.contains(&(account.into(), request_id.into())) {
            return Err(SdkError::LocalBusRefused {
                code: "MigrationApprovalConsumed".into(),
                message: "this migration fixture approval was already consumed".into(),
                body: Box::new(serde_json::json!({
                    "reason_code": "migration_approval_consumed"
                })),
            });
        }
        if approval.pending.is_some() {
            return Err(SdkError::LocalBusRefused {
                code: "MigrationApprovalAlreadyArmed".into(),
                message: "a migration fixture approval is already armed".into(),
                body: Box::new(serde_json::json!({
                    "reason_code": "migration_approval_already_armed"
                })),
            });
        }
        approval.pending =
            Some(MigrationApproval { account: account.into(), request_id: request_id.into() });
        Ok(())
    }
    /// Arm one signature for the exact plan hash in the default-off integration fixture only.
    /// The next `sign_agent_register_decision` for that plan consumes the approval.
    /// # Errors
    /// Refuses an already-armed approval or a plan hash that was already consumed.
    pub fn approve_agent_decision_once_for_test(&self, plan_hash: &str) -> Result<(), SdkError> {
        let mut approval =
            self.agent_decision_approval.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if approval.consumed.contains(plan_hash) {
            return Err(SdkError::LocalBusRefused {
                code: "AgentDecisionApprovalConsumed".into(),
                message: "this agent decision fixture approval was already consumed".into(),
                body: Box::new(serde_json::json!({
                    "reason_code": "agent_decision_approval_consumed"
                })),
            });
        }
        if approval.pending.is_some() {
            return Err(SdkError::LocalBusRefused {
                code: "AgentDecisionApprovalAlreadyArmed".into(),
                message: "an agent decision fixture approval is already armed".into(),
                body: Box::new(serde_json::json!({
                    "reason_code": "agent_decision_approval_already_armed"
                })),
            });
        }
        approval.pending = Some(plan_hash.into());
        Ok(())
    }
    /// Replace an existing item, restoring the previous bytes when the flush fails.
    fn replace_locked(
        &self,
        entries: &mut BTreeMap<String, Zeroizing<Vec<u8>>>,
        reference: &str,
        bytes: &[u8],
    ) -> Result<(), SdkError> {
        let previous = entries.insert(reference.into(), Zeroizing::new(bytes.to_vec()));
        if let Err(error) = self.flush_locked(entries) {
            match previous {
                Some(old) => {
                    entries.insert(reference.into(), old);
                }
                None => {
                    entries.remove(reference);
                }
            }
            return Err(error);
        }
        Ok(())
    }
    fn put(&self, reference: &str, bytes: &[u8]) -> Result<(), SdkError> {
        let mut entries = self.entries.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if entries.contains_key(reference) {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        entries.insert(reference.into(), Zeroizing::new(bytes.to_vec()));
        self.flush_locked(&entries)
    }
    fn get<const N: usize>(&self, reference: &str) -> Result<Zeroizing<[u8; N]>, SdkError> {
        let entries = self.entries.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let bytes = entries.get(reference).ok_or(SdkError::CustodyVaultUnavailable)?;
        if bytes.len() != N {
            return Err(SdkError::CustodyVaultUnavailable);
        }
        let mut seed = Zeroizing::new([0; N]);
        seed.copy_from_slice(bytes);
        Ok(seed)
    }
    fn flush_locked(&self, entries: &BTreeMap<String, Zeroizing<Vec<u8>>>) -> Result<(), SdkError> {
        let Some(path) = self.persist.as_ref() else {
            return Ok(());
        };
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        }
        let encoded: BTreeMap<String, String> = entries
            .iter()
            .map(|(key, value)| (key.clone(), ramflux_protocol::encode_base64url(value.as_slice())))
            .collect();
        let bytes = serde_json::to_vec(&encoded).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let tmp = tmp_path(path);
        std::fs::write(&tmp, bytes).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        std::fs::rename(&tmp, path).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        Ok(())
    }
}
fn tmp_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}
fn load_persisted(path: &Path) -> Result<BTreeMap<String, Zeroizing<Vec<u8>>>, SdkError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let bytes = std::fs::read(path).map_err(|_| SdkError::CustodyVaultUnavailable)?;
    let encoded: BTreeMap<String, String> =
        serde_json::from_slice(&bytes).map_err(|_| SdkError::CustodyVaultUnavailable)?;
    let mut entries = BTreeMap::new();
    for (reference, value) in encoded {
        let raw = ramflux_protocol::decode_base64url(&value)
            .map_err(|_| SdkError::CustodyVaultUnavailable)?;
        entries.insert(reference, Zeroizing::new(raw));
    }
    Ok(entries)
}
impl PrimaryVault for MemoryPrimaryVault {
    #[cfg(feature = "itest-memory-vault")]
    fn approve_migration_once_for_test(
        &self,
        account: &str,
        request_id: &str,
    ) -> Result<(), SdkError> {
        Self::approve_migration_once_for_test(self, account, request_id)
    }
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        let mut entries = self.entries.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        entries.remove(reference);
        self.flush_locked(&entries)
    }
    fn home_authorization_preflight(&self) -> Result<(), SdkError> {
        Ok(())
    }

    fn sign_home_authorization(
        &self,
        request: super::HomeAuthorizationRequest<'_>,
    ) -> Result<
        ramflux_protocol::home_migration::Signed<ramflux_protocol::home_migration::Authorization>,
        SdkError,
    > {
        let mut approval =
            self.migration_approval.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let matches = approval.pending.as_ref().is_some_and(|approval| {
            approval.account == request.local_account_id()
                && approval.request_id == request.request_id()
        });
        if !matches {
            return Err(super::home_authorization::unavailable());
        }
        if let Some(consumed) = approval.pending.take() {
            approval.consumed.insert((consumed.account, consumed.request_id));
        }
        drop(approval);
        let primary = self.load_primary(request.primary_reference())?;
        let now = request.requested_at;
        request.sign_once(&primary, now)
    }
    fn preflight(&self) -> Result<(), SdkError> {
        Ok(())
    }
    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        self.put(reference, &*key.vault_seed())
    }
    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        Ok(SelfSigningKey::from_vault_seed(&self.get(reference)?))
    }
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        self.put(reference, &**seeds)
    }
    fn store_agent_master(&self, reference: &str, master: &MasterKey) -> Result<(), SdkError> {
        require_vault_reference(reference, AGENT_MASTER_PREFIX)?;
        let item = encode_item(master, None)?;
        self.put(reference, &item)
    }
    fn certify_agent_master(
        &self,
        reference: &str,
        request: AgentMasterRequest,
    ) -> Result<Envelope<MasterCertificate>, SdkError> {
        require_vault_reference(reference, AGENT_MASTER_PREFIX)?;
        let mut entries = self.entries.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let stored = entries.get(reference).ok_or_else(agent_key_unavailable)?;
        let item = decode_item(stored)?;
        let (certificate, hash) =
            certify_agent_master(&item, request).map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let rewritten = encode_item(&item.master, Some(&hash))?;
        self.replace_locked(&mut entries, reference, &rewritten)?;
        Ok(certificate)
    }
    fn sign_agent_register_decision(
        &self,
        request: AgentDecisionSigning<'_>,
    ) -> Result<RegisterDecision, SdkError> {
        require_vault_reference(request.branch_reference, "branch:")?;
        // Bind the body to the exact plan first: a refused plan never consumes the approval.
        let body =
            register_decision_body(request.request).map_err(|_| SdkError::CustodySetupInvalid)?;
        let primary = self.load_primary(request.primary_reference)?;
        if primary.public_key() != request.expected_primary_public_key {
            return Err(agent_key_unavailable());
        }
        {
            let mut approval = self
                .agent_decision_approval
                .lock()
                .map_err(|_| SdkError::CustodyVaultUnavailable)?;
            let armed = approval.pending.as_deref() == Some(request.request.plan_hash.as_str());
            if !armed {
                return Err(agent_key_unavailable());
            }
            approval.pending = None;
            approval.consumed.insert(request.request.plan_hash.clone());
        }
        let branch = self.load_branch(
            request.branch_reference,
            request.principal_id,
            &request.request.signer,
        )?;
        sign_register_decision(&branch.signing, body).map_err(|_| agent_key_unavailable())
    }
    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        BranchCredentials::from_vault_seeds(principal, device, &self.get(reference)?)
    }
    fn store_provisioning_secret(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        self.put(reference, secret)
    }
    fn load_provisioning_secret(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        let entries = self.entries.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        entries.get(reference).cloned().ok_or(SdkError::CustodyVaultUnavailable)
    }
}

#[cfg(test)]
mod tests;

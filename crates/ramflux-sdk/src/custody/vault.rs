// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Non-synchronizing primary credentials; never falls back to the data vault or a file.
#[cfg(any(target_os = "linux", test))]
pub(super) mod linux;

mod reason;
pub use reason::CustodyVaultReason;

// Shared agent-master rules; every provider that stores the agent master calls them.
#[cfg(any(
    test,
    feature = "itest-memory-vault",
    target_os = "linux",
    target_os = "macos",
    windows
))]
pub(crate) mod agent_master_item;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{VAULT_CLASS_WINDOWS_DPAPI, WindowsDpapiVault};

use super::HomeAuthorizationRequest;
use crate::SdkError;
use ramflux_crypto::custody::{AgentMasterRequest, MasterKey, SelfSigningKey};
use ramflux_protocol::custody::{
    AgentDecisionRequest, Envelope, MasterCertificate, RegisterDecision,
};
use zeroize::Zeroizing;

/// Production vault-ref grammar used by Linux, macOS and test vaults.
///
/// `prefix` is `""` (primary), `"branch:"`, or `"agent-provisioning:"`. The remainder is a
/// 43-character canonical base64url 32-byte id.
///
/// # Errors
/// `CustodyVaultUnavailable` when the prefix or bound id is not the production grammar.
pub(crate) fn require_vault_reference(reference: &str, prefix: &str) -> Result<(), SdkError> {
    let rest = reference.strip_prefix(prefix).ok_or(SdkError::CustodyVaultUnavailable)?;
    if rest.len() != 43 {
        return Err(SdkError::CustodyVaultUnavailable);
    }
    let bytes =
        ramflux_protocol::decode_base64url(rest).map_err(|_| SdkError::CustodyVaultUnavailable)?;
    if bytes.len() != 32 || ramflux_protocol::encode_base64url(&bytes) != rest {
        return Err(SdkError::CustodyVaultUnavailable);
    }
    Ok(())
}

/// Implementations must be non-synchronizing, primary-local and independent of data unlock.
/// No bus method exposes these credentials; public authority reads do not load them.
pub trait PrimaryVault: Send + Sync {
    /// Arm one request-bound fixture approval. Production providers never implement this surface.
    /// # Errors
    /// Refuses unavailable fixture providers, a pending approval, or a consumed account/request pair.
    #[cfg(feature = "itest-memory-vault")]
    fn approve_migration_once_for_test(
        &self,
        _account: &str,
        _request_id: &str,
    ) -> Result<(), SdkError> {
        Err(SdkError::LocalBusRefused {
            code: "MigrationApprovalUnavailable".into(),
            message: "migration fixture approval is unavailable".into(),
            body: Box::new(serde_json::json!({
                "reason_code": "migration_approval_unavailable"
            })),
        })
    }
    /// Durable class recorded with new authority after a successful store.
    fn vault_class(&self) -> &'static str {
        VAULT_CLASS_PROTECTED
    }
    /// Check provider availability before asking a user to save recovery material.
    /// # Errors
    /// Fails closed when the provider is unsupported, locked or lacks host entitlements.
    fn preflight(&self) -> Result<(), SdkError>;
    /// # Errors
    /// Fails closed on unsupported/locked/unavailable providers and existing entries.
    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError>;
    /// # Errors
    /// Rejects unavailable or corrupt primary credentials. No portable export API exists.
    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError>;
    /// Check migration provider availability without prompting or loading branch credentials.
    /// This is never a grant of user presence.
    /// # Errors
    /// Refuses unsupported providers with the migration-specific typed error.
    fn home_authorization_preflight(&self) -> Result<(), SdkError> {
        Err(super::home_authorization::unavailable())
    }
    /// Sign a stored migration proposal after enforcing independent user presence.
    /// # Errors
    /// The default refuses: a data unlock or an existing `load_primary` implementation is insufficient.
    fn sign_home_authorization(
        &self,
        _request: HomeAuthorizationRequest<'_>,
    ) -> Result<
        ramflux_protocol::home_migration::Signed<ramflux_protocol::home_migration::Authorization>,
        SdkError,
    > {
        Err(super::home_authorization::unavailable())
    }
    /// Load only the branch credential for network possession; never loads master authority.
    /// # Errors
    /// Rejects unsupported providers and missing/corrupt branch entries.
    fn load_branch(
        &self,
        _reference: &str,
        _principal: &str,
        _device: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
    /// Remove a credential written by an incomplete creation attempt. Missing entries succeed.
    /// # Errors
    /// Returns provider failures; callers retain the fail-closed account reservation.
    fn delete(&self, reference: &str) -> Result<(), SdkError>;
    /// Store branch credentials separately from primary authority.
    /// # Errors
    /// Fails closed on provider failure or an existing entry.
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError>;
    /// Store the one-use local data passphrase for a headless participant until its custodian
    /// exports the provisioning bundle. This secret is independent of primary and branch keys.
    /// # Errors
    /// Fails closed on unsupported providers, an existing entry, or provider failure.
    fn store_provisioning_secret(&self, _reference: &str, _secret: &[u8]) -> Result<(), SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
    /// Load the pending headless-participant data passphrase without exposing authority keys.
    /// # Errors
    /// Rejects unsupported providers and missing or corrupt entries.
    fn load_provisioning_secret(&self, _reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        Err(SdkError::CustodyVaultUnavailable)
    }
    /// Store the agent master seed under `agent-master:<id>` once. Refuses an existing entry.
    /// # Errors
    /// The default refuses with `custody_key_unavailable`; providers without the operation keep it.
    fn store_agent_master(&self, _reference: &str, _master: &MasterKey) -> Result<(), SdkError> {
        Err(agent_key_unavailable())
    }
    /// Issue one master certificate for a genesis or a rebind and record its hash in its own
    /// insert-only item. A retry of the same request returns the recorded certificate; any other
    /// recorded range refuses. Nothing is returned unless the record is written or already equal.
    /// # Errors
    /// The default refuses with `custody_key_unavailable`.
    fn certify_agent_master(
        &self,
        _reference: &str,
        _request: AgentMasterRequest,
    ) -> Result<Envelope<MasterCertificate>, SdkError> {
        Err(agent_key_unavailable())
    }
    /// Remove the agent master seed and the recorded certificate items for ranges
    /// `1..=last_range`. Certificates are removed first, so a failure can be retried.
    /// # Errors
    /// The default refuses with `custody_key_unavailable`.
    fn delete_agent_master(&self, _reference: &str, _last_range: u64) -> Result<(), SdkError> {
        Err(agent_key_unavailable())
    }
    /// Sign a registration decision with the primary branch after user presence. The provider
    /// signs only the exact plan named by the request and only for its human primary.
    /// # Errors
    /// The default refuses with `custody_key_unavailable`; no presence means no signature.
    fn sign_agent_register_decision(
        &self,
        _request: AgentDecisionSigning<'_>,
    ) -> Result<RegisterDecision, SdkError> {
        Err(agent_key_unavailable())
    }
}

/// Vault-reference prefix of the agent master item (seed plus last certificate hash).
pub(crate) const AGENT_MASTER_PREFIX: &str = "agent-master:";

/// Refusal for an agent custody operation the provider cannot perform.
#[must_use]
pub(crate) fn agent_key_unavailable() -> SdkError {
    SdkError::CustodyVault(CustodyVaultReason::KeyUnavailable)
}

/// Inputs for one primary-branch registration decision signature.
pub struct AgentDecisionSigning<'a> {
    /// Primary self-signing item whose presence the provider checks.
    pub primary_reference: &'a str,
    /// Public key the primary item must still hold (checked before any signature).
    pub expected_primary_public_key: &'a str,
    /// Primary branch item (`branch:<id>`) that signs the decision.
    pub branch_reference: &'a str,
    pub principal_id: &'a str,
    pub request: &'a AgentDecisionRequest,
}
/// Data-protection keychain (or another reviewed protected OS store) without synchronization.
pub const VAULT_CLASS_PROTECTED: &str = "software_os_credential_non_synchronizing";
/// macOS login keychain, used only when the process lacks the data-protection entitlement.
/// Items are when-unlocked-this-device-only and non-synchronizing; no user-presence items.
pub const VAULT_CLASS_LOGIN_KEYCHAIN: &str = "software_os_credential_login_keychain";
/// Software OS credential vault. This is not a nonexportable hardware Ed25519 key.
/// macOS uses its protected, explicitly non-synchronizing keychain, or the login keychain
/// when the process has no data-protection entitlement (ad hoc signing). Other platforms
/// fail closed until their primary provider is implemented and reviewed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativePrimaryVault;
#[cfg(target_os = "macos")]
mod native;
#[cfg(any(target_os = "macos", test))]
mod presence;
#[cfg(any(target_os = "macos", test))]
mod primary_items;
impl PrimaryVault for NativePrimaryVault {
    fn vault_class(&self) -> &'static str {
        #[cfg(target_os = "macos")]
        if native::backend().ok() == Some(native::Backend::LoginKeychain) {
            return VAULT_CLASS_LOGIN_KEYCHAIN;
        }
        VAULT_CLASS_PROTECTED
    }
    fn home_authorization_preflight(&self) -> Result<(), SdkError> {
        #[cfg(target_os = "macos")]
        {
            // User presence requires SecAccessControl, which only the protected store has.
            match native::backend() {
                Ok(native::Backend::DataProtection) => Ok(()),
                _ => Err(super::home_authorization::unavailable()),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(super::home_authorization::unavailable())
        }
    }

    fn sign_home_authorization(
        &self,
        request: HomeAuthorizationRequest<'_>,
    ) -> Result<
        ramflux_protocol::home_migration::Signed<ramflux_protocol::home_migration::Authorization>,
        SdkError,
    > {
        #[cfg(target_os = "macos")]
        {
            let primary = presence::approved_primary(
                &native::KeychainItems::PROTECTED,
                request.primary_reference(),
                request.expected_primary_public_key(),
            )?;
            let now = super::home_authorization::now()?.max(request.requested_at);
            request.sign_once(&primary, now)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(super::home_authorization::unavailable())
        }
    }
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        #[cfg(target_os = "macos")]
        {
            native::delete(reference)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = reference;
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        #[cfg(target_os = "macos")]
        {
            let bytes = native::get_branch(reference)?;
            let mut seeds = Zeroizing::new([0; 64]);
            if bytes.len() != 64 {
                return Err(SdkError::CustodyVaultUnavailable);
            }
            seeds.copy_from_slice(&bytes);
            BranchCredentials::from_vault_seeds(principal, device, &seeds)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (reference, principal, device);
            Err(SdkError::CustodyVaultUnavailable)
        }
    }

    fn preflight(&self) -> Result<(), SdkError> {
        #[cfg(target_os = "macos")]
        {
            native::preflight()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        #[cfg(target_os = "macos")]
        {
            native::store_primary(reference, &*key.vault_seed())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (reference, key);
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        #[cfg(target_os = "macos")]
        {
            let bytes = native::get_primary(reference)?;
            let mut seed = Zeroizing::new([0; 32]);
            if bytes.len() != 32 {
                return Err(SdkError::CustodyVaultUnavailable);
            }
            seed.copy_from_slice(&bytes);
            Ok(SelfSigningKey::from_vault_seed(&seed))
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = reference;
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        #[cfg(target_os = "macos")]
        {
            native::store_branch(reference, &**seeds)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (reference, seeds);
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
    fn store_provisioning_secret(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        #[cfg(target_os = "macos")]
        {
            native::put(reference, secret)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (reference, secret);
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
    fn load_provisioning_secret(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        #[cfg(target_os = "macos")]
        {
            native::get(reference)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = reference;
            Err(SdkError::CustodyVaultUnavailable)
        }
    }
    fn store_agent_master(&self, reference: &str, master: &MasterKey) -> Result<(), SdkError> {
        #[cfg(target_os = "macos")]
        {
            agent_master_item::store(&native::AgentCells, reference, master)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (reference, master);
            Err(agent_key_unavailable())
        }
    }
    fn certify_agent_master(
        &self,
        reference: &str,
        request: AgentMasterRequest,
    ) -> Result<Envelope<MasterCertificate>, SdkError> {
        #[cfg(target_os = "macos")]
        {
            agent_master_item::certify(&native::AgentCells, reference, request)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (reference, request);
            Err(agent_key_unavailable())
        }
    }
    fn delete_agent_master(&self, reference: &str, last_range: u64) -> Result<(), SdkError> {
        #[cfg(target_os = "macos")]
        {
            agent_master_item::delete(&native::AgentCells, reference, last_range)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (reference, last_range);
            Err(agent_key_unavailable())
        }
    }
    /// Presence is the approval: the protected primary item is read with user presence (the
    /// same path as `sign_home_authorization`), then the primary branch signs the exact body.
    fn sign_agent_register_decision(
        &self,
        request: AgentDecisionSigning<'_>,
    ) -> Result<RegisterDecision, SdkError> {
        #[cfg(target_os = "macos")]
        {
            require_vault_reference(request.branch_reference, "branch:")?;
            // Bind the body to the exact plan first: a refused plan never asks for presence.
            let body = ramflux_protocol::custody::register_decision_body(request.request)
                .map_err(|_| SdkError::CustodySetupInvalid)?;
            drop(
                presence::approved_primary(
                    &native::KeychainItems::PROTECTED,
                    request.primary_reference,
                    request.expected_primary_public_key,
                )
                .map_err(|_| agent_key_unavailable())?,
            );
            let branch = self
                .load_branch(
                    request.branch_reference,
                    request.principal_id,
                    &request.request.signer,
                )
                .map_err(|_| agent_key_unavailable())?;
            ramflux_crypto::custody::sign_register_decision(&branch.signing, body)
                .map_err(|_| agent_key_unavailable())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = request;
            Err(agent_key_unavailable())
        }
    }
}

/// Branch credentials do not expose a portable export API.
#[derive(Debug)]
pub struct BranchCredentials {
    pub(crate) signing: ramflux_crypto::DeviceBranch,
    pub(crate) agreement: ramflux_crypto::X25519KeyPair,
}
impl BranchCredentials {
    pub(crate) fn signed_prekey_seed(&self) -> Zeroizing<[u8; 32]> {
        // Stable branch-only bootstrap material. Bootstrap forward secrecy requires
        // rotating random prekeys and erasure; tracked separately from identity custody.
        let secret = Zeroizing::new(self.agreement.secret.to_bytes());
        Zeroizing::new(ramflux_crypto::blake3_keyed_derive(
            &secret,
            b"ramflux.identity.custody_signed_prekey.v1",
        ))
    }

    pub(crate) fn prekey_bundle(&self) -> Result<ramflux_crypto::PrekeyBundle, SdkError> {
        let signed = ramflux_crypto::X25519KeyPair::from_seed(*self.signed_prekey_seed());
        Ok(ramflux_crypto::create_prekey_bundle(
            &self.signing,
            &self.agreement,
            "custody-prekey-v1",
            &signed,
            None,
            None,
        )?)
    }

    /// Provider boundary for a branch-only entry, separate from primary credentials.
    /// # Errors
    /// Rejects invalid device names and zero epochs.
    pub fn from_vault_seeds(
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
        seeds: &Zeroizing<[u8; 64]>,
    ) -> Result<Self, SdkError> {
        ramflux_protocol::validate_device_name(&device.device_id)?;
        if device.device_epoch == 0 {
            return Err(SdkError::CustodySetupInvalid);
        }
        let mut signing = Zeroizing::new([0; 32]);
        let mut agreement = Zeroizing::new([0; 32]);
        signing.copy_from_slice(&seeds[..32]);
        agreement.copy_from_slice(&seeds[32..]);
        Ok(Self {
            signing: ramflux_crypto::create_device_branch(
                principal,
                &device.device_id,
                device.device_epoch,
                *signing,
            ),
            agreement: ramflux_crypto::X25519KeyPair::from_seed(*agreement),
        })
    }
}

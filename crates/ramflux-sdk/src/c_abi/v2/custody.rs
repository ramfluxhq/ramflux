// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Host credential storage adapter; the existing SDK ceremony retains all authority decisions.
use crate::SdkError;
use crate::custody::{BranchCredentials, CustodyVaultReason, PrimaryVault};
use ramflux_crypto::custody::SelfSigningKey;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Version 1 host storage operations. References are opaque UTF-8, without a terminating NUL.
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum RamfluxV2CustodyOperation {
    Preflight = 0,
    StorePrimary = 1,
    LoadPrimary = 2,
    Delete = 3,
    StoreBranch = 4,
    LoadBranch = 5,
    StoreProvisioning = 6,
    LoadProvisioning = 7,
}

/// Trusted host provider, copied during open. All callbacks are required, thread safe and
/// synchronous. They must not unwind or reenter this client. `retain` is called once on
/// acceptance; `release` once after the last SDK task using the provider has finished.
/// `context` is a host token (for example a JNI global-reference registry id).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RamfluxV2CustodyProvider {
    pub abi_version: u32,
    pub context: u64,
    pub retain: Option<extern "C" fn(u64)>,
    pub release: Option<extern "C" fn(u64)>,
    /// Return 0 on success; 1 missing, 2 corrupt, 3 permission, 4 locked, 5 busy,
    /// 6 unavailable. Unknown statuses fail closed. The request is borrowed for this call.
    pub invoke: Option<extern "C" fn(context: u64, request: *mut RamfluxV2CustodyRequest) -> i32>,
}

/// One synchronous storage request. Never write beyond `output_capacity` or retain pointers.
/// Store inputs are secret bytes: primary=32, branch=64, provisioning<=4096.
/// Loads write the same bytes and set `output_len`; other operations return length 0.
/// SDK-owned output memory is erased after use. Hosts erase their own temporary copies.
#[repr(C)]
pub struct RamfluxV2CustodyRequest {
    pub operation: RamfluxV2CustodyOperation,
    pub reference: *const u8,
    pub reference_len: usize,
    pub input: *const u8,
    pub input_len: usize,
    pub output: *mut u8,
    pub output_capacity: usize,
    pub output_len: usize,
}

pub(super) struct HostVault(RamfluxV2CustodyProvider);
impl Drop for HostVault {
    fn drop(&mut self) {
        if let Some(release) = self.0.release {
            release(self.0.context);
        }
    }
}

impl HostVault {
    pub(super) fn new(table: RamfluxV2CustodyProvider) -> Result<Arc<Self>, SdkError> {
        if table.abi_version != 1
            || table.retain.is_none()
            || table.release.is_none()
            || table.invoke.is_none()
        {
            return Err(SdkError::CustodySetupInvalid);
        }
        let retain = table.retain.ok_or(SdkError::CustodySetupInvalid)?;
        retain(table.context);
        Ok(Arc::new(Self(table)))
    }

    fn invoke(
        &self,
        operation: RamfluxV2CustodyOperation,
        reference: &str,
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        const MAX_SECRET: usize = 4096;
        use RamfluxV2CustodyOperation as Op;
        match operation {
            Op::Preflight => {}
            Op::StorePrimary | Op::LoadPrimary => {
                crate::custody::require_vault_reference(reference, "")?;
            }
            Op::StoreBranch | Op::LoadBranch => {
                crate::custody::require_vault_reference(reference, "branch:")?;
            }
            Op::StoreProvisioning | Op::LoadProvisioning => {
                crate::custody::require_vault_reference(reference, "agent-provisioning:")?;
            }
            Op::Delete => {
                let prefix = if reference.starts_with("branch:") {
                    "branch:"
                } else if reference.starts_with("agent-provisioning:") {
                    "agent-provisioning:"
                } else {
                    ""
                };
                crate::custody::require_vault_reference(reference, prefix)?;
            }
        }
        if input.len() > MAX_SECRET || reference.len() > 128 {
            return Err(SdkError::CustodySetupInvalid);
        }
        let callback = self.0.invoke.ok_or(SdkError::CustodyVaultUnavailable)?;
        // Copy into SDK-owned callback memory; never lend a long-lived key allocation.
        let mut input = Zeroizing::new(input.to_vec());
        let mut output = Zeroizing::new(vec![0; MAX_SECRET]);
        let mut request = RamfluxV2CustodyRequest {
            operation,
            reference: reference.as_ptr(),
            reference_len: reference.len(),
            input: input.as_ptr(),
            input_len: input.len(),
            output: output.as_mut_ptr(),
            output_capacity: MAX_SECRET,
            output_len: 0,
        };
        let status = callback(self.0.context, &raw mut request);
        // The synchronous borrow ends here, including failed callbacks.
        input.as_mut_slice().zeroize();
        #[cfg(test)]
        record_wiped_input(&input);
        let len = request.output_len;
        let reason = match status {
            0 => None,
            1 => Some(CustodyVaultReason::Missing),
            2 => Some(CustodyVaultReason::Corrupt),
            3 => Some(CustodyVaultReason::Permission),
            4 => Some(CustodyVaultReason::Locked),
            5 => Some(CustodyVaultReason::Busy),
            _ => Some(CustodyVaultReason::PrimaryUnavailable),
        };
        if let Some(reason) = reason {
            return Err(SdkError::CustodyVault(reason));
        }
        if len > MAX_SECRET {
            return Err(SdkError::CustodyVault(CustodyVaultReason::Corrupt));
        }
        output.get_mut(len..).ok_or(SdkError::CustodySetupInvalid)?.zeroize();
        output.truncate(len);
        Ok(output)
    }

    fn store(
        &self,
        operation: RamfluxV2CustodyOperation,
        reference: &str,
        input: &[u8],
    ) -> Result<(), SdkError> {
        if !self.invoke(operation, reference, input)?.is_empty() {
            return Err(SdkError::CustodyVault(CustodyVaultReason::Corrupt));
        }
        Ok(())
    }

    fn load<const N: usize>(
        &self,
        operation: RamfluxV2CustodyOperation,
        reference: &str,
    ) -> Result<Zeroizing<[u8; N]>, SdkError> {
        let bytes = self.invoke(operation, reference, &[])?;
        let mut seed = Zeroizing::new([0; N]);
        if bytes.len() != N {
            return Err(SdkError::CustodyVault(CustodyVaultReason::Corrupt));
        }
        seed.copy_from_slice(&bytes);
        Ok(seed)
    }
}

impl PrimaryVault for HostVault {
    fn preflight(&self) -> Result<(), SdkError> {
        self.store(RamfluxV2CustodyOperation::Preflight, "", &[])
    }
    fn store_new(&self, reference: &str, key: &SelfSigningKey) -> Result<(), SdkError> {
        self.store(RamfluxV2CustodyOperation::StorePrimary, reference, &*key.vault_seed())
    }
    fn load_primary(&self, reference: &str) -> Result<SelfSigningKey, SdkError> {
        Ok(SelfSigningKey::from_vault_seed(
            &self.load(RamfluxV2CustodyOperation::LoadPrimary, reference)?,
        ))
    }
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        self.store(RamfluxV2CustodyOperation::Delete, reference, &[])
    }
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        self.store(RamfluxV2CustodyOperation::StoreBranch, reference, &**seeds)
    }
    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        BranchCredentials::from_vault_seeds(
            principal,
            device,
            &self.load(RamfluxV2CustodyOperation::LoadBranch, reference)?,
        )
    }
    fn store_provisioning_secret(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        self.store(RamfluxV2CustodyOperation::StoreProvisioning, reference, secret)
    }
    fn load_provisioning_secret(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        self.invoke(RamfluxV2CustodyOperation::LoadProvisioning, reference, &[])
    }
}

#[cfg(test)]
thread_local! { pub(super) static WIPED_INPUTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
fn record_wiped_input(input: &[u8]) {
    assert!(input.iter().all(|byte| *byte == 0), "callback input must be wiped before disposal");
    if !input.is_empty() {
        WIPED_INPUTS.with(|count| count.set(count.get() + 1));
    }
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary proof/session startup checks all real pairing owners before opening a transport.
use super::install_store;
use crate::{
    SdkError,
    custody::{BornAccount, CustodyNetworkConfig, PrimaryVault},
};

pub(crate) fn require_network_admission(
    config: &CustodyNetworkConfig,
    account: &BornAccount,
    vault: &dyn PrimaryVault,
    now: u64,
) -> Result<(), SdkError> {
    let installed = install_store::read_installed(&config.account_root, &config.account_id)?;
    if installed.is_none() && !account.pairing_adoption_required() {
        return Ok(());
    }
    let installed = installed.ok_or(SdkError::PairingCode("PublicationPending"))?;
    let reader =
        config.pairing_admission.as_ref().ok_or(SdkError::PairingCode("PublicationPending"))?;
    let adoption = reader
        .read_for(&config.account_root, &config.account_id)?
        .ok_or(SdkError::PairingCode("PublicationPending"))?;
    if installed.full_transfer.is_some() {
        super::full_generation::require_selected_full_generation(
            &config.account_root,
            &installed,
            &adoption,
        )?;
    }
    if super::activate::adoption(&installed)? != adoption
        || !crate::custody::matches_install(account, &installed)?
    {
        return Err(SdkError::PairingCode("PublicationPending"));
    }
    crate::custody::verify_pairing_local(
        &installed,
        &ramflux_protocol::custody::CustodyAuthority {
            publication: account.publication(),
            custodian_publication: account.custodian_publication(&config.account_root, now)?,
        },
        vault,
        now,
    )
}

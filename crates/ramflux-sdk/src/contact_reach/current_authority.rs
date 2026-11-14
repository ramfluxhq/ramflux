// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Current recipient and human-custodian bindings, independent of historical signer proofs.
use crate::SdkError;
use ramflux_crypto::custody::VerifiedRecord;
use ramflux_protocol::custody::{self, CustodyKind};

pub(super) fn custodian_head(authority: &VerifiedRecord) -> Result<Option<String>, SdkError> {
    let certificate = &authority.envelope().body.master_certificate.body;
    if certificate.custody_kind == CustodyKind::LocalHuman {
        return Ok(None);
    }
    let manager = authority.management_actor_authority(&certificate.primary_device_ref)?;
    Ok(Some(custody::object_hash(manager.envelope())?))
}

pub(super) fn require_binding(
    current: &VerifiedRecord,
    recipient: &str,
    custodian: Option<&str>,
) -> Result<(), SdkError> {
    if custody::object_hash(current.envelope())? != recipient
        || custodian_head(current)?.as_deref() != custodian
    {
        return Err(SdkError::InboundPending(
            "reach state requires current recipient and custodian authority".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

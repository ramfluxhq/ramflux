// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Initial home approval is certified master authority, independent of branch possession.
use super::{reject, sign_with_keys, verify_signatures};
use crate::{
    CryptoError,
    custody::{SelfSigningKey, VerifiedRecord},
};
use ramflux_protocol::{
    custody::{CustodyKind, object_hash},
    home_migration::{HomeDeclarationV1, Role, SKEW_SECONDS, Signed, Signer, SignerKey},
};

fn declaration_signer(
    body: &HomeDeclarationV1,
    authority: &VerifiedRecord,
    node: &str,
    now: u64,
) -> Result<Signer, CryptoError> {
    let record = authority.envelope();
    let cert = &record.body.master_certificate;
    if body.principal_id != record.body.principal_id
        || body.account_anchor != record.body.account_anchor
        || body.home_node != node
        || body.created_at > now.saturating_add(SKEW_SECONDS)
        || cert.body.custody_kind != CustodyKind::LocalHuman
        || record.body.principal_kind != ramflux_protocol::PrincipalKind::Human
    {
        return Err(reject("home declaration current master or home mismatch"));
    }
    Ok(Signer {
        role: Role::Management,
        key: SignerKey::MasterCertifiedHome {
            account_anchor: body.account_anchor.clone(),
            master_certificate_hash: object_hash(cert)?,
            public_key: cert.body.self_signing_public_key.clone(),
        },
    })
}

/// Verify initial home consent using the receiver's stored account authority.
/// # Errors
/// Rejects branch signatures, another principal/root/home, stale authority and malformed consent.
pub fn verify_home_declaration(
    declaration: &Signed<HomeDeclarationV1>,
    authority: &VerifiedRecord,
    node: &str,
    now: u64,
) -> Result<(), CryptoError> {
    verify_signatures(declaration)?;
    if declaration.signers != [declaration_signer(&declaration.body, authority, node, now)?] {
        return Err(reject("home declaration signer mismatch"));
    }
    Ok(())
}

impl SelfSigningKey {
    /// Approve the initial home with the current certified master, never a device branch.
    /// # Errors
    /// Rejects a mismatched master, malformed declaration or unavailable account authority.
    pub fn sign_home_declaration(
        &self,
        body: HomeDeclarationV1,
        authority: &VerifiedRecord,
        now: u64,
    ) -> Result<Signed<HomeDeclarationV1>, CryptoError> {
        let signer = declaration_signer(&body, authority, &body.home_node, now)?;
        let key = ed25519_dalek::SigningKey::from_bytes(&self.vault_seed());
        sign_with_keys(body, vec![signer], &[&key])
    }
}

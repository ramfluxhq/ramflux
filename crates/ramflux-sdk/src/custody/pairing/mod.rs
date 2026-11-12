// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant pairing install-store and SDK coordinator. Default-off.
mod activate;
pub(crate) mod admission;
mod coordinator;
mod full_bootstrap;
pub use full_bootstrap::{
    FullBootstrap, FullBootstrapFrame, FullGrantSigningRequest, FullSourceManifestSigningRequest,
};
mod native_ports;
mod participant;
pub use activate::{Installation, PairingAuthorityQuery, activate_recipient, refresh_authority};
pub use native_ports::{NativePairingPublication, NativePairingQuery};
pub use participant::{LocalPairingParticipant, ParticipantContext};
pub mod install_gate;
pub mod install_store;
pub(crate) mod local_credential;
pub(crate) mod publication;
pub(crate) mod recipient;
pub mod transfer_payload;
mod transport;
pub use coordinator::{
    PairingActor, PairingIdentity, handle_bus, install_actor, pairing_enabled, remove_actor,
    validate_head_advance,
};
pub use install_gate::{Admission, ReopenGate, reopen};
pub use install_store::{Install, decode, encode, write_installed, write_pending};
pub use local_credential::{
    CredentialOutcome, LocalCredentialProvider, PersistedReservation, SecretUtf8, acquire_setup,
    acquire_unlock, cancel_credential, load_reservation, persist_reservation, remove_reservation,
};
pub use publication::{
    HeadKind, HeadWrite, NodeHeadPersist, PublishedHead, acknowledge_as_responder, publish_head,
};
pub use recipient::{
    RecipientKeyStaging, RecipientStaging, StageExisting, StageNew, StagedRecipient,
    ordinary_networking_allowed, ordinary_session_admitted, stage_existing, stage_new,
    unadmitted_data_unlock, unlock_with_provider,
};
pub use transport::{
    FreshPairingNative, FullClaimRequest, FullRelayRequest, HttpRelay, PairingConfig,
    PairingNative, PairingTransport, PreparedCreate, PreparedIssue, ProofPairingNative,
};

#[cfg(test)]
mod component_tests;
#[cfg(test)]
mod prove_tests;
#[cfg(test)]
mod tests;

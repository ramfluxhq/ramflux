// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant committed SAS adapter. Unwired: grants no authority and does not change live behaviour.
mod cleanup;
mod full_authority;
mod full_channel;
pub use full_authority::{
    verify_full_data_lease, verify_full_lease_request, verify_full_prepublication_authority,
    verify_full_resume_pair, verify_full_tail_authority,
};
mod hpke;
mod sas;
#[cfg(test)]
mod tests;

pub use cleanup::{HpkeSecrets, PairingSecrets};
#[cfg(test)]
pub use cleanup::{last_wiped_pairing_bytes, take_pairing_secret_cleanups};
pub use full_channel::{FULL_PACKET_PLAINTEXT_BYTES, FullDataCipher, FullOpened};
pub use hpke::{FullDataKeys, FullSenderSetup, open_full_receiver, setup_full_sender};
pub use hpke::{HpkeReceiver, HpkeSender, MAX_HPKE_AEAD_TAG, MAX_HPKE_PLAINTEXT, TransferHpkeAad};
pub use sas::{
    EstablishedSas, PairingRole, PendingSas, SAS_EMOJI, SasEmoji, commit, emoji_from_indices,
};

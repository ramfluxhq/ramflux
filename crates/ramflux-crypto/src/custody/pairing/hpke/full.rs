// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One Auth-HPKE confirmation plus RFC9180 Export; bulk data never uses repeated HPKE Seal.
use super::{
    CryptoError, Deserializable, HpkeSecrets, KemEnc, OpModeS, SeededCsPrng, SuiteAead, SuiteKdf,
    SuiteKem, auth_receiver_mode, enc_bytes, local_and_peer, setup_receiver, setup_sender_with_rng,
};
use ramflux_protocol::{
    custody::pairing::{PairingWire, full_transfer::DataBinding},
    decode_base64url,
};
use zeroize::{Zeroize, Zeroizing};

/// No Clone/Debug/serde: two per-connection exporter keys, destroyed with the connection.
pub struct FullDataKeys {
    pub(crate) initiator: Zeroizing<[u8; 32]>,
    pub(crate) responder: Zeroizing<[u8; 32]>,
    pub(crate) packet_context: Vec<u8>,
}
pub struct FullSenderSetup {
    pub enc: [u8; 32],
    pub confirmation: Vec<u8>,
    pub keys: FullDataKeys,
}

fn b32(value: &str) -> Result<[u8; 32], CryptoError> {
    decode_base64url(value)
        .map_err(|_| CryptoError::Pairing("data_binding"))?
        .try_into()
        .map_err(|_| CryptoError::Pairing("data_binding"))
}
fn info(th: &[u8; 32], binding: &DataBinding) -> Result<Vec<u8>, CryptoError> {
    binding.validate()?;
    let mut info = b"ramflux.identity.transfer.full.hpke_info.v1\0".to_vec();
    info.extend_from_slice(th);
    info.extend_from_slice(&b32(&binding.transfer_id)?);
    info.extend_from_slice(&b32(&binding.manifest_hash)?);
    info.extend_from_slice(&b32(&binding.epoch)?);
    Ok(info)
}
fn exporter_context(
    role: u8,
    th: &[u8; 32],
    binding: &DataBinding,
) -> Result<Vec<u8>, CryptoError> {
    let tag: &[u8] = if role == 0 {
        b"ramflux.pairing.full.data.i.v1"
    } else {
        b"ramflux.pairing.full.data.r.v1"
    };
    let mut context = u32::try_from(tag.len())
        .map_err(|_| CryptoError::Pairing("exporter_context"))?
        .to_be_bytes()
        .to_vec();
    context.extend_from_slice(tag);
    context.extend_from_slice(th);
    context.extend_from_slice(&b32(&binding.manifest_hash)?);
    context.extend_from_slice(&b32(&binding.epoch)?);
    Ok(context)
}
fn export_keys(
    mut export: impl FnMut(&[u8], &mut [u8]) -> Result<(), CryptoError>,
    th: &[u8; 32],
    binding: &DataBinding,
) -> Result<FullDataKeys, CryptoError> {
    let packet_tag = b"ramflux.pairing.full.packet.v1";
    let mut packet_context = u32::try_from(packet_tag.len())
        .map_err(|_| CryptoError::Pairing("packet_context"))?
        .to_be_bytes()
        .to_vec();
    packet_context.extend_from_slice(packet_tag);
    packet_context.extend_from_slice(th);
    packet_context.extend_from_slice(&b32(&binding.transfer_id)?);
    packet_context.extend_from_slice(&b32(&binding.manifest_hash)?);
    packet_context.extend_from_slice(&b32(&binding.epoch)?);
    let mut keys = FullDataKeys {
        initiator: Zeroizing::new([0; 32]),
        responder: Zeroizing::new([0; 32]),
        packet_context,
    };
    export(&exporter_context(0, th, binding)?, keys.initiator.as_mut())?;
    export(&exporter_context(1, th, binding)?, keys.responder.as_mut())?;
    Ok(keys)
}
/// Fresh SAS-committed Auth key and recipient key; never use ordinary branch secrets as HPKE input.
/// The coordinator waits for authenticated Ready before transmitting the encrypted manifest.
/// # Errors
/// Refuses malformed bindings, noncontributory/reflected keys, missing entropy or HPKE failure.
pub fn setup_full_sender(
    mut sender: HpkeSecrets,
    recipient: &[u8; 32],
    th: &[u8; 32],
    binding: &DataBinding,
) -> Result<FullSenderSetup, CryptoError> {
    let result = (|| {
        let keys = local_and_peer(sender.as_bytes(), recipient)?;
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| CryptoError::Pairing("entropy"))?;
        let mut rng = SeededCsPrng::from_seed(&seed);
        seed.zeroize();
        let (enc, mut context) = setup_sender_with_rng::<SuiteAead, SuiteKdf, SuiteKem>(
            &OpModeS::Auth((keys.local_sk, keys.local_pk)),
            &keys.peer_pk,
            &info(th, binding)?,
            &mut rng,
        )
        .map_err(|_| CryptoError::Pairing("hpke_setup"))?;
        let aad = binding.to_wire_bytes()?;
        // Exact AAD as the confirmation plaintext; TH is independently authenticated by info.
        let confirmation =
            context.seal(&aad, &aad).map_err(|_| CryptoError::Pairing("hpke_aead"))?;
        let keys = export_keys(
            |label, output| {
                context.export(label, output).map_err(|_| CryptoError::Pairing("hpke_export"))
            },
            th,
            binding,
        )?;
        Ok(FullSenderSetup { enc: enc_bytes(&enc)?, confirmation, keys })
    })();
    sender.cleanup();
    result
}
/// Verify the single bounded confirmation, then export direction-separated packet keys.
/// # Errors
/// Refuses another sender/transcript/epoch/context or an altered/noncanonical confirmation.
pub fn open_full_receiver(
    mut recipient: HpkeSecrets,
    sender: &[u8; 32],
    enc: &[u8; 32],
    confirmation: &[u8],
    th: &[u8; 32],
    binding: &DataBinding,
) -> Result<FullDataKeys, CryptoError> {
    let result = (|| {
        if confirmation.len() > DataBinding::LIMIT + 16 {
            return Err(CryptoError::Pairing("payload_size"));
        }
        let keys = local_and_peer(recipient.as_bytes(), sender)?;
        let enc = KemEnc::from_bytes(enc).map_err(|_| CryptoError::Pairing("enc"))?;
        let mut context = setup_receiver::<SuiteAead, SuiteKdf, SuiteKem>(
            &auth_receiver_mode(keys.peer_pk),
            &keys.local_sk,
            &enc,
            &info(th, binding)?,
        )
        .map_err(|_| CryptoError::Pairing("hpke_setup"))?;
        let aad = binding.to_wire_bytes()?;
        let opened = Zeroizing::new(
            context.open(confirmation, &aad).map_err(|_| CryptoError::Pairing("hpke_open"))?,
        );
        if opened.as_slice() != aad {
            return Err(CryptoError::Pairing("hpke_confirmation"));
        }
        export_keys(
            |label, output| {
                context.export(label, output).map_err(|_| CryptoError::Pairing("hpke_export"))
            },
            th,
            binding,
        )
    })();
    recipient.cleanup();
    result
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::VaultSecretSource;
type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn pairing_stage_key_scope_and_unlocked_writer_are_required() -> TestResult {
    let (root, db) = crate::tests::test_db("stage-key-scope")?;
    let (stage, wrapped) = db.create_full_stage_key(&[7; 32], PairingRole::Initiator)?;
    assert_ne!(stage.key.bytes(), db.current_key.bytes());
    let encoded = wrapped.to_file_bytes()?;
    assert!(encoded.len() <= 1024);
    let wrapped = WrappedFullStageKey::from_file_bytes(&encoded)?;
    let reopened = db.open_full_stage_key(&[7; 32], PairingRole::Initiator, &wrapped)?;
    assert_eq!(stage.key.bytes(), reopened.key.bytes());
    assert!(db.open_full_stage_key(&[8; 32], PairingRole::Initiator, &wrapped).is_err());
    assert!(db.open_full_stage_key(&[7; 32], PairingRole::Responder, &wrapped).is_err());
    let mut corrupt = WrappedFullStageKey { nonce: wrapped.nonce, ciphertext: wrapped.ciphertext };
    corrupt.ciphertext[0] ^= 1;
    assert!(db.open_full_stage_key(&[7; 32], PairingRole::Initiator, &corrupt).is_err());
    let (_foreign_root, mut foreign) = crate::tests::test_db("stage-key-foreign")?;
    foreign.rekey(&AccountDbKey::generate()?)?;
    assert!(foreign.open_full_stage_key(&[7; 32], PairingRole::Initiator, &wrapped).is_err());
    let expected_aad = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::try_from(WRAP_DOMAIN.len())?.to_be_bytes());
        bytes.extend_from_slice(WRAP_DOMAIN);
        bytes.extend_from_slice(&4_u32.to_be_bytes());
        bytes.extend_from_slice(b"acct");
        bytes.extend_from_slice(&[7; 32]);
        bytes.push(0);
        bytes
    };
    assert_eq!(wrap_aad("acct", &[7; 32], PairingRole::Initiator)?, expected_aad);
    let historical = db.open_reader()?;
    assert!(historical.create_full_stage_key(&[7; 32], PairingRole::Initiator).is_err());
    drop((stage, reopened));
    drop(db); // Only the retained query snapshot remains; it is not an unlocked writer.
    assert!(historical.open_full_stage_key(&[7; 32], PairingRole::Initiator, &wrapped).is_err());
    let readable = Zeroizing::new(crate::FileVaultSecretSource::new(&root).vault_secret("acct")?);
    assert_ne!(readable.as_ref(), &[0; 32]);
    // Independent locked-file attack: using the readable file-vault secret directly
    // must not unwrap the actual stage.key bytes, even with the correct public AAD.
    let mut exposed = Zeroizing::new(wrapped.ciphertext.to_vec());
    assert!(
        ChaCha20Poly1305::new(Key::from_slice(readable.as_ref()))
            .decrypt_in_place(
                Nonce::from_slice(&wrapped.nonce),
                &wrap_aad("acct", &[7; 32], PairingRole::Initiator)?,
                &mut *exposed
            )
            .is_err(),
        "readable file-vault secret decrypted the stage key after lock"
    );
    assert!(
        historical.open_full_stage_key(&[7; 32], PairingRole::Initiator, &wrapped).is_err(),
        "readable file-vault material cannot replace ordinary unlock"
    );
    Ok(())
}
#[test]
fn pairing_stage_chunk_aead_binds_manifest_direction_index_and_length() -> TestResult {
    let (_root, db) = crate::tests::test_db("stage-chunk-aead")?;
    let (stage, _) = db.create_full_stage_key(&[7; 32], PairingRole::Initiator)?;
    let input = Zeroizing::new(vec![19; CHUNK_BYTES as usize]);
    let one = stage.seal_chunk(&[9; 32], StageDirection::Forward, 255, &input)?;
    let two = stage.seal_chunk(&[9; 32], StageDirection::Forward, 255, &input)?;
    assert_eq!(one.as_file_bytes().len(), CHUNK_BYTES as usize + 28);
    assert_ne!(&one.as_file_bytes()[..12], &two.as_file_bytes()[..12]);
    let read = EncryptedStageChunk::from_file_bytes(Zeroizing::new(one.as_file_bytes().to_vec()))?;
    assert_eq!(
        stage.open_chunk(&[9; 32], StageDirection::Forward, 255, CHUNK_BYTES, &read)?.as_slice(),
        input.as_slice()
    );
    assert!(stage.open_chunk(&[10; 32], StageDirection::Forward, 255, CHUNK_BYTES, &read).is_err());
    assert!(stage.open_chunk(&[9; 32], StageDirection::Reverse, 255, CHUNK_BYTES, &read).is_err());
    assert!(stage.open_chunk(&[9; 32], StageDirection::Forward, 256, CHUNK_BYTES, &read).is_err());
    assert!(
        stage.open_chunk(&[9; 32], StageDirection::Forward, 255, CHUNK_BYTES - 1, &read).is_err()
    );
    let mut damaged = Zeroizing::new(read.as_file_bytes().to_vec());
    damaged[12] ^= 1;
    let damaged = EncryptedStageChunk::from_file_bytes(damaged)?;
    assert!(
        stage.open_chunk(&[9; 32], StageDirection::Forward, 255, CHUNK_BYTES, &damaged).is_err()
    );
    assert!(stage.seal_chunk(&[9; 32], StageDirection::Forward, 0, &[]).is_err());
    assert!(
        stage
            .seal_chunk(&[9; 32], StageDirection::Forward, 0, &vec![0; CHUNK_BYTES as usize + 1])
            .is_err()
    );
    Ok(())
}

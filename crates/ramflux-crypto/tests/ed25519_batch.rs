use ed25519_dalek::{Signer, SigningKey};
use ramflux_crypto::{
    CanonicalSignatureBatchItem, CanonicalSignatureSingleKeyBatchItem,
    verify_canonical_signatures_batch, verify_canonical_signatures_batch_single_key,
};

#[test]
fn canonical_signature_batch_accepts_all_valid_items() {
    let (public_key, messages, signatures) = batch_fixture(8);
    let items = batch_items(&public_key, &messages, &signatures);

    assert_eq!(verify_canonical_signatures_batch(&items), Ok(()));
}

#[test]
fn canonical_signature_batch_reports_bad_signature_index() {
    let (public_key, messages, mut signatures) = batch_fixture(8);
    signatures[3][0] ^= 0x55;
    let items = batch_items(&public_key, &messages, &signatures);

    assert_eq!(verify_canonical_signatures_batch(&items), Err(vec![3]));
}

#[test]
fn canonical_signature_single_key_batch_accepts_all_valid_items() {
    let (public_key, messages, signatures) = batch_fixture(8);
    let items = single_key_batch_items(&messages, &signatures);

    assert_eq!(verify_canonical_signatures_batch_single_key(&public_key, &items), Ok(()));
}

#[test]
fn canonical_signature_single_key_batch_reports_bad_signature_index() {
    let (public_key, messages, mut signatures) = batch_fixture(8);
    signatures[4][0] ^= 0x55;
    let items = single_key_batch_items(&messages, &signatures);

    assert_eq!(verify_canonical_signatures_batch_single_key(&public_key, &items), Err(vec![4]));
}

fn batch_fixture(total: usize) -> ([u8; 32], Vec<Vec<u8>>, Vec<[u8; 64]>) {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    let mut messages = Vec::with_capacity(total);
    let mut signatures = Vec::with_capacity(total);
    for index in 0..total {
        let mut message = Vec::with_capacity(48);
        message.extend_from_slice(b"ramflux.crypto.batch_test.v1:");
        message.extend_from_slice(&u64::try_from(index).unwrap_or(u64::MAX).to_be_bytes());
        signatures.push(signing_key.sign(&message).to_bytes());
        messages.push(message);
    }
    (public_key, messages, signatures)
}

fn batch_items<'a>(
    public_key: &'a [u8; 32],
    messages: &'a [Vec<u8>],
    signatures: &'a [[u8; 64]],
) -> Vec<CanonicalSignatureBatchItem<'a>> {
    messages
        .iter()
        .zip(signatures.iter())
        .map(|(message, signature)| CanonicalSignatureBatchItem {
            public_key_bytes: public_key,
            canonical: message,
            signature_bytes: signature,
        })
        .collect()
}

fn single_key_batch_items<'a>(
    messages: &'a [Vec<u8>],
    signatures: &'a [[u8; 64]],
) -> Vec<CanonicalSignatureSingleKeyBatchItem<'a>> {
    messages
        .iter()
        .zip(signatures.iter())
        .map(|(message, signature)| CanonicalSignatureSingleKeyBatchItem {
            canonical: message,
            signature_bytes: signature,
        })
        .collect()
}

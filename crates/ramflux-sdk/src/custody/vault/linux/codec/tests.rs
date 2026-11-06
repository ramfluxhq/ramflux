// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::super::cleanup::observer;
use super::*;
use serde::Deserialize;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Deserialize)]
struct Corpus {
    oracle: String,
    commit: String,
    source_sha256: String,
    vectors: Vec<Vector>,
}
#[derive(Deserialize)]
struct Vector {
    name: String,
    realm: u8,
    kind: u8,
    vault_id: String,
    generation: u64,
    key_id: String,
    nonce: String,
    account: String,
    reference: String,
    plaintext: String,
    key: String,
    record: String,
}
fn hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()
}
fn vectors() -> Result<Corpus, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/fixtures/linux_vault_vectors.json"
    )))?)
}
impl Vector {
    fn binding(&self) -> Result<Binding<'_>, Box<dyn std::error::Error>> {
        Ok(Binding {
            realm: self.realm,
            kind: self.kind,
            vault_id: hex(&self.vault_id)?.try_into().map_err(|_| "vault id")?,
            generation: self.generation,
            key_id: hex(&self.key_id)?.try_into().map_err(|_| "key id")?,
            account: &self.account,
            reference: &self.reference,
        })
    }
    fn kek(&self) -> Result<Secret<32>, Box<dyn std::error::Error>> {
        let mut key = Secret::new("p02-kek");
        key.bytes_mut().copy_from_slice(&hex(&self.key)?);
        Ok(key)
    }
}
fn assert_error(binding: Binding<'_>, key: &Secret<32>, record: &[u8], expected: Error) {
    assert_eq!(open(binding, key, record).err(), Some(expected));
}
#[test]
fn linux_vault_codec_matches_libsodium_and_rejects_transplants() -> TestResult {
    let vectors = vectors()?;
    assert_eq!(vectors.oracle, "libsodium C 1.0.20");
    assert_eq!(vectors.commit, "9511c982fb1d046470a8b42aa36556cdb7da15de");
    assert_eq!(
        vectors.source_sha256,
        "533e374cf8fd1e3356d39d1ad95c8e23dd95d6340db187ed2b57b04b87d1195b"
    );
    for v in &vectors.vectors {
        let binding = v.binding()?;
        let key = v.kek()?;
        let plaintext = Plaintext::new(&hex(&v.plaintext)?)?;
        let record = hex(&v.record)?;
        let nonce: [u8; 24] = hex(&v.nonce)?.try_into().map_err(|_| "nonce")?;
        assert_eq!(seal_nonce(binding, &key, &plaintext, &nonce)?, record, "{}", v.name);
        let opened = open(binding, &key, &record)?;
        assert_eq!(opened.bytes(), plaintext.bytes(), "{}", v.name);
        let parsed = Header::decode(&record)?;
        assert_eq!(parsed.encode(), record[..HEADER_LEN]);
        assert_eq!(
            seal_nonce(binding, &key, &opened, &parsed.nonce)?,
            record,
            "decode/encode identity"
        );
        if v.name == "maximum" {
            assert_eq!(record.len(), MAX_RECORD);
            assert_eq!(opened.bytes().len(), MAX_PLAINTEXT);
        }
    }
    let base = vectors.vectors.first().ok_or("base vector")?;
    let binding = base.binding()?;
    let key = base.kek()?;
    let original = hex(&base.record)?;
    assert_header_negatives(&vectors, &original, binding, &key)?;
    // Valid foreign records cannot use their self-described IDs as caller authority.
    for (field, mut foreign) in [("vault", binding), ("generation", binding), ("key", binding)] {
        match field {
            "vault" => foreign.vault_id[0] ^= 1,
            "generation" => foreign.generation += 1,
            _ => foreign.key_id[0] ^= 1,
        }
        assert_error(foreign, &key, &original, Error::Authentication);
    }
    assert_error(
        Binding { account: "account_b", ..binding },
        &key,
        &original,
        Error::Authentication,
    );
    let reference = format!("agent-provisioning:B{}", "A".repeat(42));
    assert_error(
        Binding { reference: &reference, ..binding },
        &key,
        &original,
        Error::Authentication,
    );
    assert_error(
        Binding {
            realm: 1,
            kind: 1,
            reference: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ..binding
        },
        &key,
        &original,
        Error::Authentication,
    );
    assert_error(
        Binding { kind: 4, reference: "unlock:account_a", ..binding },
        &key,
        &original,
        Error::Authentication,
    );
    let unlock = vectors.vectors.iter().find(|v| v.name == "kind").ok_or("unlock vector")?;
    assert_error(
        Binding { reference: "unlock:other", ..unlock.binding()? },
        &unlock.kek()?,
        &hex(&unlock.record)?,
        Error::Reference,
    );
    let mut wrong_key = Secret::<32>::new("p02-kek");
    wrong_key.bytes_mut().fill(7);
    assert_error(binding, &wrong_key, &original, Error::Authentication);
    for account in ["", ".", "..", "a/b", "a\0", "é", &"a".repeat(129)] {
        assert_error(Binding { account, ..binding }, &key, &original, Error::Account);
    }
    for reference in [
        "",
        "../x",
        "agent-provisioning:A",
        "branch:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "agent-provisioning:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ] {
        assert_error(Binding { reference, ..binding }, &key, &original, Error::Reference);
    }
    let input = Plaintext::new(&[17; 32])?;
    let first = seal(binding, &key, &input)?;
    let second = seal(binding, &key, &input)?;
    assert_ne!(&first[52..76], &second[52..76]);
    assert_eq!(open(binding, &key, &first)?.bytes(), input.bytes());
    Ok(())
}

fn assert_header_negatives(
    vectors: &Corpus,
    original: &[u8],
    binding: Binding<'_>,
    key: &Secret<32>,
) -> TestResult {
    // Every serialized header field, and ciphertext/tag, has a specific refusal.
    for (offset, value, error) in [
        (0, 0, Error::Magic),
        (8, 1, Error::Version),
        (10, 4, Error::Realm),
        (11, 5, Error::Kind),
        (10, 1, Error::Combination),
        (11, 4, Error::Authentication),
        (12, 255, Error::Authentication),
        (28, 1, Error::Authentication),
        (35, 0, Error::Generation),
        (36, 255, Error::Authentication),
        (52, 255, Error::Authentication),
        (79, 31, Error::RecordSize),
        (80, 255, Error::Authentication),
        (original.len() - 1, 255, Error::Authentication),
    ] {
        let mut record = original.to_vec();
        record[offset] = value;
        assert_error(binding, key, &record, error);
    }
    for len in [0_u32, 8193, u32::MAX] {
        let mut record = original.to_vec();
        record[76..80].copy_from_slice(&len.to_be_bytes());
        assert_error(binding, key, &record, Error::Length);
    }
    for (realm, kind) in [(1, 2), (1, 3), (1, 4), (2, 1), (2, 3), (2, 4), (3, 1), (3, 2)] {
        let mut record = original.to_vec();
        record[10] = realm;
        record[11] = kind;
        assert_error(binding, key, &record, Error::Combination);
    }
    for realm in [0, 4, 255] {
        let mut record = original.to_vec();
        record[10] = realm;
        assert_error(binding, key, &record, Error::Realm);
    }
    for kind in [0, 5, 255] {
        let mut record = original.to_vec();
        record[11] = kind;
        assert_error(binding, key, &record, Error::Kind);
    }
    for v in &vectors.vectors {
        let mut record = hex(&v.record)?;
        for len in [0_u32, 31, 33, 63, 65, 8193] {
            if v.kind <= 2 {
                record[76..80].copy_from_slice(&len.to_be_bytes());
                assert_error(v.binding()?, &v.kek()?, &record, Error::Length);
            }
        }
    }
    let mut trailing = original.to_vec();
    trailing.push(0);
    assert_error(binding, key, &trailing, Error::RecordSize);
    assert_error(binding, key, &original[..original.len() - 1], Error::RecordSize);
    assert_error(binding, key, &[], Error::RecordSize);
    assert_error(binding, key, &vec![0; MAX_RECORD + 1], Error::RecordSize);
    Ok(())
}

fn observed(case: &str, expected: &[&str]) {
    let observations = observer::take();
    for label in expected {
        assert!(observations.iter().any(|item| item.label == *label), "{case}: missing {label}");
    }
    for observation in observations {
        assert!(
            observation.bytes.iter().all(|byte| *byte == 0),
            "{case}: uncleared {}",
            observation.label
        );
    }
}
#[test]
fn linux_vault_owned_buffers_clear_on_all_exits() -> TestResult {
    let vectors = vectors()?;
    let base = vectors.vectors.first().ok_or("base")?;
    let binding = base.binding()?;
    observer::begin();
    {
        let key = base.kek()?;
        let input = Plaintext::new(&[33; 32])?;
        let record = seal(binding, &key, &input)?;
        let opened = open(binding, &key, &record)?;
        assert_eq!(opened.bytes(), input.bytes());
    }
    observed("P02 success", &["p02-kek", "p02-input", "p02-nonce", "p02-aead", "p02-readback"]);
    observer::begin();
    {
        let key = base.kek()?;
        let mut record = hex(&base.record)?;
        record[80] ^= 1;
        assert_error(binding, &key, &record, Error::Authentication);
    }
    observed("P02 failed decrypt", &["p02-kek", "p02-readback"]);
    observer::begin();
    {
        let key = base.kek()?;
        let input = Plaintext::new(&[44; 32])?;
        let result = seal_random(binding, &key, &input, |nonce| {
            nonce.fill(55);
            Err(Error::Random)
        });
        assert_eq!(result, Err(Error::Random));
    }
    observed("P02 partial RNG failure", &["p02-kek", "p02-input", "p02-nonce"]);
    observer::begin();
    {
        let key = base.kek()?;
        let input = Plaintext::new(&[66; 32])?;
        assert_eq!(
            seal(Binding { generation: 0, ..binding }, &key, &input),
            Err(Error::Generation)
        );
        assert!(matches!(Plaintext::new(&[]), Err(Error::Length)));
        assert!(matches!(Plaintext::new(&[0; MAX_PLAINTEXT + 1]), Err(Error::Length)));
    }
    observed("P02 format rejection", &["p02-kek", "p02-input"]);
    observer::begin();
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let (ready, wait) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let mut key = Secret::<32>::new("p02-kek");
            key.bytes_mut().fill(77);
            let input = Plaintext::new(&[88; 32])?;
            let binding = Binding {
                realm: 3,
                kind: 3,
                vault_id: [1; 16],
                generation: 1,
                key_id: [2; 16],
                account: "account_a",
                reference: "agent-provisioning:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            };
            let record = seal(binding, &key, &input)?;
            let readback = open(binding, &key, &record)?;
            let _held = (key, input, readback);
            assert!(ready.send(()).is_ok());
            std::future::pending::<Result<(), Error>>().await
        });
        wait.await?;
        handle.abort();
        assert!(handle.await.is_err_and(|error| error.is_cancelled()));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    observed(
        "P02 cancelled owner",
        &["p02-kek", "p02-input", "p02-nonce", "p02-aead", "p02-readback"],
    );
    Ok(())
}

const RULE_ACCOUNT: &str = "account_a";

fn rule_binding<'a>(realm: u8, kind: u8, account: &'a str, reference: &'a str) -> Binding<'a> {
    Binding { realm, kind, vault_id: [1; 16], generation: 1, key_id: [2; 16], account, reference }
}

fn rule_len(kind: u8) -> usize {
    if kind == 2 { 64 } else { 32 }
}

fn rule_seal(
    realm: u8,
    kind: u8,
    account: &str,
    reference: &str,
    len: usize,
) -> Result<(Vec<u8>, Secret<32>), Box<dyn std::error::Error>> {
    let mut key = Secret::<32>::new("p02-kek");
    key.bytes_mut().fill(9);
    let input = Plaintext::new(&vec![7; len])?;
    let binding = rule_binding(realm, kind, account, reference);
    let record = seal(binding, &key, &input)?;
    assert_eq!(open(binding, &key, &record)?.bytes().len(), len);
    Ok((record, key))
}

#[test]
fn linux_vault_reference_rules_are_isolated_per_kind() -> TestResult {
    // Canonical 43-char base64url suffix of 32 bytes; the 0x5a tail char is 'o' (index 40).
    let canonical = ramflux_protocol::encode_base64url([0x5a_u8; 32]);
    assert_eq!(canonical.len(), 43);
    // Same 43 chars with unused tail bits set (index 41 = 'p'): 43 chars, noncanonical.
    let mut tail = canonical.clone();
    tail.pop();
    tail.push('p');
    // Inclusive suffix bounds: all-zero and all-0xff bytes, both canonical 43-char strings.
    let zero = ramflux_protocol::encode_base64url([0_u8; 32]);
    let full = ramflux_protocol::encode_base64url([0xff_u8; 32]);
    assert_eq!((zero.len(), full.len(), tail.len()), (43, 43, 43));

    // Primary (realm 1, no prefix), branch (realm 2), agent-provisioning (realm 3).
    for (realm, kind, prefix) in
        [(1_u8, 1_u8, ""), (2, 2, "branch:"), (3, 3, "agent-provisioning:")]
    {
        let len = rule_len(kind);
        let (record, key) =
            rule_seal(realm, kind, RULE_ACCOUNT, &format!("{prefix}{canonical}"), len)?;
        let mut cases: Vec<(&str, String)> = vec![
            // Suffix length rule: 43 chars is exactly 32 decoded bytes.
            ("suffix short 42", format!("{prefix}{}", &canonical[..42])),
            ("suffix long 44", format!("{prefix}{canonical}A")),
            // Canonical rule: decodable 43 chars whose unused tail bits are nonzero.
            ("noncanonical tail", format!("{prefix}{tail}")),
            // Alphabet rule: padding and standard-base64 characters are not base64url.
            ("alphabet padding", format!("{prefix}{}=", &canonical[..42])),
            ("alphabet plus", format!("{prefix}+{}", &canonical[1..])),
        ];
        if kind != 1 {
            // Prefix rule: branch and agent-provisioning require their exact prefix.
            cases.push(("prefix missing", canonical.clone()));
            let other = if kind == 2 { "agent-provisioning:" } else { "branch:" };
            cases.push(("prefix wrong", format!("{other}{canonical}")));
        }
        for (label, reference) in cases {
            assert_eq!(
                open(rule_binding(realm, kind, RULE_ACCOUNT, &reference), &key, &record).err(),
                Some(Error::Reference),
                "kind {kind}: {label}"
            );
        }
        // Positive controls at the inclusive suffix bounds, with the same kind-specific length.
        for bound in [&zero, &full] {
            rule_seal(realm, kind, RULE_ACCOUNT, &format!("{prefix}{bound}"), len)?;
        }
    }

    // Unlock (realm 3, kind 4): the reference must be exactly `unlock:<account>`.
    let (record, key) = rule_seal(3, 4, RULE_ACCOUNT, "unlock:account_a", 32)?;
    for (label, reference) in [
        ("prefix missing", RULE_ACCOUNT.to_owned()),
        ("prefix wrong", "lock:account_a".to_owned()),
        ("subject other account", "unlock:account_b".to_owned()),
        ("subject trailing space", "unlock:account_a ".to_owned()),
    ] {
        assert_eq!(
            open(rule_binding(3, 4, RULE_ACCOUNT, &reference), &key, &record).err(),
            Some(Error::Reference),
            "kind 4: {label}"
        );
    }
    // Positive controls at the inclusive bounds: 128-char account, plaintext 1 and 8192.
    let max_account = "a".repeat(128);
    let max_reference = format!("unlock:{max_account}");
    rule_seal(3, 4, &max_account, &max_reference, 1)?;
    rule_seal(3, 4, &max_account, &max_reference, MAX_PLAINTEXT)?;
    // Agent-provisioning kind 3 at plaintext bounds 1 and 8192.
    let kind3 = format!("agent-provisioning:{full}");
    rule_seal(3, 3, RULE_ACCOUNT, &kind3, 1)?;
    rule_seal(3, 3, RULE_ACCOUNT, &kind3, MAX_PLAINTEXT)?;
    Ok(())
}

// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant sidecar signatures, bound to independently refreshed native custody heads.
use crate::custody::{SelfSigningKey, VerifiedRecord};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ramflux_protocol::{
    PrincipalKind,
    agent_profile::{
        AgentProfileEnvelope, AgentProfileError as E, AgentProfileV1, decode_agent_profile,
        encode_agent_profile,
    },
    custody::{CustodyKind, object_hash, signing_bytes},
    domain,
};

fn authority(
    body: &AgentProfileV1,
    agent: &VerifiedRecord,
    human: &VerifiedRecord,
    now: u64,
) -> Result<(), E> {
    // Both arguments must be fresh heads selected under the caller's durable authority pins.
    let custodian = &human.envelope().body;
    if custodian.principal_kind != PrincipalKind::Human
        || custodian.master_certificate.body.custody_kind != CustodyKind::LocalHuman
        || agent.envelope().body.master_certificate.body.primary_device_ref
            != custodian.master_certificate.body.primary_device_ref
    {
        return Err(E::NativeAuthority);
    }
    human
        .authorize(&custodian.master_certificate.body.primary_device_ref, "register", now)
        .map_err(|_| E::NativeAuthority)?;
    let native = &agent.envelope().body;
    if native.principal_kind != PrincipalKind::HeadlessAi
        || native.profile.kind != PrincipalKind::HeadlessAi
        || native.master_certificate.body.custody_kind != CustodyKind::ExternalHuman
    {
        return Err(E::Kind);
    }
    if native.account_anchor != body.agent_anchor {
        return Err(E::AgentAnchor);
    }
    if object_hash(agent.envelope()).map_err(|_| E::NativeAuthority)? != body.agent_custody_hash {
        return Err(E::NativeHead);
    }
    if native.profile.custodian.as_ref() != Some(&body.custodian_primary)
        || body.custodian_anchor != human.envelope().body.account_anchor
        || body.custodian_primary
            != human.envelope().body.master_certificate.body.primary_device_ref
    {
        return Err(E::Custodian);
    }
    Ok(())
}

impl SelfSigningKey {
    /// Sign local metadata using the current certified agent primary, after human consent.
    /// The caller owns consent and fresh durable head selection; no master key is loaded.
    /// # Errors
    /// Rejects malformed metadata, stale/wrong native authority and unrelated signers.
    pub fn sign_agent_profile(
        &self,
        body: AgentProfileV1,
        agent: &VerifiedRecord,
        human: &VerifiedRecord,
        now: u64,
    ) -> Result<AgentProfileEnvelope, E> {
        let body = body.normalize_local()?;
        authority(&body, agent, human, now)?;
        if self.public_key()
            != agent.envelope().body.master_certificate.body.self_signing_public_key
        {
            return Err(E::Signer);
        }
        let bytes = signing_bytes(domain::AGENT_PROFILE, &body).map_err(|_| E::Wire)?;
        let key = SigningKey::from_bytes(&self.vault_seed());
        let envelope = AgentProfileEnvelope {
            body,
            signature: ramflux_protocol::encode_base64url(key.sign(&bytes).to_bytes()),
        };
        encode_agent_profile(&envelope)?;
        Ok(envelope)
    }
}

/// Verify original received bytes against fresh independently selected agent and human heads.
/// # Errors
/// Refuses wire violations, stale native heads, wrong custody or invalid primary signatures.
pub fn verify_agent_profile(
    bytes: &[u8],
    agent: &VerifiedRecord,
    human: &VerifiedRecord,
    now: u64,
) -> Result<AgentProfileEnvelope, E> {
    let envelope = decode_agent_profile(bytes)?;
    authority(&envelope.body, agent, human, now)?;
    let raw = ramflux_protocol::decode_base64url(
        &agent.envelope().body.master_certificate.body.self_signing_public_key,
    )
    .map_err(|_| E::NativeAuthority)?;
    let raw: [u8; 32] = raw.try_into().map_err(|_| E::NativeAuthority)?;
    let key = VerifyingKey::from_bytes(&raw).map_err(|_| E::NativeAuthority)?;
    let signature =
        ramflux_protocol::decode_base64url(&envelope.signature).map_err(|_| E::Signature)?;
    let signature = Signature::from_slice(&signature).map_err(|_| E::Signature)?;
    key.verify_strict(
        &signing_bytes(domain::AGENT_PROFILE, &envelope.body).map_err(|_| E::Wire)?,
        &signature,
    )
    .map_err(|_| E::Signature)?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::{GenesisInput, MasterKey, RecoveryPhrase, create_genesis, verify_record};
    use ramflux_protocol::{
        MAX_SAFE_JSON_INTEGER,
        agent_profile::agent_profile_digest,
        canonical_json_bytes,
        custody::{DeviceSet, Envelope},
        encode_base64url,
    };
    use serde_json::{Value, json};
    use zeroize::Zeroizing;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    const NOW: u64 = 1_700_000_000;

    fn genesis(
        seed: u8,
        kind: PrincipalKind,
        custodian: Option<ramflux_protocol::custody::DeviceRef>,
    ) -> Result<(SelfSigningKey, Envelope<DeviceSet>)> {
        let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[seed; 32])?)?;
        let primary = SelfSigningKey::from_vault_seed(&Zeroizing::new([seed + 2; 32]));
        let branch = crate::create_device_branch("vector.example", "primary", 1, [seed + 3; 32]);
        let agreement = crate::X25519KeyPair::from_seed([seed + 4; 32]);
        let record = create_genesis(
            &master,
            &primary,
            &branch,
            &agreement,
            GenesisInput {
                principal_kind: kind,
                display_name: "Vector Human".into(),
                issued_at: NOW,
                master_cert_id: encode_base64url([5; 32]),
                branch_cert_id: encode_base64url([6; 32]),
                external_human_primary: custodian,
            },
        )?;
        Ok((primary, record))
    }

    fn body(agent: &VerifiedRecord, human: &VerifiedRecord) -> Result<AgentProfileV1> {
        Ok(AgentProfileV1 {
            schema: domain::AGENT_PROFILE.into(),
            version: 1,
            agent_anchor: agent.envelope().body.account_anchor.clone(),
            agent_custody_hash: object_hash(agent.envelope())?,
            custodian_anchor: human.envelope().body.account_anchor.clone(),
            custodian_primary: human
                .envelope()
                .body
                .master_certificate
                .body
                .primary_device_ref
                .clone(),
            kind: "headless_ai".into(),
            profile_epoch: 1,
            responsibility: "Research".into(),
            provider: "local".into(),
            model: "model".into(),
            persona_version: 1,
            persona_hash: encode_base64url([7; 32]),
        })
    }

    fn raw_sign(body: AgentProfileV1, signer: &SelfSigningKey) -> Result<AgentProfileEnvelope> {
        let bytes = signing_bytes(domain::AGENT_PROFILE, &body)?;
        let key = SigningKey::from_bytes(&signer.vault_seed());
        Ok(AgentProfileEnvelope { body, signature: encode_base64url(key.sign(&bytes).to_bytes()) })
    }

    fn refused(value: &Value, expected: E) -> Result {
        assert_eq!(decode_agent_profile(&canonical_json_bytes(value)?), Err(expected));
        Ok(())
    }

    #[test]
    fn agent_profile_sidecar_binds_current_native_authority() -> Result {
        let (human_key, human_record) = genesis(0, PrincipalKind::Human, None)?;
        let human = verify_record(&human_record, NOW, None, None)?;
        let (key, record) = genesis(
            10,
            PrincipalKind::HeadlessAi,
            Some(human_record.body.master_certificate.body.primary_device_ref.clone()),
        )?;
        let agent = verify_record(&record, NOW, None, Some(&human))?;
        let profile = body(&agent, &human)?;
        let signed = key.sign_agent_profile(profile.clone(), &agent, &human, NOW)?;
        let wire = encode_agent_profile(&signed)?;
        assert_eq!(verify_agent_profile(&wire, &agent, &human, NOW)?, signed);
        // Actual successor native head makes the previously valid signed sidecar stale.
        let mut next = record.body.clone();
        next.device_set_epoch += 1;
        next.previous_record_hash = Some(object_hash(&record)?);
        let next = key.sign_record(next)?;
        let next = verify_record(&next, NOW, None, Some(&human))?;
        assert_eq!(verify_agent_profile(&wire, &next, &human, NOW), Err(E::NativeHead));
        let mut stale = profile.clone();
        stale.agent_custody_hash = encode_base64url([8; 32]);
        let stale = raw_sign(stale, &key)?;
        assert_eq!(
            verify_agent_profile(&encode_agent_profile(&stale)?, &agent, &human, NOW),
            Err(E::NativeHead)
        );
        oracle(&signed, &record)?;

        // Every independently signed body field, including every nested reference field.
        let original = serde_json::to_value(&signed)?;
        for (path, replacement, expected) in [
            ("/body/schema", json!("other"), E::Field("schema")),
            ("/body/version", json!(2), E::AgentProfileUpgradeRequired),
            ("/body/agent_anchor", json!(encode_base64url([9; 32])), E::AgentAnchor),
            ("/body/agent_custody_hash", json!(encode_base64url([9; 32])), E::NativeHead),
            ("/body/custodian_anchor", json!(encode_base64url([9; 32])), E::Custodian),
            (
                "/body/custodian_primary/account_anchor",
                json!(encode_base64url([9; 32])),
                E::Custodian,
            ),
            ("/body/custodian_primary/device_id", json!("other"), E::Custodian),
            ("/body/custodian_primary/device_epoch", json!(2), E::Custodian),
            ("/body/kind", json!("human"), E::Field("kind")),
            ("/body/profile_epoch", json!(2), E::Signature),
            ("/body/responsibility", json!("Other"), E::Signature),
            ("/body/provider", json!("other"), E::Signature),
            ("/body/model", json!("other"), E::Signature),
            ("/body/persona_version", json!(2), E::Signature),
            ("/body/persona_hash", json!(encode_base64url([9; 32])), E::Signature),
            ("/signature", json!(encode_base64url([9; 64])), E::Signature),
        ] {
            let mut value = original.clone();
            *value.pointer_mut(path).ok_or("tamper path")? = replacement;
            assert_eq!(
                verify_agent_profile(&canonical_json_bytes(&value)?, &agent, &human, NOW),
                Err(expected),
                "{path}"
            );
        }
        assert_eq!(
            human_key.sign_agent_profile(profile.clone(), &agent, &human, NOW),
            Err(E::Signer)
        );
        let wrong_signer = raw_sign(profile.clone(), &human_key)?;
        assert_eq!(
            verify_agent_profile(&encode_agent_profile(&wrong_signer)?, &agent, &human, NOW),
            Err(E::Signature)
        );
        let (_, other_human_record) = genesis(20, PrincipalKind::Human, None)?;
        let other_human = verify_record(&other_human_record, NOW, None, None)?;
        assert_eq!(verify_agent_profile(&wire, &agent, &other_human, NOW), Err(E::NativeAuthority));
        assert_eq!(
            verify_agent_profile(&wire, &agent, &human, NOW + 2_592_301),
            Err(E::NativeAuthority)
        );
        let human_body = body(&human, &human)?;
        assert_eq!(human_key.sign_agent_profile(human_body, &human, &human, NOW), Err(E::Kind));
        let (_, bot_record) = genesis(
            30,
            PrincipalKind::Bot,
            Some(human_record.body.master_certificate.body.primary_device_ref.clone()),
        )?;
        let bot = verify_record(&bot_record, NOW, None, Some(&human))?;
        assert_eq!(verify_agent_profile(&wire, &bot, &human, NOW), Err(E::Kind));

        bounds(&original)?;
        maxima(&key, &agent, &human, &profile)?;
        predecessor_goldens(&human_record)?;
        Ok(())
    }

    fn predecessor_goldens(human_record: &Envelope<DeviceSet>) -> Result {
        // Original native vector remains byte-for-byte identical to its independent predecessor.
        let golden: Value =
            serde_json::from_str(include_str!("../tests/fixtures/custody_v3.json"))?;
        assert_eq!(
            hex::encode(canonical_json_bytes(human_record)?),
            golden["record_canonical_hex"]
        );
        assert_eq!(object_hash(human_record)?, golden["record_hash"]);
        let old: Value = serde_json::from_str(include_str!(
            "../../../scripts/reference/username_directory/wire_vectors.json"
        ))?;
        let old_profile = old["legacy"]["profile"].as_str().ok_or("v1 golden")?;
        let old_native = old["legacy"]["native"].as_str().ok_or("native golden")?;
        let v1: ramflux_protocol::SignedIdentityProfile = serde_json::from_str(old_profile)?;
        assert_eq!(canonical_json_bytes(&v1)?, old_profile.as_bytes());
        assert_eq!(
            ramflux_protocol::identity_profile_signing_bytes(&v1)?,
            old["legacy"]["signing"].as_str().ok_or("v1 transcript")?.as_bytes()
        );
        let native: ramflux_protocol::custody::Profile = serde_json::from_str(old_native)?;
        assert_eq!(canonical_json_bytes(&native)?, old_native.as_bytes());
        let directory = old["valid"]
            .as_array()
            .ok_or("directory corpus")?
            .iter()
            .find(|v| v["type"] == "SignedIdentityProfileV2")
            .ok_or("directory golden")?;
        let bytes = directory["wire"].as_str().ok_or("directory bytes")?.as_bytes();
        let v2: ramflux_protocol::username_directory::SignedIdentityProfileV2 =
            ramflux_protocol::username_directory::decode(bytes)?;
        assert_eq!(ramflux_protocol::username_directory::encode(&v2)?, bytes);

        Ok(())
    }

    fn maxima(
        key: &SelfSigningKey,
        agent: &VerifiedRecord,
        human: &VerifiedRecord,
        profile: &AgentProfileV1,
    ) -> Result {
        let mut maximum = profile.clone();
        maximum.responsibility = "é".repeat(128);
        maximum.provider = "p".repeat(128);
        maximum.model = "m".repeat(128);
        maximum.profile_epoch = MAX_SAFE_JSON_INTEGER;
        maximum.persona_version = MAX_SAFE_JSON_INTEGER;
        let maximum = key.sign_agent_profile(maximum, agent, human, NOW)?;
        assert_eq!(
            verify_agent_profile(&encode_agent_profile(&maximum)?, agent, human, NOW)?,
            maximum
        );
        maximum_native_reference()?;
        let mut local = profile.clone();
        local.responsibility = "e\u{301}".into();
        assert_eq!(key.sign_agent_profile(local, agent, human, NOW)?.body.responsibility, "é");

        Ok(())
    }

    fn maximum_native_reference() -> Result {
        let (human_key, mut human_record) = genesis(0, PrincipalKind::Human, None)?;
        let master = MasterKey::from_phrase(&RecoveryPhrase::from_entropy(&[0; 32])?)?;
        let mut cert = human_record.body.master_certificate.body.clone();
        cert.primary_device_ref.device_id = "\\".repeat(256);
        cert.primary_device_ref.device_epoch = MAX_SAFE_JSON_INTEGER;
        let reference = cert.primary_device_ref.clone();
        human_record.body.master_certificate = master.certify(cert)?;
        let device = human_record.body.devices.first_mut().ok_or("primary roster")?;
        let mut branch = device.branch_certificate.as_ref().ok_or("primary branch")?.body.clone();
        branch.master_certificate_hash = object_hash(&human_record.body.master_certificate)?;
        branch.device_id.clone_from(&reference.device_id);
        branch.device_epoch = reference.device_epoch;
        device.device_id.clone_from(&reference.device_id);
        device.device_epoch = reference.device_epoch;
        device.branch_certificate = Some(human_key.certify_branch(branch)?);
        let human_record = human_key.sign_record(human_record.body)?;
        let human = verify_record(&human_record, NOW, None, None)?;
        let (key, record) = genesis(10, PrincipalKind::HeadlessAi, Some(reference))?;
        let agent = verify_record(&record, NOW, None, Some(&human))?;
        let mut full = body(&agent, &human)?;
        full.responsibility = "\\".repeat(256);
        full.provider = "\\".repeat(128);
        full.model = "\\".repeat(128);
        full.profile_epoch = MAX_SAFE_JSON_INTEGER;
        full.persona_version = MAX_SAFE_JSON_INTEGER;
        let full = key.sign_agent_profile(full, &agent, &human, NOW)?;
        let bytes = encode_agent_profile(&full)?;
        assert_eq!(bytes.len(), 2215); // Independent JSON maximum, including escape expansion.
        assert!(bytes.len() <= 4096);
        assert_eq!(verify_agent_profile(&bytes, &agent, &human, NOW)?, full);
        Ok(())
    }

    fn bounds(original: &Value) -> Result {
        for (path, field) in [
            ("/body/profile_epoch", "profile_epoch"),
            ("/body/persona_version", "persona_version"),
            ("/body/custodian_primary/device_epoch", "custodian_primary.device_epoch"),
        ] {
            for bad in [0, MAX_SAFE_JSON_INTEGER + 1] {
                let mut v = original.clone();
                *v.pointer_mut(path).ok_or("counter")? = json!(bad);
                let typed: AgentProfileEnvelope = serde_json::from_value(v.clone())?;
                assert_eq!(typed.body.validate(), Err(E::Field(field)));
                refused(&v, if bad == 0 { E::Field(field) } else { E::Wire })?;
            }
            for good in [1, MAX_SAFE_JSON_INTEGER] {
                let mut v = original.clone();
                *v.pointer_mut(path).ok_or("counter")? = json!(good);
                decode_agent_profile(&canonical_json_bytes(&v)?)?;
            }
        }
        for (path, field) in [
            ("/body/agent_anchor", "agent_anchor"),
            ("/body/agent_custody_hash", "agent_custody_hash"),
            ("/body/custodian_anchor", "custodian_anchor"),
            ("/body/custodian_primary/account_anchor", "custodian_primary.account_anchor"),
            ("/body/persona_hash", "persona_hash"),
            ("/signature", "signature"),
        ] {
            for bad in [
                String::new(),
                "a".repeat(42),
                "!".repeat(43),
                format!("{}=", "a".repeat(43)),
                "a".repeat(87),
            ] {
                let mut v = original.clone();
                *v.pointer_mut(path).ok_or("binary")? = json!(bad);
                refused(&v, E::Field(field))?;
            }
        }
        for (path, field, max) in [
            ("/body/responsibility", "responsibility", 256),
            ("/body/provider", "provider", 128),
            ("/body/model", "model", 128),
            ("/body/custodian_primary/device_id", "custodian_primary.device_id", 256),
        ] {
            for bad in ["x".repeat(max + 1), "x\ny".into(), "x\0y".into()] {
                let mut v = original.clone();
                *v.pointer_mut(path).ok_or("text")? = json!(bad);
                refused(&v, E::Field(field))?;
            }
            for length in [1, max] {
                let mut v = original.clone();
                *v.pointer_mut(path).ok_or("text")? = json!("x".repeat(length));
                decode_agent_profile(&canonical_json_bytes(&v)?)?;
            }
        }
        for (path, bad, field) in [
            ("/body/responsibility", "e\u{301}", "responsibility"),
            ("/body/responsibility", "x\u{202e}", "responsibility"),
            ("/body/provider", "é", "provider"),
            ("/body/model", "é", "model"),
            ("/body/provider", "x\u{7f}", "provider"),
            ("/body/custodian_primary/device_id", "", "custodian_primary.device_id"),
        ] {
            let mut v = original.clone();
            *v.pointer_mut(path).ok_or("text safety")? = json!(bad);
            refused(&v, E::Field(field))?;
        }
        wire_rules(original)?;
        Ok(())
    }

    fn wire_rules(original: &Value) -> Result {
        // Every mandatory field refuses omission and null; every level refuses unknown fields.
        for parent in ["", "/body", "/body/custodian_primary"] {
            let object = original.pointer(parent).and_then(Value::as_object).ok_or("object")?;
            for field in object.keys() {
                for null in [false, true] {
                    let mut v = original.clone();
                    let map =
                        v.pointer_mut(parent).and_then(Value::as_object_mut).ok_or("object")?;
                    if null {
                        map.insert(field.clone(), Value::Null);
                    } else {
                        map.remove(field);
                    }
                    refused(&v, E::Wire)?;
                }
            }
            let mut v = original.clone();
            v.pointer_mut(parent)
                .and_then(Value::as_object_mut)
                .ok_or("object")?
                .insert("unknown".into(), json!(1));
            refused(&v, E::Wire)?;
        }
        let wire = canonical_json_bytes(original)?;
        let mut padded = wire.clone();
        padded.push(b' ');
        assert_eq!(decode_agent_profile(&padded), Err(E::Noncanonical));
        assert_eq!(decode_agent_profile(&vec![b' '; 4097]), Err(E::TooLarge));
        assert_eq!(decode_agent_profile(&vec![b' '; 4096]), Err(E::Wire));
        let text = String::from_utf8(wire)?;
        let duplicate = text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
        assert_eq!(decode_agent_profile(duplicate.as_bytes()), Err(E::Wire));
        let escaped = text.replacen("Research", "\\u0052esearch", 1);
        assert_eq!(decode_agent_profile(escaped.as_bytes()), Err(E::Noncanonical));
        Ok(())
    }

    // Independent oracle: scripts/reference/agent_profile/oracle.py (CPython 3.14, run with -I).
    // BLAKE3 is the pure-Python primitive pinned at commit 3fde72e (no FFI, not the Rust crate);
    // Ed25519 is PyCA cryptography 46.0.3. The native record and sidecar envelope are built and
    // serialized in Python. Lineage is recorded in scripts/reference/agent_profile/manifest.json.
    // No production serializer/signature/hash helper generates these expected values.
    fn oracle(signed: &AgentProfileEnvelope, record: &Envelope<DeviceSet>) -> Result {
        assert_eq!(object_hash(record)?, "WS9hoFDbwEmVP2IXEfYQm3KzyPq6-KXSR1iLSiNZvJo");
        assert_eq!(signing_bytes(domain::AGENT_PROFILE, &signed.body)?, br#"{"body":{"agent_anchor":"rXml-r2nvpP5gnl4HMblKj52UQQlEhGMu2VESyQ0U1g","agent_custody_hash":"WS9hoFDbwEmVP2IXEfYQm3KzyPq6-KXSR1iLSiNZvJo","custodian_anchor":"CFeUxoWMBsa9yAAoCz0GXjxP6R7ZQr3-SUty7OxO4EI","custodian_primary":{"account_anchor":"CFeUxoWMBsa9yAAoCz0GXjxP6R7ZQr3-SUty7OxO4EI","device_epoch":1,"device_id":"primary"},"kind":"headless_ai","model":"model","persona_hash":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc","persona_version":1,"profile_epoch":1,"provider":"local","responsibility":"Research","schema":"ramflux.agent.profile.v1","version":1},"domain":"ramflux.agent.profile.v1"}"#);
        assert_eq!(
            signed.signature,
            "oQtBtYep0hY2BRjGzrXj4DhG_6ZeIjHOnEjpCTdGrR-NzTadps8E3UNhkYUeE1T8olJm6sm-KboL9PTl26-MBQ"
        );
        assert_eq!(agent_profile_digest(signed)?, "W3juonkTVGcnBDxemcO8yCohbpW35OPOHZ5PVj27U5g");
        Ok(())
    }
}

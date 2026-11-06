// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
//! Frozen owner retirement transcript; signature evidence is not operation admission.
use super::{
    FormatError,
    grant::{signing, verify},
    native::{Cursor, identity},
};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRetirement {
    pub reference_id: [u8; 32],
    pub grant_id: [u8; 32],
    pub grant_hash: [u8; 32],
    pub grant_epoch: u64,
    pub source_authority: String,
    pub authority_generation: u64,
    pub operation_id: [u8; 32],
    pub issued_at: u64,
}
#[derive(Debug, Clone)]
pub struct VerifiedAttachmentRetirement {
    request: AttachmentRetirement,
    signer: [u8; 32],
    signature: [u8; 64],
}
impl VerifiedAttachmentRetirement {
    #[must_use]
    pub fn request(&self) -> &AttachmentRetirement {
        &self.request
    }
    #[must_use]
    pub fn signer(&self) -> &[u8; 32] {
        &self.signer
    }
    #[must_use]
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}
impl AttachmentRetirement {
    /// # Errors
    /// Refuses zero epochs or invalid authority identities.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FormatError> {
        if self.grant_epoch == 0 || self.authority_generation == 0 {
            return Err(FormatError("retirement epoch"));
        }
        let mut out = b"RFR1".to_vec();
        out.extend(1_u32.to_be_bytes());
        out.extend(self.reference_id);
        out.extend(self.grant_id);
        out.extend(self.grant_hash);
        out.extend(self.grant_epoch.to_be_bytes());
        identity(&mut out, &self.source_authority)?;
        out.extend(self.authority_generation.to_be_bytes());
        out.extend(self.operation_id);
        out.extend(self.issued_at.to_be_bytes());
        Ok(out)
    }
    /// # Errors
    /// Refuses malformed canonical fields.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, FormatError> {
        signing("ramflux.attachment.retire.sign.v1", &self.canonical_bytes()?)
    }
    /// Signature verification only; the relay must also authenticate current owner authority.
    /// # Errors
    /// Refuses noncanonical, oversized, trailing or incorrectly signed input.
    pub fn verify(
        input: &[u8],
        signature: &[u8; 64],
        owner: &[u8; 32],
    ) -> Result<VerifiedAttachmentRetirement, FormatError> {
        if input.len() > 512 {
            return Err(FormatError("retirement cap"));
        }
        let mut c = Cursor(input);
        if c.take(4)? != b"RFR1" || c.u32()? != 1 {
            return Err(FormatError("retirement version"));
        }
        let request = Self {
            reference_id: c.array()?,
            grant_id: c.array()?,
            grant_hash: c.array()?,
            grant_epoch: c.u64()?,
            source_authority: c.identity()?,
            authority_generation: c.u64()?,
            operation_id: c.array()?,
            issued_at: c.u64()?,
        };
        if !c.0.is_empty() || request.canonical_bytes()? != input {
            return Err(FormatError("retirement canonical"));
        }
        verify(owner, &request.signing_bytes()?, signature)?;
        Ok(VerifiedAttachmentRetirement { request, signer: *owner, signature: *signature })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    #[test]
    fn retirement_transcript_has_frozen_framing_and_strict_signature()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = AttachmentRetirement {
            reference_id: [1; 32],
            grant_id: [2; 32],
            grant_hash: [3; 32],
            grant_epoch: 7,
            source_authority: "source".into(),
            authority_generation: 9,
            operation_id: [4; 32],
            issued_at: 11,
        };
        // Independent construction from the section12 field sequence, not a codec roundtrip.
        let mut expected = b"RFR1\0\0\0\x01".to_vec();
        expected.extend([1; 32]);
        expected.extend([2; 32]);
        expected.extend([3; 32]);
        expected.extend(7_u64.to_be_bytes());
        expected.extend([0, 0, 0, 6]);
        expected.extend(b"source");
        expected.extend(9_u64.to_be_bytes());
        expected.extend([4; 32]);
        expected.extend(11_u64.to_be_bytes());
        assert_eq!(request.canonical_bytes()?, expected);
        let domain = b"ramflux.attachment.retire.sign.v1";
        let mut transcript = u32::try_from(domain.len())?.to_be_bytes().to_vec();
        transcript.extend(domain);
        transcript.extend(u32::try_from(expected.len())?.to_be_bytes());
        transcript.extend(&expected);
        assert_eq!(request.signing_bytes()?, transcript);
        let key = SigningKey::from_bytes(&[9; 32]);
        let sig = key.sign(&transcript).to_bytes();
        let public = key.verifying_key().to_bytes();
        assert_eq!(AttachmentRetirement::verify(&expected, &sig, &public)?.request(), &request);
        for offset in [4, 8, 40, 72, 104, 112, 118, 126, 158, 162] {
            let mut bad = expected.clone();
            bad[offset] ^= 1;
            let error = match offset {
                4 => "retirement version",
                112 => "native identity length",
                _ => "grant signature",
            };
            assert_eq!(
                AttachmentRetirement::verify(&bad, &sig, &public).err(),
                Some(FormatError(error))
            );
        }
        expected.push(0);
        assert_eq!(
            AttachmentRetirement::verify(&expected, &sig, &public).err(),
            Some(FormatError("retirement canonical"))
        );
        Ok(())
    }
}

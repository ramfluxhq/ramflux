// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! English BIP39 entropy transcription, never the wallet PBKDF2 seed function.
use crate::CryptoError;
use bip39::{Language, Mnemonic};
use std::fmt;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

fn invalid() -> CryptoError {
    CryptoError::IdentityAuthority("invalid 24-word English recovery phrase")
}
/// A checked 256-bit recovery phrase whose buffers are erased on drop.
/// Debug deliberately reveals no words or entropy.
pub struct RecoveryPhrase(Zeroizing<Mnemonic>);
impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryPhrase(<redacted>)")
    }
}
impl RecoveryPhrase {
    /// Generate 256 independent random bits and their checked English transcription.
    /// # Errors
    /// Returns an error if OS randomness is unavailable.
    pub fn generate() -> Result<Self, CryptoError> {
        let entropy = super::random_secret()?;
        Self::from_entropy(&entropy)
    }
    /// Transcribe exactly 256 bits; intended also for published nonproduction vectors.
    /// # Errors
    /// Returns a provider error without disclosing entropy.
    pub fn from_entropy(entropy: &[u8; 32]) -> Result<Self, CryptoError> {
        let mnemonic =
            Mnemonic::from_entropy_in(Language::English, entropy).map_err(|_| invalid())?;
        Ok(Self(Zeroizing::new(mnemonic)))
    }
    /// Decode NFKD/lowercase/whitespace-normalized English words or unique four-letter prefixes.
    /// # Errors
    /// Rejects wrong word counts, unknown/ambiguous tokens, invalid checksums and excessive input.
    pub fn parse(input: &str) -> Result<Self, CryptoError> {
        if input.len() > 4096 {
            return Err(invalid());
        }
        let mut normalized = Zeroizing::new(input.nfkd().collect::<String>());
        normalized.make_ascii_lowercase();
        let tokens = normalized.split_whitespace().collect::<Vec<_>>();
        if tokens.len() != 24 {
            return Err(invalid());
        }
        let mut expanded = Zeroizing::new(String::with_capacity(256));
        for token in tokens {
            let list = Language::English.word_list();
            let word = if let Some(word) = list.iter().find(|word| **word == token) {
                *word
            } else {
                if token.len() != 4 || !token.is_ascii() {
                    return Err(invalid());
                }
                let mut matches = list.iter().filter(|word| word.starts_with(token));
                let word = matches.next().ok_or_else(invalid)?;
                if matches.next().is_some() {
                    return Err(invalid());
                }
                *word
            };
            if !expanded.is_empty() {
                expanded.push(' ');
            }
            expanded.push_str(word);
        }
        let mnemonic =
            Mnemonic::parse_in_normalized(Language::English, &expanded).map_err(|_| invalid())?;
        Ok(Self(Zeroizing::new(mnemonic)))
    }
    /// Access a zeroizing copy only for the explicit local show-once ceremony.
    #[must_use]
    pub fn display_words(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.to_string())
    }
    /// Obtain the original checked entropy for HKDF, not a BIP39 wallet seed.
    #[must_use]
    pub fn entropy(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_entropy())
    }
    /// Compare a saved word against one one-based challenge position, using the same normalization.
    /// # Errors
    /// Rejects positions outside 1..24 or malformed word input.
    pub fn matches_word(&self, position: usize, input: &str) -> Result<bool, CryptoError> {
        if !(1..=24).contains(&position) || input.len() > 128 {
            return Err(invalid());
        }
        let mut normalized = Zeroizing::new(input.nfkd().collect::<String>());
        normalized.make_ascii_lowercase();
        let mut tokens = normalized.split_whitespace();
        let token = tokens.next().ok_or_else(invalid)?;
        if tokens.next().is_some() {
            return Err(invalid());
        }
        let expected = self.0.words().nth(position - 1).ok_or_else(invalid)?;
        Ok(token == expected || (token.len() == 4 && expected.starts_with(token)))
    }
}

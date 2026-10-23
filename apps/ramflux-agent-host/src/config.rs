// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const MAX_TEXT_BYTES: usize = 16_384;
pub const MAX_CONFIG_BYTES: u64 = 65_536;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub pattern: String,
    pub reply: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub socket: PathBuf,
    pub state_file: PathBuf,
    pub account_id: String,
    pub rules: Vec<Rule>,
    #[serde(default = "poll")]
    pub poll_interval_ms: u64,
    #[serde(default = "interval")]
    pub per_conversation_interval_ms: u64,
    #[serde(default = "conversations")]
    pub max_conversations: usize,
}
const fn poll() -> u64 {
    250
}
const fn interval() -> u64 {
    1000
}
const fn conversations() -> usize {
    128
}
impl Config {
    /// # Errors
    /// Rejects unreadable, oversized or invalid configuration files.
    pub fn load(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|_| Error::Config)?;
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes).map_err(|_| Error::Config)?;
        if bytes.len() > usize::try_from(MAX_CONFIG_BYTES).map_err(|_| Error::Limit)? {
            return Err(Error::Config);
        }
        let config: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Config)?;
        config.validate()?;
        Ok(config)
    }
    /// # Errors
    /// Enforces finite rule, reply, polling, identifier and state budgets.
    pub fn validate(&self) -> Result<()> {
        if self.account_id.is_empty()
            || self.account_id.len() > 256
            || self.socket == self.state_file
            || self.rules.is_empty()
            || self.rules.len() > 64
            || !(50..=60_000).contains(&self.poll_interval_ms)
            || !(100..=3_600_000).contains(&self.per_conversation_interval_ms)
            || !(1..=1024).contains(&self.max_conversations)
            || self.rules.iter().any(|r| {
                r.pattern.is_empty()
                    || r.pattern.len() > 1024
                    || r.reply.is_empty()
                    || r.reply.len() > MAX_TEXT_BYTES
            })
        {
            return Err(Error::Config);
        }
        Ok(())
    }
}

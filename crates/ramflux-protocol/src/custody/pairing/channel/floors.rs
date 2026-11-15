// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Closed retained-floor references carried only inside the encrypted transfer payload.
use super::{Deserialize, Result, Serialize, b32, integer, require};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestingHead {
    pub epoch: u64,
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum RetainedFloor {
    #[serde(rename = "root_floor")]
    Root { root: String, epoch: u64, attesting_head: AttestingHead },
    #[serde(rename = "device_floor")]
    Device { root: String, device: String, epoch: u64, attesting_head: AttestingHead },
}
impl RetainedFloor {
    /// # Errors
    /// Rejects malformed root/device references, epochs or attesting hashes.
    pub fn validate(&self) -> Result<()> {
        let (root, epoch, head) = match self {
            Self::Root { root, epoch, attesting_head } => (root, *epoch, attesting_head),
            Self::Device { root, device, epoch, attesting_head } => {
                require(
                    !device.is_empty()
                        && device.len() <= 128
                        && !device.chars().any(char::is_control),
                    "floor.device",
                )?;
                (root, *epoch, attesting_head)
            }
        };
        b32(root, "floor.root")?;
        integer(epoch, "floor.epoch")?;
        integer(head.epoch, "floor.attesting_head.epoch")?;
        require(epoch > 0 && head.epoch >= epoch, "floor.epoch")?;
        b32(&head.hash, "floor.attesting_head.hash")
    }
}

/// Commitment to a separately assembled SAS-channel artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedFloorsRef {
    pub count: u64,
    pub total_len: u64,
    pub object_hash: String,
}
impl RetainedFloorsRef {
    /// # Errors
    /// Rejects references outside the retained-floor artifact limits.
    pub fn validate(&self) -> Result<()> {
        require(
            self.count <= 8192 && (2..=1_048_576).contains(&self.total_len),
            "TransferFloorsTooLarge",
        )?;
        b32(&self.object_hash, "retained_floors.object_hash")
    }
}

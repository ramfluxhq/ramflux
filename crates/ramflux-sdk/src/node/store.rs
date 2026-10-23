// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable daemon-level pins, defaults, and local enabled settings.
use super::{
    BTreeMap, Deserialize, NodePinSource, NodeProfile, OpenOptionsExt, Path, SdkError, Serialize,
    WellKnownClientRecord, Write, node_error, verify_client_discovery_record,
};
#[derive(Clone)]
pub(crate) struct PendingNode {
    pub record: WellKnownClientRecord,
    pub cache_until: u64,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub(crate) struct NodeStore {
    pub profiles: BTreeMap<String, NodeProfile>,
    pub default_node_id: Option<String>,
    #[serde(skip)]
    pub pending: BTreeMap<String, PendingNode>,
}

impl NodeStore {
    pub(crate) fn load(root: &Path, builtins: &[NodeProfile]) -> Result<Self, SdkError> {
        let path = root.join("nodes.json");
        let mut store: Self = if path.exists() {
            serde_json::from_slice(&std::fs::read(path)?)?
        } else {
            Self::default()
        };
        for profile in builtins {
            if !profile.builtin
                || profile.pin_source != NodePinSource::Builtin
                || !ramflux_protocol::decode_base64url(&profile.node_public_key)
                    .is_ok_and(|key| key.len() == 32)
            {
                return Err(node_error("built-in profiles require a factory public key pin"));
            }
            if let Some(existing) = store.profiles.get(&profile.node_id) {
                if existing.node_public_key != profile.node_public_key {
                    return Err(node_error("built-in node key conflicts with stored pin"));
                }
            } else {
                store.profiles.insert(profile.node_id.clone(), profile.clone());
            }
        }
        Ok(store)
    }

    pub(crate) fn save(&self, root: &Path) -> Result<(), SdkError> {
        std::fs::create_dir_all(root)?;
        let path = root.join("nodes.json");
        let temporary = root.join("nodes.json.tmp");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec_pretty(self)?)?;
        file.sync_all()?;
        std::fs::rename(temporary, path)?;
        std::fs::File::open(root)?.sync_all()?;
        Ok(())
    }

    pub(crate) fn selected(
        &self,
        id: Option<&str>,
        allow_disabled: bool,
    ) -> Result<Option<NodeProfile>, SdkError> {
        let Some(id) = id.or(self.default_node_id.as_deref()) else {
            return Ok(None);
        };
        let profile = self.profiles.get(id).ok_or_else(|| node_error("unknown node"))?;
        if !allow_disabled && !profile.enabled {
            return Err(node_error("node is disabled for new accounts"));
        }
        Ok(Some(profile.clone()))
    }

    pub(crate) fn observe(&mut self, record: &WellKnownClientRecord) -> bool {
        if let Some(profile) = self.profiles.get_mut(&record.node_id)
            && profile.node_public_key != record.node_public_key
        {
            profile.safety_warnings.insert("key_changed".to_owned());
            return true;
        }
        false
    }

    pub(crate) fn confirm(
        &mut self,
        record: WellKnownClientRecord,
        source: NodePinSource,
        expected: Option<&str>,
        now: u64,
    ) -> Result<NodeProfile, SdkError> {
        verify_client_discovery_record(&record, now)?;
        if record.expires_at <= now {
            return Err(node_error("discovery candidate expired; add again"));
        }
        if source == NodePinSource::Builtin {
            return Err(node_error("built-in profiles must be injected at daemon startup"));
        }
        if source != NodePinSource::Tofu && expected != Some(record.node_public_key.as_str()) {
            return Err(node_error(
                "operator or invitation confirmation requires a matching expected_public_key",
            ));
        }
        let mut profile = NodeProfile::from_record(record, now);
        profile.pin_source = source;
        if let Some(existing) = self.profiles.get(&profile.node_id) {
            if existing.builtin {
                return Err(node_error("built-in profile cannot be replaced through discovery"));
            }
            if existing.node_public_key != profile.node_public_key && source == NodePinSource::Tofu
            {
                return Err(node_error(
                    "node key changed; explicit operator or invitation pin required",
                ));
            }
            if existing.pin_source != NodePinSource::Tofu && source == NodePinSource::Tofu {
                return Err(node_error("cannot downgrade a trusted pin to TOFU"));
            }
            profile.enabled = existing.enabled;
            profile.safety_warnings.extend(existing.safety_warnings.clone());
        }
        if source != NodePinSource::Tofu {
            profile.safety_warnings.clear();
        }
        self.profiles.insert(profile.node_id.clone(), profile.clone());
        Ok(profile)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityLifecycleRecord {
    pub identity_commitment: String,
    pub lifecycle_state: String,
    pub lifecycle_epoch: u64,
    pub causal_event_id: String,
    pub reason_code: Option<String>,
    pub timelock_until: Option<i64>,
    pub grace_window_until: Option<i64>,
    pub finalization_time: Option<i64>,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactVerificationRecord {
    pub contact_identity_commitment: String,
    pub verification_state: String,
    pub safety_number_hash: String,
    pub verified_device_set_hash: String,
    pub verified_lineage_head: String,
    pub verified_at: i64,
    pub verified_by_device_id: String,
    pub last_change_event_id: Option<String>,
    pub last_change_seen_at: Option<i64>,
    pub kt_tree_size: Option<u64>,
    pub kt_tree_root_hash: Option<String>,
    pub kt_leaf_index: Option<u64>,
    pub last_gossip_lineage_head: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactVerificationUpdate<'a> {
    pub contact_identity_commitment: &'a str,
    pub safety_number_hash: &'a str,
    pub device_set_hash: &'a str,
    pub lineage_head: &'a str,
    pub verified_at: i64,
    pub verified_by_device_id: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactKeyObservation<'a> {
    pub contact_identity_commitment: &'a str,
    pub safety_number_hash: &'a str,
    pub device_set_hash: &'a str,
    pub lineage_head: &'a str,
    pub change_event_id: &'a str,
    pub seen_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactKtCheckpointUpdate<'a> {
    pub contact_identity_commitment: &'a str,
    pub tree_size: u64,
    pub tree_root_hash: &'a str,
    pub leaf_index: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactGossipObservation<'a> {
    pub contact_identity_commitment: &'a str,
    pub expected_lineage_head: &'a str,
    pub reported_lineage_head: &'a str,
    pub change_event_id: &'a str,
    pub seen_at: i64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdentityLifecycleTiming<'a> {
    pub reason_code: Option<&'a str>,
    pub timelock_until: Option<i64>,
    pub grace_window_until: Option<i64>,
    pub finalization_time: Option<i64>,
    pub updated_at: i64,
}

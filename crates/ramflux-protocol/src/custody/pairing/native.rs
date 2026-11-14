// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant native issuance, signed descriptors and exact reply codecs.
use super::super::{Envelope, framed_hash, signing_bytes};
use super::{
    Common, DataSelection, Deserialize, DeviceRef, PairingWire, Result, Serialize, WireError, b32,
    budget, decode_base64url, domain, encode_base64url, header, integer, reference, require,
};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSpec {
    pub schema: String,
    pub version: u32,
    pub account_anchor: String,
    pub primary_ref: DeviceRef,
    pub base_record_hash: String,
    pub base_epoch: u64,
    pub purpose: String,
    pub recipient_mode: String,
    #[serde(deserialize_with = "super::required_nullable")]
    pub destination_ref: Option<DeviceRef>,
    pub capabilities: Vec<String>,
    pub lease_not_before: u64,
    pub lease_expires_at: u64,
    pub data_selection: Vec<DataSelection>,
    pub ttl_seconds: u64,
}
impl CreateSpec {
    fn common(
        &self,
        invitation_id: String,
        issuer_seq: u64,
        expires_at: u64,
        transfer_id: Option<String>,
    ) -> Common {
        Common {
            schema: "ramflux.pairing.Common.v2".into(),
            version: 2,
            invitation_id,
            issuer_seq,
            account_anchor: self.account_anchor.clone(),
            master_public_key: encode_base64url([0; 32]),
            record_hash: self.base_record_hash.clone(),
            device_set_epoch: self.base_epoch,
            principal_kind: "human".into(),
            sas_suite: domain::CUSTODY_PAIRING_EMOJI_SUITE.into(),
            hpke_suite: (self.purpose == "primary_transfer")
                .then(|| domain::CUSTODY_TRANSFER_HPKE_SUITE.into()),
            purpose: self.purpose.clone(),
            requested_role: if self.purpose == "enroll" { "secondary" } else { "primary" }.into(),
            recipient_mode: self.recipient_mode.clone(),
            destination_ref: self.destination_ref.clone(),
            capabilities: self.capabilities.clone(),
            lease_not_before: self.lease_not_before,
            lease_expires_at: self.lease_expires_at,
            expires_at,
            transfer_id,
            data_selection: self.data_selection.clone(),
        }
    }
    /// Existing custody object-hash framing over the exact canonical specification.
    /// # Errors
    /// Rejects malformed or noncanonical ordered fields.
    pub fn spec_hash(&self) -> Result<String> {
        self.validate()?;
        framed_hash(domain::CUSTODY_OBJECT_HASH, self).map_err(|_| WireError::Json)
    }
}
impl PairingWire for CreateSpec {
    fn normalize(&mut self) {
        self.capabilities.sort();
        self.data_selection.sort();
    }
    const LIMIT: usize = 14_000;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "CreateSpec")?;
        self.common(
            encode_base64url([0; 32]),
            1,
            300,
            (self.purpose == "primary_transfer").then(|| encode_base64url([0; 32])),
        )
        .validate()?;
        reference(&self.primary_ref)?;
        require(self.primary_ref.account_anchor == self.account_anchor, "primary_anchor")?;
        if let Some(v) = &self.destination_ref {
            require(v.device_id != self.primary_ref.device_id, "destination_is_primary")?;
        }
        require(self.ttl_seconds == 300, "ttl_seconds")?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issue {
    pub schema: String,
    pub version: u32,
    pub spec: CreateSpec,
}
impl PairingWire for Issue {
    fn normalize(&mut self) {
        self.spec.normalize();
    }
    const LIMIT: usize = 14_336;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Issue")?;
        self.spec.validate()?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTicket {
    pub schema: String,
    pub version: u32,
    pub node_key: String,
    pub boot_id: String,
    pub create_id: String,
    pub issuer_seq: u64,
    pub account_anchor: String,
    pub primary_ref: DeviceRef,
    pub spec_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl PairingWire for CreateTicket {
    const LIMIT: usize = 2_048;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "CreateTicket")?;
        for (v, f) in [
            (&self.node_key, "node_key"),
            (&self.boot_id, "boot_id"),
            (&self.create_id, "create_id"),
            (&self.account_anchor, "account_anchor"),
            (&self.spec_hash, "spec_hash"),
        ] {
            b32(v, f)?;
        }
        sequence(self.issuer_seq)?;
        reference(&self.primary_ref)?;
        require(self.primary_ref.account_anchor == self.account_anchor, "primary_anchor")?;
        lifetime(self.issued_at, self.expires_at)?;
        budget(self, Self::LIMIT)
    }
}
fn sequence(v: u64) -> Result<()> {
    integer(v, "issuer_seq")?;
    require(v >= 1, "issuer_seq")
}
fn lifetime(start: u64, end: u64) -> Result<()> {
    integer(start, "created_at")?;
    integer(end, "expires_at")?;
    require(end.checked_sub(start) == Some(300), "invitation_lifetime")
}
fn signed<T: PairingWire>(v: &Envelope<T>, limit: usize) -> Result<()> {
    v.body.validate()?;
    let raw = decode_base64url(&v.signature).map_err(|_| WireError::Field("signature"))?;
    require(raw.len() == 64 && encode_base64url(&raw) == v.signature, "signature")?;
    budget(v, limit)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    pub schema: String,
    pub version: u32,
    pub ticket: Envelope<CreateTicket>,
    pub spec: CreateSpec,
}
impl PairingWire for Create {
    fn normalize(&mut self) {
        self.spec.normalize();
    }
    const LIMIT: usize = 16_384;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Create")?;
        signed(&self.ticket, 2048)?;
        self.spec.validate()?;
        let t = &self.ticket.body;
        require(
            t.account_anchor == self.spec.account_anchor && t.primary_ref == self.spec.primary_ref,
            "ticket_context",
        )?;
        require(t.spec_hash == self.spec.spec_hash()?, "spec_hash")?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub schema: String,
    pub version: u32,
    pub invitation_id: String,
    pub issuer_seq: u64,
    pub request_id: String,
    pub node_key: String,
    pub public_origin: String,
    pub account_anchor: String,
    pub primary_ref: DeviceRef,
    pub base_record_hash: String,
    pub base_epoch: u64,
    pub purpose: String,
    pub recipient_mode: String,
    #[serde(deserialize_with = "super::required_nullable")]
    pub destination_ref: Option<DeviceRef>,
    pub capabilities: Vec<String>,
    pub lease_not_before: u64,
    pub lease_expires_at: u64,
    pub data_selection: Vec<DataSelection>,
    #[serde(deserialize_with = "super::required_nullable")]
    pub transfer_id: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
}
impl Invitation {
    fn spec(&self) -> CreateSpec {
        CreateSpec {
            schema: "ramflux.pairing.CreateSpec.v2".into(),
            version: 2,
            ttl_seconds: 300,
            account_anchor: self.account_anchor.clone(),
            primary_ref: self.primary_ref.clone(),
            base_record_hash: self.base_record_hash.clone(),
            base_epoch: self.base_epoch,
            purpose: self.purpose.clone(),
            recipient_mode: self.recipient_mode.clone(),
            destination_ref: self.destination_ref.clone(),
            capabilities: self.capabilities.clone(),
            lease_not_before: self.lease_not_before,
            lease_expires_at: self.lease_expires_at,
            data_selection: self.data_selection.clone(),
        }
    }
    /// Project the signed descriptor with independently verified authority evidence.
    /// # Errors
    /// Rejects malformed descriptor or authority fields.
    pub fn project_common(&self, master_public_key: String) -> Result<Common> {
        self.validate()?;
        let mut c = self.spec().common(
            self.invitation_id.clone(),
            self.issuer_seq,
            self.expires_at,
            self.transfer_id.clone(),
        );
        c.master_public_key = master_public_key;
        c.validate()?;
        Ok(c)
    }
}
impl PairingWire for Invitation {
    fn normalize(&mut self) {
        self.capabilities.sort();
        self.data_selection.sort();
    }
    const LIMIT: usize = 15_872;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Invitation")?;
        self.spec().validate()?;
        for (v, f) in [
            (&self.invitation_id, "invitation_id"),
            (&self.request_id, "request_id"),
            (&self.node_key, "node_key"),
        ] {
            b32(v, f)?;
        }
        sequence(self.issuer_seq)?;
        lifetime(self.created_at, self.expires_at)?;
        self.spec()
            .common(
                self.invitation_id.clone(),
                self.issuer_seq,
                self.expires_at,
                self.transfer_id.clone(),
            )
            .validate()?;
        require(valid_origin(&self.public_origin), "public_origin")?;
        budget(self, Self::LIMIT)
    }
}
fn valid_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else { return false };
    if value.len() > 256 || !value.is_ascii() || authority.is_empty() {
        return false;
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((address, suffix)) = rest.split_once(']') else { return false };
        if address.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        (
            address,
            if suffix.is_empty() {
                None
            } else {
                let Some(p) = suffix.strip_prefix(':') else { return false };
                Some(p)
            },
        )
    } else {
        let (host, port) =
            authority.split_once(':').map_or((authority, None), |(h, p)| (h, Some(p)));
        if host.is_empty()
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return false;
        }
        (host, port)
    };
    !host.is_empty()
        && port.is_none_or(|p| {
            !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
        })
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issued {
    pub schema: String,
    pub version: u32,
    pub ticket: Envelope<CreateTicket>,
}
impl PairingWire for Issued {
    const LIMIT: usize = 2_304;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Issued")?;
        signed(&self.ticket, 2048)?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Created {
    pub schema: String,
    pub version: u32,
    pub request_id: String,
    pub invitation: Envelope<Invitation>,
    pub primary_token: String,
    pub recipient_token: String,
}
impl PairingWire for Created {
    const LIMIT: usize = 20_480;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Created")?;
        b32(&self.request_id, "request_id")?;
        signed(&self.invitation, 16000)?;
        b32(&self.primary_token, "primary_token")?;
        b32(&self.recipient_token, "recipient_token")?;
        require(self.primary_token != self.recipient_token, "distinct_tokens")?;
        require(self.request_id == self.invitation.body.request_id, "request_binding")?;
        budget(self, Self::LIMIT)
    }
}
impl Created {
    /// Check the complete server-issued response against the saved exact Create.
    /// # Errors
    /// Rejects a changed ticket, projected specification, id, clock or node.
    pub fn validate_create(&self, create: &Create) -> Result<()> {
        self.validate()?;
        create.validate()?;
        let t = &create.ticket.body;
        let i = &self.invitation.body;
        require(
            self.request_id == t.create_id
                && i.issuer_seq == t.issuer_seq
                && i.node_key == t.node_key
                && i.created_at == t.issued_at
                && i.expires_at == t.expires_at
                && i.spec() == create.spec,
            "created_binding",
        )
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteToken {
    pub schema: String,
    pub version: u32,
    pub invitation: Envelope<Invitation>,
    pub recipient_token: String,
}
impl PairingWire for InviteToken {
    const LIMIT: usize = 16_384;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "InviteToken")?;
        signed(&self.invitation, 16000)?;
        b32(&self.recipient_token, "recipient_token")?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub schema: String,
    pub version: u32,
    pub code: String,
    #[serde(deserialize_with = "super::required_nullable")]
    pub retry_after_ms: Option<u64>,
}
impl PairingWire for Failure {
    const LIMIT: usize = 512;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "Failure")?;
        require(
            matches!(
                self.code.as_str(),
                "Busy"
                    | "InvalidInput"
                    | "Expired"
                    | "Retired"
                    | "WrongRole"
                    | "WrongContext"
                    | "Replay"
                    | "HeadChanged"
                    | "PrimaryRequired"
                    | "SasMismatch"
                    | "PublicationPending"
                    | "TransferCapacity"
                    | "TransferFloorsTooLarge"
                    | "LeaseExpired"
                    | "UpdateRequired"
                    | "VaultUnavailable"
                    | "NotFound"
            ),
            "code",
        )?;
        require(
            if self.code == "Busy" {
                self.retry_after_ms.is_some_and(|v| (1000..=30000).contains(&v))
            } else {
                self.retry_after_ms.is_none()
            },
            "retry_after_ms",
        )?;
        budget(self, Self::LIMIT)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NativeReply {
    Issued(Box<Issued>),
    Created(Box<Created>),
    Failure(Failure),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingReply {
    pub schema: String,
    pub version: u32,
    pub reply: NativeReply,
}
impl PairingWire for PairingReply {
    const LIMIT: usize = 20_480;
    fn validate(&self) -> Result<()> {
        header(&self.schema, self.version, "PairingReply")?;
        match &self.reply {
            NativeReply::Issued(v) => v.validate()?,
            NativeReply::Created(v) => v.validate()?,
            NativeReply::Failure(v) => v.validate()?,
        }
        budget(self, Self::LIMIT)
    }
}
/// Signing transcript for the verified node's invitation body.
/// # Errors
/// Rejects invalid descriptors.
pub fn invitation_signing_bytes(v: &Invitation) -> Result<Vec<u8>> {
    v.validate()?;
    signing_bytes(domain::CUSTODY_PAIRING_INVITATION_V2, v).map_err(|_| WireError::Json)
}
/// Signing transcript for the verified node's one-use ticket body.
/// # Errors
/// Rejects invalid tickets.
pub fn ticket_signing_bytes(v: &CreateTicket) -> Result<Vec<u8>> {
    v.validate()?;
    signing_bytes(domain::CUSTODY_PAIRING_CREATE_TICKET_V2, v).map_err(|_| WireError::Json)
}
/// Codec-side retirement evidence. Call only after authenticating the node signature.
/// The allocator, expiry clocks and fresh primary proof remain server-owned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateSlot {
    Missing,
    Issued,
    Live,
}
impl Create {
    /// Prior-boot and absent-slot requests are always retired, never new issuance.
    /// # Errors
    /// Rejects malformed Create, retired ticket or an expired deadline.
    pub fn validate_admission(
        &self,
        boot_id: &str,
        slot: CreateSlot,
        wall_now: u64,
        deadline_live: bool,
    ) -> Result<()> {
        self.validate()?;
        require(self.ticket.body.boot_id == boot_id && slot != CreateSlot::Missing, "retired")?;
        require(deadline_live && wall_now < self.ticket.body.expires_at, "expired")
    }
}

impl std::fmt::Debug for Created {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Created { redacted }")
    }
}
impl Drop for Created {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.primary_token);
        zeroize::Zeroize::zeroize(&mut self.recipient_token);
    }
}

impl std::fmt::Debug for InviteToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InviteToken { redacted }")
    }
}
impl Drop for InviteToken {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.recipient_token);
    }
}

impl PairingWire for Envelope<CreateTicket> {
    const LIMIT: usize = 2048;
    fn validate(&self) -> Result<()> {
        signed(self, Self::LIMIT)
    }
}
impl PairingWire for Envelope<Invitation> {
    const LIMIT: usize = 16000;
    fn validate(&self) -> Result<()> {
        signed(self, Self::LIMIT)
    }
}

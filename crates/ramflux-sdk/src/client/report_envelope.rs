// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant S10a P07 candidate: every-envelope collapse tag and report commitment.
//! Unwired until activation (P24/P25). Live franking JSON is unchanged.
#![cfg_attr(not(test), expect(dead_code, reason = "dormant S10a P07 candidate until P24/P25"))]

use ramflux_crypto::{
    AssembledReportOpening, ReportA0, ReportDeliveryClass, ReportDeliveryMode, ReportPriority,
    assemble_report_opening, verify_report_opening,
};

use crate::SdkError;

/// Producer kinds that must emit a 32-byte tag and 32-byte commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum CandidateKind {
    DirectMessage,
    Receipt,
    OwnDeviceCopy,
    OwnDeviceCopyBackground,
    GroupMessage,
    GroupControl,
    GroupSenderKeyDistribution,
    Federation,
    OwnSentMessage,
    OwnSentDelivery,
    ObjectSlot,
    PairReply,
    RoutedSeal,
}

/// Candidate report fields. `report_commitment` is required on every kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CandidateReport {
    pub kind: CandidateKind,
    pub collapse_tag: [u8; 32],
    pub report_commitment: Option<[u8; 32]>,
    pub opening: [u8; 32],
    pub framed_plaintext: Vec<u8>,
    pub a0: Vec<u8>,
    pub inner: Vec<u8>,
}

pub(crate) fn produce(
    kind: CandidateKind,
    inner: &[u8],
    opening: [u8; 32],
    collapse_tag: [u8; 32],
) -> Result<CandidateReport, SdkError> {
    let fields = ReportA0 {
        envelope_id: kind.envelope_id(),
        source_principal_id: b"s10a-p07-source",
        source_device_id: b"s10a-p07-device",
        target_delivery_id: kind.target_delivery_id(),
        delivery_class: kind.delivery_class(),
        priority: kind.priority(),
        ttl_seconds: 300,
        created_at: 1_762_128_000,
        collapse_tag: &collapse_tag,
        delivery_mode: CandidateKind::delivery_mode(),
    };
    let assembled = assemble_report_opening(inner, &fields, opening)?;
    Ok(from_assembled(kind, inner, assembled))
}

pub(crate) fn produce_kind(kind: CandidateKind) -> Result<CandidateReport, SdkError> {
    produce(kind, kind.inner(), kind.opening(), kind.collapse_tag())
}

fn from_assembled(
    kind: CandidateKind,
    inner: &[u8],
    assembled: AssembledReportOpening,
) -> CandidateReport {
    CandidateReport {
        kind,
        collapse_tag: assembled.collapse_tag,
        report_commitment: Some(assembled.report_commitment),
        opening: assembled.opening,
        framed_plaintext: assembled.framed_plaintext,
        a0: assembled.a0,
        inner: inner.to_vec(),
    }
}

impl CandidateKind {
    const fn inner(self) -> &'static [u8] {
        match self {
            Self::DirectMessage => b"inner.dm.text",
            Self::Receipt => b"inner.receipt",
            Self::OwnDeviceCopy => b"inner.own-copy",
            Self::OwnDeviceCopyBackground => b"inner.own-copy-bg",
            Self::GroupMessage => b"inner.group.message",
            Self::GroupControl => b"inner.group.control",
            Self::GroupSenderKeyDistribution => b"inner.group.skd",
            Self::Federation => b"inner.federation",
            Self::OwnSentMessage => b"inner.own-sent-message",
            Self::OwnSentDelivery => b"inner.own-sent-delivery",
            Self::ObjectSlot => b"inner.object-slot",
            Self::PairReply => b"inner.pair-reply",
            Self::RoutedSeal => b"inner.routed-seal",
        }
    }

    const fn envelope_id(self) -> &'static [u8] {
        match self {
            Self::DirectMessage => b"env.dm",
            Self::Receipt => b"env.receipt",
            Self::OwnDeviceCopy => b"env.own-copy",
            Self::OwnDeviceCopyBackground => b"env.own-copy-bg",
            Self::GroupMessage => b"env.group-msg",
            Self::GroupControl => b"env.group-ctl",
            Self::GroupSenderKeyDistribution => b"env.group-skd",
            Self::Federation => b"env.fed",
            Self::OwnSentMessage => b"env.own-sent",
            Self::OwnSentDelivery => b"env.own-sent-del",
            Self::ObjectSlot => b"env.object-slot",
            Self::PairReply => b"env.pair-reply",
            Self::RoutedSeal => b"env.routed-seal",
        }
    }

    const fn target_delivery_id(self) -> &'static [u8] {
        self.envelope_id()
    }

    const fn delivery_class(self) -> ReportDeliveryClass {
        match self {
            Self::PairReply => ReportDeliveryClass::CallWake,
            _ => ReportDeliveryClass::Message,
        }
    }

    const fn priority(self) -> ReportPriority {
        match self {
            Self::PairReply => ReportPriority::High,
            Self::Receipt => ReportPriority::Low,
            _ => ReportPriority::Normal,
        }
    }

    const fn delivery_mode() -> ReportDeliveryMode {
        ReportDeliveryMode::Durable
    }

    fn opening(self) -> [u8; 32] {
        let mut opening = [0x33_u8; 32];
        opening[31] = self as u8;
        opening
    }

    fn collapse_tag(self) -> [u8; 32] {
        let mut tag = [0x22_u8; 32];
        tag[31] = self as u8;
        tag
    }
}

pub(crate) fn assert_uniform_tag_and_commitment(report: &CandidateReport) -> Result<(), SdkError> {
    assert_eq!(report.collapse_tag.len(), 32, "{:?} missing collapse_tag", report.kind);
    let Some(commitment) = report.report_commitment.as_ref() else {
        return Err(SdkError::InboundRejected(format!(
            "{:?} missing report_commitment",
            report.kind
        )));
    };
    assert_eq!(commitment.len(), 32, "{:?} report_commitment is not 32 bytes", report.kind);
    verify_report_opening(&report.opening, &report.inner, &report.a0, commitment)?;
    let (inner, opening) = ramflux_crypto::parse_report_plaintext(&report.framed_plaintext)?;
    assert_eq!(inner, report.inner);
    verify_report_opening(&opening, &inner, &report.a0, commitment)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CandidateKind, assert_uniform_tag_and_commitment};
    use crate::SdkError;

    #[test]
    fn every_envelope_has_uniform_tag_and_commitment() -> Result<(), SdkError> {
        let reports = [
            crate::dm::candidate_report()?,
            crate::bus::delivery_receipts::candidate_report()?,
            crate::bus::own_device_copy::candidate_report()?,
            crate::bus::own_device_copy::candidate_background_report()?,
            crate::bus::dispatch::group::candidate_group_message_report()?,
            crate::bus::dispatch::group::candidate_group_control_report()?,
            crate::bus::dispatch::group::candidate_group_skd_report()?,
            super::super::federation::candidate_report()?,
            super::super::own_sent_message::candidate_report()?,
            super::super::own_sent_delivery::candidate_report()?,
            super::super::routed::candidate_object_slot_report()?,
            super::super::routed::candidate_pair_reply_report()?,
            super::super::routed::candidate_routed_seal_report()?,
        ];
        assert_eq!(reports.len(), 13);
        let mut kinds = std::collections::BTreeSet::new();
        let mut commitments = std::collections::BTreeSet::new();
        for report in &reports {
            assert_uniform_tag_and_commitment(report)?;
            assert!(kinds.insert(report.kind), "duplicate {:?}", report.kind);
            let Some(commitment) = report.report_commitment else {
                return Err(SdkError::InboundRejected(format!(
                    "{:?} missing report_commitment",
                    report.kind
                )));
            };
            assert!(commitments.insert(commitment), "shared commitment {:?}", report.kind);
        }
        assert_eq!(kinds.len(), 13);
        assert_eq!(commitments.len(), 13);
        Ok(())
    }

    #[test]
    fn produce_kind_covers_direct_message_fixture() -> Result<(), SdkError> {
        let report = super::produce_kind(CandidateKind::DirectMessage)?;
        assert_uniform_tag_and_commitment(&report)
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
//! Dormant pre-Session contract checks. These checks do not issue finite TLS evidence.
//! Registry entries must come from reviewed source evidence before production use.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdentityField {
    SourcePatch,
    RuntimeFeatures,
    OwnerLayout,
    Target,
    Allocator,
    Provider,
    Configuration,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ByteField {
    RetainedInputMax,
    InternalPeakMax,
    OutputPeakMax,
    KeyPeakMax,
    TotalPeakMax,
    BaseAllowance,
    RetainedInputNow,
    OutputCapacity,
    ReadLen,
}
/// Opaque nonempty IDs/digests, compared exactly without numeric interpretation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TlsIdentity<'a> {
    pub(crate) source_patch: &'a str,
    pub(crate) runtime_features: &'a str,
    pub(crate) owner_layout: &'a str,
    pub(crate) target: &'a str,
    pub(crate) allocator: &'a str,
    pub(crate) provider: &'a str,
    pub(crate) configuration: &'a str,
}
impl TlsIdentity<'_> {
    fn fields(&self) -> [(IdentityField, &str); 7] {
        [
            (IdentityField::SourcePatch, self.source_patch),
            (IdentityField::RuntimeFeatures, self.runtime_features),
            (IdentityField::OwnerLayout, self.owner_layout),
            (IdentityField::Target, self.target),
            (IdentityField::Allocator, self.allocator),
            (IdentityField::Provider, self.provider),
            (IdentityField::Configuration, self.configuration),
        ]
    }
}
/// The five bounds are physical allocation capacity bytes including simultaneous owners.
/// `None` is missing evidence; zero requires explicit finite component evidence.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TlsEnvelope<'a> {
    pub(crate) identity: TlsIdentity<'a>,
    pub(crate) retained_input_max: Option<u64>,
    pub(crate) internal_peak_max: Option<u64>,
    pub(crate) output_peak_max: Option<u64>,
    pub(crate) key_peak_max: Option<u64>,
    pub(crate) total_peak_max: Option<u64>,
    pub(crate) space: u8,
    pub(crate) sequence: u8,
    pub(crate) generation: u64,
    pub(crate) call_index: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsSpace {
    Initial,
    Handshake,
    Data,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsSequence {
    ReadThenWrite,
    WriteOnly,
    KeyUpdate,
}
/// Trusted registry data, never inferred by querying a Session or an envelope.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TlsRegistryEntry<'a> {
    /// Maximum from the pinned target identity, not a cast from envelope data.
    pub(crate) target_usize_max: u64,
    pub(crate) permitted: &'a [(TlsSpace, TlsSequence)],
}
/// Trusted live state supplied before any Session call. Byte fields describe existing
/// base allowance, retained/prepared capacity and requested read bytes; key counts
/// are physically prepared slots and the registry-derived maximum slot demand.
/// Base allowance excludes non-spendable allocator excess and grants no new credit.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TlsContext<'a> {
    pub(crate) identity: TlsIdentity<'a>,
    pub(crate) registry: Option<TlsRegistryEntry<'a>>,
    pub(crate) base_allowance: u64,
    pub(crate) retained_input_now: u64,
    pub(crate) output_capacity: u64,
    pub(crate) read_len: u64,
    pub(crate) key_slots: u32,
    pub(crate) key_slots_required: u32,
    pub(crate) space: TlsSpace,
    pub(crate) sequence: TlsSequence,
    pub(crate) generation: u64,
    pub(crate) call_index: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsContractError {
    MissingEnvelope,
    UnsupportedProviderConfiguration,
    EmptyIdentity(IdentityField),
    IdentityMismatch(IdentityField),
    MissingBound(ByteField),
    BytesNotRepresentable(ByteField),
    ZeroTotalPeak,
    PeakSumOverflow,
    ComponentPeaksExceedTotal,
    BaseAllowanceExceeded,
    InvalidSpaceTag(u8),
    InvalidSequenceTag(u8),
    SpaceMismatch,
    SequenceMismatch,
    DisallowedSpaceSequence,
    GenerationMismatch,
    CallIndexMismatch,
    RetainedInputExceeded,
    ReadInputExceeded,
    UnexpectedReadInput,
    OutputCapacityInsufficient,
    KeySlotsInsufficient,
}
/// Only validation constructs this token. It is neither a certificate nor extra credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTlsEnvelope {
    bounds: [u64; 5],
    space: TlsSpace,
    sequence: TlsSequence,
    generation: u64,
    call_index: u64,
}
/// Validate without invoking any Session method, allocator or provider callback.
///
/// # Errors
/// Returns the exact failed contract rule; no missing bound is defaulted.
pub(crate) fn validate(
    envelope: Option<&TlsEnvelope<'_>>,
    context: &TlsContext<'_>,
) -> Result<ValidatedTlsEnvelope, TlsContractError> {
    use TlsContractError::*;
    let envelope = envelope.ok_or(MissingEnvelope)?;
    let registry = context.registry.ok_or(UnsupportedProviderConfiguration)?;
    for ((field, actual), (_, expected)) in
        envelope.identity.fields().into_iter().zip(context.identity.fields())
    {
        if actual.is_empty() || expected.is_empty() {
            return Err(EmptyIdentity(field));
        }
        if actual != expected {
            return Err(IdentityMismatch(field));
        }
    }
    let mut bounds = [0; 5];
    for (slot, (field, value)) in bounds.iter_mut().zip([
        (ByteField::RetainedInputMax, envelope.retained_input_max),
        (ByteField::InternalPeakMax, envelope.internal_peak_max),
        (ByteField::OutputPeakMax, envelope.output_peak_max),
        (ByteField::KeyPeakMax, envelope.key_peak_max),
        (ByteField::TotalPeakMax, envelope.total_peak_max),
    ]) {
        *slot = value.ok_or(MissingBound(field))?;
        if *slot > registry.target_usize_max {
            return Err(BytesNotRepresentable(field));
        }
    }
    for (field, value) in [
        (ByteField::BaseAllowance, context.base_allowance),
        (ByteField::RetainedInputNow, context.retained_input_now),
        (ByteField::OutputCapacity, context.output_capacity),
        (ByteField::ReadLen, context.read_len),
    ] {
        if value > registry.target_usize_max {
            return Err(BytesNotRepresentable(field));
        }
    }
    let [retained, internal, output, keys, total] = bounds;
    if total == 0 {
        return Err(ZeroTotalPeak);
    }
    let sum = retained
        .checked_add(internal)
        .and_then(|v| v.checked_add(output))
        .and_then(|v| v.checked_add(keys))
        .ok_or(PeakSumOverflow)?;
    if sum > total {
        return Err(ComponentPeaksExceedTotal);
    }
    if total > context.base_allowance {
        return Err(BaseAllowanceExceeded);
    }
    let space = match envelope.space {
        0 => TlsSpace::Initial,
        1 => TlsSpace::Handshake,
        2 => TlsSpace::Data,
        tag => return Err(InvalidSpaceTag(tag)),
    };
    let sequence = match envelope.sequence {
        0 => TlsSequence::ReadThenWrite,
        1 => TlsSequence::WriteOnly,
        2 => TlsSequence::KeyUpdate,
        tag => return Err(InvalidSequenceTag(tag)),
    };
    if space != context.space {
        return Err(SpaceMismatch);
    }
    if sequence != context.sequence {
        return Err(SequenceMismatch);
    }
    if (sequence == TlsSequence::KeyUpdate && space != TlsSpace::Data)
        || !registry.permitted.contains(&(space, sequence))
    {
        return Err(DisallowedSpaceSequence);
    }
    if envelope.generation != context.generation {
        return Err(GenerationMismatch);
    }
    if envelope.call_index != context.call_index {
        return Err(CallIndexMismatch);
    }
    let remaining =
        retained.checked_sub(context.retained_input_now).ok_or(RetainedInputExceeded)?;
    if sequence == TlsSequence::ReadThenWrite {
        if context.read_len > remaining {
            return Err(ReadInputExceeded);
        }
    } else if context.read_len != 0 {
        return Err(UnexpectedReadInput);
    }
    if context.output_capacity < output {
        return Err(OutputCapacityInsufficient);
    }
    if context.key_slots < context.key_slots_required {
        return Err(KeySlotsInsufficient);
    }
    Ok(ValidatedTlsEnvelope {
        bounds,
        space,
        sequence,
        generation: envelope.generation,
        call_index: envelope.call_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{self, Session};
    use crate::transport_parameters::TransportParameters;
    use crate::{ConnectionId, Side, TransportError};
    use std::{any::Any, cell::Cell};
    use TlsContractError::*;
    const PERMITTED: &[(TlsSpace, TlsSequence)] = &[
        (TlsSpace::Initial, TlsSequence::ReadThenWrite),
        (TlsSpace::Initial, TlsSequence::WriteOnly),
        (TlsSpace::Handshake, TlsSequence::ReadThenWrite),
        (TlsSpace::Handshake, TlsSequence::WriteOnly),
        (TlsSpace::Data, TlsSequence::ReadThenWrite),
        (TlsSpace::Data, TlsSequence::WriteOnly),
        (TlsSpace::Data, TlsSequence::KeyUpdate),
    ];
    struct Fixture {
        envelope: Option<TlsEnvelope<'static>>,
        context: TlsContext<'static>,
    }
    impl Fixture {
        fn valid() -> Self {
            let identity = TlsIdentity {
                source_patch: "synthetic-source_patch",
                runtime_features: "synthetic-runtime_features",
                owner_layout: "synthetic-owner_layout",
                target: "synthetic-target",
                allocator: "synthetic-allocator",
                provider: "synthetic-provider",
                configuration: "synthetic-configuration",
            };
            Self {
                envelope: Some(TlsEnvelope {
                    identity,
                    retained_input_max: Some(16),
                    internal_peak_max: Some(16),
                    output_peak_max: Some(16),
                    key_peak_max: Some(16),
                    total_peak_max: Some(128),
                    space: 1,
                    sequence: 0,
                    generation: 7,
                    call_index: 9,
                }),
                context: TlsContext {
                    identity,
                    registry: Some(TlsRegistryEntry {
                        target_usize_max: u64::MAX,
                        permitted: PERMITTED,
                    }),
                    base_allowance: 256,
                    retained_input_now: 4,
                    output_capacity: 256,
                    read_len: 1,
                    key_slots: 8,
                    key_slots_required: 2,
                    space: TlsSpace::Handshake,
                    sequence: TlsSequence::ReadThenWrite,
                    generation: 7,
                    call_index: 9,
                },
            }
        }
        fn envelope(&mut self) -> &mut TlsEnvelope<'static> {
            self.envelope.as_mut().unwrap()
        }
        // Independent full-rule oracle: u128 arithmetic, all applicable violations collected.
        // It never calls validate or consumes the validator's first-error result.
        fn violations(&self) -> Vec<TlsContractError> {
            let mut errors = Vec::new();
            let Some(e) = self.envelope else { return vec![MissingEnvelope] };
            let c = &self.context;
            let registry = c.registry;
            if registry.is_none() {
                errors.push(UnsupportedProviderConfiguration);
            }
            if e.identity.source_patch.is_empty() || c.identity.source_patch.is_empty() {
                errors.push(EmptyIdentity(IdentityField::SourcePatch));
            } else if e.identity.source_patch != c.identity.source_patch {
                errors.push(IdentityMismatch(IdentityField::SourcePatch));
            }
            if e.identity.runtime_features.is_empty() || c.identity.runtime_features.is_empty() {
                errors.push(EmptyIdentity(IdentityField::RuntimeFeatures));
            } else if e.identity.runtime_features != c.identity.runtime_features {
                errors.push(IdentityMismatch(IdentityField::RuntimeFeatures));
            }
            if e.identity.owner_layout.is_empty() || c.identity.owner_layout.is_empty() {
                errors.push(EmptyIdentity(IdentityField::OwnerLayout));
            } else if e.identity.owner_layout != c.identity.owner_layout {
                errors.push(IdentityMismatch(IdentityField::OwnerLayout));
            }
            if e.identity.target.is_empty() || c.identity.target.is_empty() {
                errors.push(EmptyIdentity(IdentityField::Target));
            } else if e.identity.target != c.identity.target {
                errors.push(IdentityMismatch(IdentityField::Target));
            }
            if e.identity.allocator.is_empty() || c.identity.allocator.is_empty() {
                errors.push(EmptyIdentity(IdentityField::Allocator));
            } else if e.identity.allocator != c.identity.allocator {
                errors.push(IdentityMismatch(IdentityField::Allocator));
            }
            if e.identity.provider.is_empty() || c.identity.provider.is_empty() {
                errors.push(EmptyIdentity(IdentityField::Provider));
            } else if e.identity.provider != c.identity.provider {
                errors.push(IdentityMismatch(IdentityField::Provider));
            }
            if e.identity.configuration.is_empty() || c.identity.configuration.is_empty() {
                errors.push(EmptyIdentity(IdentityField::Configuration));
            } else if e.identity.configuration != c.identity.configuration {
                errors.push(IdentityMismatch(IdentityField::Configuration));
            }
            let options = [
                (ByteField::RetainedInputMax, e.retained_input_max),
                (ByteField::InternalPeakMax, e.internal_peak_max),
                (ByteField::OutputPeakMax, e.output_peak_max),
                (ByteField::KeyPeakMax, e.key_peak_max),
                (ByteField::TotalPeakMax, e.total_peak_max),
            ];
            for (field, value) in options {
                match value {
                    None => errors.push(MissingBound(field)),
                    Some(v) if registry.is_some_and(|r| v > r.target_usize_max) => {
                        errors.push(BytesNotRepresentable(field))
                    }
                    _ => {}
                }
            }
            if registry.is_some_and(|r| c.base_allowance > r.target_usize_max) {
                errors.push(BytesNotRepresentable(ByteField::BaseAllowance));
            }
            if registry.is_some_and(|r| c.retained_input_now > r.target_usize_max) {
                errors.push(BytesNotRepresentable(ByteField::RetainedInputNow));
            }
            if registry.is_some_and(|r| c.output_capacity > r.target_usize_max) {
                errors.push(BytesNotRepresentable(ByteField::OutputCapacity));
            }
            if registry.is_some_and(|r| c.read_len > r.target_usize_max) {
                errors.push(BytesNotRepresentable(ByteField::ReadLen));
            }
            let representable = options
                .iter()
                .all(|(_, v)| v.is_some_and(|v| registry.is_none_or(|r| v <= r.target_usize_max)));
            if representable {
                let retained = e.retained_input_max.unwrap();
                let internal = e.internal_peak_max.unwrap();
                let output = e.output_peak_max.unwrap();
                let keys = e.key_peak_max.unwrap();
                let total = e.total_peak_max.unwrap();
                if total == 0 {
                    errors.push(ZeroTotalPeak);
                }
                let sum = u128::from(retained)
                    + u128::from(internal)
                    + u128::from(output)
                    + u128::from(keys);
                if sum > u128::from(u64::MAX) {
                    errors.push(PeakSumOverflow);
                } else if sum > u128::from(total) {
                    errors.push(ComponentPeaksExceedTotal);
                }
                if registry.is_none_or(|r| c.base_allowance <= r.target_usize_max)
                    && total > c.base_allowance
                {
                    errors.push(BaseAllowanceExceeded);
                }
                if registry.is_none_or(|r| c.retained_input_now <= r.target_usize_max) {
                    if c.retained_input_now > retained {
                        errors.push(RetainedInputExceeded);
                    } else if e.sequence == 0
                        && registry.is_none_or(|r| c.read_len <= r.target_usize_max)
                        && u128::from(c.retained_input_now) + u128::from(c.read_len)
                            > u128::from(retained)
                    {
                        errors.push(ReadInputExceeded);
                    }
                }
                if registry.is_none_or(|r| c.output_capacity <= r.target_usize_max)
                    && c.output_capacity < output
                {
                    errors.push(OutputCapacityInsufficient);
                }
            }
            let space = [TlsSpace::Initial, TlsSpace::Handshake, TlsSpace::Data]
                .get(usize::from(e.space))
                .copied();
            let sequence =
                [TlsSequence::ReadThenWrite, TlsSequence::WriteOnly, TlsSequence::KeyUpdate]
                    .get(usize::from(e.sequence))
                    .copied();
            match space {
                None => errors.push(InvalidSpaceTag(e.space)),
                Some(s) if s != c.space => errors.push(SpaceMismatch),
                _ => {}
            }
            match sequence {
                None => errors.push(InvalidSequenceTag(e.sequence)),
                Some(s) if s != c.sequence => errors.push(SequenceMismatch),
                _ => {}
            }
            if let (Some(s), Some(q)) = (space, sequence) {
                if s == c.space
                    && q == c.sequence
                    && ((q == TlsSequence::KeyUpdate && s != TlsSpace::Data)
                        || registry.is_some_and(|r| !r.permitted.contains(&(s, q))))
                {
                    errors.push(DisallowedSpaceSequence);
                }
                if q != TlsSequence::ReadThenWrite && c.read_len != 0 {
                    errors.push(UnexpectedReadInput);
                }
            }
            if e.generation != c.generation {
                errors.push(GenerationMismatch);
            }
            if e.call_index != c.call_index {
                errors.push(CallIndexMismatch);
            }
            if c.key_slots < c.key_slots_required {
                errors.push(KeySlotsInsufficient);
            }
            errors
        }
        fn rejects(self, expected: TlsContractError) {
            assert_eq!(
                self.violations(),
                vec![expected],
                "fixture must violate exactly its owned rule"
            );
            let mut session = CountingSession::default();
            let callbacks = Cell::new(0);
            let result = crypto::with_validated_tls_envelope(
                self.envelope.as_ref(),
                &self.context,
                &mut session,
                |s, _| {
                    callbacks.set(callbacks.get() + 1);
                    s.is_handshaking()
                },
            );
            assert_eq!(result, Err(expected));
            assert_eq!(
                session.calls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "no Session method on rejection"
            );
            assert_eq!(callbacks.get(), 0, "no provider callback on rejection");
        }
    }
    #[derive(Default)]
    struct CountingSession {
        calls: std::sync::atomic::AtomicUsize,
    }
    impl CountingSession {
        fn called(&self) {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl Session for CountingSession {
        fn initial_keys(&self, _: &ConnectionId, _: Side) -> crypto::Keys {
            self.called();
            panic!("unexpected initial_keys")
        }
        fn handshake_data(&self) -> Option<Box<dyn Any>> {
            self.called();
            None
        }
        fn peer_identity(&self) -> Option<Box<dyn Any>> {
            self.called();
            None
        }
        fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
            self.called();
            None
        }
        fn early_data_accepted(&self) -> Option<bool> {
            self.called();
            None
        }
        fn is_handshaking(&self) -> bool {
            self.called();
            true
        }
        fn read_handshake(&mut self, _: &[u8]) -> Result<bool, TransportError> {
            self.called();
            Ok(false)
        }
        fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
            self.called();
            Ok(None)
        }
        fn write_handshake(&mut self, _: &mut Vec<u8>) -> Option<crypto::Keys> {
            self.called();
            None
        }
        fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
            self.called();
            None
        }
        fn is_valid_retry(&self, _: &ConnectionId, _: &[u8], _: &[u8]) -> bool {
            self.called();
            false
        }
        fn export_keying_material(
            &self,
            _: &mut [u8],
            _: &[u8],
            _: &[u8],
        ) -> Result<(), crypto::ExportKeyingMaterialError> {
            self.called();
            Ok(())
        }
    }
    #[test]
    fn valid_envelope_reaches_session_once() {
        let f = Fixture::valid();
        assert!(f.violations().is_empty());
        let mut session = CountingSession::default();
        let callbacks = Cell::new(0);
        assert_eq!(
            crypto::with_validated_tls_envelope(
                f.envelope.as_ref(),
                &f.context,
                &mut session,
                |s, _| {
                    callbacks.set(callbacks.get() + 1);
                    s.is_handshaking()
                }
            ),
            Ok(true)
        );
        assert_eq!(session.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(callbacks.get(), 1);
    }
    #[test]
    fn missing_envelope() {
        let mut f = Fixture::valid();
        f.envelope = None;
        f.rejects(MissingEnvelope);
    }
    #[test]
    fn unsupported_provider_configuration() {
        let mut f = Fixture::valid();
        f.context.registry = None;
        f.rejects(UnsupportedProviderConfiguration);
    }
    #[test]
    fn empty_identity_source_patch() {
        let mut f = Fixture::valid();
        f.envelope().identity.source_patch = "";
        f.rejects(EmptyIdentity(IdentityField::SourcePatch));
    }
    #[test]
    fn mismatched_identity_source_patch() {
        let mut f = Fixture::valid();
        f.envelope().identity.source_patch = "other";
        f.rejects(IdentityMismatch(IdentityField::SourcePatch));
    }
    #[test]
    fn empty_identity_runtime_features() {
        let mut f = Fixture::valid();
        f.envelope().identity.runtime_features = "";
        f.rejects(EmptyIdentity(IdentityField::RuntimeFeatures));
    }
    #[test]
    fn mismatched_identity_runtime_features() {
        let mut f = Fixture::valid();
        f.envelope().identity.runtime_features = "other";
        f.rejects(IdentityMismatch(IdentityField::RuntimeFeatures));
    }
    #[test]
    fn empty_identity_owner_layout() {
        let mut f = Fixture::valid();
        f.envelope().identity.owner_layout = "";
        f.rejects(EmptyIdentity(IdentityField::OwnerLayout));
    }
    #[test]
    fn mismatched_identity_owner_layout() {
        let mut f = Fixture::valid();
        f.envelope().identity.owner_layout = "other";
        f.rejects(IdentityMismatch(IdentityField::OwnerLayout));
    }
    #[test]
    fn empty_identity_target() {
        let mut f = Fixture::valid();
        f.envelope().identity.target = "";
        f.rejects(EmptyIdentity(IdentityField::Target));
    }
    #[test]
    fn mismatched_identity_target() {
        let mut f = Fixture::valid();
        f.envelope().identity.target = "other";
        f.rejects(IdentityMismatch(IdentityField::Target));
    }
    #[test]
    fn empty_identity_allocator() {
        let mut f = Fixture::valid();
        f.envelope().identity.allocator = "";
        f.rejects(EmptyIdentity(IdentityField::Allocator));
    }
    #[test]
    fn mismatched_identity_allocator() {
        let mut f = Fixture::valid();
        f.envelope().identity.allocator = "other";
        f.rejects(IdentityMismatch(IdentityField::Allocator));
    }
    #[test]
    fn empty_identity_provider() {
        let mut f = Fixture::valid();
        f.envelope().identity.provider = "";
        f.rejects(EmptyIdentity(IdentityField::Provider));
    }
    #[test]
    fn mismatched_identity_provider() {
        let mut f = Fixture::valid();
        f.envelope().identity.provider = "other";
        f.rejects(IdentityMismatch(IdentityField::Provider));
    }
    #[test]
    fn empty_identity_configuration() {
        let mut f = Fixture::valid();
        f.envelope().identity.configuration = "";
        f.rejects(EmptyIdentity(IdentityField::Configuration));
    }
    #[test]
    fn mismatched_identity_configuration() {
        let mut f = Fixture::valid();
        f.envelope().identity.configuration = "other";
        f.rejects(IdentityMismatch(IdentityField::Configuration));
    }
    #[test]
    fn missing_bound_retained_input_max() {
        let mut f = Fixture::valid();
        f.envelope().retained_input_max = None;
        f.rejects(MissingBound(ByteField::RetainedInputMax));
    }
    #[test]
    fn missing_bound_internal_peak_max() {
        let mut f = Fixture::valid();
        f.envelope().internal_peak_max = None;
        f.rejects(MissingBound(ByteField::InternalPeakMax));
    }
    #[test]
    fn missing_bound_output_peak_max() {
        let mut f = Fixture::valid();
        f.envelope().output_peak_max = None;
        f.rejects(MissingBound(ByteField::OutputPeakMax));
    }
    #[test]
    fn missing_bound_key_peak_max() {
        let mut f = Fixture::valid();
        f.envelope().key_peak_max = None;
        f.rejects(MissingBound(ByteField::KeyPeakMax));
    }
    #[test]
    fn missing_bound_total_peak_max() {
        let mut f = Fixture::valid();
        f.envelope().total_peak_max = None;
        f.rejects(MissingBound(ByteField::TotalPeakMax));
    }
    #[test]
    fn unrepresentable_bytes_retained_input_max() {
        let mut f = Fixture::valid();
        f.context.registry.as_mut().unwrap().target_usize_max = 255;
        f.context.base_allowance = 255;
        f.context.output_capacity = 255;
        f.envelope().retained_input_max = Some(256);
        f.rejects(BytesNotRepresentable(ByteField::RetainedInputMax));
    }
    #[test]
    fn unrepresentable_bytes_internal_peak_max() {
        let mut f = Fixture::valid();
        f.context.registry.as_mut().unwrap().target_usize_max = 255;
        f.context.base_allowance = 255;
        f.context.output_capacity = 255;
        f.envelope().internal_peak_max = Some(256);
        f.rejects(BytesNotRepresentable(ByteField::InternalPeakMax));
    }
    #[test]
    fn unrepresentable_bytes_output_peak_max() {
        let mut f = Fixture::valid();
        f.context.registry.as_mut().unwrap().target_usize_max = 255;
        f.context.base_allowance = 255;
        f.context.output_capacity = 255;
        f.envelope().output_peak_max = Some(256);
        f.rejects(BytesNotRepresentable(ByteField::OutputPeakMax));
    }
    #[test]
    fn unrepresentable_bytes_key_peak_max() {
        let mut f = Fixture::valid();
        f.context.registry.as_mut().unwrap().target_usize_max = 255;
        f.context.base_allowance = 255;
        f.context.output_capacity = 255;
        f.envelope().key_peak_max = Some(256);
        f.rejects(BytesNotRepresentable(ByteField::KeyPeakMax));
    }
    #[test]
    fn unrepresentable_bytes_total_peak_max() {
        let mut f = Fixture::valid();
        f.context.registry.as_mut().unwrap().target_usize_max = 255;
        f.context.base_allowance = 255;
        f.context.output_capacity = 255;
        f.envelope().total_peak_max = Some(256);
        f.rejects(BytesNotRepresentable(ByteField::TotalPeakMax));
    }
    #[test]
    fn unrepresentable_bytes_base_allowance() {
        let mut f = Fixture::valid();
        f.context.registry.as_mut().unwrap().target_usize_max = 255;
        f.context.base_allowance = 255;
        f.context.output_capacity = 255;
        f.context.base_allowance = 256;
        f.rejects(BytesNotRepresentable(ByteField::BaseAllowance));
    }
    #[test]
    fn unrepresentable_bytes_retained_input_now() {
        let mut f = Fixture::valid();
        f.context.registry.as_mut().unwrap().target_usize_max = 255;
        f.context.base_allowance = 255;
        f.context.output_capacity = 255;
        f.context.retained_input_now = 256;
        f.rejects(BytesNotRepresentable(ByteField::RetainedInputNow));
    }
    #[test]
    fn unrepresentable_bytes_output_capacity() {
        let mut f = Fixture::valid();
        f.context.registry.as_mut().unwrap().target_usize_max = 255;
        f.context.base_allowance = 255;
        f.context.output_capacity = 255;
        f.context.output_capacity = 256;
        f.rejects(BytesNotRepresentable(ByteField::OutputCapacity));
    }
    #[test]
    fn unrepresentable_bytes_read_len() {
        let mut f = Fixture::valid();
        f.context.registry.as_mut().unwrap().target_usize_max = 255;
        f.context.base_allowance = 255;
        f.context.output_capacity = 255;
        f.context.read_len = 256;
        f.rejects(BytesNotRepresentable(ByteField::ReadLen));
    }
    #[test]
    fn zero_total_peak() {
        let mut f = Fixture::valid();
        f.envelope().retained_input_max = Some(0);
        f.envelope().internal_peak_max = Some(0);
        f.envelope().output_peak_max = Some(0);
        f.envelope().key_peak_max = Some(0);
        f.envelope().total_peak_max = Some(0);
        f.context.retained_input_now = 0;
        f.context.read_len = 0;
        f.rejects(ZeroTotalPeak);
    }
    #[test]
    fn component_peak_sum_overflow() {
        let mut f = Fixture::valid();
        f.envelope().retained_input_max = Some(u64::MAX);
        f.envelope().total_peak_max = Some(u64::MAX);
        f.context.base_allowance = u64::MAX;
        f.rejects(PeakSumOverflow);
    }
    #[test]
    fn component_peaks_exceed_total() {
        let mut f = Fixture::valid();
        f.envelope().total_peak_max = Some(63);
        f.rejects(ComponentPeaksExceedTotal);
    }
    #[test]
    fn total_exceeds_base_allowance() {
        let mut f = Fixture::valid();
        f.context.base_allowance = 127;
        f.rejects(BaseAllowanceExceeded);
    }
    #[test]
    fn unknown_space_tag() {
        let mut f = Fixture::valid();
        f.envelope().space = 255;
        f.rejects(InvalidSpaceTag(255));
    }
    #[test]
    fn unknown_sequence_tag() {
        let mut f = Fixture::valid();
        f.envelope().sequence = 255;
        f.rejects(InvalidSequenceTag(255));
    }
    #[test]
    fn wrong_live_space() {
        let mut f = Fixture::valid();
        f.envelope().space = 0;
        f.rejects(SpaceMismatch);
    }
    #[test]
    fn wrong_requested_sequence() {
        let mut f = Fixture::valid();
        f.envelope().sequence = 1;
        f.context.read_len = 0;
        f.rejects(SequenceMismatch);
    }
    #[test]
    fn disallowed_space_sequence() {
        let mut f = Fixture::valid();
        f.envelope().sequence = 2;
        f.context.sequence = TlsSequence::KeyUpdate;
        f.context.read_len = 0;
        f.rejects(DisallowedSpaceSequence);
    }
    #[test]
    fn stale_generation() {
        let mut f = Fixture::valid();
        f.envelope().generation = 6;
        f.rejects(GenerationMismatch);
    }
    #[test]
    fn stale_call_index() {
        let mut f = Fixture::valid();
        f.envelope().call_index = 8;
        f.rejects(CallIndexMismatch);
    }
    #[test]
    fn retained_input_exceeds_bound() {
        let mut f = Fixture::valid();
        f.context.retained_input_now = 17;
        f.context.read_len = 0;
        f.rejects(RetainedInputExceeded);
    }
    #[test]
    fn read_exceeds_remaining_input() {
        let mut f = Fixture::valid();
        f.context.read_len = 13;
        f.rejects(ReadInputExceeded);
    }
    #[test]
    fn non_read_sequence_has_input() {
        let mut f = Fixture::valid();
        f.envelope().sequence = 1;
        f.context.sequence = TlsSequence::WriteOnly;
        f.rejects(UnexpectedReadInput);
    }
    #[test]
    fn insufficient_prepared_output() {
        let mut f = Fixture::valid();
        f.context.output_capacity = 15;
        f.rejects(OutputCapacityInsufficient);
    }
    #[test]
    fn insufficient_prepared_key_slots() {
        let mut f = Fixture::valid();
        f.context.key_slots = 1;
        f.rejects(KeySlotsInsufficient);
    }
}

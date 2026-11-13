// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::codec::Kind;
use super::{DecodeError, WireType, scan, valid_custody_id};
use serde_json::Value;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const VECTORS: &str = include_str!("../../fixtures/dm_fs_v3/wire_vectors.json");
const SCHEMA: &str = include_str!("../../fixtures/dm_fs_v3/wire_schema.json");

fn json() -> Result<(Value, Value)> {
    Ok((serde_json::from_str(SCHEMA)?, serde_json::from_str(VECTORS)?))
}
fn bytes(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd fixture hex".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(Into::into))
        .collect()
}
fn number(v: &Value) -> Result<usize> {
    Ok(usize::try_from(v.as_u64().ok_or("fixture integer")?)?)
}
fn string(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| "fixture string".into())
}
fn array(v: &Value) -> Result<&[Value]> {
    v.as_array().map(Vec::as_slice).ok_or_else(|| "fixture array".into())
}
fn kind(schema: &Value, name: &Value) -> Result<WireType> {
    Ok(WireType::try_from(u8::try_from(number(&schema["types"][string(name)?]["code"])?)?)?)
}

fn expected_kind(schema: &Value, name: &str) -> Result<Kind> {
    let nested = |name: &str| kind(schema, &Value::String(name.to_owned()));
    Ok(match name {
        "u64" => Kind::Fixed(8),
        "u32" => Kind::Fixed(4),
        "id" | "hash" | "key" => Kind::Fixed(32),
        "sig" => Kind::Fixed(64),
        "text" => Kind::Text,
        "profile" => Kind::Profile,
        "code" => Kind::Code,
        "bytes" => Kind::Bytes,
        "opt_id" | "opt_key" => Kind::OptionalFixed(32),
        value if value.starts_with("opt@") => Kind::OptionalNested(nested(&value[4..])?),
        value if value.starts_with('@') => Kind::Nested(nested(&value[1..])?),
        value if value.starts_with("list") => {
            let (count, name) = value[4..].split_once('@').ok_or("collection kind")?;
            Kind::List(count.parse()?, nested(name)?)
        }
        _ => return Err("unknown manifest kind".into()),
    })
}

#[test]
fn scanner_layout_and_borrowed_fields_match_p01_manifest() -> Result {
    let (schema, vectors) = json()?;
    let types = schema["types"].as_object().ok_or("types")?;
    assert_eq!(types.len(), 19);
    for (name, layout) in types {
        let kind = kind(&schema, &Value::String(name.clone()))?;
        assert_eq!(kind.ceiling(), number(&layout["ceiling"])?);
        assert_eq!(layout["version"], 1);
        let fields = array(&layout["fields"])?;
        assert_eq!(kind.specs().len(), fields.len());
        for (spec, field) in kind.specs().iter().zip(fields) {
            assert_eq!(usize::from(spec.id), number(&field["id"])?);
            assert_eq!(spec.max, number(&field["max_bytes"])?);
            assert_eq!(spec.kind, expected_kind(&schema, string(&field["kind"])?)?);
            assert_eq!(field["required"], true);
        }
    }
    assert!(WireType::try_from(0).is_err());
    assert!(WireType::try_from(20).is_err());
    for vector in array(&vectors["positive"])? {
        let kind = kind(&schema, &vector["type"])?;
        let raw = bytes(string(&vector["bytes"])?)?;
        let view = scan(kind, &raw)?;
        assert_eq!(view.kind(), kind);
        assert_eq!(view.as_bytes().as_ptr(), raw.as_ptr());
        assert_eq!(view.fields().count(), kind.specs().len());
        for (field, spec) in view.fields().zip(kind.specs()) {
            assert_eq!(field.id, spec.id);
            assert_eq!(view.field(field.id), Some(field.value));
            assert!(field.value.as_ptr() >= raw.as_ptr());
            assert!(field.value.as_ptr_range().end <= raw.as_ptr_range().end);
        }
        assert!(view.field(u16::MAX).is_none());
    }
    Ok(())
}

#[test]
fn dm_fs_v3_unknown_and_extra_fields_rejected() -> Result {
    let (schema, vectors) = json()?;
    let negatives = array(&vectors["negative"])?;
    assert_eq!(negatives.len(), 132);
    for vector in negatives {
        let raw = bytes(string(&vector["bytes"])?)?;
        assert!(scan(kind(&schema, &vector["type"])?, &raw).is_err(), "{}", vector["name"]);
    }
    // ID+1, invalid UTF-8, control characters, scalar width and total/per-field caps.
    let valid = array(&vectors["positive"])?[0].clone();
    let original = bytes(string(&valid["bytes"])?)?;
    for value in [vec![b'x'; 257], vec![0xff], b"bad\nID".to_vec(), Vec::new()] {
        let invalid = replace_field(WireType::QualifiedBranch, &original, 3, &value)?;
        assert!(scan(WireType::QualifiedBranch, &invalid).is_err());
    }
    let invalid = replace_field(WireType::QualifiedBranch, &original, 1, &[0; 31])?;
    assert_eq!(scan(WireType::QualifiedBranch, &invalid).err(), Some(DecodeError::Value));
    let id_rows: Vec<_> = array(&vectors["invalid_inputs"])?
        .iter()
        .filter(|v| matches!(v["name"].as_str(), Some("id_257" | "id_control" | "id_empty")))
        .collect();
    assert_eq!(id_rows.len(), 3);
    for row in id_rows {
        assert_eq!(row["type"], "QualifiedBranch");
        let invalid = replace_field(
            WireType::QualifiedBranch,
            &original,
            3,
            string(&row["input"]["device_id"])?.as_bytes(),
        )?;
        assert!(scan(WireType::QualifiedBranch, &invalid).is_err(), "{}", row["name"]);
    }
    let mut invalid = original;
    invalid.resize(WireType::QualifiedBranch.ceiling() + 1, 0);
    assert_eq!(scan(WireType::QualifiedBranch, &invalid).err(), Some(DecodeError::TypeCeiling));
    Ok(())
}

#[test]
fn dm_fs_v3_trailing_bytes_rejected() -> Result {
    let (schema, vectors) = json()?;
    for vector in array(&vectors["positive"])? {
        let mut raw = bytes(string(&vector["bytes"])?)?;
        raw.push(0);
        assert_eq!(scan(kind(&schema, &vector["type"])?, &raw).err(), Some(DecodeError::Trailing));
    }
    Ok(())
}

fn replace_field(kind: WireType, raw: &[u8], id: u16, value: &[u8]) -> Result<Vec<u8>> {
    let view = scan(kind, raw)?;
    let mut out = raw[..8].to_vec();
    for field in view.fields() {
        let bytes = if field.id == id { value } else { field.value };
        out.extend_from_slice(&field.id.to_be_bytes());
        out.extend_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

#[test]
fn dm_fs_v3_length_prefix_lies_rejected_without_allocation() -> Result {
    let (schema, vectors) = json()?;
    // The observer measures System allocator calls; an allocating control proves it is live.
    let (control, stats) = allocation::measure(|| Vec::<u8>::with_capacity(256));
    assert!(stats.calls > 0 && stats.requested >= 256 && stats.peak >= 256);
    drop(control);
    for vector in array(&vectors["positive"])? {
        let kind = kind(&schema, &vector["type"])?;
        let raw = bytes(string(&vector["bytes"])?)?;
        let (result, stats) = allocation::measure(|| scan(kind, &raw));
        assert!(result.is_ok());
        assert_eq!(stats, allocation::Stats::default(), "borrowed scanner allocated");
    }
    let mut huge = vec![0; 5 * 1024 * 1024];
    huge[..14].copy_from_slice(&[b'R', b'F', b'S', b'1', 1, 1, 0, 8, 0, 1, 0xff, 0xff, 0xff, 0xff]);
    let mut truncated = b"RFS1\x01\x01\x00\x08\x00\x01\x00\x00\x00\x20".to_vec();
    let ((), stats) = allocation::measure(|| ()); // preinitialize observer TLS outside assertions
    assert_eq!(stats, allocation::Stats::default());
    for (input, error) in [(&huge, DecodeError::TypeCeiling), (&truncated, DecodeError::Truncated)]
    {
        let (result, stats) = allocation::measure(|| scan(WireType::QualifiedBranch, input).err());
        assert_eq!(result, Some(error), "remaining-length rejection must return an error");
        // Zero-copy scanning has zero allocator requests, stronger than cap + 0 overhead.
        assert_eq!(stats, allocation::Stats::default(), "untrusted prefix caused allocation");
        assert!(
            stats.requested <= WireType::QualifiedBranch.ceiling()
                && stats.peak <= WireType::QualifiedBranch.ceiling()
        );
    }
    truncated[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(scan(WireType::QualifiedBranch, &truncated).err(), Some(DecodeError::FieldCeiling));
    // Nested collection element length lies, within its own declared type ceiling.
    let vector = array(&vectors["positive"])?
        .iter()
        .find(|v| v["type"] == "OwnerPrekeyUpdate")
        .ok_or("update")?;
    let original = bytes(string(&vector["bytes"])?)?;
    let raw = replace_field(WireType::OwnerPrekeyUpdate, &original, 4, &[0, 1, 0, 0, 2, 0])?;
    let (result, stats) = allocation::measure(|| scan(WireType::OwnerPrekeyUpdate, &raw).err());
    assert_eq!(result, Some(DecodeError::Truncated));
    assert_eq!(stats, allocation::Stats::default());
    Ok(())
}

#[test]
fn dm_fs_v3_malformed_input_never_panics() -> Result {
    let (schema, vectors) = json()?;
    for vector in array(&vectors["positive"])? {
        let kind = kind(&schema, &vector["type"])?;
        let raw = bytes(string(&vector["bytes"])?)?;
        // Every prefix of all 27 fixed wire fixtures, plus each single-byte XOR.
        for length in 0..raw.len() {
            assert!(
                scan(kind, &raw[..length]).is_err(),
                "test: accepted truncated prefix {length}"
            );
        }
        let mut changed = raw;
        for offset in 0..changed.len() {
            changed[offset] ^= 0xff;
            let _result = scan(kind, &changed);
            changed[offset] ^= 0xff;
        }
    }
    Ok(())
}

#[test]
fn scanner_collection_and_optional_boundaries() -> Result {
    let (schema, vectors) = json()?;
    for vector in array(&vectors["positive"])? {
        let kind = kind(&schema, &vector["type"])?;
        let raw = bytes(string(&vector["bytes"])?)?;
        for spec in kind.specs() {
            match spec.kind {
                Kind::List(cap, _) => {
                    let count = u16::try_from(cap)?;
                    let invalid = replace_field(kind, &raw, spec.id, &(count + 1).to_be_bytes())?;
                    assert_eq!(scan(kind, &invalid).err(), Some(DecodeError::Count));
                    let at_cap = replace_field(kind, &raw, spec.id, &count.to_be_bytes())?;
                    assert_eq!(scan(kind, &at_cap).err(), Some(DecodeError::Truncated));
                    let trailing = replace_field(kind, &raw, spec.id, &[0, 0, 1])?;
                    assert_eq!(scan(kind, &trailing).err(), Some(DecodeError::Trailing));
                }
                Kind::OptionalFixed(_) | Kind::OptionalNested(_) => {
                    for value in [&[2][..], &[0, 1][..], &[1][..]] {
                        let invalid = replace_field(kind, &raw, spec.id, value)?;
                        assert!(scan(kind, &invalid).is_err());
                    }
                }
                Kind::Code => {
                    for value in [b"bad\ncode".as_slice(), "bad\u{80}code".as_bytes()] {
                        let invalid = replace_field(kind, &raw, spec.id, value)?;
                        assert_eq!(scan(kind, &invalid).err(), Some(DecodeError::Value));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[test]
fn dm_fs_v3_id_validation_matches_custody() {
    // The sibling verifier is private. Pin its actual predicate without widening it.
    let source = include_str!("../../../ramflux-crypto/src/custody/validate.rs");
    let source = source.split("pub(super) fn id(").nth(1).unwrap_or_default();
    let body = source.split("pub(super) fn time(").next().unwrap_or_default();
    let normalized: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        normalized
            .contains("ifvalue.is_empty()||value.len()>256||value.chars().any(char::is_control)")
    );
    for value in ["", "valid", "设备", "a\0b", "a\u{7f}b", "a\u{80}b", "a\u{9f}b", "a\u{200b}b"] {
        let custody_accepts =
            !(value.is_empty() || value.len() > 256 || value.chars().any(char::is_control));
        assert_eq!(valid_custody_id(value), custody_accepts);
    }
    for size in [255, 256, 257] {
        assert_eq!(valid_custody_id(&"x".repeat(size)), size <= 256);
    }
    assert!(valid_custody_id(&"é".repeat(128)));
    assert!(!valid_custody_id(&"é".repeat(129)));
    for code in (0..=0x1f).chain(0x7f..=0x9f) {
        if let Some(ch) = char::from_u32(code) {
            assert!(!valid_custody_id(&format!("a{ch}b")));
        }
    }
}

// This narrowly scoped test observer is the only unsafe code in the new module.
// Production scanning uses safe borrowed slices and never consults these counters.
#[allow(unsafe_code)]
mod allocation {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(super) struct Stats {
        pub calls: usize,
        pub requested: usize,
        pub peak: usize,
        live: usize,
    }
    thread_local! { static ACTIVE:Cell<Option<Stats>>=const {Cell::new(None)}; }
    struct Observer;
    #[global_allocator]
    static ALLOCATOR: Observer = Observer;
    fn record(request: Option<usize>, added: usize, removed: usize) {
        let _ = ACTIVE.try_with(|cell| {
            if let Some(mut stats) = cell.get() {
                if let Some(size) = request {
                    stats.calls = stats.calls.saturating_add(1);
                    stats.requested = stats.requested.saturating_add(size);
                }
                stats.live = stats.live.saturating_sub(removed).saturating_add(added);
                stats.peak = stats.peak.max(stats.live);
                cell.set(Some(stats));
            }
        });
    }
    // SAFETY: every allocation/deallocation is forwarded unchanged to System;
    // the observer only touches constant-initialized thread-local integer cells.
    unsafe impl GlobalAlloc for Observer {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller supplies the GlobalAlloc layout contract.
            let ptr = unsafe { System.alloc(layout) };
            record(Some(layout.size()), if ptr.is_null() { 0 } else { layout.size() }, 0);
            ptr
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller supplies the GlobalAlloc layout contract.
            let ptr = unsafe { System.alloc_zeroed(layout) };
            record(Some(layout.size()), if ptr.is_null() { 0 } else { layout.size() }, 0);
            ptr
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            // SAFETY: caller owns ptr with this layout and supplies a valid new size.
            let out = unsafe { System.realloc(ptr, layout, size) };
            if out.is_null() {
                record(Some(size), 0, 0);
            } else {
                record(Some(size), size, layout.size());
            }
            out
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            record(None, 0, layout.size());
            // SAFETY: caller owns the allocation and supplies its original layout.
            unsafe { System.dealloc(ptr, layout) };
        }
    }
    struct Scope;
    impl Drop for Scope {
        fn drop(&mut self) {
            ACTIVE.set(None);
        }
    }
    pub(super) fn measure<T>(f: impl FnOnce() -> T) -> (T, Stats) {
        assert!(ACTIVE.get().is_none());
        ACTIVE.set(Some(Stats::default()));
        let scope = Scope;
        let result = f();
        let stats = ACTIVE.get().unwrap_or_default();
        drop(scope);
        (result, stats)
    }
}

fn maximum_collection_scans(owner: &str, field: u16, element: &str, count: u16) -> Result {
    let (schema, vectors) = json()?;
    let maxima = array(&vectors["filled_maximum"])?;
    let vector = maxima.iter().find(|v| v["type"] == owner).ok_or("owner maximum")?;
    let raw = bytes(string(&vector["bytes"])?)?;
    let wire_type = kind(&schema, &vector["type"])?;
    let view = scan(wire_type, &raw)?;
    let mut list = view.field(field).ok_or("collection field")?;
    let observed = u16::from_be_bytes(list.get(..2).ok_or("count")?.try_into()?);
    assert_eq!(observed, count);
    list = &list[2..];
    let child_type = kind(&schema, &Value::String(element.to_owned()))?;
    for _ in 0..count {
        let length =
            usize::try_from(u32::from_be_bytes(list.get(..4).ok_or("length")?.try_into()?))?;
        list = &list[4..];
        scan(child_type, list.get(..length).ok_or("element")?)?;
        list = &list[length..];
    }
    assert_eq!(list, b"");
    assert_maximum_fields(wire_type, &raw)?;
    if wire_type == WireType::OwnerStatusQuery {
        assert_eq!(raw.len(), 16_390);
        let frame =
            maxima.iter().find(|v| v["type"] == "NativePrekeyStatus").ok_or("frame maximum")?;
        scan(WireType::NativePrekeyStatus, &bytes(string(&frame["bytes"])?)?)?;
    }
    Ok(())
}

fn canonical_maximum(kind: WireType) -> Result<usize> {
    kind.specs().iter().try_fold(8usize, |total, spec| {
        let size = match spec.kind {
            Kind::Fixed(n) => n,
            Kind::Profile => b"ramflux.dm.bootstrap.fs.v1".len(),
            Kind::Text | Kind::Code | Kind::Bytes => match (kind, spec.id) {
                (WireType::PrekeyLeaseResult, 10) => 4,
                (WireType::OwnerStatusEntry, 6) => 8,
                (WireType::NativePrekeyRequest, 2) => 7,
                (WireType::NativePrekeyResult, 3) => 6,
                (WireType::NativePrekeyResult, 6 | 7) => 0,
                _ => spec.max,
            },
            Kind::Nested(child) => canonical_maximum(child)?
                .checked_sub(match (kind, spec.id) {
                    (WireType::NativePrekeyLease, 2) => 2,
                    (WireType::NativePrekeyStatus, 2) => 1,
                    _ => 0,
                })
                .ok_or("size underflow")?,
            Kind::OptionalFixed(n) => n.checked_add(1).ok_or("size overflow")?,
            Kind::OptionalNested(_) if kind == WireType::NativePrekeyResult && spec.id == 4 => 1,
            Kind::OptionalNested(child) => {
                canonical_maximum(child)?.checked_add(1).ok_or("size overflow")?
            }
            Kind::List(count, child) => canonical_maximum(child)?
                .checked_add(4)
                .and_then(|n| n.checked_mul(count))
                .and_then(|n| n.checked_add(2))
                .ok_or("size overflow")?,
        };
        total.checked_add(6).and_then(|n| n.checked_add(size)).ok_or_else(|| "size overflow".into())
    })
}

fn assert_maximum_fields(kind: WireType, raw: &[u8]) -> Result {
    let view = scan(kind, raw)?;
    for (field, spec) in view.fields().zip(kind.specs()) {
        match spec.kind {
            Kind::Text => assert_eq!(field.value.len(), 256),
            Kind::Code => match (kind, spec.id) {
                (WireType::PrekeyLeaseResult, 10) => assert_eq!(field.value, b"none"),
                (WireType::OwnerStatusEntry, 6) => assert_eq!(field.value, b"unleased"),
                (WireType::NativePrekeyRequest, 2) => {
                    assert!(matches!(field.value, b"lease" | b"publish" | b"status"));
                }
                (WireType::NativePrekeyResult, 3) => assert_eq!(field.value, b"status"),
                (WireType::NativePrekeyResult, 6 | 7) => assert_eq!(field.value, b""),
                _ => assert_eq!(field.value.len(), spec.max),
            },
            Kind::Bytes => assert_eq!(field.value.len(), spec.max),
            Kind::Nested(child) => assert_maximum_fields(child, field.value)?,
            Kind::OptionalNested(_) if kind == WireType::NativePrekeyResult && spec.id == 4 => {
                assert_eq!(field.value, &[0]);
            }
            Kind::OptionalNested(child) => {
                assert_eq!(field.value.first(), Some(&1));
                assert_maximum_fields(child, &field.value[1..])?;
            }
            Kind::OptionalFixed(size) => {
                assert_eq!(field.value.first(), Some(&1));
                assert_eq!(field.value.len(), size + 1);
            }
            Kind::List(count, child) => {
                let mut rest = field.value;
                assert_eq!(usize::from(u16::from_be_bytes(rest[..2].try_into()?)), count);
                rest = &rest[2..];
                for _ in 0..count {
                    let length = usize::try_from(u32::from_be_bytes(rest[..4].try_into()?))?;
                    rest = &rest[4..];
                    assert_maximum_fields(child, &rest[..length])?;
                    rest = &rest[length..];
                }
                assert_eq!(rest, b"");
            }
            Kind::Fixed(_) | Kind::Profile => {}
        }
    }
    Ok(())
}

#[test]
fn scanner_worst_case_frames_all_fit() -> Result {
    let (schema, vectors) = json()?;
    let maxima = array(&vectors["filled_maximum"])?;
    assert_eq!(maxima.len(), 19);
    for vector in maxima {
        let kind = kind(&schema, &vector["type"])?;
        let raw = bytes(string(&vector["bytes"])?)?;
        let worst = canonical_maximum(kind)?;
        let row = &schema["size_policy"]["table"][string(&vector["type"])?];
        assert_eq!(raw.len(), worst);
        assert_eq!(worst, number(&row["worst_case_bytes"])?);
        let ceiling = worst.checked_mul(102).ok_or("size overflow")?.div_ceil(102_400) * 1024;
        assert_eq!(kind.ceiling(), ceiling);
        assert_eq!(ceiling, number(&row["ceiling"])?);
        assert_maximum_fields(kind, &raw)?;
    }
    Ok(())
}

#[test]
fn owner_update_maximum_additive_opks_scan() -> Result {
    maximum_collection_scans("OwnerPrekeyUpdate", 4, "SignedNativeOpk", 64)
}
#[test]
fn owner_update_maximum_retirements_scan() -> Result {
    maximum_collection_scans("OwnerPrekeyUpdate", 5, "RetirementRef", 400)
}
#[test]
fn publication_snapshot_maximum_pending_retirements_scan() -> Result {
    maximum_collection_scans("PrekeyPublicationSnapshot", 6, "RetirementRef", 400)
}
#[test]
fn owner_status_query_maximum_requested_ids_scan() -> Result {
    maximum_collection_scans("OwnerStatusQuery", 3, "RetirementRef", 200)
}
#[test]
fn owner_status_maximum_entries_scan() -> Result {
    maximum_collection_scans("OwnerPrekeyStatus", 9, "OwnerStatusEntry", 200)
}

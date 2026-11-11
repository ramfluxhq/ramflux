// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Compiled owners choose key columns; this codec supplies only the frozen OVP-10 grammar.
//! A contribution reference is stored separately and is never confused with native authorship.
use super::{CellType, Result, WireError, require};
use zeroize::Zeroizing;

pub const MAX_STABLE_KEY_BYTES: usize = 32_768;

/// Encode declared key cells in column order, including exact finite f64 wire bits (A5.M3).
/// The resulting string is compared bytewise; it is deliberately not a numeric SQL order.
/// # Errors
/// Refuses wrong physical types, nonfinite floats, invalid UTF-8 or an over-limit key before
/// allocating beyond the fixed key budget. Unknown/undeclared key columns belong to the catalog.
pub fn encode_stable_key<'a>(
    cells: impl IntoIterator<Item = (CellType, &'a [u8])>,
) -> Result<Zeroizing<String>> {
    let mut framed = Zeroizing::new(Vec::with_capacity(MAX_STABLE_KEY_BYTES));
    for (kind, bytes) in cells {
        let tag = match kind {
            CellType::Null => {
                require(bytes.is_empty(), "UnsupportedRecord")?;
                0
            }
            CellType::I64 => {
                require(bytes.len() == 8, "UnsupportedRecord")?;
                1
            }
            CellType::F64 => {
                let raw: [u8; 8] =
                    bytes.try_into().map_err(|_| WireError::Field("UnsupportedRecord"))?;
                require(f64::from_be_bytes(raw).is_finite(), "UnsupportedRecord")?;
                2
            }
            CellType::Utf8 => {
                require(std::str::from_utf8(bytes).is_ok(), "UnsupportedRecord")?;
                3
            }
            CellType::Bytes => 4,
        };
        let next = framed
            .len()
            .checked_add(5)
            .and_then(|length| length.checked_add(bytes.len()))
            .ok_or(WireError::Field("UnsupportedRecord"))?;
        require(next <= MAX_STABLE_KEY_BYTES, "UnsupportedRecord")?;
        framed.push(tag);
        framed.extend_from_slice(
            &u32::try_from(bytes.len())
                .map_err(|_| WireError::Field("UnsupportedRecord"))?
                .to_be_bytes(),
        );
        framed.extend_from_slice(bytes);
    }
    require(!framed.is_empty(), "UnsupportedRecord")?;
    Ok(Zeroizing::new(crate::encode_base64url(framed.as_slice())))
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn full_stable_key_framing_pins_all_five_types_and_exact_float_bits() -> TestResult {
        let integer = (-2_i64).to_be_bytes();
        let real = (-0.0_f64).to_be_bytes();
        let key = encode_stable_key([
            (CellType::Null, b"".as_slice()),
            (CellType::I64, integer.as_slice()),
            (CellType::F64, real.as_slice()),
            (CellType::Utf8, "é".as_bytes()),
            (CellType::Bytes, &[0, 255]),
        ])?;
        // Literal independent frame: tags 0/1/2/3/4, u32 lengths, raw big-endian values.
        let expected = [
            0, 0, 0, 0, 0, 1, 0, 0, 0, 8, 255, 255, 255, 255, 255, 255, 255, 254, 2, 0, 0, 0, 8,
            128, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 2, 195, 169, 4, 0, 0, 0, 2, 0, 255,
        ];
        assert_eq!(crate::decode_base64url(key.as_str())?, expected);
        let positive_zero = encode_stable_key([(CellType::F64, 0.0_f64.to_be_bytes().as_slice())])?;
        let negative_zero = encode_stable_key([(CellType::F64, real.as_slice())])?;
        assert_ne!(positive_zero.as_str(), negative_zero.as_str());
        for real in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(encode_stable_key([(CellType::F64, real.to_be_bytes().as_slice())]).is_err());
        }
        assert!(encode_stable_key([(CellType::Null, b"x".as_slice())]).is_err());
        assert!(encode_stable_key([(CellType::I64, b"1".as_slice())]).is_err());
        assert!(encode_stable_key([(CellType::Utf8, [255].as_slice())]).is_err());
        Ok(())
    }
    #[test]
    fn full_stable_key_exact_bound_is_checked_before_output() -> TestResult {
        let bytes = vec![1; MAX_STABLE_KEY_BYTES - 5];
        let key = encode_stable_key([(CellType::Bytes, bytes.as_slice())])?;
        assert_eq!(crate::decode_base64url(key.as_str())?.len(), MAX_STABLE_KEY_BYTES);
        assert!(
            encode_stable_key([
                (CellType::Bytes, bytes.as_slice()),
                (CellType::Null, b"".as_slice())
            ])
            .is_err()
        );
        assert!(encode_stable_key(std::iter::empty()).is_err());
        Ok(())
    }
}

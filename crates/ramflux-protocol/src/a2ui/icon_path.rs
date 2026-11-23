// SPDX-License-Identifier: BSD-3-Clause
//! Path data only. No SVG document, XML parser, links or external resources.
use super::Reject;
pub(super) fn validate(path: &str) -> Result<(), Reject> {
    if path.len() > 4096 {
        return Err(Reject::Limit);
    }
    let bytes = path.as_bytes();
    let mut position = 0usize;
    let mut commands = 0usize;
    let mut first = true;
    while position < bytes.len() {
        space(bytes, &mut position);
        if position == bytes.len() {
            break;
        }
        let command = *bytes.get(position).ok_or(Reject::Expression)?;
        position += 1;
        let arity = match command.to_ascii_uppercase() {
            b'M' | b'L' | b'T' => 2,
            b'H' | b'V' => 1,
            b'C' => 6,
            b'S' | b'Q' => 4,
            b'A' => 7,
            b'Z' => 0,
            _ => return Err(Reject::Expression),
        };
        if first && !matches!(command, b'M' | b'm') {
            return Err(Reject::Expression);
        }
        first = false;
        if arity == 0 {
            commands += 1;
        } else {
            let mut groups = 0usize;
            loop {
                for i in 0..arity {
                    space(bytes, &mut position);
                    if bytes.get(position) == Some(&b',') {
                        if i == 0 && groups == 0 {
                            return Err(Reject::Expression);
                        }
                        position += 1;
                        space(bytes, &mut position);
                    }
                    if command.eq_ignore_ascii_case(&b'A') && matches!(i, 3 | 4) {
                        if !matches!(bytes.get(position), Some(b'0' | b'1')) {
                            return Err(Reject::Expression);
                        }
                        position += 1;
                    } else {
                        let number = number(path, &mut position)?;
                        if command.eq_ignore_ascii_case(&b'A') && i < 2 && number < 0.0 {
                            return Err(Reject::Expression);
                        }
                    }
                }
                commands += 1;
                groups += 1;
                if commands > 1024 {
                    return Err(Reject::Limit);
                }
                space(bytes, &mut position);
                if bytes.get(position).is_none_or(u8::is_ascii_alphabetic) {
                    break;
                }
            }
        }
        if commands > 1024 {
            return Err(Reject::Limit);
        }
    }
    if first {
        return Err(Reject::Expression);
    }
    Ok(())
}
fn space(bytes: &[u8], position: &mut usize) {
    while bytes.get(*position).is_some_and(u8::is_ascii_whitespace) {
        *position += 1;
    }
}
fn number(path: &str, position: &mut usize) -> Result<f64, Reject> {
    let bytes = path.as_bytes();
    let start = *position;
    if bytes.get(*position).is_some_and(|c| matches!(c, b'+' | b'-')) {
        *position += 1;
    }
    let mut digits = 0usize;
    while bytes.get(*position).is_some_and(u8::is_ascii_digit) {
        *position += 1;
        digits += 1;
    }
    if bytes.get(*position) == Some(&b'.') {
        *position += 1;
        while bytes.get(*position).is_some_and(u8::is_ascii_digit) {
            *position += 1;
            digits += 1;
        }
    }
    if digits == 0 {
        return Err(Reject::Expression);
    }
    if bytes.get(*position).is_some_and(|c| matches!(c, b'e' | b'E')) {
        *position += 1;
        if bytes.get(*position).is_some_and(|c| matches!(c, b'+' | b'-')) {
            *position += 1;
        }
        let exponent = *position;
        while bytes.get(*position).is_some_and(u8::is_ascii_digit) {
            *position += 1;
        }
        if exponent == *position {
            return Err(Reject::Expression);
        }
    }
    path.get(start..*position)
        .and_then(|text| text.parse::<f64>().ok())
        .filter(|n| n.is_finite())
        .ok_or(Reject::Expression)
}

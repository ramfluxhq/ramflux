// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes { output.push(char::from(DIGITS[usize::from(byte >> 4)])); output.push(char::from(DIGITS[usize::from(byte & 15)])); }
    output
}

#[test]
fn sweep2_hash_transcripts_match_fixed_vectors() -> Result<(), Box<dyn std::error::Error>> {
    // Independently calculated with the Python blake3 package and explicit byte concatenation.
    let vectors: serde_json::Value = serde_json::from_str(include_str!("sweep2_hash_vectors.json"))?;
    let author = QualifiedDevice { account_anchor: "anchor".into(), device_id: "device".into(), device_epoch: 1 };
    let id: Vec<u8> = (0..32).collect();
    let inputs = [
        ("id", event_transcript(&author, "c", 42)?, derive(&author, "c", 42)?),
        ("tombstone", tombstone_transcript(&id)?, delete_tombstone(&id)?),
        ("page", super::super::history_chain::transcript(&id, 1, &[17;32], &[b"\x0a\x03one", b"\x0a\x03two"])?,
            super::super::history_chain::digest(&id, 1, &[17;32], &[b"\x0a\x03one", b"\x0a\x03two"])?),
    ];
    for (name, transcript, output) in inputs {
        assert_eq!(hex(&transcript), vectors[name]["transcript"].as_str().ok_or("transcript missing")?, "{name} transcript");
        assert_eq!(hex(&output), vectors[name]["output"].as_str().ok_or("output missing")?, "{name} output");
    }
    Ok(())
}

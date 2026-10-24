#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Reject direct bare-device identity indexes and untyped device key builders.

This deliberately complements Rust's typed API checks: it inspects production
source, so introducing another String key helper cannot bypass those APIs.
Wire fields and display metadata are permitted; using them directly as an index
or as the input of an identity key builder is not. Historical reads must have
an explicitly named legacy function and check retained root provenance.
"""
import re
import sys
from pathlib import Path

FUNCTION = re.compile(r"\bfn\s+(\w+)\s*(?:<[^{}]*?>)?\s*\(")
DEVICE = r"(?:\w+\.)*(?:\w*_)?(?:device_id|device|sender|receiver|actor|member|local|remote)(?:_id)?"
STRING_ARG = re.compile(rf"\b({DEVICE})\s*:\s*(?:&\s*(?:str|String)|String)\b")
INDEX = re.compile(rf"\.(?:get|get_mut|insert|entry|contains_key|remove)\s*\(\s*&?\s*({DEVICE})(?:\.clone\(\)|\.to_owned\(\))?\s*[,)]")


def functions(source):
    # Comments cannot hide a match or manufacture a key expression.
    source = re.sub(r"/\*.*?\*/|//[^\n]*", lambda m: "\n" * m[0].count("\n"), source, flags=re.S)
    for match in FUNCTION.finditer(source):
        opening = source.find("{", match.end())
        semicolon = source.find(";", match.end())
        if opening < 0 or 0 <= semicolon < opening:
            continue
        depth, i = 1, opening + 1
        # Mask literals for brace balancing; retain them in the returned body.
        masked = re.sub(r'"(?:\\.|[^"\\])*"', lambda m: " " * len(m[0]), source)
        while i < len(source) and depth:
            depth += (masked[i] == "{") - (masked[i] == "}")
            i += 1
        yield match[1], source[match.end():opening], source[opening:i], source.count("\n", 0, match.start()) + 1


def violations(source, path):
    found = []
    for name, signature, body, line in functions(source):
        if name.startswith("legacy_"):
            continue
        typed = "RootQualifiedDeviceRef" in signature or "RootQualifiedDeviceIdentity" in signature
        args = STRING_ARG.findall(signature)
        if args and not typed and re.search(r"(?:_key|_bucket|_replay|_dedup|_receipt)$", name):
            if re.search(r"\b(?:format!|canonical_json_bytes|hash_base64url|blake3_256)", body):
                found.append((line, f"{name}: device key builder requires RootQualifiedDeviceRef"))
        for assignment in re.finditer(r"let\s+(?:mut\s+)?(\w*(?:key|bucket|dedup|replay)\w*)\s*=([^;]+);", body):
            expression = assignment[2]
            if not typed and re.search(r"format!|canonical_json_bytes|hash_base64url|blake3_256", expression):
                if any(re.search(rf"\b{re.escape(arg)}\b", expression) for arg in args) or re.search(r"\b(?:\w*device_id|sender_id|receiver_id)\b", expression):
                    found.append((line, f"{name}: inline device identity key requires RootQualifiedDeviceRef"))
        for index in INDEX.finditer(body):
            value = index[1]
            # Typed key access is permitted; serializing the qualified reference at
            # a DB boundary is explicit via storage_key(), not an implicit coercion.
            if value in args or "." in value and value.endswith("device_id"):
                found.append((line, f"{name}: direct device index {value}; require a qualified reference"))
    if path == "crates/ramflux-crypto/src/device_reference.rs":
        declaration = re.search(r"struct\s+RootQualifiedDeviceRef\s*\{([^}]+)\}", source, re.S)
        if not declaration or re.search(r"\bpub\b", declaration[1]):
            found.append((1, "authenticated device reference fields must stay private"))
        if re.search(r"impl\s+(?:<[^>]+>\s*)?(?:\w+::)*(?:Deserialize|From|TryFrom|Deref|Display|AsRef)\b[^{}]*\b(?:for\s+)?RootQualifiedDeviceRef", source):
            found.append((1, "authenticated device reference cannot acquire a string or deserialization shortcut"))
        if re.search(r"#\[derive\([^]]*(?:Serialize|Deserialize)[^]]*\)\]", source):
            found.append((1, "authenticated device reference must not derive wire serialization"))
    if path != "crates/ramflux-crypto/src/device_reference.rs":
        if re.search(r"impl\s+(?:ramflux_protocol::)?RootQualifiedDeviceIdentity\s+for", source):
            found.append((1, "only the authenticated crypto reference implements the identity view"))
    return found


def check(root):
    errors = []
    for base in (root / "crates", root / "apps"):
        for file in sorted(base.rglob("*.rs")):
            path = file.relative_to(root).as_posix()
            if "tests" in file.parts or file.stem.endswith("tests") or file.stem == "test_support":
                continue
            source = file.read_text().split("#[cfg(test)]", 1)[0]
            errors.extend(f"{path}:{line}: {message}" for line, message in violations(source, path))
    return errors


if __name__ == "__main__":
    errors = check(Path(__file__).resolve().parents[1])
    print("\n".join(errors) if errors else "Device identity structure: PASS")
    sys.exit(bool(errors))

#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Mutation checks for the device identity structural gate."""
import importlib.util
import unittest
import sys
sys.dont_write_bytecode = True
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "identity_gate", Path(__file__).with_name("check-device-identity.py")
)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class DeviceIdentityGateTests(unittest.TestCase):
    def rejects(self, source):
        self.assertTrue(GATE.violations(source, "crates/example/src/identity.rs"))

    def test_new_string_key_builder_fails(self):
        self.rejects('fn replay_key(device_id: &str) -> String { format!("seen/{device_id}") }')

    def test_unrelated_function_name_cannot_hide_an_inline_key(self):
        self.rejects('fn persist(device_id: &str) { let cache_key = format!("seen/{device_id}"); save(cache_key); }')

    def test_bare_string_index_and_wire_field_index_fail(self):
        self.rejects('fn receive(device_id: &str) { entries.get(device_id); }')
        self.rejects('fn receive(entry: &Envelope) { entries.insert(entry.source_device_id.clone(), true); }')

    def test_renaming_the_source_does_not_restore_a_string_key_api(self):
        self.rejects('fn replay_key(value: &str) -> String { format!("seen/{value}") }')

    def test_inline_wire_sender_cannot_become_a_replay_key(self):
        self.rejects('fn receive(entry: &Envelope) { let replay_key = format!("seen/{}", entry.source_device_id); }')

    def test_local_identity_trait_impostor_fails(self):
        self.rejects("impl RootQualifiedDeviceIdentity for UncheckedString {}")

    def test_typed_key_and_explicit_legacy_read_are_distinct(self):
        self.assertFalse(GATE.violations(
            'fn replay_key(device: &RootQualifiedDeviceRef) { format!("seen/{}", device.storage_key()) }',
            "crates/example/src/identity.rs",
        ))
        self.assertFalse(GATE.violations(
            'fn legacy_read(device_id: &str) { rows.get(device_id).filter(|row| row.root == expected_root) }',
            "crates/example/src/legacy.rs",
        ))

    def test_inbound_paths_cannot_reintroduce_ambiguous_device_metadata_reads(self):
        for path in ["crates/ramflux-sdk/src/client/inbox_failure.rs", "crates/ramflux-sdk/src/client/group_quarantine.rs", "crates/ramflux-sdk/src/client/surface/signer.rs", "crates/ramflux-sdk/src/bus/dispatch/task_approval_transport.rs"]:
            self.assertTrue(GATE.violations('fn receive(entry: &Envelope) { db.client_record("device", &entry.source_device_id)?; }', path))
            self.assertTrue(GATE.violations('fn receive(entry: &Envelope) { db.client_device_record_by_name(&entry.source_device_id)?; }', path))
            self.assertFalse(GATE.violations('fn receive(source: &RootQualifiedDeviceRef) { db.client_device_record(source)?; }', path))

    def test_reference_cannot_gain_public_fields_or_deserialization(self):
        path = "crates/ramflux-crypto/src/device_reference.rs"
        self.assertTrue(GATE.violations("pub struct RootQualifiedDeviceRef { pub name: String }", path))
        self.assertTrue(GATE.violations(
            "#[derive(Deserialize)] pub struct RootQualifiedDeviceRef { name: String }", path
        ))
        self.assertTrue(GATE.violations(
            "#[derive(Default)] pub struct RootQualifiedDeviceRef { name: String }", path
        ))
        self.assertTrue(GATE.violations(
            "pub struct RootQualifiedDeviceRef { name: String } impl From<String> for RootQualifiedDeviceRef {}", path
        ))


if __name__ == "__main__":
    unittest.main()

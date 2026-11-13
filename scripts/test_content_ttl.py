#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Prove test masking and closed lifetime classification do not hide live sends."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('content_ttl', Path(__file__).with_name('check-content-ttl.py'))
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class ContentTtlGuardTests(unittest.TestCase):
    def test_explicit_test_file_is_hidden_but_cfg_text_in_a_string_is_not(self):
        body = 'fn send() { Envelope {\n ttl: 300,\n } }\n'
        self.assertNotIn('ttl:', CHECKER.production('#![cfg(test)]\n' + body))
        live = 'const DOC: &str = "#![cfg(test)]";\n' + body
        self.assertIn('ttl:', CHECKER.production(live))

    def test_typing_classification_rejects_changed_lifetimes_and_other_sites(self):
        site = 'client/typing/send.rs'
        self.assertEqual(CHECKER.classification(site, 'if active { 5 } else { 1 },'), 'Ephemeral')
        for expr in ['if active { 50 } else { 1 },', 'if active { 5 } else { 10 },', '604800,']:
            self.assertIsNone(CHECKER.classification(site, expr))
        self.assertIsNone(CHECKER.classification('client/unreviewed.rs', 'if active { 5 } else { 1 },'))


if __name__ == '__main__':
    unittest.main()

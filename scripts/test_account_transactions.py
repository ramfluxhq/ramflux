#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Mutation fixtures for the production account transaction source guard."""
import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('guard', Path(__file__).with_name('check-account-transactions.py'))
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class TransactionGuardTests(unittest.TestCase):
    def check(self, source, rejected=True, path='account_db/messages.rs'):
        self.assertEqual(bool(guard.violations(source, path)), rejected, source)

    def test_original_closure_savepoint_and_transaction_variants(self):
        for method in ('savepoint', 'savepoint_with_name', 'transaction', 'transaction_with_behavior', 'unchecked_transaction'):
            self.check(f'fn write() {{ connection.call(|db| {{ db.\n {method} ()?; Ok(()) }}) }}')

    def test_sql_normal_raw_multiline_and_comments(self):
        for literal in ('"BEGIN"', '"begin immediate;"', 'r##"\n BEGIN DEFERRED;"##', '"SELECT 1; BEGIN;"', '"/* policy */ BEGIN;"', '"-- policy\nBEGIN;"', '"SAVEPOINT bypass"', '"\\nBEGIN"', '"-- policy\\nBEGIN;"', '"\\x42EGIN;"', '"\\u{42}EGIN;"'):
            self.check(f'fn write() {{ connection.execute_batch({literal})?; }}')

    def test_comments_literals_and_triggers_are_not_method_calls(self):
        self.check('fn write() { /* db.savepoint()? */ // db.transaction()?\n let x = "db.savepoint()"; }', False)
        self.check('fn upgrade() { db.execute_batch("CREATE TRIGGER t AFTER INSERT ON x BEGIN SELECT 1; END;")?; }', False)

    def test_tests_are_excluded_but_production_after_them_is_not(self):
        self.check('#[cfg(test)] mod tests { fn x() { db.savepoint()?; } }', False)
        self.check('#![cfg(test)]\nfn x() { db.savepoint()?; }', False)
        self.check('#[cfg(test)] mod tests {}\nfn write() { db.savepoint()?; }')

    def test_allowlist_is_function_scoped(self):
        self.check('fn merge_backup() { db.execute_batch("BEGIN IMMEDIATE")?; }', False, 'account_db/backup_merge.rs')
        self.check('fn live_write() { db.execute_batch("BEGIN IMMEDIATE")?; }', True, 'account_db/backup_merge.rs')
        self.check('fn transaction() { db.execute_batch("BEGIN IMMEDIATE")?; }', False, 'database.rs')
        self.check('fn call() { db.savepoint()?; }', True, 'database.rs')

    def test_raw_strings_and_nested_comments_preserve_function_boundaries(self):
        self.check('fn harmless() { let s = r#" } // "#; /* outer /* nested */ */ }\nfn bad() { db.savepoint()?; }')


if __name__ == '__main__':
    unittest.main()

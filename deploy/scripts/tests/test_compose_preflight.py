#!/usr/bin/env python3
"""Preflight rejects unsafe migrations without disclosing configuration values."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'compose-preflight.py'
spec = importlib.util.spec_from_file_location('preflight', SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_check(self, contents, process=None, more_files=(), implicit=False):
        path = self.root / '.env'
        path.write_text(contents)
        files = [] if implicit else ['--env-file', str(path)]
        for index, contents in enumerate(more_files):
            extra = self.root / f'{index}.env'
            extra.write_text(contents)
            files.extend(['--env-file', str(extra)])
        return subprocess.run([sys.executable, str(SCRIPT), *files], cwd=self.root,
                              env={'PATH': os.environ['PATH'], **(process or {})},
                              text=True, capture_output=True, timeout=10)

    def test_old_names_only_and_mismatches_refuse_every_mapped_key_without_values(self):
        for old, new in preflight.MAPPING.items():
            for text in [f'{old}=DO_NOT_LOG', f'{old}=DO_NOT_LOG\n{new}=DIFFERENT_SECRET']:
                with self.subTest(key=old):
                    result = self.run_check(text)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(old, result.stderr)
                    self.assertIn(new, result.stderr)
                    self.assertNotIn('DO_NOT_LOG', result.stderr)
                    self.assertNotIn('DIFFERENT_SECRET', result.stderr)

    def test_migrated_and_equal_dual_names_accept_export_quotes_comments_and_precedence(self):
        old, new = 'RAMFLUX_FEDERATION_ADMIN_TOKEN', 'RF_COMPOSE_FEDERATION_ADMIN_TOKEN'
        result = self.run_check(f'export {old}="secret#value" # comment\n{new}=secret#value')
        self.assertEqual(result.returncode, 0, result.stderr)
        # Process values override env files, later files override earlier files.
        result = self.run_check(f'{old}=first\n{new}=first',
                                {old: 'last', new: 'last'}, [f'{new}=second'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.run_check(f'{old}=first\n{new}=first',
                                           more_files=[f'{new}=second']).returncode, 0)

    def test_implicit_dotenv_and_process_legacy_names_are_checked(self):
        self.assertNotEqual(self.run_check('RAMFLUX_NODE_ID=private-name', implicit=True).returncode, 0)
        result = self.run_check('', {'RAMFLUX_NODE_ID': 'private-name'})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('private-name', result.stderr)

    def test_public_default_secret_is_refused_even_with_new_or_equal_names(self):
        for text in ['RF_COMPOSE_FEDERATION_ADMIN_TOKEN=ramflux-local-admin-token',
                     'RAMFLUX_ROUTER_ADMIN_TOKEN=ramflux-local-admin-token\n'
                     'RF_COMPOSE_ROUTER_ADMIN_TOKEN=ramflux-local-admin-token']:
            result = self.run_check(text)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('ramflux-local-admin-token', result.stderr)

    def test_interpolation_uses_process_then_previous_files_and_quoted_literals_remain_literal(self):
        values = preflight.read_env(self._file("export RF_COMPOSE_NODE_ID=${HOST_NAME:-fallback}\n"),
                                    {}, {'HOST_NAME': 'example.test'})
        self.assertEqual(values['RF_COMPOSE_NODE_ID'], 'example.test')
        result = self.run_check("RF_COMPOSE_NODE_ID='${DO_NOT_LOG}'")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('DO_NOT_LOG', result.stderr)

    def _file(self, contents):
        path = self.root / 'parse.env'
        path.write_text(contents)
        return path

    def test_bad_dotenv_and_unreadable_files_do_not_echo_their_contents(self):
        result = self.run_check('DO_NOT_LOG malformed secret')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('DO_NOT_LOG', result.stderr)
        with self.assertRaises(preflight.InputError) as error:
            preflight.read_env(self.root / 'absent', {}, {})
        self.assertEqual(str(error.exception), 'ENV_FILE')

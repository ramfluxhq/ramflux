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

    def test_implicit_dotenv_comes_from_compose_project_directory(self):
        project = self.root / 'project'
        project.mkdir()
        compose = project / 'compose.yaml'
        compose.write_text('services: {}\n')
        (project / '.env').write_text('RAMFLUX_NODE_ID=DO_NOT_LOG\n')
        result = subprocess.run(
            [sys.executable, str(SCRIPT), '-f', str(compose)],
            cwd=self.root, env={'PATH': os.environ['PATH']}, text=True,
            capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RAMFLUX_NODE_ID', result.stderr)
        self.assertNotIn('DO_NOT_LOG', result.stderr)

    def test_project_directory_overrides_first_compose_file_for_dotenv(self):
        compose_dir = self.root / 'compose'
        project = self.root / 'project'
        compose_dir.mkdir()
        project.mkdir()
        compose = compose_dir / 'compose.yaml'
        compose.write_text('services: {}\n')
        (compose_dir / '.env').write_text('SAFE=value\n')
        (project / '.env').write_text('RAMFLUX_NODE_ID=DO_NOT_LOG\n')
        result = subprocess.run(
            [sys.executable, str(SCRIPT), '-f', str(compose),
             '--project-directory', str(project)],
            cwd=self.root, env={'PATH': os.environ['PATH']}, text=True,
            capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RAMFLUX_NODE_ID', result.stderr)
        self.assertNotIn('DO_NOT_LOG', result.stderr)

    def test_compose_env_files_are_checked_in_order_and_missing_files_fail_closed(self):
        first = self.root / 'first.env'
        second = self.root / 'second.env'
        first.write_text('RAMFLUX_NODE_ID=first\nRF_COMPOSE_NODE_ID=first\n')
        second.write_text('RAMFLUX_NODE_ID=DO_NOT_LOG\n')
        environment = {
            'PATH': os.environ['PATH'],
            'COMPOSE_ENV_FILES': 'first.env,second.env',
        }
        result = subprocess.run([sys.executable, str(SCRIPT)], cwd=self.root,
                                env=environment, text=True, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RAMFLUX_NODE_ID', result.stderr)
        self.assertNotIn('DO_NOT_LOG', result.stderr)
        environment['COMPOSE_ENV_FILES'] = 'missing.env'
        result = subprocess.run([sys.executable, str(SCRIPT)], cwd=self.root,
                                env=environment, text=True, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ENV_FILE', result.stderr)

    def test_explicit_env_file_takes_precedence_over_compose_env_files(self):
        explicit = self.root / 'explicit.env'
        explicit.write_text('SAFE=value\n')
        result = subprocess.run(
            [sys.executable, str(SCRIPT), '--env-file', str(explicit)], cwd=self.root,
            env={'PATH': os.environ['PATH'], 'COMPOSE_ENV_FILES': 'missing.env'},
            text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_compose_file_from_environment_selects_project_dotenv(self):
        project = self.root / 'project'
        project.mkdir()
        (project / 'compose.yaml').write_text('services: {}\n')
        (project / '.env').write_text('RAMFLUX_NODE_ID=DO_NOT_LOG\n')
        result = subprocess.run(
            [sys.executable, str(SCRIPT)], cwd=self.root,
            env={'PATH': os.environ['PATH'], 'COMPOSE_FILE': 'project/compose.yaml'},
            text=True, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RAMFLUX_NODE_ID', result.stderr)
        self.assertNotIn('DO_NOT_LOG', result.stderr)

    def test_dotenv_compose_file_loads_new_project_dotenv_at_lower_precedence(self):
        project = self.root / 'project'
        project.mkdir()
        (self.root / 'compose.yaml').write_text('services: {}\n')
        (self.root / '.env').write_text(
            'COMPOSE_FILE=project/compose.yaml\nRAMFLUX_NODE_ID=primary\n')
        (project / '.env').write_text(
            'RAMFLUX_NODE_ID=secondary\nRF_COMPOSE_NODE_ID=secondary\n')
        result = subprocess.run(
            [sys.executable, str(SCRIPT)], cwd=self.root,
            env={'PATH': os.environ['PATH']}, text=True, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RAMFLUX_NODE_ID', result.stderr)

    def test_disable_default_env_file_uses_only_process_environment(self):
        (self.root / '.env').write_text('RAMFLUX_NODE_ID=DO_NOT_LOG\n')
        result = subprocess.run(
            [sys.executable, str(SCRIPT)], cwd=self.root,
            env={'PATH': os.environ['PATH'], 'COMPOSE_DISABLE_ENV_FILE': 'true'},
            text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_public_default_secret_is_refused_even_with_new_or_equal_names(self):
        for text in ['RF_COMPOSE_FEDERATION_ADMIN_TOKEN=ramflux-local-admin-token',
                     "RF_COMPOSE_FEDERATION_ADMIN_TOKEN=' ramflux-local-admin-token '",
                     'RAMFLUX_ROUTER_ADMIN_TOKEN=ramflux-local-admin-token\n'
                     'RF_COMPOSE_ROUTER_ADMIN_TOKEN=ramflux-local-admin-token']:
            result = self.run_check(text)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('ramflux-local-admin-token', result.stderr)

    def test_quoted_control_escapes_cannot_hide_the_public_default_token(self):
        for escape in ('f', 'v', 'n', 'r', 't'):
            text = 'RF_COMPOSE_FEDERATION_ADMIN_TOKEN="' + chr(92) + escape
            text += 'ramflux-local-admin-token' + chr(92) + escape + '"'
            with self.subTest(escape=escape):
                result = self.run_check(text)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('RF_COMPOSE_FEDERATION_ADMIN_TOKEN', result.stderr)
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

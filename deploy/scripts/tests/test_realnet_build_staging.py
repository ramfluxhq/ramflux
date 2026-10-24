#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""The image staging inputs must be the artifacts produced by this Cargo invocation."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

BINS = ('gateway', 'router', 'notify', 'federation', 'relay', 'signaling', 'retention')

class BuildStagingTests(unittest.TestCase):
    def test_external_target_never_stages_stale_workspace_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / 'ramflux'
            scripts = repo / 'deploy/scripts'
            scripts.mkdir(parents=True)
            runner = scripts / 'run-realnet.sh'
            shutil.copyfile(Path(__file__).resolve().parents[1] / 'run-realnet.sh', runner)
            wrappers = root / 'tools'
            wrappers.mkdir()
            cargo = wrappers / 'cargo'
            cargo.write_text('''#!/usr/bin/env python3
import os, pathlib, sys
args=sys.argv[1:]
target=pathlib.Path(args[args.index('--target-dir')+1] if '--target-dir' in args else os.environ['CARGO_TARGET_DIR'])
if not target.is_absolute(): target=pathlib.Path.cwd()/target
profile='release' if '--release' in args else 'debug'
for index,arg in enumerate(args):
    if arg=='--bin':
        name=args[index+1]
        output=target/profile/name
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text('current:'+name)
''')
            cargo.chmod(0o755)
            for name, body in [('rustc', "echo 'host: x86_64-unknown-linux-gnu'"), ('rustup', 'exit 1'), ('strip', 'exit 0')]:
                path = wrappers / name
                path.write_text('#!/bin/sh\n' + body + '\n')
                path.chmod(0o755)
            stale = repo / 'target/debug'
            stale.mkdir(parents=True)
            for name in BINS:
                (stale / ('ramflux-' + name)).write_text('stale:' + name)
            env = os.environ.copy()
            env.update(PATH=str(wrappers) + os.pathsep + env['PATH'], CARGO_TARGET_DIR=str(root / 'cargo-output'), RAMFLUX_REALNET_PREBUILD_ONLY='1')
            for name in ('RAMFLUX_PERF_RELEASE', 'RAMFLUX_GATEWAY_COMPIO', 'RAMFLUX_ROUTER_COMPIO', 'RAMFLUX_FEDERATION_COMPIO', 'RAMFLUX_NOTIFY_COMPIO', 'RAMFLUX_RELAY_ALLOC_PROF', 'RAMFLUX_RELAY_REDB_CACHE_PROBE'):
                env.pop(name, None)
            # The fixture preserves the user's real HOME and intercepts only tool executables.
            result = subprocess.run(['sh', str(runner)], env=env, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name in BINS:
                staged = repo / 'deploy/itest-bin' / ('ramflux-' + name)
                self.assertEqual(staged.read_text(), 'current:ramflux-' + name)

if __name__ == '__main__':
    unittest.main()

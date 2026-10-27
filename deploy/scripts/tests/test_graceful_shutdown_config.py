#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Guard production PID 1 and Compose shutdown configuration."""

from pathlib import Path
import re
import unittest

DEPLOY = Path(__file__).resolve().parents[2]
SERVICES = ("gateway", "router", "notify", "federation", "relay", "signaling", "retention")


class GracefulShutdownConfigTests(unittest.TestCase):
    def test_runtime_stages_use_exec_form_service_entrypoint(self):
        dockerfile = (DEPLOY / "Dockerfile").read_text()
        self.assertEqual(
            dockerfile.count('ENTRYPOINT ["/usr/local/bin/ramflux-service"]'), 2
        )
        self.assertNotIn('ENTRYPOINT ["/bin/sh", "-c"', dockerfile)

    def test_every_production_service_has_five_second_stop_grace(self):
        compose = (DEPLOY / "docker-compose.yml").read_text()
        for service in SERVICES:
            with self.subTest(service=service):
                section = re.search(
                    rf"^  ramflux-{service}:\n(.*?)(?=^  ramflux-|^volumes:)",
                    compose,
                    re.MULTILINE | re.DOTALL,
                )
                self.assertIsNotNone(section)
                self.assertIn("stop_grace_period: 5s", section.group(1))


if __name__ == "__main__":
    unittest.main()

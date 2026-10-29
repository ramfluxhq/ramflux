#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Prebuilt image metadata must identify seven distinct service executables."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "demo_image_check", Path(__file__).resolve().parents[1] / "demo-image-check.py"
)
IMAGES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGES)


class DemoImageTests(unittest.TestCase):
    def setUp(self):
        self.images = {
            service: {"Id": f"sha256:{service}", "Config": {"Env": [f"RAMFLUX_BIN=ramflux-{service}"]}}
            for service in IMAGES.SERVICES
        }

    def verify(self, images=None, raw=None, failed=None):
        images = self.images if images is None else images

        def inspect(command, **_kwargs):
            self.assertEqual(command[:3], ["test-engine", "image", "inspect"])
            service = command[-1].split("/ramflux-", 1)[1].split(":", 1)[0]
            output = (raw or {}).get(service, json.dumps([images[service]]))
            return subprocess.CompletedProcess(command, 1 if service == failed else 0, output, "")

        error = io.StringIO()
        with mock.patch.object(IMAGES.subprocess, "run", side_effect=inspect) as runner, \
                contextlib.redirect_stderr(error):
            accepted = IMAGES.verify_images("test-engine", "v2")
        self.assertEqual(runner.call_count, 7)
        return accepted, error.getvalue()

    def test_distinct_images_with_correct_environment_are_accepted(self):
        self.assertEqual(self.verify(), (True, ""))

    def test_label_metadata_and_podman_uppercase_id_are_accepted(self):
        for service, image in self.images.items():
            image["ID"] = image.pop("Id")
            image["Config"] = {"Labels": {"RAMFLUX_BIN": f"ramflux-{service}"}, "Env": None}
        self.assertEqual(self.verify(), (True, ""))

    def test_duplicate_identity_is_refused_even_with_correct_service_metadata(self):
        self.images["router"]["Id"] = "gateway"
        accepted, error = self.verify()
        self.assertFalse(accepted)
        self.assertIn("demo images share an image ID: gateway, router", error)

    def test_missing_or_conflicting_binary_declarations_are_refused(self):
        for config in ({}, {"Env": ["RAMFLUX_BIN=ramflux-gateway"]},
                       {"Env": ["RAMFLUX_BIN=ramflux-router", "RAMFLUX_BIN=ramflux-gateway"]},
                       {"Env": ["RAMFLUX_BIN=ramflux-router"],
                        "Labels": {"RAMFLUX_BIN": "ramflux-gateway"}}):
            with self.subTest(config=config):
                self.images["router"]["Config"] = config
                accepted, error = self.verify()
                self.assertFalse(accepted)
                self.assertIn("invalid demo image identity or RAMFLUX_BIN: router", error)

    def test_malformed_inspection_metadata_is_refused_with_service_names(self):
        for raw in ("invalid-json", "[]", "{}", "[null]", '[{"Config": {}}]',
                    '[{"Id": "sha256:", "Config": {}}]'):
            with self.subTest(raw=raw):
                accepted, error = self.verify(raw={"notify": raw})
                self.assertFalse(accepted)
                self.assertIn("invalid demo image identity or RAMFLUX_BIN: notify", error)

    def test_missing_image_is_named_without_accepting_the_other_six(self):
        accepted, error = self.verify(failed="retention")
        self.assertFalse(accepted)
        self.assertIn("ghcr.io/ramfluxhq/ramflux-retention:v2", error)


if __name__ == "__main__":
    unittest.main()

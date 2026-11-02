#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain

"""Probe an occupied loopback port and require the exact owned router mapping."""
import copy
import importlib.util
from pathlib import Path
import socket
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "router-admin-port.py"
spec = importlib.util.spec_from_file_location("router_admin_port", SCRIPT)
router_admin_port = importlib.util.module_from_spec(spec)
spec.loader.exec_module(router_admin_port)


class RouterAdminPortTests(unittest.TestCase):
    def setUp(self):
        self.occupied = socket.socket()
        self.addCleanup(self.occupied.close)
        self.occupied.bind(("127.0.0.1", 0))
        self.occupied.listen()
        self.port = str(self.occupied.getsockname()[1])
        self.mapping = {
            "Config": {"Labels": {
                "org.ramflux.demo.owner": "owner",
                "com.docker.compose.project": "project",
                "com.docker.compose.service": "ramflux-router",
            }},
            "State": {"Running": True},
            "NetworkSettings": {"Ports": {"7443/tcp": [
                {"HostPort": self.port, "HostIp": "127.0.0.1"},
            ]}},
        }

    def test_existing_owned_router_mapping_allows_the_occupied_port(self):
        router_admin_port.check(self.port, "project", "owner", [self.mapping])

    def test_wrong_owner_project_service_or_state_cannot_adopt_an_occupied_port(self):
        for key in ("org.ramflux.demo.owner", "com.docker.compose.project", "com.docker.compose.service", "running", "address", "port"):
            with self.subTest(key=key):
                mapping = copy.deepcopy(self.mapping)
                if key == "running":
                    mapping["State"]["Running"] = False
                elif key in ("address", "port"):
                    field = "HostIp" if key == "address" else "HostPort"
                    mapping["NetworkSettings"]["Ports"]["7443/tcp"][0][field] = "other"
                else:
                    mapping["Config"]["Labels"][key] = "other"
                with self.assertRaisesRegex(SystemExit, "already in use"):
                    router_admin_port.check(self.port, "project", "owner", [mapping])

    def test_unowned_listener_refuses_with_a_clear_message(self):
        with self.assertRaisesRegex(SystemExit, f"router admin loopback port {self.port} is already in use"):
            router_admin_port.check(self.port, "project", "owner", [])

    def test_available_loopback_port_needs_no_container(self):
        with socket.socket() as candidate:
            candidate.bind(("127.0.0.1", 0))
            port = str(candidate.getsockname()[1])
        router_admin_port.check(port, "project", "owner", [])

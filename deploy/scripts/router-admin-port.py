#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain

"""Refuse an occupied router admin port unless the running owned router publishes it."""
import errno
import json
import socket
import sys


def check(port, project, owner, containers):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", int(port)))
            return
        except OSError as error:
            if error.errno != errno.EADDRINUSE:
                raise
    for container in containers:
        labels = (container.get("Config") or {}).get("Labels") or {}
        bindings = (container.get("NetworkSettings") or {}).get("Ports") or {}
        if ((container.get("State") or {}).get("Running")
                and labels.get("org.ramflux.demo.owner") == owner
                and labels.get("com.docker.compose.project") == project
                and labels.get("com.docker.compose.service") == "ramflux-router"
                and any(str(row.get("HostPort")) == port and row.get("HostIp") == "127.0.0.1"
                        for row in bindings.get("7443/tcp") or [])):
            return
    sys.exit(f"router admin loopback port {port} is already in use; choose a free port")


if __name__ == "__main__":
    check(*sys.argv[1:4], json.load(sys.stdin))

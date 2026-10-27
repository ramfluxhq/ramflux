#!/usr/bin/env python3
"""Docker v2 / Podman Compose 1.3-shaped CLI fixtures; never start containers."""
import argparse
import json
from pathlib import Path
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--fixture-root", type=Path, required=True)
parser.add_argument("--name", required=True)
options, args = parser.parse_known_args()
root = options.fixture_root
control = json.loads((root / "control.json").read_text())
provider = (root / "provider.txt").read_text()
name = options.name
normalized = ["compose", *args] if name == "podman-compose" else args
with (root / "commands.jsonl").open("a") as output:
    output.write(json.dumps(normalized) + "\n")
with (root / "cli.jsonl").open("a") as output:
    output.write(json.dumps({"name": name, "args": args, "cwd": str(Path.cwd())}) + "\n")

if name == "sleep":
    clock = root / "clock"
    clock.write_text(str(int(clock.read_text()) + int(args[0])))
    sys.exit(0)
if name == "date":
    print((root / "clock").read_text())
    sys.exit(0)
if args == ["--version"]:
    print("podman version 5.4.2" if provider != "docker" else "Docker version 27.0.0")
    sys.exit(0)
if normalized == ["compose", "version"]:
    if name == "podman-compose":
        print("podman-compose version: 1.3.0")
    else:
        print("Docker Compose version v2.30.0" if provider == "docker" else "podman-compose version: 1.3.0")
    sys.exit(0)
if args[:2] == ["image", "inspect"]:
    image = args[2]
    if image in control.get("missing_images", []):
        sys.exit(1)
    print("[]")
    sys.exit(0)
if args == ["info", "--format", "json"]:
    print(json.dumps({"host": {
        "security": {"rootless": control.get("rootless", provider != "docker")},
        "serviceIsRemote": control.get("service_is_remote", False),
        "os": control.get("host_os", "linux"),
    }}))
    sys.exit(0)

state = root / "data"
deployed = root / "deployed"
services = ["gateway", "router", "notify", "federation", "relay", "signaling", "retention"]
if normalized and normalized[0] == "compose":
    if any(flag in normalized for flag in ("--project-directory", "--wait", "--wait-timeout")):
        sys.exit("unsupported compose option (podman-compose 1.3.0)")
    if Path.cwd() != state:
        sys.exit("compose must run from the isolated project directory")
    for flag in ("--env-file", "-f"):
        for index, value in enumerate(normalized):
            if value == flag:
                path = Path(normalized[index + 1])
                if not path.is_absolute() or not path.is_file():
                    sys.exit(f"compose requires an existing absolute {flag} path")
    if normalized[normalized.index("-p") + 1] != "demo-test":
        sys.exit("unexpected compose project")
    if "up" in normalized:
        if control.get("up_exit"):
            sys.exit(control["up_exit"])
        deployed.touch()
        if control.get("corrupt_env_after_up"):
            with (state / "runtime.env").open("a") as output:
                output.write("RF_COMPOSE_FEDERATION_ADMIN_TOKEN=DO_NOT_LOG\n")
    elif "down" in normalized:
        deployed.unlink(missing_ok=True)
    elif "ps" in normalized and "-q" in normalized:
        sys.exit("podman-compose 1.3.0 ps -q does not support per-service selection")
    elif "logs" in normalized:
        print("mock project logs")
    sys.exit(0)

service_filter = next((value.split("=", 2)[-1] for value in args
                       if value.startswith("label=com.docker.compose.service=")), None)
kind = None
if args[:2] == ["ps", "-aq"]:
    kind = "container"
if args[:3] == ["volume", "ls", "-q"]:
    kind = "volume"
if args[:3] == ["network", "ls", "-q"]:
    kind = "network"
if args == ["volume", "ls", "-q"] and control.get("unlabeled") == "volume":
    print("demo-test_gateway-redb")
elif args == ["network", "ls", "--format", "{{.Name}}"] and control.get("unlabeled") == "network":
    print("demo-test_default")
elif kind and control.get("foreign") == kind:
    print("foreign-resource")
elif kind == "container" and deployed.exists():
    if service_filter:
        if not control.get("stopped"):
            print(f"id-{service_filter}")
            if control.get("duplicate"):
                print(f"duplicate-{service_filter}")
    else:
        for service in services:
            print(f"id-ramflux-{service}")
elif args and (args[0] == "inspect" or (len(args) > 1 and args[1] == "inspect")):
    token = (state / "owner.token").read_text().strip()
    if "--format" in args:
        target = args[-1]
        print("foreign-owner" if target == "foreign-resource" or "_" in target else token)
    else:
        health = control.get("health", "healthy")
        if int((root / "clock").read_text()) < control.get("healthy_after", 0):
            health = "starting"
        item = {"Config": {"Labels": {"org.ramflux.demo.owner": token}},
                "State": {"Status": control.get("container_state", "running")}}
        if not control.get("missing_health"):
            field = "Healthcheck" if provider != "docker" else "Health"
            item["State"][field] = {"Status": health}
        runtime_env = state / "runtime.env"
        values = dict(line.split("=", 1) for line in runtime_env.read_text().splitlines()
                      if "=" in line) if runtime_env.exists() else {}
        item["Config"]["Env"] = [f"{key}={value}" for key, value in values.items()]
        if args[-1] == "id-ramflux-relay" and "RAMFLUX_RELAY_VOICE_UDP_PORT" in values:
            bind, port = values["RAMFLUX_RELAY_VOICE_UDP_PORT"].rsplit(":", 1)
            item["NetworkSettings"] = {"Ports": {
                "17449/udp": [{"HostIp": bind, "HostPort": port}],
            }}
        print(json.dumps([item]))

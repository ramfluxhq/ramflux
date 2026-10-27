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
    service = image.split("/ramflux-", 1)[1].split(":", 1)[0]
    identity = control.get("image_ids", {}).get(service, f"sha256:{service}")
    binary = control.get("image_bins", {}).get(service, f"ramflux-{service}")
    item = {"Id": identity, "Config": {"Env": [f"RAMFLUX_BIN={binary}"]}}
    item = control.get("image_metadata", {}).get(service, item)
    print(json.dumps([item]))
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
resource_file = root / "resources.json"
resources = json.loads(resource_file.read_text()) if resource_file.exists() else {}


def save_resources():
    resource_file.write_text(json.dumps(resources))


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
        runtime = state / "runtime.env"
        values = dict(line.split("=", 1) for line in runtime.read_text().splitlines()
                      if "=" in line) if runtime.exists() else {}
        if values.get("RAMFLUX_VERSION") in control.get("fail_up_versions", []):
            sys.exit("controlled version-specific compose failure")
        if control.get("up_exit"):
            sys.exit(control["up_exit"])
        loaded_version = root / "router-loaded-version"
        version = values.get("RAMFLUX_VERSION", "")
        if not deployed.exists() or not loaded_version.exists() or loaded_version.read_text() != version:
            record = state / "secrets/custody/node-record.json"
            (root / "router-loaded-record").write_bytes(record.read_bytes() if record.exists() else b"")
            loaded_version.write_text(version)
        deployed.touch()
        token = (state / "owner.token").read_text().strip()
        for service in services:
            resources[f"id-ramflux-{service}"] = {
                "kind": "container", "project": "demo-test", "owner": token,
            }
            resources[f"demo-test_{service}-redb"] = {
                "kind": "volume", "project": "demo-test", "owner": token,
            }
        resources["id-demo-network"] = {"kind": "network", "project": "demo-test", "owner": token}
        save_resources()
        if control.get("corrupt_env_after_up"):
            with (state / "runtime.env").open("a") as output:
                output.write("RF_COMPOSE_FEDERATION_ADMIN_TOKEN=DO_NOT_LOG\n")
    elif "restart" in normalized:
        if normalized[normalized.index("restart"):] != ["restart", "ramflux-router"]:
            sys.exit("unexpected restart scope")
        if control.get("restart_exit"):
            sys.exit(control["restart_exit"])
        (root / "router-loaded-record").write_bytes((state / "secrets/custody/node-record.json").read_bytes())
    elif "down" in normalized:
        deployed.unlink(missing_ok=True)
        resources = {key: value for key, value in resources.items()
                     if value["project"] != "demo-test"
                     or (value["kind"] == "volume" and "--volumes" not in normalized)}
        save_resources()
    elif "ps" in normalized and "-q" in normalized:
        sys.exit("podman-compose 1.3.0 ps -q does not support per-service selection")
    elif "logs" in normalized:
        print("mock project logs")
    sys.exit(0)

if args[:2] in (["rm", "-f"], ["network", "rm"], ["volume", "rm"]):
    target = args[-1]
    if control.get("remove_exit"):
        sys.exit(control["remove_exit"])
    if any(dependent in resources for dependent
           in control.get("remove_dependencies", {}).get(target, [])):
        sys.exit("container has dependent containers which must be removed before it")
    if target not in resources or resources[target]["project"] != "demo-test":
        sys.exit("refusing removal outside the selected project")
    del resources[target]
    save_resources()
    if not any(value["kind"] == "container" and value["project"] == "demo-test"
               for value in resources.values()):
        deployed.unlink(missing_ok=True)
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
        for key, value in resources.items():
            if value["kind"] == "container" and value["project"] == "demo-test":
                print(key)
elif kind in ("network", "volume"):
    selected_project = next((value.split("=", 2)[-1] for value in args
                             if value.startswith("label=com.docker.compose.project=")), None)
    for key, value in resources.items():
        if value["kind"] == kind and (selected_project is None or value["project"] == selected_project):
            print(key)
elif args and (args[0] == "inspect" or (len(args) > 1 and args[1] == "inspect")):
    if "--format" in args:
        target = args[-1]
        unlabeled_collision = (
            control.get("unlabeled") == "volume" and target == "demo-test_gateway-redb"
        ) or (control.get("unlabeled") == "network" and target == "demo-test_default")
        print(resources[target]["owner"] if target in resources and not unlabeled_collision
              else "foreign-owner")
    else:
        token = (state / "owner.token").read_text().strip()
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

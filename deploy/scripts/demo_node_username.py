# SPDX-License-Identifier: BSD-3-Clause
"""Opt-in, isolated demo directory roles; no implicit trust or database recovery."""
import ipaddress
import json
import os
from pathlib import Path
import re
import sys

CENTER_UID = 10001
WITNESS_UID = 10002
PEER_GID = 10003
ROOT = "/var/lib/ramflux/username"


def settings():
    enabled = os.environ.get("DEMO_USERNAME_DIRECTORY", "0")
    if enabled not in ("0", "1"):
        sys.exit("DEMO_USERNAME_DIRECTORY must be 0 or 1")
    if enabled == "0":
        return {}
    node = os.environ["DEMO_NODE_ID"]
    if len(node) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                  for label in node.split(".")):
        sys.exit("username directory requires a canonical lowercase DNS DEMO_NODE_ID")
    try:
        ipaddress.ip_address(node)
    except ValueError:
        pass
    else:
        sys.exit("username directory requires a DNS DEMO_NODE_ID, not an IP address")
    result = {"DEMO_USERNAME_DIRECTORY": "1"}
    occupied = {os.environ.get(key, "") for key in (
        "DEMO_GATEWAY_PORT", "DEMO_RELAY_PORT", "DEMO_HTTP_PORT", "DEMO_TURN_PORT",
        "DEMO_MESH_PORT", "DEMO_ADMIN_LOOPBACK_PORT", "RAMFLUX_ROUTER_ADMIN_PORT",
        "RAMFLUX_DEMO_VOICE_UDP_PORT")}
    for suffix, default in (("CENTER_PORT", "59484"), ("HOME_PORT", "59485")):
        key = "DEMO_USERNAME_" + suffix
        value = os.environ.get(key, default)
        if not re.fullmatch(r"[1-9][0-9]{3,4}", value) or not 1024 <= int(value) <= 65535:
            sys.exit(key + " must be a canonical port in 1024..65535")
        if value in occupied:
            sys.exit(key + " conflicts with another demo port")
        occupied.add(value)
        result[key] = value
    return result


def enable_only(previous, selected):
    """An existing custody-provisioned demo may explicitly enable the extra roles."""
    ordinary = lambda values: {k: v for k, v in values.items() if not k.startswith("DEMO_USERNAME_")}
    return (not previous.get("DEMO_USERNAME_DIRECTORY")
            and selected.get("DEMO_USERNAME_DIRECTORY") == "1"
            and ordinary(previous) == ordinary(selected))


def validate_snapshot(source):
    """A rollback cannot change roles or leave an orphaned authority serving."""
    saved = json.loads((source / "owner.json").read_text())["settings"]
    previous = {key: value for key, value in saved.items() if key.startswith("DEMO_USERNAME_")}
    if previous != settings():
        sys.exit("rollback username directory selection differs from its snapshot")


def origins(config):
    host = os.environ["DEMO_HOST"].lower()
    return (f"https://{host}:{config['DEMO_USERNAME_CENTER_PORT']}",
            f"https://{host}:{config['DEMO_USERNAME_HOME_PORT']}")


def render(state, override, label, record):
    config = settings()
    if not config:
        return
    if record is None:
        sys.exit("DEMO_USERNAME_REQUIRES_CUSTODY: provision the existing node identity first")
    center, home = origins(config)
    common = {
        "RAMFLUX_USERNAME_CENTER_URL": center,
        "RAMFLUX_USERNAME_CENTER_ID": os.environ["DEMO_NODE_ID"],
        "RAMFLUX_USERNAME_CENTER_PUBLIC_KEY": "${DEMO_EXPECTED_NODE_PUBLIC_KEY}",
        "RAMFLUX_USERNAME_CENTER_TLS_SERVER_NAME": "ramflux-federation",
        "RAMFLUX_USERNAME_CENTER_CA_FILE": "/etc/ramflux/mesh/ca.pem",
        "RAMFLUX_USERNAME_TRUST_GENERATION": "1",
    }
    home_env = dict(common, RAMFLUX_USERNAME_ROLE="home",
        RAMFLUX_USERNAME_HOME_DB=ROOT+"/home/home.redb",
        RAMFLUX_USERNAME_HOME_URL=home,
        RAMFLUX_USERNAME_HOME_TLS_SERVER_NAME="ramflux-federation",
        RAMFLUX_USERNAME_LISTEN_ADDR="0.0.0.0:"+config['DEMO_USERNAME_HOME_PORT'],
        RAMFLUX_USERNAME_PRIVATE_PEERS_FILE="/etc/ramflux/username-private.json",
        RAMFLUX_HOME_MIGRATION_ENABLED="1",
        RAMFLUX_HOME_MIGRATION_FEDERATION_ADMIN_ORIGIN="http://ramflux-federation:18084",
        RAMFLUX_HOME_MIGRATION_FEDERATION_ADMIN_TOKEN="${RF_COMPOSE_FEDERATION_ADMIN_TOKEN}",
        RAMFLUX_CLIENT_GATEWAY_TCP_ADDR="${RF_COMPOSE_CLIENT_GATEWAY_TCP_ADDR}",
        RAMFLUX_FEDERATION_PUBLIC_ENDPOINT="ramflux-federation:7443")
    services = override["services"]
    for name in ("router", "federation"):
        item = services["ramflux-"+name]
        item.setdefault("environment", {}).update(home_env)
        item.setdefault("volumes", []).extend([
            "./username-start.sh:/etc/ramflux/username-start.sh:ro",
            "./username-private.json:/etc/ramflux/username-private.json:ro"])
        item["entrypoint"] = ["/bin/sh", "/etc/ramflux/username-start.sh", name]
    router = services["ramflux-router"]
    if "./certs/node-identity/node-signing.key:/etc/ramflux/pairing/node-signing.key:ro" not in router["volumes"]:
        router["volumes"].append("./certs/node-identity/node-signing.key:/etc/ramflux/pairing/node-signing.key:ro")
    router["group_add"] = ["${RAMFLUX_SECRET_GID:-0}"]
    federation = services["ramflux-federation"]
    federation["volumes"].append("username-home:"+ROOT+"/home")
    federation["ports"] = [f"{os.environ['DEMO_BIND_ADDR']}:{config['DEMO_USERNAME_HOME_PORT']}:{config['DEMO_USERNAME_HOME_PORT']}/tcp"]
    image = "ghcr.io/ramfluxhq/ramflux-federation:${RAMFLUX_VERSION}"
    for role, uid in (("witness", WITNESS_UID), ("center", CENTER_UID)):
        env = dict(common, RAMFLUX_USERNAME_ROLE=role,
            RAMFLUX_USERNAME_WITNESS_SOCKET=ROOT+"/socket/witness.sock",
            RAMFLUX_USERNAME_CENTER_UID=str(CENTER_UID),
            RAMFLUX_USERNAME_WITNESS_UID=str(WITNESS_UID))
        env["RAMFLUX_USERNAME_"+("WITNESS_DB" if role == "witness" else "PRIMARY_DB")] = ROOT+"/"+role+"/"+role+".redb"
        volumes = ["./config/federation.toml:/etc/ramflux/config/federation.toml:ro",
                   "./username-start.sh:/etc/ramflux/username-start.sh:ro",
                   "username-"+role+":"+ROOT+"/"+role,
                   "username-"+role+"-privacy:/etc/ramflux/config/node-identity",
                   "username-socket:"+ROOT+"/socket"]
        if role == "witness":
            env.update(RAMFLUX_USERNAME_LISTEN_ADDR="0.0.0.0:"+config['DEMO_USERNAME_CENTER_PORT'],
                RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE="/etc/ramflux/node-identity/node-signing.key")
            volumes.extend(["./certs/node-identity:/etc/ramflux/node-identity:ro",
                            "./certs/federation:/etc/ramflux/mesh:ro"])
        item = dict(image=image, restart="unless-stopped", labels=label,
            user=f"{uid}:{PEER_GID}",
            group_add=["0", "${RAMFLUX_SECRET_GID:-0}"] if role == "witness" else [],
            security_opt=["no-new-privileges:true"], cap_drop=["ALL"], read_only=True,
            tmpfs=["/tmp"], environment=env, volumes=volumes,
            entrypoint=["/bin/sh", "/etc/ramflux/username-start.sh", role],
            command=["--config", "/etc/ramflux/config/federation.toml"],
            healthcheck=dict(test=["CMD-SHELL", "test -S "+ROOT+"/socket/witness.sock" if role == "witness"
                else "test -s "+ROOT+"/center/center.redb"], interval="2s", timeout="2s", retries=30))
        if role == "center":
            item["depends_on"] = {"ramflux-username-witness": {"condition": "service_healthy"}}
        else:
            item["ports"] = [f"{os.environ['DEMO_BIND_ADDR']}:{config['DEMO_USERNAME_CENTER_PORT']}:{config['DEMO_USERNAME_CENTER_PORT']}/{protocol}"
                             for protocol in ("tcp", "udp")]
        services["ramflux-username-"+role] = item
    services["ramflux-username-init"] = dict(image=image, restart="no", user="0:0", labels=label,
        entrypoint=["/bin/sh", "/etc/ramflux/username-init.sh"], read_only=True,
        security_opt=["no-new-privileges:true"], cap_drop=["ALL"], cap_add=["CHOWN", "FOWNER", "DAC_OVERRIDE"],
        volumes=["./username-init.sh:/etc/ramflux/username-init.sh:ro"]+
                [f"username-{name}:{ROOT}/{name}" for name in ("center", "witness", "socket", "home", "center-privacy", "witness-privacy")])
    for name in ("center", "witness", "socket", "home", "center-privacy", "witness-privacy"):
        override["volumes"]["username-"+name] = {"labels": label}


def material(state, atomic_bytes):
    config = settings()
    if not config:
        return
    identity = dict(line.split("=", 1) for line in (state/"identity.env").read_text().splitlines())
    center, home = origins(config)
    public = identity["DEMO_EXPECTED_NODE_PUBLIC_KEY"]
    pin = dict(url=center, id=os.environ["DEMO_NODE_ID"], public_key=public, generation=1)
    atomic_bytes(state/"username-pin.json", (json.dumps(pin, indent=2)+"\n").encode(), mode=0o644)
    peers = [dict(node=os.environ["DEMO_NODE_ID"], public_key=public, origin=home)]
    atomic_bytes(state/"username-private.json", json.dumps(peers, sort_keys=True, separators=(",", ":")).encode(), mode=0o644)
    source = Path(__file__).parent
    for name in ("start", "init"):
        atomic_bytes(state/f"username-{name}.sh", (source/f"demo-username-{name}.sh").read_bytes(), mode=0o644)

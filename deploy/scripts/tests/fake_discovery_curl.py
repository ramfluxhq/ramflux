#!/usr/bin/env python3
"""Stand in for curl during demo-node tests and return a signed discovery record.

A version listed in control.json public_unhealthy_versions fails before any probe
line is recorded. A successful fetch appends public-probes.jsonl and writes a
record that verify-remote-discovery.py accepts with the real OpenSSL.

The signed client_capabilities list is the federation base plus the gateway
capabilities in the applied router and federation config. The signed version is
the build stamped on the selected image (`0.2.0 (abcdef012345)` by default),
not RAMFLUX_EXPECTED_PRODUCT_* and not the image tag. control.json may set
public_client_capabilities, public_version, image_product, or
image_product_by_tag to publish a different signed record.
"""
import importlib.util
import json
from pathlib import Path
import sys
import time


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE_CLIENT_CAPABILITIES = ["opaque_delivery", "prekey", "object_relay"]


def signed_client_capabilities(control, state, verify):
    override = control.get("public_client_capabilities")
    if override is not None:
        if (
            not isinstance(override, list)
            or any(not isinstance(item, str) or item == "" for item in override)
        ):
            sys.exit("public_client_capabilities must be a list of non-empty strings")
        return override
    router = state / "config" / "router.toml"
    federation = state / "config" / "federation.toml"
    names = list(BASE_CLIENT_CAPABILITIES)
    if not router.is_file() or not federation.is_file():
        return names
    try:
        router_names = verify.gateway_capability_names(router.read_text(encoding="utf-8"))
        federation_names = verify.gateway_capability_names(
            federation.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError) as error:
        sys.exit(f"cannot read applied gateway capabilities: {error}")
    if router_names is None or federation_names is None or router_names != federation_names:
        sys.exit("applied router and federation gateway capabilities disagree")
    names.extend(router_names)
    return names


def published_product(control, image_tag):
    """Build identity of the selected image. Keep the default aligned with fake_demo_runtime."""
    if control.get("omit_image_product"):
        sys.exit("published image has no product labels")
    selected = (control.get("image_product_by_tag") or {}).get(
        image_tag, control.get("image_product")
    )
    if selected is None:
        return "0.2.0", "abcdef012345"
    if not isinstance(selected, dict) or "version" not in selected or "revision" not in selected:
        sys.exit("image_product must include version and revision")
    return selected["version"], selected["revision"]


def signed_version(control, values):
    if "public_version" in control:
        version = control["public_version"]
        if not isinstance(version, str) or not version.strip():
            sys.exit("public_version must be a non-empty string")
        return version
    product_version, revision = published_product(control, values.get("RAMFLUX_VERSION", ""))
    return f"{product_version} ({revision})"


def main():
    if len(sys.argv) < 3 or sys.argv[1] != "--fixture-root":
        sys.exit("usage: fake_discovery_curl.py --fixture-root ROOT curl-arguments")
    root = Path(sys.argv[2])
    args = sys.argv[3:]
    try:
        output = Path(args[args.index("--output") + 1])
    except (ValueError, IndexError):
        sys.exit("discovery curl stub requires --output")
    url = args[-1]
    suffix = "/.well-known/ramflux/client"
    origin = url[: -len(suffix)] if url.endswith(suffix) else url
    state = root / "data"
    control = json.loads((root / "control.json").read_text())
    runtime_path = state / "runtime.env"
    values = {}
    if runtime_path.is_file():
        values = dict(
            line.split("=", 1)
            for line in runtime_path.read_text().splitlines()
            if "=" in line
        )
    version = values.get("RAMFLUX_VERSION", "")
    if version in control.get("public_unhealthy_versions", []):
        sys.exit("published discovery endpoint unhealthy")
    compose_path = state / "compose.yml"
    compose = compose_path.read_text() if compose_path.is_file() else ""
    with (root / "public-probes.jsonl").open("a", encoding="utf-8") as probe:
        probe.write(json.dumps({"origin": origin, "version": version, "compose": compose}) + "\n")
    identity_path = state / "identity.env"
    if not identity_path.is_file():
        sys.exit("demo identity.env is missing")
    identity = dict(
        line.split("=", 1) for line in identity_path.read_text().splitlines() if "=" in line
    )
    pin = identity.get("DEMO_EXPECTED_NODE_PUBLIC_KEY", "")
    seed_path = state / "certs" / "node-identity" / "node-signing.key"
    if not seed_path.is_file() or not pin:
        sys.exit("demo discovery seed is missing")
    scripts = Path(__file__).resolve().parents[1]
    trust = load("demo_node_trust", scripts / "demo-node-trust.py")
    verify = load("verify_remote_discovery", scripts / "verify-remote-discovery.py")
    now = int(time.time())
    ca_path = state / "certs" / "ca.pem"
    record = {
        "schema": verify.SCHEMA,
        "node_id": "demo.invalid",
        "node_public_key": pin,
        "node_ca_cert_pem": ca_path.read_text() if ca_path.is_file() else "test CA",
        "gateway_quic_addr": "demo.example.org:59443",
        "gateway_tcp_addr": "demo.example.org:59443",
        "gateway_server_name": "ramflux-gateway",
        "relay_quic_addr": "demo.example.org:59447",
        "relay_server_name": "ramflux-relay",
        "prekey_http_url": origin,
        "signaling_turn_addr": "demo.example.org:59478",
        "protocol_versions": ["v1"],
        "client_capabilities": signed_client_capabilities(control, state, verify),
        "version": signed_version(control, values),
        "updated_at": now,
        "expires_at": now + 3600,
        "signature": "",
    }
    seed = trust.b64url_decode(seed_path.read_text().strip(), "discovery seed")
    record["signature"] = trust.b64url(
        trust.ed25519_sign(seed, verify.canonical_signing_bytes(record))
    )
    output.write_text(json.dumps(record), encoding="utf-8")


if __name__ == "__main__":
    main()

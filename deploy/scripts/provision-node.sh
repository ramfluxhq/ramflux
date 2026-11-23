#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
deploy_dir="${RAMFLUX_DEPLOY_DIR:-$(CDPATH='' cd -- "${script_dir}/.." && pwd)}"
# Refuse unknown names before any service file is replaced. Unset selects the
# pair the gateway build serves. An explicit empty list is refused.
capability_block=$(python3 - <<'PY'
import os
import sys

push = "gateway.session_push.v1"
ephemeral = "gateway.ephemeral.v1"
known = (push, ephemeral)
if "DEMO_GATEWAY_CLIENT_CAPABILITIES" in os.environ:
    raw = os.environ["DEMO_GATEWAY_CLIENT_CAPABILITIES"]
else:
    raw = push + "," + ephemeral
if raw.strip() == "":
    sys.exit("DEMO_GATEWAY_CLIENT_CAPABILITIES rejects an empty list")
selected = []
for part in raw.split(","):
    name = part.strip()
    if name == "":
        sys.exit("DEMO_GATEWAY_CLIENT_CAPABILITIES has an empty name")
    if name not in known:
        sys.exit("DEMO_GATEWAY_CLIENT_CAPABILITIES refuses unknown name: " + name)
    if name not in selected:
        selected.append(name)
if push not in selected:
    sys.exit("DEMO_GATEWAY_CLIENT_CAPABILITIES requires gateway.session_push.v1")
ordered = [name for name in known if name in selected]
lines = [
    "# Published by federation and echoed by the router.",
    "gateway_client_capabilities = [",
]
lines.extend(f'  "{name}",' for name in ordered)
lines.append("]")
print("\n".join(lines))
PY
) || exit 1
if [ "${1:-}" = --check ]; then
  exit 0
fi
mkdir -p "${deploy_dir}/config"

endpoint_for() {
  case "$1" in
    gateway) printf 'ramflux-gateway:7443' ;;
    router) printf 'ramflux-router:7443' ;;
    notify) printf 'ramflux-notify:7443' ;;
    federation) printf 'ramflux-federation:7443' ;;
    relay) printf 'ramflux-relay:7443' ;;
    signaling) printf 'ramflux-signaling:7443' ;;
    retention) printf 'ramflux-retention:7443' ;;
    *) printf 'unknown service: %s\n' "$1" >&2; exit 1 ;;
  esac
}

for service in gateway router notify federation relay signaling retention; do
  destination="${deploy_dir}/config/${service}.toml"
  temporary=$(mktemp "${deploy_dir}/config/.${service}.toml.XXXXXX")
  trap 'rm -f -- "${temporary}"' EXIT HUP INT TERM
  capability_prefix=
  authority_endpoint=
  authority_origins=
  if [ "$service" = router ] || [ "$service" = federation ]; then
    capability_prefix="$capability_block
"
  fi
  case "$service" in
    gateway|router) authority_endpoint='notify-authority = "ramflux-notify:18085"' ;;
    notify)
      authority_endpoint='router-async = "ramflux-router:17444"'
      authority_origins='[send_authority]
root_budget = 4096

[send_authority.origins]
"spiffe://localhost/ramflux-router" = "ramflux-router:17444"
"spiffe://localhost/ramflux-gateway/ramflux-gateway" = "ramflux-gateway:7443"'
      ;;
  esac
  cat > "${temporary}" <<EOF
node_id = "localhost"
service_id = "ramflux-${service}"
redb_path = "/var/lib/ramflux/${service}/${service}.redb"
${capability_prefix}
[mesh]
listen_addr = "0.0.0.0:7443"
ca_cert = "/etc/ramflux/mesh/ca.pem"
service_cert = "/etc/ramflux/mesh/${service}.pem"
service_key = "/etc/ramflux/mesh/${service}-key.pem"
allowed_service_ids = [
  "ramflux-gateway",
  "ramflux-router",
  "ramflux-notify",
  "ramflux-federation",
  "ramflux-relay",
  "ramflux-signaling",
  "ramflux-retention",
]

[mesh.endpoints]
gateway = "$(endpoint_for gateway)"
router = "$(endpoint_for router)"
notify = "$(endpoint_for notify)"
federation = "$(endpoint_for federation)"
relay = "$(endpoint_for relay)"
signaling = "$(endpoint_for signaling)"
retention = "$(endpoint_for retention)"
${authority_endpoint}

[gateway]
public_listen_addr = "0.0.0.0:443"

[signaling]
turn_udp_addr = "0.0.0.0:3478"
turn_tcp_addr = "0.0.0.0:3478"

${authority_origins}
EOF
  chmod 644 "${temporary}"
  python3 - "${temporary}" "${destination}" <<'PY'
import os
from pathlib import Path
import sys

temporary = Path(sys.argv[1])
destination = Path(sys.argv[2])
with temporary.open("rb") as source:
    os.fsync(source.fileno())
os.replace(temporary, destination)
directory = os.open(destination.parent, os.O_RDONLY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
  trap - EXIT HUP INT TERM
done
# No [relay] service_key block: v3 (Ed25519 issuer trust) is the only production
# object data plane; the default/production relay loads no object HMAC key
# (T22-A3). Retired shared-HMAC object data planes are refused in every build.

printf 'provision-node complete: %s/config\n' "${deploy_dir}"

#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
deploy_dir="${RAMFLUX_DEPLOY_DIR:-$(CDPATH= cd -- "${script_dir}/.." && pwd)}"
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
  cat > "${deploy_dir}/config/${service}.toml" <<EOF
node_id = "localhost"
service_id = "ramflux-${service}"
redb_path = "/var/lib/ramflux/${service}/${service}.redb"

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

[gateway]
public_listen_addr = "0.0.0.0:443"

[signaling]
turn_udp_addr = "0.0.0.0:3478"
turn_tcp_addr = "0.0.0.0:3478"

[relay]
service_key_ref = "literal:ramflux-relay-itest-service-key"
EOF
done

printf 'provision-node complete: %s/config\n' "${deploy_dir}"

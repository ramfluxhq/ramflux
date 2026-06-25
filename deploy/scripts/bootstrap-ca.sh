#!/usr/bin/env sh
set -eu

if ! command -v openssl >/dev/null 2>&1; then
  printf 'openssl is required to bootstrap the local mesh CA\n' >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
deploy_dir="${RAMFLUX_DEPLOY_DIR:-$(CDPATH= cd -- "${script_dir}/.." && pwd)}"
cert_dir="${deploy_dir}/certs"
mkdir -p "${cert_dir}"

if [ ! -f "${cert_dir}/ca-key.pem" ] || [ ! -f "${cert_dir}/ca.pem" ]; then
  rm -f "${cert_dir}/ca-key.pem" "${cert_dir}/ca.pem" "${cert_dir}/ca.srl"
  openssl genpkey -algorithm ED25519 -out "${cert_dir}/ca-key.pem"
  openssl req \
    -new \
    -x509 \
    -key "${cert_dir}/ca-key.pem" \
    -out "${cert_dir}/ca.pem" \
    -days 3650 \
    -subj "/CN=Ramflux Local Mesh CA"
fi

chmod 600 "${cert_dir}/ca-key.pem"
printf 'bootstrap-ca complete: %s\n' "${cert_dir}/ca.pem"

#!/usr/bin/env sh
set -eu

if ! command -v openssl >/dev/null 2>&1; then
  printf 'openssl is required to issue local mesh certificates\n' >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
deploy_dir="${RAMFLUX_DEPLOY_DIR:-$(CDPATH= cd -- "${script_dir}/.." && pwd)}"
cert_dir="${deploy_dir}/certs"
ca_cert="${cert_dir}/ca.pem"
ca_key="${cert_dir}/ca-key.pem"

if [ ! -f "${ca_cert}" ] || [ ! -f "${ca_key}" ]; then
  printf 'missing CA material; run %s/scripts/bootstrap-ca.sh first\n' "${deploy_dir}" >&2
  exit 1
fi

services='gateway router notify federation relay signaling retention'
node_id="${RAMFLUX_NODE_ID:-localhost}"
for service in ${services}; do
  service_dir="${cert_dir}/${service}"
  key_path="${service_dir}/${service}-key.pem"
  csr_path="${service_dir}/${service}.csr"
  cert_path="${service_dir}/${service}.pem"
  ext_path="${service_dir}/${service}.ext"
  mkdir -p "${service_dir}"

  openssl genpkey -algorithm ED25519 -out "${key_path}"
  cat > "${ext_path}" <<EOF
subjectAltName = DNS:ramflux-${service}, DNS:${service}, DNS:localhost, URI:spiffe://${node_id}/ramflux-${service}
extendedKeyUsage = serverAuth, clientAuth
keyUsage = digitalSignature
EOF
  openssl req \
    -new \
    -key "${key_path}" \
    -out "${csr_path}" \
    -subj "/CN=ramflux-${service}"
  openssl x509 \
    -req \
    -in "${csr_path}" \
    -CA "${ca_cert}" \
    -CAkey "${ca_key}" \
    -CAcreateserial \
    -out "${cert_path}" \
    -days 825 \
    -extfile "${ext_path}"
  cp "${ca_cert}" "${service_dir}/ca.pem"
  rm -f "${csr_path}" "${ext_path}"
  chmod 600 "${key_path}"
done

printf 'issue-certs complete: %s\n' "${cert_dir}"

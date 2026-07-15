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

normalize_service_mesh_permissions() {
  for _service in ${services}; do
    _cert="${cert_dir}/${_service}/${_service}.pem"
    _key="${cert_dir}/${_service}/${_service}-key.pem"
    _ca="${cert_dir}/${_service}/ca.pem"
    if [ -f "${_cert}" ]; then
      chmod 644 "${_cert}"
    fi
    if [ -f "${_key}" ]; then
      chmod 644 "${_key}"
    fi
    if [ -f "${_ca}" ]; then
      chmod 644 "${_ca}"
    fi
  done
}

# A service is complete only when its key/cert pair is internally consistent
# (matching public keys) AND the cert verifies against the *current* CA. If the
# CA was just regenerated, the old leaves fail verification and are reissued.
service_is_complete() {
  for _service in ${services}; do
    _sd="${cert_dir}/${_service}"
    [ -s "${_sd}/${_service}-key.pem" ] && [ -s "${_sd}/${_service}.pem" ] \
      && [ -s "${_sd}/ca.pem" ] || return 1
    _kpub=$(openssl pkey -in "${_sd}/${_service}-key.pem" -pubout 2>/dev/null) || return 1
    _cpub=$(openssl x509 -in "${_sd}/${_service}.pem" -pubkey -noout 2>/dev/null) || return 1
    [ "${_kpub}" = "${_cpub}" ] || return 1
    openssl verify -CAfile "${ca_cert}" "${_sd}/${_service}.pem" >/dev/null 2>&1 || return 1
  done
  return 0
}

issue_one_service() {
  _service="$1"
  _service_dir="${cert_dir}/${_service}"
  mkdir -p "${_service_dir}"
  _key="${_service_dir}/${_service}-key.pem"
  _cert="${_service_dir}/${_service}.pem"
  _tmp_key=$(mktemp "${_service_dir}/.key.XXXXXX")
  _tmp_csr=$(mktemp "${_service_dir}/.csr.XXXXXX")
  _tmp_ext=$(mktemp "${_service_dir}/.ext.XXXXXX")
  _tmp_cert=$(mktemp "${_service_dir}/.cert.XXXXXX")
  openssl genpkey -algorithm ED25519 -out "${_tmp_key}"
  cat > "${_tmp_ext}" <<EOF
subjectAltName = DNS:ramflux-${_service}, DNS:${_service}, DNS:localhost, URI:spiffe://${node_id}/ramflux-${_service}
extendedKeyUsage = serverAuth, clientAuth
keyUsage = digitalSignature
EOF
  openssl req \
    -new \
    -key "${_tmp_key}" \
    -out "${_tmp_csr}" \
    -subj "/CN=ramflux-${_service}"
  openssl x509 \
    -req \
    -in "${_tmp_csr}" \
    -CA "${ca_cert}" \
    -CAkey "${ca_key}" \
    -CAcreateserial \
    -out "${_tmp_cert}" \
    -days 825 \
    -extfile "${_tmp_ext}"
  chmod 644 "${_tmp_key}"
  chmod 644 "${_tmp_cert}"
  # Publish the matched key/cert pair atomically so a concurrent reader never
  # sees a key from one issuance with a cert from another.
  mv -f "${_tmp_key}" "${_key}"
  mv -f "${_tmp_cert}" "${_cert}"
  cp "${ca_cert}" "${_service_dir}/ca.pem"
  chmod 644 "${_service_dir}/ca.pem"
  rm -f "${_tmp_csr}" "${_tmp_ext}"
}

issue_certs_locked() {
  if service_is_complete; then
    normalize_service_mesh_permissions
    return 0
  fi
  for _service in ${services}; do
    issue_one_service "${_service}"
  done
  normalize_service_mesh_permissions
}

# Share the certs-dir lock with bootstrap-ca.sh so issuance can never run while
# the CA is being regenerated, and so concurrent issuers serialize instead of
# interleaving key/cert halves on the shared deploy/certs directory.
lock_file="${cert_dir}/.certs.lock"
if command -v flock >/dev/null 2>&1; then
  exec 9>"${lock_file}"
  flock 9
  issue_certs_locked
  flock -u 9
else
  lock_dir="${cert_dir}/.certs.lock.d"
  _waited=0
  while ! mkdir "${lock_dir}" 2>/dev/null; do
    if [ "${_waited}" -ge 120 ]; then
      rmdir "${lock_dir}" 2>/dev/null || true
    fi
    sleep 1
    _waited=$((_waited + 1))
  done
  trap 'rmdir "${lock_dir}" 2>/dev/null || true' EXIT INT TERM
  issue_certs_locked
  rmdir "${lock_dir}" 2>/dev/null || true
  trap - EXIT INT TERM
fi

printf 'issue-certs complete: %s\n' "${cert_dir}"

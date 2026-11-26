#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Provision the username centre secrets once and emit its pin (K7).

  publish-username-pin.py --dir DIR --centre-id HOST --public-url https://HOST:PORT
                          [--ca-cert CA.pem --ca-key CA.key] [--generation N]

Creates on first run (refused if they exist; rotation is deliberate):
  DIR/witness/{node.key,ca.pem,service.pem,service.key,federation.toml}
  DIR/center/{ca.pem,service.pem,service.key,federation.toml}
  DIR/witness/ca.pem is the CA the homes pin. With --ca-cert the centre's existing CA signs
  the username listener certificate (plan section 1.4); without it a throwaway CA is made
  for the scratch run only.

Every run writes public outputs derived from the node signing seed:
  DIR/username-pin.json  the `username` member of the rfc-centre-pin-1 bundle (section 0)
  DIR/witness.env, DIR/center.env  the RAMFLUX_USERNAME_* inputs per role (no secret material)
  DIR/home.env           RAMFLUX_USERNAME_CENTER_* for a home node (+ DIR/home-ca.pem, its CA file)

Container paths are used inside federation.toml and the env files. The cluster format and the
pin location are pending centre confirmation (plan section 1).
"""
import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

TLS_NAME = "ramflux-federation"
ROOT = "/var/lib/ramflux/username"
PORT_IN_CONTAINER = 8443


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def run(args, **kw):
    done = subprocess.run([str(a) for a in args], capture_output=True, timeout=120, **kw)
    if done.returncode:
        sys.exit(f"publish-username-pin: {args[0]} failed: {done.stderr.decode(errors='replace')[:300]}")
    return done.stdout


def public_key_from_seed(seed: bytes) -> str:
    der = bytes.fromhex("302e020100300506032b657004220420") + seed
    return b64(run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input=der)[-32:])


def provision(d: Path, centre_id: str, ca_cert: Path | None, ca_key: Path | None) -> None:
    witness, center = d / "witness", d / "center"
    if (witness / "node.key").exists():
        sys.exit("publish-username-pin: secrets already exist in DIR; rotation is a separate step")
    for p in (witness, center):
        p.mkdir(parents=True, exist_ok=True, mode=0o700)
    ca_pem = witness / "ca.pem"
    if ca_cert:
        ca_pem.write_bytes(ca_cert.read_bytes())
        signer = ["-CA", ca_cert, "-CAkey", ca_key]
    else:
        cnf = d / "ca.cnf"
        cnf.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=UsernameCentreScratchCA\n"
                       "[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                       "subjectKeyIdentifier=hash\n")
        run(["openssl", "req", "-x509", "-config", cnf, "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "30",
             "-keyout", d / "ca.key", "-out", ca_pem])
        cnf.unlink()
        ca_key = d / "ca.key"
        signer = ["-CA", ca_pem, "-CAkey", ca_key]
    ext = d / "service.ext"
    ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                   "extendedKeyUsage=serverAuth,clientAuth\n"
                   f"subjectAltName=DNS:{TLS_NAME},DNS:{centre_id},DNS:username-witness,IP:127.0.0.1\n")
    run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={TLS_NAME}",
         "-keyout", witness / "service.key", "-out", d / "service.csr"])
    run(["openssl", "x509", "-req", "-in", d / "service.csr", *signer, "-CAcreateserial", "-sha256", "-days", "365",
         "-extfile", ext, "-out", witness / "service.pem"])
    for f in (d / "service.csr", ext, d / "ca.srl"):
        f.unlink(missing_ok=True)
    (d / "ca.key").unlink(missing_ok=True)
    (witness / "node.key").write_text(b64(secrets.token_bytes(32)))
    for name in ("ca.pem", "service.pem", "service.key"):
        (center / name).write_bytes((witness / name).read_bytes())
    for p in (witness / "node.key", witness / "service.key", center / "service.key"):
        os.chmod(p, 0o600)
    for role, etc in (("witness", witness), ("center", center)):
        cfg = etc / "federation.toml"
        cfg.write_text(
            f'node_id = "{centre_id}"\nservice_id = "{TLS_NAME}"\n'
            f'redb_path = "{ROOT}/{role}/unused.redb"\n'
            '[mesh]\nlisten_addr = "127.0.0.1:0"\n'
            f'ca_cert = "{ROOT}/{role}/etc/ca.pem"\nservice_cert = "{ROOT}/{role}/etc/service.pem"\n'
            f'service_key = "{ROOT}/{role}/etc/service.key"\n'
            f'allowed_service_ids = ["{TLS_NAME}"]\n[mesh.endpoints]\nfederation = "username-witness:{PORT_IN_CONTAINER}"\n')
        os.chmod(cfg, 0o600)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, type=Path)
    ap.add_argument("--centre-id", required=True, help="DNS name; equals the pin id and the node_id")
    ap.add_argument("--public-url", required=True, help="https://HOST:PORT that homes and clients reach")
    ap.add_argument("--ca-cert", type=Path)
    ap.add_argument("--ca-key", type=Path)
    ap.add_argument("--generation", type=int, default=1)
    a = ap.parse_args()
    if not a.public_url.startswith("https://") or not a.public_url.rsplit(":", 1)[-1].isdigit():
        sys.exit("publish-username-pin: --public-url must be https://HOST:PORT")
    if bool(a.ca_cert) != bool(a.ca_key):
        sys.exit("publish-username-pin: --ca-cert and --ca-key go together")
    a.dir.mkdir(parents=True, exist_ok=True)
    a.dir.chmod(0o700)
    if not (a.dir / "witness" / "node.key").exists():
        provision(a.dir, a.centre_id, a.ca_cert, a.ca_key)
    seed = unb64((a.dir / "witness" / "node.key").read_text().strip())
    public_key = public_key_from_seed(seed)
    url = a.public_url.rstrip("/")
    pin = {"url": url, "id": a.centre_id, "public_key": public_key, "generation": a.generation,
           "tls_server_name": TLS_NAME, "ca_pem": (a.dir / "witness" / "ca.pem").read_text()}
    (a.dir / "username-pin.json").write_text(json.dumps(pin, indent=2, sort_keys=True) + "\n")
    common = {
        "RAMFLUX_USERNAME_CENTER_URL": url,
        "RAMFLUX_USERNAME_CENTER_ID": a.centre_id,
        "RAMFLUX_USERNAME_CENTER_PUBLIC_KEY": public_key,
        "RAMFLUX_USERNAME_CENTER_TLS_SERVER_NAME": TLS_NAME,
        "RAMFLUX_USERNAME_TRUST_GENERATION": str(a.generation),
        "RAMFLUX_USERNAME_WITNESS_SOCKET": f"{ROOT}/socket/witness.sock",
        "RAMFLUX_USERNAME_CENTER_UID": "10001",
        "RAMFLUX_USERNAME_WITNESS_UID": "10002",
    }
    # The federation refuses keys that do not belong to its role (config.rs from_values).
    witness = dict(common, RAMFLUX_USERNAME_ROLE="witness",
                   RAMFLUX_USERNAME_CENTER_CA_FILE=f"{ROOT}/witness/etc/ca.pem",
                   RAMFLUX_USERNAME_LISTEN_ADDR=f"0.0.0.0:{PORT_IN_CONTAINER}",
                   RAMFLUX_USERNAME_WITNESS_DB=f"{ROOT}/witness/checkpoint.redb",
                   RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE=f"{ROOT}/witness/etc/node.key")
    center = dict(common, RAMFLUX_USERNAME_ROLE="center",
                  RAMFLUX_USERNAME_CENTER_CA_FILE=f"{ROOT}/center/etc/ca.pem",
                  RAMFLUX_USERNAME_PRIMARY_DB=f"{ROOT}/center/primary.redb")
    for name, values in (("witness.env", witness), ("center.env", center)):
        (a.dir / name).write_text("".join(f"{k}={v}\n" for k, v in values.items()))
    # A home takes only the pin (CENTER_UID is a centre-host key the home role refuses). Its CA file
    # is the pin's ca_pem, written next to home.env; a home operator may move it and edit the path.
    home_ca = a.dir / "home-ca.pem"
    home_ca.write_text(pin["ca_pem"])
    home = [f"{k}={v}" for k, v in common.items()
            if k.startswith("RAMFLUX_USERNAME_CENTER_") and k != "RAMFLUX_USERNAME_CENTER_UID"]
    home.append(f"RAMFLUX_USERNAME_CENTER_CA_FILE={home_ca.resolve()}")
    home.append(f"RAMFLUX_USERNAME_TRUST_GENERATION={a.generation}")
    (a.dir / "home.env").write_text("\n".join(home) + "\n")
    print(json.dumps({"username_pin": str(a.dir / "username-pin.json"),
                      "status": "pending centre confirmation (cluster format, pin location)"}, sort_keys=True))


if __name__ == "__main__":
    main()

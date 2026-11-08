#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Independent RFC 9180 Auth application vector for pairing transfer HPKE.
# Command (from crates/ramflux-crypto):
#   python3 tests/fixtures/gen_pairing_hpke_app_vector.py
# Requires: pip install 'pyhpke==0.6.2'
"""Pin ramflux info/AAD bytes and an Auth ciphertext from pyhpke."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMKeyPair

LABEL = b"ramflux.identity.transfer.hpke_info.v1"
SCHEMA = "ramflux.identity.transfer.aad.v1"
SK_S = bytes([21] * 32)
SK_R = bytes([22] * 32)
TH = bytes([31] * 32)
TRANSFER_ID = bytes([1] * 32)
RECORD_HASH = bytes([2] * 32)
EPOCH = 7
PT = b"transfer-body"
SK_E = bytes([25] * 32)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pub_of(sk: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw()


def kem_key(sk: bytes) -> KEMKey:
    pk = pub_of(sk)
    return KEMKey.from_jwk(
        {
            "kty": "OKP",
            "crv": "X25519",
            "d": b64url(sk),
            "x": b64url(pk),
        }
    )


def kem_pub(pk: bytes) -> KEMKey:
    return KEMKey.from_jwk({"kty": "OKP", "crv": "X25519", "x": b64url(pk)})


def main() -> None:
    info = LABEL + b"\x00" + TH
    aad_obj = {
        "current_record_hash": b64url(RECORD_HASH),
        "device_set_epoch": EPOCH,
        "schema": SCHEMA,
        "transfer_id": b64url(TRANSFER_ID),
        "version": 1,
    }
    aad = json.dumps(aad_obj, separators=(",", ":"), sort_keys=True).encode("ascii")
    suite = CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM
    )
    sks = kem_key(SK_S)
    skr = kem_key(SK_R)
    pkr = kem_pub(pub_of(SK_R))
    pks = kem_pub(pub_of(SK_S))
    ske = kem_key(SK_E)
    pke = kem_pub(pub_of(SK_E))
    enc, sender = suite.create_sender_context(
        pkr, info=info, sks=sks, eks=KEMKeyPair(ske, pke)
    )
    ct = sender.seal(PT, aad)
    recipient = suite.create_recipient_context(enc, skr, info=info, pks=pks)
    opened = recipient.open(ct, aad)
    if opened != PT:
        raise SystemExit("pyhpke round-trip mismatch")
    out = {
        "command": "python3 tests/fixtures/gen_pairing_hpke_app_vector.py",
        "pyhpke": "0.6.2",
        "mode": 2,
        "kem_id": 32,
        "kdf_id": 1,
        "aead_id": 2,
        "skSm": SK_S.hex(),
        "skRm": SK_R.hex(),
        "skEm": SK_E.hex(),
        "pkSm": pub_of(SK_S).hex(),
        "pkRm": pub_of(SK_R).hex(),
        "th": TH.hex(),
        "info": info.hex(),
        "aad": aad.hex(),
        "enc": enc.hex(),
        "ct": ct.hex(),
        "pt": PT.hex(),
        "transfer_id": TRANSFER_ID.hex(),
        "current_record_hash": RECORD_HASH.hex(),
        "device_set_epoch": EPOCH,
    }
    dest = Path(__file__).with_name("pairing_hpke_app_vector.json")
    dest.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {dest}")


if __name__ == "__main__":
    main()

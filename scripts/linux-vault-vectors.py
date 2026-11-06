#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic vault vectors from pinned libsodium C, independently of RustCrypto."""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import urllib.request

COMMIT = '9511c982fb1d046470a8b42aa36556cdb7da15de'
SHA256 = '533e374cf8fd1e3356d39d1ad95c8e23dd95d6340db187ed2b57b04b87d1195b'
FIXTURE = Path(__file__).resolve().parent / 'fixtures/linux_vault_vectors.json'


def oracle(cache):
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / 'source.tar.gz'
    if not archive.exists():
        with urllib.request.urlopen(f'https://codeload.github.com/jedisct1/libsodium/tar.gz/{COMMIT}', timeout=60) as response:
            archive.write_bytes(response.read(8 * 1024 * 1024))
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == SHA256, 'oracle source checksum'
    source = cache / f'libsodium-{COMMIT}'
    library = source / 'src/libsodium/.libs/libsodium.so'
    if not library.exists():
        with tarfile.open(archive) as tar:
            tar.extractall(cache, filter='data')
        subprocess.run(['./configure', '--disable-static', '--enable-shared'], cwd=source, check=True, timeout=180)
        subprocess.run(['make', '-j2'], cwd=source, check=True, timeout=300)
        (cache / 'library.sha256').write_text(hashlib.sha256(library.read_bytes()).hexdigest())
    assert hashlib.sha256(library.read_bytes()).hexdigest() == (cache / 'library.sha256').read_text()
    lib = ctypes.CDLL(str(library))
    assert lib.sodium_init() >= 0
    lib.sodium_version_string.restype = ctypes.c_char_p
    assert lib.sodium_version_string() == b'1.0.20'
    lib.crypto_aead_xchacha20poly1305_ietf_encrypt.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.crypto_aead_xchacha20poly1305_ietf_decrypt.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_void_p]
    return lib


def lp(value):
    return struct.pack('>I', len(value)) + value


def vectors(lib):
    base = dict(name='base', realm=3, kind=3, vault_id=bytes(range(16)), generation=1,
                key_id=bytes(range(16, 32)), nonce=bytes(range(24)), account='account_a',
                reference='agent-provisioning:' + 'A' * 43, plaintext=bytes(range(32)), key=bytes(range(32)))
    changes = [dict(), dict(name='primary', realm=1, kind=1, reference='A' * 43),
               dict(name='branch', realm=2, kind=2, reference='branch:' + 'A' * 43, plaintext=bytes(range(64))),
               dict(name='kind', kind=4, reference='unlock:account_a'),
               dict(name='vault', vault_id=bytes(range(1, 17))), dict(name='generation', generation=2),
               dict(name='key_id', key_id=bytes(range(32, 48))), dict(name='nonce', nonce=bytes(range(1, 25))),
               dict(name='account', account='account_b'), dict(name='reference', reference='agent-provisioning:' + 'B' + 'A' * 42),
               dict(name='length', plaintext=b'x'), dict(name='key', key=bytes(range(1, 33))),
               dict(name='maximum', kind=4, reference='unlock:' + 'a' * 128, account='a' * 128,
                    generation=2**64-1, vault_id=b'\xff'*16, key_id=b'\xff'*16, nonce=b'\xff'*24,
                    plaintext=bytes(range(256))*32)]
    result = []
    for change in changes:
        v = base | change
        header = b'RFVLT001' + struct.pack('>HBB', 1, v['realm'], v['kind']) + v['vault_id'] + struct.pack('>Q', v['generation']) + v['key_id'] + v['nonce'] + struct.pack('>I', len(v['plaintext']))
        assert len(header) == 80
        aad = lp(b'ramflux.identity.linux_vault.entry.v1') + header + lp(v['account'].encode()) + lp(v['reference'].encode())
        out = ctypes.create_string_buffer(len(v['plaintext']) + 16)
        size = ctypes.c_ulonglong()
        assert lib.crypto_aead_xchacha20poly1305_ietf_encrypt(out, ctypes.byref(size), v['plaintext'], len(v['plaintext']), aad, len(aad), None, v['nonce'], v['key']) == 0
        ciphertext = out.raw[:size.value]
        decoded = ctypes.create_string_buffer(len(v['plaintext']))
        assert lib.crypto_aead_xchacha20poly1305_ietf_decrypt(decoded, ctypes.byref(size), None, ciphertext, len(ciphertext), aad, len(aad), v['nonce'], v['key']) == 0
        assert decoded.raw == v['plaintext']
        assert len(header + ciphertext) <= 8288
        result.append({k: value.hex() if isinstance(value, bytes) else value for k, value in v.items()} | {'record': (header + ciphertext).hex()})
    return dict(oracle='libsodium C 1.0.20', commit=COMMIT, source_sha256=SHA256, vectors=result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle-dir', type=Path, required=True)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = vectors(oracle(args.oracle_dir.resolve()))
    if args.write:
        FIXTURE.write_text(json.dumps(generated, indent=2) + '\n')
    else:
        assert json.loads(FIXTURE.read_text()) == generated, 'independent vault vectors differ'
    print(f'libsodium {COMMIT}: {len(generated["vectors"])} vault vectors verified; max record 8288 bytes')

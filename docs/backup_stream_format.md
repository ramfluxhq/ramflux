# Authenticated backup stream format

The `ramflux_crypto::backup_stream` API encrypts arbitrary byte streams in bounded
memory. The daemon integrates it with encrypted SQLCipher snapshots; the job workflow is
described in `account_backup.md`.

The envelope begins with ASCII `RFLXBA02`, followed by a four-byte big-endian JSON
header length and that many exact JSON bytes. Headers are limited to 4096 bytes;
this is a framing metadata bound, not a limit on content or item counts. The header
contains schema `ramflux.account.backup.stream.v2`, version 2, account ID, creation
time, per-category totals and database_bytes, 65536-byte chunk size, cipher `xchacha20poly1305-stream64be`, KDF
`argon2id-v19`, its fixed parameters, a random 32-byte salt, random 24-byte wrapping
nonce and random 15-byte stream prefix. Unsupported parameters are rejected
before expensive KDF work. Account IDs are nonempty and at most 1024 UTF-8 bytes.

The wrapping key is the existing recovery-secret derivation: Argon2id version
0x13, 262144 KiB memory, time cost 3, parallelism 1 and 32-byte output. The existing
minimum input length of 16 bytes applies; that length check is not an entropy
estimator. Generate high-entropy recovery material. Salt and nonces come from the
operating-system CSPRNG.

A separate random 32-byte file key is wrapped with XChaCha20-Poly1305 under that
wrapping key. Associated data is the exact magic, encoded length and JSON header.
The 48-byte wrapped key follows the header. Each chunk authenticates the exact
same header prefix **and** these wrapped-key bytes as its associated data. File
keys and plaintext chunk buffers are zeroized on drop. No keys belong in logs.

Each chunk is `length_u32be || final_u8 || ciphertext_with_16_byte_tag`. Nonfinal
chunks contain exactly 65536 plaintext bytes. The final chunk contains 0 through
65535 plaintext bytes. An exact multiple of the chunk size therefore ends with an
authenticated empty final chunk. The 24-byte chunk nonce is:

```text
random_prefix[15] || sequential_chunk_number_u64be[8] || final_u8[1]
```

Chunk numbers start at zero. The final bit is included in the nonce, so changing
it cannot turn an ordinary chunk into an authenticated end marker. All counter
and total-length arithmetic is checked. There is no item-count or file-count cap;
u64 arithmetic exhaustion is an explicit format error. Files never reuse a file
key/nonce sequence. Encryption does not rewind its input or buffer a whole file.

The decoder checks lengths before allocation, authenticates every chunk under its
expected sequential number, requires an authenticated final chunk and requires
physical EOF immediately afterward. Truncation, deletion, reordering, duplication,
cross-file splicing, modified metadata, wrong credentials and appended data are
rejected. I/O errors remain typed errors and cannot produce a successful partial
export. The caller must flush/fsync and atomically publish the final output file.

Decryption writes only to caller-owned private staging. Successfully authenticated
prefix chunks are **not** a verified archive. The caller must wait for successful
final verification, validate its content, then commit installation separately.
Failure requires discarding the entire staging area. Never decrypt directly into
a live account database or overwrite a final attachment as chunks arrive.

SQLite account snapshots use the SQLite backup API in bounded 128-page steps,
with a fresh random SQLCipher key for the encrypted destination. This copies
all tables and BLOBs, including current WAL content, without materializing each
row or attachment in Rust. The destination must be a new file in a private staging
directory. Snapshot key material is secret and may enter only the authenticated
encrypted archive. A busy snapshot or I/O failure fails rather than truncating.


The account payload is `identity_length_u64be || identity_JSON || encrypted_database`.
Identity JSON contains the recovery manifest, the fresh snapshot database key and
CA bytes. Its 16 MiB metadata budget does not limit database contents. The complete
payload, including those keys, is inside the authenticated stream. Verification
rekeys the staged database under an independently derived RAM-only staging key
and seals identity metadata with AES-256-GCM under a separate derived key. Database
integrity, actual counts and every attachment's existing ChaCha20-Poly1305 tag and
hashes must agree before the job can become Verified. A complete stream alone does
not authorize installation or outbound chain resumption.

The authenticated `totals.missing_attachments` field counts explicitly approved source omissions (absent means zero for older archives). Their selectors and expected manifest/plaintext hashes are stored in the encrypted database table `backup_missing_attachment`, authenticated by the stream. A count alone never authorizes an omission: verification matches each row to its still-missing reference. All present payloads must still pass AEAD and both hash checks.

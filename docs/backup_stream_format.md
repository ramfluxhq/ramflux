# Authenticated backup stream format

The `ramflux_crypto::backup_stream` API encrypts arbitrary byte streams in bounded
memory. Account export/import integration is separate from this primitive; the
current account backup API is described in `account_backup.md`.

The envelope begins with ASCII `RFLXBA02`, followed by a four-byte big-endian JSON
header length and that many exact JSON bytes. Headers are limited to 4096 bytes;
this is a framing metadata bound, not a limit on content or item counts. The header
contains schema `ramflux.account.backup.stream.v2`, version 2, account ID, creation
time, 65536-byte chunk size, cipher `xchacha20poly1305-stream64be`, KDF
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
with the same SQLCipher key and a separately encrypted destination. This copies
all tables and BLOBs, including current WAL content, without materializing each
row or attachment in Rust. The destination must be a new file in a private staging
directory. Snapshot key material is secret and may enter only the authenticated
encrypted archive. A busy snapshot or I/O failure fails rather than truncating.

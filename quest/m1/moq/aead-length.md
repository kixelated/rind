# [S] AEADs refuse over-long messages

## Goal

AES-GCM, ChaCha20-Poly1305, and XChaCha20-Poly1305 `encrypt` return
`Result<(), Error>` and refuse a message past the algorithm's limit, and
`decrypt` refuses one too, on every backend, so no counter wraps silently.

## Plan

Planned by the maintainer on 2026-10-28, from the follow-ups of the m1 PRs. Today `encrypt` returns `()` and does not check: AES-GCM's AVX-512 path
counts blocks in 64 bits and its AVX path in 32 bits, so past GCM's
2^32 - 2 block limit (about 64 GiB) the two disagree. ChaCha20's 32-bit block
counter has the same problem at 256 GiB. Inherited from graviola.

Decided (maintainer, 2026-10-28): return an error, as ring, aws-lc-rs,
RustCrypto's `aes-gcm`, OpenSSL, and BoringSSL do, and as rind's raw ciphers
already do for counter wrap. Rejected: a panic, which keeps the API but is the
outlier, and rind never panics on caller input: it makes misuse
unrepresentable in the types, or returns an error (maintainer, 2026-10-28).

- Breaking: the PR title carries `!`, and every `rind-*` adapter updates its
  call sites, mapping the error into its consumer's error type.
- Test the boundary without allocating 64 GiB, for example through the length
  check alone.

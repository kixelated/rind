# [S] SHA-1 and HMAC-SHA1

## Goal

rind's graviola backend hashes SHA-1 and computes HMAC-SHA1 through its public
API, for STUN MESSAGE-INTEGRITY and SRTP AES-CM-HMAC-SHA1-80.

## Plan

Settled (maintainer, 2026-10-26): browsers require both, so WebRTC in MoQ
(str0m and dimpl) cannot work without them.

Guidance:

- SHA-1 is broken for collision resistance; offer it only where these
  protocols need it, under a name that says so, and keep it out of signature
  verification.
- HMAC-SHA1 should reuse rind's existing HMAC over the new hash.
- Test with the NIST CAVP SHA-1 vectors in `thirdparty/cavp`, Wycheproof's
  HMAC-SHA1 vectors, and differentially against aws-lc-rs. Add a benchmark.

Public API: SHA-1 and HMAC-SHA1 under `hashing`.

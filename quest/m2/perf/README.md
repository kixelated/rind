# Close measured speed gaps

## Goal

Each speed gap against aws-lc-rs that rind's own PRs found on a path MoQ uses
is either closed, or measured on CodSpeed or real MoQ load and shown not to
matter, with the numbers recorded in the PR that closes its quest.

## Plan

Decided by the maintainer on 2026-10-27, after the HKDF PR traded expand speed
for a wipeable key:

- One epic for every gap the m1 PRs reported, rather than fixing each inside
  the PR that found it, so correctness lands first.
- m2, after MoQ switches to rind: none of these gaps blocks the switch.
- Each child measures first. If CodSpeed or real MoQ load shows the gap does
  not matter at MoQ's call rate, record the numbers and delete the quest
  instead of optimizing.

ChaCha20-Poly1305's 1.7-3x gap is already tracked by
[Re-measure accepted costs](/quest/m2/remeasure.md), which turns it into a
quest here if it still matters.

## Required

- [SHA-1 without SHA-NI](/quest/m2/perf/sha1-avx2.md) - an AVX2 message schedule for x86_64 hosts without SHA extensions
- [armv7 AEAD copy](/quest/m2/perf/armv7-aead-copy.md) - armv7 AEADs seal and open in place without copying the buffer
- [armv7 P-256 signing](/quest/m2/perf/armv7-p256-nonce.md) - armv7 ECDSA P-256 computes its nonce point once

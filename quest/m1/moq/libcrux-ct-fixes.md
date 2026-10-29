# [XS] libcrux releases its constant-time fixes

## Goal

libcrux releases on crates.io fix both constant-time reports from armv7
ctgrind, filed privately as
[GHSA-rxqx-6qw3-m3xr](https://github.com/celabshq/libcrux/security/advisories/GHSA-rxqx-6qw3-m3xr)
(`libcrux-hacl-rs` bignum) and
[GHSA-73q3-5f3v-83gw](https://github.com/celabshq/libcrux/security/advisories/GHSA-73q3-5f3v-83gw)
(`libcrux-chacha20poly1305`). Check each advisory's state and patched
versions with `gh api repos/celabshq/libcrux/security-advisories/<id>`, and
the crates' versions on crates.io. Both were in triage on 2026-10-29.

Once both releases exist, bump rind to them, drop any `admin/ctgrind.supp`
entry for either report, confirm armv7 ctgrind passes in debug and release,
and delete this quest.

## Plan

armv7's ChaCha20-Poly1305 and XChaCha20-Poly1305 no longer call libcrux's
AEAD: they share the other arches' composition over HACL*'s Poly1305 and
rind's `ct_equal`, so the ChaCha report needs no suppression. Once its fix
ships, armv7 could return to libcrux's verified AEAD; keeping the shared
composition is simpler unless the maintainer wants the whole AEAD verified.

The bignum report has no workaround in rind. If it is still unfixed when
[armv7 ctgrind](https://github.com/kixelated/rind/pull/36) lands, that PR
suppresses it, and this quest drops the suppression.

# [XS] libcrux releases its bignum constant-time fix

## Goal

A `libcrux-hacl-rs` release on crates.io fixes the bignum constant-time
report from armv7 ctgrind, filed privately as
[GHSA-rxqx-6qw3-m3xr](https://github.com/celabshq/libcrux/security/advisories/GHSA-rxqx-6qw3-m3xr).
Check the advisory's state and patched versions with
`gh api repos/celabshq/libcrux/security-advisories/GHSA-rxqx-6qw3-m3xr`, and
the crate's versions on crates.io. It was in triage on 2026-10-29.

Once that release exists, bump rind's libcrux crates to it, drop the bignum
entries from `admin/ctgrind.supp`, confirm armv7 ctgrind passes, and delete
this quest.

## Plan

Settled (maintainer, 2026-10-30): armv7 ctgrind landed without waiting on
libcrux, with this finding suppressed. Settled (2026-10-29): this quest only
bumps libcrux for the bignum fix and drops that suppression. armv7's
ChaCha20-Poly1305 and XChaCha20-Poly1305 keep the shared composition over
rind's ChaCha20, HACL*'s Poly1305, and rind's `ct_equal`, and do not go back
to libcrux's AEAD, so libcrux's ChaCha report needs nothing here.

# [S] ChaCha20 header protection from HACL*'s block function

## Goal

On x86_64 and aarch64, `rind::cipher::ChaCha20` either runs HACL*'s verified
block function for the one-block masks it is used for (QUIC header protection,
DTLS record numbers), or this quest records why the cost is not worth it and
is deleted. armv7 already runs that block function.

## Plan

Five bytes of keystream, rind (Graviola's SIMD ChaCha20) against HACL*'s
block function as rind copies it for armv7 (`low/arm/chacha20.rs`), criterion
medians, bench-tmp run 41147916836 and a local run:

| host | rind | HACL\* ✓ |
|---|---|---|
| i7-8700 | 94.7 ns | 102.5 ns |
| EPYC 7763 | 141.3 ns | 133.6 ns |
| Neoverse-N2 | 129.1 ns | 123.7 ns |

That is as fast within noise, which `AGENTS.md` resolves for the verified
source. At 1200B Graviola is 2.8-5x faster, so the AEADs and any long
keystream keep it.

The cost: x86_64 and aarch64 would build `libcrux-hacl-rs` and
`libcrux-macros` (needed by the copied file) and carry a second ChaCha20 for
a few nanoseconds either way. Decide whether a length threshold (one block
on HACL\*, more on Graviola) is worth that, or drop the quest.

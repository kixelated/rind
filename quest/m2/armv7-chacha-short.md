# [S] armv7 ChaCha20-Poly1305 for short messages

## Goal

On armv7 with NEON, sealing a 32-byte ChaCha20-Poly1305 message (with 32
bytes of AAD) costs no more than RustCrypto's pure Rust, or this quest records
why the gap stays and is deleted.

## Plan

After [moq-dev/rind#106](https://github.com/moq-dev/rind/pull/106) moved armv7
to aws-lc's `chacha-armv4` and NEON Poly1305, rind is level with aws-lc-rs from
2KB up, but at 32B the `chacha20poly1305` bench on the bench runner (Neoverse-N2
running the armv7 build) measured rind 628-697 ns, aws-lc-rs 629 ns, and
RustCrypto 403 ns. QUIC ACK-only and other small packets sit in this range on
armv7 cores without AES hardware.

- Profile a 32B seal and attribute the fixed cost: the Poly1305 key block,
  NEON Poly1305 setup and finish, the AEAD composition, and the length block.
  #106 measured HACL*'s Poly1305 51 ns faster than the NEON one at 32B.
- If a length cutoff wins, pick it from measurements at 32B, 64B, 128B and
  256B, decided per call from the length only, and keep both paths under the
  existing Wycheproof, aws-lc-rs and ctgrind tests.
- Add the in-between sizes to the bench if the cutoff needs them.

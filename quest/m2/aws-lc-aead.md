# [M] AEAD keys bound to an algorithm

## Goal

`rind::aead` and `rind::cipher` keys are built from an algorithm constant and
key bytes, so the constant, not the key's length, picks AES-128 or AES-256,
and a wrong length is an error. A caller-nonce key flags in its name that the
caller owns nonce uniqueness, and a randomized-nonce key picks its own.
`AesGcm`, `ChaCha20Poly1305`, and `XChaCha20Poly1305` leave the public API.

## Plan

Part of [Learn from aws-lc-rs's API](/quest/m2/aws-lc-api.md); decisions 1, 3,
and 4 of [moq-dev/rind#72](https://github.com/moq-dev/rind/pull/72) shape it.
A sketch following aws-lc-rs, to adjust as the implementation finds better:

```rust
pub mod aead {
    pub struct Algorithm { .. } // key_len(), tag_len(), nonce_len()
    pub static AES_128_GCM: Algorithm;
    pub static AES_256_GCM: Algorithm;
    pub static CHACHA20_POLY1305: Algorithm;

    pub struct UnboundKey { .. } // expanded once, wiped on drop
    impl UnboundKey {
        pub fn new(algorithm: &'static Algorithm, key: &[u8]) -> Result<Self, Error>;
    }

    pub struct Nonce { .. } // not Clone, so one value seals once
    impl Nonce {
        pub fn assume_unique_for_key(nonce: [u8; 12]) -> Self;
    }
    pub struct Aad<A: AsRef<[u8]>>(A); // Aad::from, Aad::empty
    pub struct Tag { .. } // AsRef<[u8]>

    pub struct LessSafeKey { .. }
    impl LessSafeKey {
        pub fn new(key: UnboundKey) -> Self;
        pub fn seal_in_place_separate_tag<A>(&self, nonce: Nonce, aad: Aad<A>, in_out: &mut [u8]) -> Result<Tag, Error>;
        pub fn seal_in_place_append_tag<A, InOut>(&self, nonce: Nonce, aad: Aad<A>, in_out: &mut InOut) -> Result<(), Error>
        where InOut: AsMut<[u8]> + for<'a> Extend<&'a u8>;
        pub fn open_in_place<'a, A>(&self, nonce: Nonce, aad: Aad<A>, in_out: &'a mut [u8]) -> Result<&'a mut [u8], Error>;
        pub fn open_in_place_separate_tag<'a, A>(&self, nonce: Nonce, aad: Aad<A>, tag: &[u8], in_out: &'a mut [u8]) -> Result<&'a mut [u8], Error>;
    }

    // XChaCha20-Poly1305 with a random 192-bit nonce per seal.
    pub struct RandomizedNonceKey { .. }
    impl RandomizedNonceKey {
        pub fn new(key: &[u8; 32]) -> Self;
        pub fn seal_in_place_append_tag<A, InOut>(&self, aad: Aad<A>, in_out: &mut InOut) -> Result<RandomNonce, Error>;
        pub fn open_in_place<'a, A>(&self, nonce: &RandomNonce, aad: Aad<A>, in_out: &'a mut [u8]) -> Result<&'a mut [u8], Error>;
    }
    pub struct RandomNonce { .. } // [u8; 24]: AsRef<[u8]> to store it, From<[u8; 24]> to open with a received one
}

pub mod cipher {
    pub struct Algorithm { .. }
    pub static AES_128: Algorithm;
    pub static AES_256: Algorithm;
    // Aes::new and AesCtr::new take (&'static Algorithm, &[u8]); ChaCha20 keeps its array key.
}
```

- `UnboundKey` stays even though only `LessSafeKey` binds it today: adding it
  later would break `LessSafeKey::new` again, and HKDF derives one directly
  ([Typed HKDF output](/quest/m2/aws-lc-hkdf.md)).
- Methods are only those a consumer calls: separate-tag sealing (rustls,
  QUIC, dimpl, SRTP, MoQ's Retry tag), append-tag sealing (MoQ e2ee and QUIC
  tokens, the ticketer), and both opens. aws-lc-rs's `open_within`,
  `seal_in_place_scatter`, and `open_separate_gather` have none.
- Keep the length limits each AEAD enforces today, and the cleared buffer on
  a failed open.

Migration:

- `AesGcm::new(key)?` becomes
  `LessSafeKey::new(UnboundKey::new(&AES_128_GCM, key)?)`, naming the size.
- `encrypt(&nonce, aad, buf, &mut tag)` becomes
  `seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), buf)`,
  returning the tag; `decrypt` becomes `open_in_place_separate_tag`.
- `XChaCha20Poly1305` becomes `RandomizedNonceKey`, which returns the nonce
  it picked.
- `Aes::new(key)` and `AesCtr::new(key)` take `&cipher::AES_128` or
  `&cipher::AES_256` first.

Consumers:

- `rind-rustls`: TLS 1.2 and 1.3 record keys and QUIC packet keys hold a
  `LessSafeKey`; the ticketer moves to `RandomizedNonceKey`. Its ticket
  format is server-private and rotates every six hours, so no compatibility
  is owed.
- `rind-dimpl`: drops its key-length guard and its `Aead` enum.
- `rind-str0m`: the SRTP AES-GCM profiles name their constant; AES-CM and the
  key-derivation block name `cipher::AES_128` or `AES_256`.
- MoQ: moq-e2ee's `protect.rs` and `name.rs` and moq-quic's Retry tag and
  token key port with a path change from aws-lc-rs.

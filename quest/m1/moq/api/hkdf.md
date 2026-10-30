# [S] Typed HKDF output

## Goal

`rind::hkdf` derives key material whose length is fixed by what it becomes:
expanding for an AEAD or HMAC algorithm yields exactly that key, built
directly into an `aead::UnboundKey` or `hmac::Key`, so derived bytes and the
key that consumes them cannot disagree in length.

## Plan

Part of [Learn from aws-lc-rs's API](/quest/m1/moq/api/README.md). Decided by
the maintainer on 2026-10-30 in
[moq-dev/rind#72](https://github.com/moq-dev/rind/pull/72): algorithm
constants, aws-lc-rs's module names, and aws-lc-rs's typed `Okm` that also
accepts a plain length. A sketch following aws-lc-rs:

```rust
pub mod hkdf {
    #[derive(Clone, Copy)]
    pub struct Algorithm { .. } // hmac_algorithm()
    pub static HKDF_SHA256: Algorithm;
    pub static HKDF_SHA384: Algorithm;
    pub static HKDF_SHA512: Algorithm;

    pub struct Salt { .. } // new(algorithm, salt: &[u8]), extract(&self, secret: &[u8]) -> Prk
    pub struct Prk { .. } // wiped on drop
    impl Prk {
        pub fn expand<'a, L: KeyType>(&'a self, info: &'a [&'a [u8]], len: L) -> Result<Okm<'a, L>, Error>;
    }
    pub trait KeyType { fn len(&self) -> usize; }
    pub struct Okm<'a, L: KeyType> { .. } // fill(self, out: &mut [u8]): WrongLength unless out.len() == len
}
// KeyType for &'static aead::Algorithm, hmac::Algorithm, and usize.
// From<Okm<&'static aead::Algorithm>> for aead::UnboundKey; From<Okm<hmac::Algorithm>> for hmac::Key.
```

- `KeyType for usize` is rind's addition: MoQ defines a `struct Len(usize)`
  newtype twice, in moq-e2ee and moq-quic, only to expand raw bytes through
  aws-lc-rs.
- The `From` conversions fill a stack buffer that is wiped before return,
  since the key it becomes owns the secret.

Migration: `Prk::<Sha256>::extract(salt, ikm)` becomes
`Salt::new(HKDF_SHA256, salt).extract(ikm)`; `prk.expand(info, &mut out)?`
becomes `prk.expand(info, out.len())?.fill(&mut out)?`, or
`UnboundKey::from(prk.expand(info, &AES_256_GCM)?)` when the bytes become a key.

Consumers: no adapter (rustls runs HKDF over `rind-rustls`'s HMAC). MoQ:
moq-quic's reset HMAC key, connection-ID key, and token AEAD key, and
moq-e2ee's credential derivation, all from aws-lc-rs's identical shape.

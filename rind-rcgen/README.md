<h1 align="center">rind-rcgen</h1>
<img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">

[![Latest release](https://img.shields.io/crates/v/rind-rcgen)](https://crates.io/crates/rind-rcgen)
[![Documentation](https://img.shields.io/docsrs/rind-rcgen)](https://docs.rs/rind-rcgen/)

This crate provides an ECDSA P-256 signing key for [rcgen](https://github.com/rustls/rcgen), backed by [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).

Build rcgen with `default-features = false` so it compiles no other crypto backend.
rcgen then needs each certificate's serial number set explicitly.

```rust
let key = rind_rcgen::KeyPair::generate().unwrap();

let mut serial = [0u8; 16];
rind::random::fill(&mut serial).unwrap();

let mut params = rcgen::CertificateParams::new(["localhost".to_string()]).unwrap();
params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));

let cert = params.self_signed(&key).unwrap();
let key = key.to_pkcs8_der().unwrap();
```

License: Apache-2.0 OR ISC OR MIT-0

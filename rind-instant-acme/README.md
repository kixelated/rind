<h1 align="center">rind-instant-acme</h1>
<img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">

This crate provides a `CryptoProvider` for [instant-acme](https://github.com/djc/instant-acme), backed by [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).

Build instant-acme with `default-features = false`, since its default features compile aws-lc-rs.
Then hand the provider to each account, alongside an HTTPS client such as instant-acme's `DefaultClient` on [rind-rustls](../rind-rustls):

```rust
use std::sync::Arc;

use instant_acme::{Account, DefaultClient};

let http = DefaultClient::new(Arc::new(rind_rustls::default_provider())).unwrap();
let builder = Account::builder(Box::new(http), &rind_instant_acme::DEFAULT_PROVIDER).unwrap();
```

It signs account requests with ECDSA P-256 (ES256) keys, the same PKCS#8 keys instant-acme's aws-lc-rs and ring providers make, so stored credentials keep working.
It signs External Account Binding with HMAC-SHA256 and hashes JWK thumbprints and challenge digests with SHA-256.

It targets instant-acme's unreleased provider interface, so it is not yet published.

License: Apache-2.0 OR ISC OR MIT-0

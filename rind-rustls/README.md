<h1 align="center">rind-rustls</h1>
<img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">

[![Latest release](https://img.shields.io/crates/v/rind-rustls)](https://crates.io/crates/rind-rustls)
[![Documentation](https://img.shields.io/docsrs/rind-rustls)](https://docs.rs/rind-rustls/)

This crate provides an integration between [rustls](https://github.com/rustls/rustls) and [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).

Use it like:

```rust
rind_rustls::default_provider().install_default().unwrap();
```

And then use rustls as normal.

License: Apache-2.0 OR ISC OR MIT-0

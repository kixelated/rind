mod criterion;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

struct Len(usize);

impl aws_lc_rs::hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

impl ring::hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

// A 32-byte key for one label: what a QUIC token or an e2ee track key derives
// from a long-lived PRK.
fn sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("hkdf-sha256");
    let secret = [0x5a; 32];
    let info: [&[u8]; 1] = [b"label"];

    group.bench_function("extract/ring", |b| {
        b.iter(|| {
            black_box(ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"salt").extract(&secret))
        })
    });
    group.bench_function("extract/aws-lc-rs", |b| {
        b.iter(|| {
            black_box(
                aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA256, b"salt").extract(&secret),
            )
        })
    });
    group.bench_function("extract/rind", |b| {
        b.iter(|| {
            black_box(rind::hashing::hkdf::Prk::<rind::hashing::Sha256>::extract(
                b"salt", &secret,
            ))
        })
    });

    let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"salt").extract(&secret);
    group.bench_function("expand/ring", |b| {
        b.iter(|| {
            let mut out = [0u8; 32];
            prk.expand(&info, Len(32)).unwrap().fill(&mut out).unwrap();
            black_box(out)
        })
    });

    let prk = aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA256, b"salt").extract(&secret);
    group.bench_function("expand/aws-lc-rs", |b| {
        b.iter(|| {
            let mut out = [0u8; 32];
            prk.expand(&info, Len(32)).unwrap().fill(&mut out).unwrap();
            black_box(out)
        })
    });

    let prk = rind::hashing::hkdf::Prk::<rind::hashing::Sha256>::extract(b"salt", &secret);
    group.bench_function("expand/rind", |b| {
        b.iter(|| {
            let mut out = [0u8; 32];
            prk.expand(&info, &mut out).unwrap();
            black_box(out)
        })
    });
}

criterion_group!(benches, sha256);
criterion_main!(benches);

mod criterion;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hmac::{KeyInit, Mac};

fn test_ring_sha1(key: &[u8], data: &[u8]) {
    let mut ctx = ring::hmac::Context::with_key(&ring::hmac::Key::new(
        ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        key,
    ));
    ctx.update(data);
    black_box(ctx.sign());
}

fn test_ring_sha256(key: &[u8], data: &[u8]) {
    let mut ctx =
        ring::hmac::Context::with_key(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key));
    ctx.update(data);
    black_box(ctx.sign());
}

fn test_ring_sha384(key: &[u8], data: &[u8]) {
    let mut ctx =
        ring::hmac::Context::with_key(&ring::hmac::Key::new(ring::hmac::HMAC_SHA384, key));
    ctx.update(data);
    black_box(ctx.sign());
}

fn test_aws_sha1(key: &[u8], data: &[u8]) {
    let mut ctx = aws_lc_rs::hmac::Context::with_key(&aws_lc_rs::hmac::Key::new(
        aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        key,
    ));
    ctx.update(data);
    black_box(ctx.sign());
}

fn test_aws_sha256(key: &[u8], data: &[u8]) {
    let mut ctx = aws_lc_rs::hmac::Context::with_key(&aws_lc_rs::hmac::Key::new(
        aws_lc_rs::hmac::HMAC_SHA256,
        key,
    ));
    ctx.update(data);
    black_box(ctx.sign());
}

fn test_aws_sha384(key: &[u8], data: &[u8]) {
    let mut ctx = aws_lc_rs::hmac::Context::with_key(&aws_lc_rs::hmac::Key::new(
        aws_lc_rs::hmac::HMAC_SHA384,
        key,
    ));
    ctx.update(data);
    black_box(ctx.sign());
}

fn test_rc_sha1(key: &[u8], data: &[u8]) {
    let mut ctx = hmac::Hmac::<sha1::Sha1>::new_from_slice(key).unwrap();
    ctx.update(data);
    black_box(ctx.finalize());
}

fn test_rc_sha256(key: &[u8], data: &[u8]) {
    let mut ctx = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    ctx.update(data);
    black_box(ctx.finalize());
}

fn test_rc_sha384(key: &[u8], data: &[u8]) {
    let mut ctx = hmac::Hmac::<sha2::Sha384>::new_from_slice(key).unwrap();
    ctx.update(data);
    black_box(ctx.finalize());
}

fn test_rind_sha1(key: &[u8], data: &[u8]) {
    let mut ctx = rind::hashing::hmac::Hmac::<rind::hashing::LegacySha1>::new(key);
    ctx.update(data);
    black_box(ctx.finish());
}

fn test_rind_sha256(key: &[u8], data: &[u8]) {
    let mut ctx = rind::hashing::hmac::Hmac::<rind::hashing::Sha256>::new(key);
    ctx.update(data);
    black_box(ctx.finish());
}

fn test_rind_sha384(key: &[u8], data: &[u8]) {
    let mut ctx = rind::hashing::hmac::Hmac::<rind::hashing::Sha384>::new(key);
    ctx.update(data);
    black_box(ctx.finish());
}

fn sha1(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac-sha1");
    let key = [0xff; 20];

    for (size, size_name) in [(32, "32B"), (2048, "2KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Elements(1));

        group.bench_with_input(BenchmarkId::new("ring", size_name), &input, |b, input| {
            b.iter(|| test_ring_sha1(&key, input))
        });
        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| b.iter(|| test_aws_sha1(&key, input)),
        );
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| b.iter(|| test_rc_sha1(&key, input)),
        );
        group.bench_with_input(BenchmarkId::new("rind", size_name), &input, |b, input| {
            b.iter(|| test_rind_sha1(&key, input))
        });
    }
}

fn sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac-sha256");
    let key = [0xff; 48];

    for (size, size_name) in [(32, "32B"), (2048, "2KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Elements(1));

        group.bench_with_input(BenchmarkId::new("ring", size_name), &input, |b, input| {
            b.iter(|| test_ring_sha256(&key, input))
        });
        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| b.iter(|| test_aws_sha256(&key, input)),
        );
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| b.iter(|| test_rc_sha256(&key, input)),
        );
        group.bench_with_input(BenchmarkId::new("rind", size_name), &input, |b, input| {
            b.iter(|| test_rind_sha256(&key, input))
        });
    }
}

fn sha384(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac-sha384");
    let key = [0xff; 48];

    for (size, size_name) in [(32, "32B"), (2048, "2KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Elements(1));

        group.bench_with_input(BenchmarkId::new("ring", size_name), &input, |b, input| {
            b.iter(|| test_ring_sha384(&key, input))
        });
        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| b.iter(|| test_aws_sha384(&key, input)),
        );
        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| b.iter(|| test_rc_sha384(&key, input)),
        );
        group.bench_with_input(BenchmarkId::new("rind", size_name), &input, |b, input| {
            b.iter(|| test_rind_sha384(&key, input))
        });
    }
}

criterion_group!(benches, sha1, sha256, sha384);
criterion_main!(benches);

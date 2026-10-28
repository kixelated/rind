mod criterion;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn bench_aes_ctr(c: &mut Criterion) {
    let key = [0u8; 16];
    let nonce = [0u8; 12];

    let mut group = c.benchmark_group("aes128-ctr");
    for (size, size_name) in [(32, "32B"), (1200, "1200B"), (16384, "16KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("aws-lc-rs", size_name),
            &input,
            |b, input| {
                use aws_lc_rs::cipher::{
                    AES_128, EncryptingKey, EncryptionContext, UnboundCipherKey,
                };
                let key =
                    EncryptingKey::ctr(UnboundCipherKey::new(&AES_128, &key).unwrap()).unwrap();
                let mut iv = [0u8; 16];
                iv[..12].copy_from_slice(&nonce);
                b.iter(|| {
                    let mut buf = input.clone();
                    key.less_safe_encrypt(&mut buf, EncryptionContext::Iv128(iv.into()))
                        .unwrap();
                    buf
                });
            },
        );
        group.bench_with_input(BenchmarkId::new("rind", size_name), &input, |b, input| {
            let key = rind::cipher::AesCtr::new(&key).unwrap();
            b.iter(|| {
                let mut buf = input.clone();
                key.apply_keystream(&nonce, 0, &mut buf).unwrap();
                buf
            });
        });
    }
}

// The QUIC header protection mask: one cipher call on a 16-byte sample.
fn bench_header_protection(c: &mut Criterion) {
    let sample = [0x5au8; 16];
    let mut group = c.benchmark_group("quic-header-protection");

    group.bench_function("aes128/aws-lc-rs", |b| {
        use aws_lc_rs::aead::quic::{AES_128, HeaderProtectionKey};
        let key = HeaderProtectionKey::new(&AES_128, &[0u8; 16]).unwrap();
        b.iter(|| key.new_mask(&sample).unwrap());
    });
    group.bench_function("aes128/rind", |b| {
        let key = rind::cipher::Aes::new(&[0u8; 16]).unwrap();
        b.iter(|| {
            let mut block = sample;
            key.encrypt_block(&mut block);
            block
        });
    });

    group.bench_function("chacha20/aws-lc-rs", |b| {
        use aws_lc_rs::aead::quic::{CHACHA20, HeaderProtectionKey};
        let key = HeaderProtectionKey::new(&CHACHA20, &[0u8; 32]).unwrap();
        b.iter(|| key.new_mask(&sample).unwrap());
    });
    group.bench_function("chacha20/rind", |b| {
        let key = rind::cipher::ChaCha20::new([0u8; 32]);
        let (counter, nonce) = sample.split_at(4);
        let counter = u32::from_le_bytes(counter.try_into().unwrap());
        let nonce: &[u8; 12] = nonce.try_into().unwrap();
        b.iter(|| {
            let mut mask = [0u8; 5];
            key.apply_keystream(nonce, counter, &mut mask).unwrap();
            mask
        });
    });
}

criterion_group!(benches, bench_aes_ctr, bench_header_protection);
criterion_main!(benches);

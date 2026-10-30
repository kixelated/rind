mod criterion;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn test_rc_chacha(key: &chacha20poly1305::XChaCha20Poly1305, aad: &[u8], plain: &[u8]) {
    use chacha20poly1305::AeadInOut;
    let mut nonce = [0u8; 24];
    rind::random::fill(&mut nonce).unwrap();
    let nonce = &nonce;

    let mut ct = plain.to_vec();
    let _tag = key
        .encrypt_inout_detached(nonce.into(), aad, ct.as_mut_slice().into())
        .unwrap();
}

fn test_rind_chacha(key: &rind::aead::RandomizedNonceKey, aad: &[u8], plain: &[u8]) {
    // Room for the appended tag, so sealing does not reallocate.
    let mut ct = Vec::with_capacity(plain.len() + 16);
    ct.extend_from_slice(plain);
    let _nonce = key
        .seal_in_place_append_tag(rind::aead::Aad::from(aad), &mut ct)
        .unwrap();
}

fn bench_chacha20poly1305(c: &mut Criterion) {
    // Each seal draws a fresh random nonce, as a randomized-nonce key must.
    let key = [0u8; 32];
    let aad = [0u8; 32];

    let mut group = c.benchmark_group("xchacha20poly1305");
    for (size, size_name) in [(32, "32B"), (2048, "2KB"), (16384, "16KB")] {
        let input = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("rustcrypto", size_name),
            &input,
            |b, input| {
                use chacha20poly1305::KeyInit;
                let key = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key).unwrap();
                b.iter(|| test_rc_chacha(&key, &aad, input));
            },
        );
        group.bench_with_input(BenchmarkId::new("rind", size_name), &input, |b, input| {
            let key = rind::aead::RandomizedNonceKey::new(&key);
            b.iter(|| test_rind_chacha(&key, &aad, input));
        });
    }
}

criterion_group!(benches, bench_chacha20poly1305);
criterion_main!(benches);

use criterion::{criterion_group, criterion_main, Criterion};
use crypto_bigint::{rand_core::OsRng, RandomBits, Uint};

fn bench(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("primality");

    let mut rng = OsRng;
    let t = 10u32;

    group.bench_function("generate 1024 bits", |b| {
        b.iter(|| {
            crypto_primality::miller_rabin::generate_probable_prime::<16, 32, OsRng>(
                1024, t, &mut rng,
            );
        });
    });

    group.bench_function("generate 1024 bits in oversized", |b| {
        b.iter(|| {
            crypto_primality::miller_rabin::generate_probable_prime::<64, 128, OsRng>(
                1024, t, &mut rng,
            );
        });
    });

    group.bench_function("test 1024 bits", |b| {
        b.iter(|| {
            let candidate = Uint::<64>::random_bits(&mut rng, 1024);
            crypto_primality::miller_rabin::is_composite::<64, 128>(candidate, t, &mut rng);
        });
    });

    group.bench_function("test 2048 bits", |b| {
        b.iter(|| {
            let candidate = Uint::<128>::random_bits(&mut rng, 2048);
            crypto_primality::miller_rabin::is_composite::<128, 256>(candidate, t, &mut rng);
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);

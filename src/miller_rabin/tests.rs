use crate::miller_rabin::is_composite;
use crypto_bigint::rand_core::OsRng;
use crypto_bigint::{Bounded, ConstZero, Uint};
use std::ops::Not;

use super::generate_probable_prime;

const T: u32 = 10;

#[test]
fn generate_probable_prime_1024() {
    let mut rng = OsRng;
    let p = generate_probable_prime::<16, 32, OsRng>(1024u32, T, &mut rng);
}

#[test]
fn generate_probable_prime_2048() {
    let mut rng = OsRng;
    let p = generate_probable_prime::<32, 64, OsRng>(2048u32, T, &mut rng);
    println!("p {}", p);
}

#[test]
fn first_34_primes_are_not_composite() {
    let mut rng = OsRng;

    // Known primes pass
    let primes: [u64; 34] = [
        2, 3, 5, 7, 13, 17, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 71, 73, 79, 83, 89, 97, 101,
        103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
    ];
    for p in primes {
        println!("p {}", p);
        let composite: bool = is_composite::<4, 8>(Uint::<4>::from_u64(p), T, &mut rng).into();
        assert!(!composite, "some known primes fail")
    }
}

#[test]
fn number_of_primes_below_100000() {
    let mut rng = OsRng;

    let mut count = 0;
    for i in 2..10_000u64 {
        if is_composite(Uint::<4>::from_u64(i), T * 5, &mut rng)
            .not()
            .into()
        {
            count += 1;
        }
    }

    assert_eq!(
        1229, count,
        "wrong count. Could happen due to false positive"
    );
}

#[test]
fn two_primes_are_not_codivisible() {
    let mut rng = OsRng;
    let p = generate_probable_prime::<8, 16, OsRng>(Uint::<8>::BITS, T, &mut rng);
    let q = generate_probable_prime::<8, 16, OsRng>(Uint::<8>::BITS, T, &mut rng);
    let (_, r) = p.div_rem(&q.to_nz().unwrap());
    assert_ne!(r, Uint::ZERO);
}

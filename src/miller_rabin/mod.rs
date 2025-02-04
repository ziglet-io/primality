use crypto_bigint::modular::MontyForm;
use crypto_bigint::modular::MontyParams;
use crypto_bigint::rand_core::RngCore;
use crypto_bigint::subtle::Choice;
use crypto_bigint::Concat;
use crypto_bigint::RandomBits;
use crypto_bigint::Split;
use crypto_bigint::{Integer, Odd, RandomMod, Uint};

/// Miller Rabin Composite Test
///
/// Tests whether a candidate prime $p$ is composite. If $p$ is not found to be composite,
/// it is likely, though not guaranteed to be prime.
///
/// # Parameters
///
/// * $p$: a big, unsigned integer that is a candidate prime
/// * $t$: the bound on the desired probability that $p$ is composite = $P\[composite\] < {{1/4}^{t}}$
/// * rng: random number generator for selecting $a \in [2..{n-2}]$
/// * LIMBS: The size in [Limb]s of the resulting big integer
/// * LIMBS_DOUBLE: Double the size of LIMBS. Needed because Montgomery forms in [crypto_bigint] sometimes need to widen
///
/// # Notes
///
/// * Choosing a value of $t$ that is not $t << p$ will result in a high
/// probability of re-testing the same $a \leftarrow_R [2..(n-2)]$ with no decrease in the probability
/// of compositeness.
///
/// # Dependencies
///
/// This package is intended to be used for cryptographic operations on large numbers. It relies
/// on the [crypto_bigint] crate;
///
/// # References
/// [1](https://www.cis.upenn.edu/~jean/RSA-primality-testing.pdf)
/// Gallier, Jean, and Jocelyn Quaintance. “Notes on Primality Testing And Public Key Cryptography Part 1: Randomized Algorithms Miller–Rabin and Solovay–Strassen Tests,” n.d.
///
/// [2](https://kconrad.math.uconn.edu/blurbs/ugradnumthy/millerrabin.pdf) Conrad, Keith. “THE MILLER–RABIN TEST,” n.d.
///
/// [3](https://en.wikipedia.org/w/index.php?title=Miller%E2%80%93Rabin_primality_test) “Miller–Rabin Primality Test.” In Wikipedia, January 3, 2025.
// TODO accept references instead of moving
pub fn is_composite<const LIMBS: usize, const LIMBS_DOUBLE: usize>(
    p: Uint<LIMBS>,
    t: u32,
    rng: &mut impl RngCore,
) -> Choice
where
    Uint<LIMBS>: Concat<Output = Uint<LIMBS_DOUBLE>>,
    Uint<LIMBS_DOUBLE>: Split<Output = Uint<LIMBS>>,
{
    assert!(t > 0);

    #[allow(non_snake_case)]
    let FALSE = Choice::from(0);
    #[allow(non_snake_case)]
    let TRUE = Choice::from(1);

    let two = two::<LIMBS>();
    let three = two + Uint::ONE;

    if &p == &two || &p == &three {
        return FALSE;
    }

    let p_minus_1 = p - Uint::ONE;
    let p_minus_3 = p_minus_1 - Uint::ONE - Uint::ONE;

    if p.is_even().into() {
        return TRUE;
    }

    // Find s * q = (p-1), s is power of two, q is odd
    let mut s = Uint::<LIMBS>::ZERO;
    let mut q = p - Uint::<LIMBS>::ONE;
    while q.is_even().unwrap_u8() == 1u8 {
        q = q / two;
        s += Uint::ONE;
    }

    // For $t$ trials, pick random values of $a \in 2..{n-1}$
    't: for _ in 0..t {
        let mut a: Uint<LIMBS> = Uint::ZERO;

        while a.is_even().unwrap_u8() == 1u8 && a < two {
            a = Uint::<LIMBS>::random_mod(rng, &p_minus_3.to_nz().unwrap()) + two;
        }

        // Test $a^q$
        let mut a = MontyForm::new(&a, MontyParams::new(Odd::new(p).unwrap()));
        a = a.pow(&q);
        if &a.retrieve() == &Uint::ONE {
            continue;
        }

        // Test all $a^{2^xq}$ for $x \in 1..(s-1)$
        let mut current_s = s;
        while current_s > Uint::ZERO {
            // println!("s {}", s);
            a = a.square();
            if &a.retrieve() == &p_minus_1 || &a.retrieve() == &Uint::<LIMBS>::ONE {
                continue 't;
            }

            current_s = current_s - Uint::ONE;
        }

        return TRUE;
    }

    FALSE
}

#[inline(always)]
fn two<const LIMBS: usize>() -> Uint<LIMBS> {
    Uint::<LIMBS>::ONE + Uint::<LIMBS>::ONE
}

/// Generate a probable prime that is up to `bits` in size and store it in a
/// [Uint] with `LIMBS`
pub fn generate_probable_prime<const LIMBS: usize, const LIMBS_DOUBLE: usize, R: RngCore>(
    bits: u32,
    t: u32,
    mut rng: &mut R,
) -> Uint<LIMBS>
where
    Uint<LIMBS>: Concat<Output = Uint<LIMBS_DOUBLE>>,
    Uint<LIMBS_DOUBLE>: Split<Output = Uint<LIMBS>>,
{
    assert!(Uint::<LIMBS>::BITS >= bits, "bits are larger than limbs");

    let two = Uint::<LIMBS>::ONE + Uint::<LIMBS>::ONE;
    let mut p = Uint::<LIMBS>::ZERO;

    while p.is_even().unwrap_u8() == 1u8 {
        p = Uint::<LIMBS>::random_bits(&mut rng, bits);
    }

    loop {
        if is_composite(p, t, &mut rng).unwrap_u8() == 0u8 {
            return p;
        }

        p += two;
    }
}

#[cfg(test)]
mod tests;

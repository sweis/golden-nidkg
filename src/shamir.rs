//! Shamir secret sharing over `F_p` (Section 3.3 of the paper).
//!
//! `Share(x, n, t)` builds a uniformly random degree-`(t-1)` polynomial
//! `f(Z) = x + a_1 Z + … + a_{t-1} Z^{t-1}` and outputs `f(1), …, f(n)`.
//!
//! `Recover(t, {(i, x̄_i)})` interpolates `f(0) = x` from any `≥ t` shares.

use crate::curves::Fp;
use crate::errors::{GoldenError, GoldenResult};
use ark_ff::{Field, Zero};
use ark_std::rand::{CryptoRng, Rng};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A polynomial `f(Z) = a_0 + a_1 Z + … + a_{deg} Z^{deg}` over `F_p`.
///
/// `coeffs[0] = f(0)` is the secret.  Coefficients are zeroized on drop
/// (`ark_ff::Fp` implements `Zeroize`, so `Vec<Fp>::zeroize` is a true
/// volatile scrub of the limbs, not an optimisable-away assignment).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Polynomial {
    coeffs: Vec<Fp>,
}

impl Polynomial {
    /// Build a random polynomial of degree `t-1` with `f(0) = secret`.
    pub fn random_with_secret(secret: Fp, t: u32, rng: &mut (impl Rng + CryptoRng)) -> Self {
        assert!(t >= 1, "threshold must be at least 1");
        let mut coeffs = Vec::with_capacity(t as usize);
        coeffs.push(secret);
        for _ in 1..t {
            coeffs.push(ark_ff::UniformRand::rand(rng));
        }
        Self { coeffs }
    }

    /// Build a polynomial from explicit coefficients `[a_0, a_1, …]`.
    /// Used for deterministic test vectors.
    pub fn from_coeffs(coeffs: Vec<Fp>) -> Self {
        assert!(
            !coeffs.is_empty(),
            "polynomial must have at least one coefficient"
        );
        Self { coeffs }
    }

    /// Evaluate `f(z)`.
    pub fn evaluate(&self, z: Fp) -> Fp {
        // Horner.
        let mut acc = Fp::zero();
        for c in self.coeffs.iter().rev() {
            acc = acc * z + c;
        }
        acc
    }

    /// Threshold `t` (number of coefficients = degree + 1).
    pub fn t(&self) -> u32 {
        self.coeffs.len() as u32
    }

    /// Coefficients (used by Feldman commitment).
    pub fn coeffs(&self) -> &[Fp] {
        &self.coeffs
    }

    /// `f(0)` — the secret.
    pub fn secret(&self) -> Fp {
        self.coeffs[0]
    }
}

/// `Share(x, n, t)` — produce `(f, [(1, f(1)), …, (n, f(n))])`.
///
/// Indices are **1-based**: `f(0)` is the secret.
pub fn share(
    secret: Fp,
    n: u32,
    t: u32,
    rng: &mut (impl Rng + CryptoRng),
) -> (Polynomial, Vec<(u32, Fp)>) {
    assert!(t >= 1 && t <= n, "require 1 ≤ t ≤ n");
    let poly = Polynomial::random_with_secret(secret, t, rng);
    let shares = (1..=n).map(|i| (i, poly.evaluate(Fp::from(i)))).collect();
    (poly, shares)
}

/// Lagrange coefficient `L_i(z)` evaluated at `z`, for the index set `idx`.
///
/// `L_i(z) = ∏_{j ∈ idx, j ≠ i} (z - j) / (i - j)`.
pub fn lagrange_coeff(idx: &[u32], i: u32, z: Fp) -> Fp {
    let xi = Fp::from(i);
    let mut num = Fp::from(1u64);
    let mut den = Fp::from(1u64);
    for &j in idx {
        if j == i {
            continue;
        }
        let xj = Fp::from(j);
        num *= z - xj;
        den *= xi - xj;
    }
    num * den
        .inverse()
        .expect("distinct indices ⇒ nonzero denominator")
}

/// `Recover(t, shares)` — interpolate `f(0)` from `≥ t` shares with distinct
/// indices.  Errors if fewer than `t` shares or duplicate indices.
pub fn recover(t: u32, shares: &[(u32, Fp)]) -> GoldenResult<Fp> {
    if (shares.len() as u32) < t {
        return Err(GoldenError::NotEnoughShares {
            have: shares.len() as u32,
            need: t,
        });
    }
    let idx: Vec<u32> = shares.iter().map(|(i, _)| *i).collect();
    {
        let mut sorted = idx.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != idx.len() {
            return Err(GoldenError::DuplicateShareIndex);
        }
        if sorted.contains(&0) {
            return Err(GoldenError::InvalidShareIndex);
        }
    }
    let mut acc = Fp::zero();
    for &(i, xi) in shares {
        acc += xi * lagrange_coeff(&idx, i, Fp::zero());
    }
    Ok(acc)
}

/// Interpolate `f(z)` from `≥ t` shares (used in tests, e.g. recomputing a
/// missing share index for partial-set tests).
pub fn interpolate_at(shares: &[(u32, Fp)], z: Fp) -> Fp {
    let idx: Vec<u32> = shares.iter().map(|(i, _)| *i).collect();
    shares
        .iter()
        .map(|&(i, xi)| xi * lagrange_coeff(&idx, i, z))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use rand::SeedableRng;

    #[test]
    fn share_recover_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        for (n, t) in [(1, 1), (3, 2), (5, 3), (10, 7)] {
            let secret = Fp::rand(&mut rng);
            let (_, shares) = share(secret, n, t, &mut rng);
            // Use exactly t shares
            let recovered = recover(t, &shares[..t as usize]).unwrap();
            assert_eq!(recovered, secret);
            // Use all n shares
            let recovered_all = recover(t, &shares).unwrap();
            assert_eq!(recovered_all, secret);
        }
    }

    #[test]
    fn fewer_than_t_shares_fails() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let secret = Fp::rand(&mut rng);
        let (_, shares) = share(secret, 5, 3, &mut rng);
        assert!(recover(3, &shares[..2]).is_err());
    }

    #[test]
    fn t_minus_one_shares_do_not_reveal() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let secret = Fp::rand(&mut rng);
        let (_, shares) = share(secret, 5, 3, &mut rng);
        // Force "recovery" with only t-1 shares by lying about `t`.
        let bad = recover(2, &shares[..2]).unwrap();
        assert_ne!(bad, secret);
    }

    #[test]
    fn duplicate_indices_rejected() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let secret = Fp::rand(&mut rng);
        let (_, shares) = share(secret, 5, 3, &mut rng);
        let dup = vec![shares[0], shares[0], shares[1]];
        assert!(recover(3, &dup).is_err());
    }

    #[test]
    fn index_zero_rejected() {
        // index 0 *is* the secret; treating it as a share must error.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let secret = Fp::rand(&mut rng);
        let (poly, shares) = share(secret, 5, 3, &mut rng);
        let bad = vec![(0u32, poly.secret()), shares[0], shares[1]];
        assert!(recover(3, &bad).is_err());
    }

    #[test]
    fn interpolate_arbitrary_point() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let secret = Fp::rand(&mut rng);
        let (poly, shares) = share(secret, 5, 3, &mut rng);
        let z = Fp::from(42u64);
        assert_eq!(interpolate_at(&shares[..3], z), poly.evaluate(z));
    }
}

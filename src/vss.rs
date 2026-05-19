//! Feldman verifiable secret sharing (Section 3.3).
//!
//! Commits to a polynomial `f(Z) = a_0 + a_1 Z + … + a_{t-1} Z^{t-1}` by
//! publishing `C = (g_out^{a_0}, …, g_out^{a_{t-1}})`.  Anyone can derive the
//! commitment to a *share* `f(j)` as `X_j = ∏_{l=0}^{t-1} A_l^{j^l}`.

use crate::curves::{Fp, GoutAffine, GoutProj};
use crate::shamir::Polynomial;
use ark_ec::{CurveGroup, PrimeGroup};

/// `C = (g_out^{a_0}, …, g_out^{a_{t-1}})`.  Batch-normalised: one inversion
/// for all `t` coefficients.
pub fn commit(poly: &Polynomial) -> Vec<GoutAffine> {
    let g = GoutProj::generator();
    let proj: Vec<GoutProj> = poly.coeffs().iter().map(|c| g * c).collect();
    GoutProj::normalize_batch(&proj)
}

/// `X_j = ∏_{l=0}^{t-1} A_l^{j^l} = g_out^{f(j)}` — Feldman share commitment
/// via Horner-in-the-exponent.
pub fn share_commitment(commitment: &[GoutAffine], j: u32) -> GoutAffine {
    share_commitment_proj(commitment, j).into_affine()
}

/// Projective form of [`share_commitment`], for callers that immediately add
/// the result into another accumulator (skips the affine inversion).
///
/// Each Horner step multiplies the accumulator by the small participant
/// index `j` (a u32).  `mul_bits_be` over `j`'s ≈⌈log₂ j⌉ bits is a plain
/// double-and-add; `* Fp::from(j)` and `mul_bigint([j])` would both route
/// through BLS12-381 G1's GLV decomposition, which heap-allocates a handful
/// of `BigInt`s and iterates the full 128-bit half-width regardless of `j`.
pub fn share_commitment_proj(commitment: &[GoutAffine], j: u32) -> GoutProj {
    let mut acc = GoutProj::from(commitment[commitment.len() - 1]);
    for a in commitment.iter().rev().skip(1) {
        acc = acc.mul_bits_be(ark_ff::BitIteratorBE::new([j as u64])) + a;
    }
    acc
}

/// `g_out^{f(j)} == X_j`?  Used by tests — protocol verification computes
/// `X_j` directly from the commitment.
pub fn verify_share(commitment: &[GoutAffine], j: u32, share: Fp) -> bool {
    GoutProj::generator() * share == share_commitment_proj(commitment, j)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir;
    use ark_std::UniformRand;
    use rand::SeedableRng;

    #[test]
    fn share_commitments_match() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let secret = Fp::rand(&mut rng);
        let (poly, shares) = shamir::share(secret, 5, 3, &mut rng);
        let c = commit(&poly);
        assert_eq!(c.len(), 3);
        for (j, x) in shares {
            assert!(verify_share(&c, j, x));
        }
        // and the secret commitment is C[0]
        let pk = (GoutProj::generator() * secret).into_affine();
        assert_eq!(c[0], pk);
    }

    #[test]
    fn tampered_share_rejected() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let secret = Fp::rand(&mut rng);
        let (poly, shares) = shamir::share(secret, 5, 3, &mut rng);
        let c = commit(&poly);
        let (j, x) = shares[0];
        assert!(!verify_share(&c, j, x + Fp::from(1u64)));
    }
}

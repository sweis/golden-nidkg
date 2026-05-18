//! Feldman verifiable secret sharing (Section 3.3).
//!
//! Commits to a polynomial `f(Z) = a_0 + a_1 Z + … + a_{t-1} Z^{t-1}` by
//! publishing `C = (g_out^{a_0}, …, g_out^{a_{t-1}})`.  Anyone can derive the
//! commitment to a *share* `f(j)` as `X_j = ∏_{l=0}^{t-1} A_l^{j^l}`.

use crate::curves::{Fp, GoutAffine, GoutProj};
use crate::shamir::Polynomial;
use ark_ec::CurveGroup;
use ark_ec::PrimeGroup;
use ark_ff::Field;

/// `C = (g_out^{a_0}, …, g_out^{a_{t-1}})`.
pub fn commit(poly: &Polynomial) -> Vec<GoutAffine> {
    let g = GoutProj::generator();
    poly.coeffs().iter().map(|c| (g * c).into_affine()).collect()
}

/// `X_j = ∏_{l=0}^{t-1} A_l^{j^l} = g_out^{f(j)}`.
pub fn share_commitment(commitment: &[GoutAffine], j: u32) -> GoutAffine {
    let z = Fp::from(j);
    // Horner in the exponent: X = A_{t-1}; for l = t-2..0: X = X^z · A_l.
    let mut acc = GoutProj::from(commitment[commitment.len() - 1]);
    for a in commitment.iter().rev().skip(1) {
        acc = acc * z + GoutProj::from(*a);
    }
    acc.into_affine()
}

/// Aggregate VSS commitments from several dealers element-wise (used to
/// derive the joint per-party public-key shares).
pub fn aggregate_share_commitment(commitments: &[&[GoutAffine]], j: u32) -> GoutAffine {
    let mut acc = GoutProj::default();
    for c in commitments {
        acc += GoutProj::from(share_commitment(c, j));
    }
    acc.into_affine()
}

/// `g_out^{f(j)} == X_j`?  Used by tests — protocol verification computes
/// `X_j` directly from the commitment.
pub fn verify_share(commitment: &[GoutAffine], j: u32, share: Fp) -> bool {
    let lhs = (GoutProj::generator() * share).into_affine();
    lhs == share_commitment(commitment, j)
}

/// Same as `share_commitment` but allowing a field-element evaluation point.
pub fn share_commitment_at(commitment: &[GoutAffine], z: Fp) -> GoutAffine {
    let mut acc = GoutProj::from(commitment[commitment.len() - 1]);
    for a in commitment.iter().rev().skip(1) {
        acc = acc * z + GoutProj::from(*a);
    }
    acc.into_affine()
}

#[allow(dead_code)]
fn powers(base: Fp, n: usize) -> Vec<Fp> {
    let mut out = Vec::with_capacity(n);
    let mut acc = Fp::ONE;
    for _ in 0..n {
        out.push(acc);
        acc *= base;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir;
    use ark_std::UniformRand;

    #[test]
    fn share_commitments_match() {
        let mut rng = ark_std::test_rng();
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
        let mut rng = ark_std::test_rng();
        let secret = Fp::rand(&mut rng);
        let (poly, shares) = shamir::share(secret, 5, 3, &mut rng);
        let c = commit(&poly);
        let (j, x) = shares[0];
        assert!(!verify_share(&c, j, x + Fp::from(1u64)));
    }
}

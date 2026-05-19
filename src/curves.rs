//! Curve and field type aliases for the two-curve setup used by Golden.
//!
//! `G_in`  — the **embedded** curve, where Diffie-Hellman PKI keys live.
//!           We use *Jubjub* (`ark-ed-on-bls12-381`), a twisted Edwards curve
//!           defined over `F_p` (the BLS12-381 scalar field).
//! `G_out` — the **outer** curve, where the DKG's public key, the Feldman VSS
//!           commitments and the eVRF pad commitments live.  We use BLS12-381 G1.
//!
//! Crucially, `G_out` has prime order `p`, which is also the base field of
//! `G_in`.  This means the eVRF's heavy work (Jubjub scalar multiplications and
//! coordinate extraction) lives natively in the constraint field of a SNARK
//! over `G_out`.
//!
//! Field cheat sheet:
//! ```text
//!   F_p = BLS12-381 Fr  = Jubjub Fq      255-bit (Golden's "Z_p")
//!   F_s = Jubjub Fr                      252-bit
//!   F_q = BLS12-381 Fq                   381-bit (we never compute over this)
//! ```

pub use ark_bls12_381::{Fr as Fp, G1Affine as GoutAffine, G1Projective as GoutProj};
pub use ark_ed_on_bls12_381::{
    EdwardsAffine as GinAffine, EdwardsProjective as GinProj, Fr as Fs, JubjubConfig as GinConfig,
};

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};

/// `int(P.x)`: cast the affine x-coordinate of a `G_in` point into `F_p`.
///
/// Because Jubjub is defined *over* `F_p`, the x-coordinate is already an
/// `F_p` element; this is the identity map.  We return `0` for the point at
/// infinity / identity.  Callers must make sure the identity never arises
/// (i.e. reject all-zero secret keys before the DH step).
///
/// On Jubjub (twisted Edwards, cofactor 8), `x` is *injective* on the
/// prime-order subgroup: `(x, y)` and `(x, -y)` differ by the 2-torsion point
/// `(0, -1)`, which is not in the prime-order subgroup.  So there is no
/// `±`-ambiguity (unlike short-Weierstrass `.X`).
#[inline]
pub fn x_coord(p: &GinAffine) -> Fp {
    if p.is_zero() {
        Fp::from(0u64)
    } else {
        p.x
    }
}

/// Reduce an `F_p` element modulo `s` and reinterpret as `F_s` (the
/// `int(·)` cast from the eVRF, used to drive `G_in` exponentiations).
///
/// `F_s` is smaller than `F_p`, so this is a (slightly biased) modular
/// reduction.  See BUGS.md §8.
#[inline]
pub fn fp_to_fs(p: &Fp) -> Fs {
    Fs::from_le_bytes_mod_order(&p.into_bigint().to_bytes_le())
}

/// Generator of `G_in` (Jubjub prime-order subgroup).
#[inline]
pub fn gin_gen() -> GinAffine {
    GinAffine::generator()
}

/// Generator of `G_out` (BLS12-381 `G1`).
#[inline]
pub fn gout_gen() -> GoutAffine {
    GoutAffine::generator()
}

/// `g_out^s` for `s ∈ F_p`.
#[inline]
pub fn gout_mul(s: &Fp) -> GoutAffine {
    (GoutProj::generator() * s).into_affine()
}

/// `g_in^s` for `s ∈ F_s`.
#[inline]
pub fn gin_mul(s: &Fs) -> GinAffine {
    (GinProj::generator() * s).into_affine()
}

/// Prime-order-subgroup membership for any arkworks affine point.
///
/// `arkworks::CanonicalDeserialize` performs this check on deserialization
/// (`Validate::Yes` is the default), but the library cannot assume callers
/// only obtain points by deserialization.  Both Jubjub (cofactor 8) and
/// BLS12-381 G1 (cofactor `3·11²·10177²·…` — smallest prime factor **3**)
/// have small-order subgroups, so an off-subgroup element is something a
/// motivated adversary can grind for; see BUGS.md §12.  The per-element
/// check is `O(log #E)` and cannot be soundly batched: a random-linear-
/// combination batch test passes a bad order-`q` element with prob. `1/q`,
/// so order-3 components survive a third of the time.
#[inline]
pub fn is_in_prime_subgroup<P: ark_serialize::Valid>(p: &P) -> bool {
    p.check().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use rand::SeedableRng;

    #[test]
    fn jubjub_x_is_injective_on_prime_subgroup() {
        // The eVRF leans on `S.x` being an (almost) injective extraction.
        // For twisted Edwards with even cofactor, `(x, y)` and `(x, -y)` differ
        // by a 2-torsion point so they cannot both be in the odd-order subgroup.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        for _ in 0..50 {
            let p = (GinProj::generator() * Fs::rand(&mut rng)).into_affine();
            let neg = -p;
            assert_ne!(
                x_coord(&p),
                x_coord(&neg),
                "P and -P must have distinct x on Jubjub"
            );
        }
    }

    #[test]
    fn jubjub_base_field_is_bls_scalar_field() {
        assert_eq!(
            <Fp as PrimeField>::MODULUS,
            <ark_ed_on_bls12_381::Fq as PrimeField>::MODULUS,
        );
    }
}

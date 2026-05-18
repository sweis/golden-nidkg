//! Hash-to-`G_in` (Jubjub) via try-and-increment, with cofactor clearing.
//!
//! In the random-oracle model this is a sound `H : {0,1}* → G_in` (each
//! attempt picks a fresh y-coordinate from a hash; ≈½ are valid; multiply by
//! the cofactor to land in the prime-order subgroup).  This is *not*
//! constant-time — for production a SSWU/Elligator2 map should be used.  The
//! eVRF circuit (zk/evrf_circuit.rs) does *not* re-derive the hash inside the
//! constraint system; `H₁(msg)` and `H₂(msg)` are *public inputs*, so the
//! circuit only does fixed-base scalar multiplication by these public points.

use crate::curves::{Fp, GinAffine, GinProj};
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::{AffineRepr, CurveConfig, CurveGroup};
use ark_ed_on_bls12_381::JubjubConfig;
use ark_ff::{Field, PrimeField};
use sha2::{Digest, Sha512};

/// Hash arbitrary bytes (with a domain separator) to a non-identity point in
/// the Jubjub prime-order subgroup.
pub fn hash_to_gin(domain: &[u8], msg: &[u8]) -> GinAffine {
    let a = JubjubConfig::COEFF_A;
    let d = JubjubConfig::COEFF_D;
    let cofactor = <JubjubConfig as CurveConfig>::COFACTOR; // [8]
    let mut ctr: u32 = 0;
    loop {
        let mut h = Sha512::new();
        h.update(b"golden-nidkg/h2c/v1");
        h.update((domain.len() as u64).to_le_bytes());
        h.update(domain);
        h.update((msg.len() as u64).to_le_bytes());
        h.update(msg);
        h.update(ctr.to_le_bytes());
        let digest = h.finalize();
        let y = Fp::from_le_bytes_mod_order(&digest);
        // x² = (1 - y²) / (a - d·y²)
        let num = Fp::ONE - y.square();
        let den = a - d * y.square();
        if let Some(deninv) = den.inverse() {
            let x2 = num * deninv;
            if let Some(x_root) = x2.sqrt() {
                // Pick the "smaller" root to make the map deterministic.
                let x = canonical_sqrt(x_root);
                let p = GinAffine::new_unchecked(x, y);
                debug_assert!(p.is_on_curve());
                // Clear the cofactor.
                let mut q = GinProj::from(p);
                for _ in 0..cofactor[0].trailing_zeros() {
                    q.double_in_place();
                }
                let q = q.into_affine();
                if !q.is_zero() {
                    return q;
                }
            }
        }
        ctr += 1;
    }
}

/// `H₁` and `H₂` from the eVRF, each evaluated at `(sid, msg)` so different
/// sessions produce independent base points (BUGS.md §5).
pub fn h1(sid: &[u8], msg: &[u8]) -> GinAffine {
    let mut input = Vec::with_capacity(sid.len() + msg.len() + 8);
    input.extend_from_slice(&(sid.len() as u64).to_le_bytes());
    input.extend_from_slice(sid);
    input.extend_from_slice(msg);
    hash_to_gin(b"H1", &input)
}

pub fn h2(sid: &[u8], msg: &[u8]) -> GinAffine {
    let mut input = Vec::with_capacity(sid.len() + msg.len() + 8);
    input.extend_from_slice(&(sid.len() as u64).to_le_bytes());
    input.extend_from_slice(sid);
    input.extend_from_slice(msg);
    hash_to_gin(b"H2", &input)
}

/// Pick the canonical square root: the one whose little-endian repr is
/// lexicographically smaller.
fn canonical_sqrt(r: Fp) -> Fp {
    let neg = -r;
    if r.into_bigint() <= neg.into_bigint() {
        r
    } else {
        neg
    }
}

/// Hash to `F_p` for deriving `β` (the LHL constant) and the Bulletproofs
/// generator vector seeds.
pub fn hash_to_fp(domain: &[u8], msg: &[u8]) -> Fp {
    let mut h = Sha512::new();
    h.update(b"golden-nidkg/h2f/v1");
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain);
    h.update((msg.len() as u64).to_le_bytes());
    h.update(msg);
    Fp::from_le_bytes_mod_order(&h.finalize())
}

/// Hash to `G_out` (BLS12-381 G1) by hashing to `F_p` and multiplying the
/// generator.  Note this is **not** an oblivious hash-to-curve (the discrete
/// log of the output is `hash_to_fp(...)`), so this is only used for deriving
/// public Bulletproofs generators where dlog knowledge is harmless (and even
/// helpful for the simulator); see `zk/generators.rs` for a real "nothing up
/// my sleeve" derivation if dlog hardness is needed.
pub fn hash_to_gout_with_known_dlog(domain: &[u8], msg: &[u8]) -> crate::curves::GoutAffine {
    let s = hash_to_fp(domain, msg);
    crate::curves::gout_mul(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2c_in_subgroup_and_deterministic() {
        let p1 = hash_to_gin(b"test", b"hello");
        let p2 = hash_to_gin(b"test", b"hello");
        assert_eq!(p1, p2);
        assert!(p1.is_on_curve());
        assert!(!p1.is_zero());
        // Different messages → different points
        let p3 = hash_to_gin(b"test", b"world");
        assert_ne!(p1, p3);
        // Different domains → different points
        let p4 = hash_to_gin(b"test2", b"hello");
        assert_ne!(p1, p4);
        // H1 != H2 on the same input
        assert_ne!(h1(b"sid", b"hello"), h2(b"sid", b"hello"));
        // sid binding
        assert_ne!(h1(b"sid1", b"hello"), h1(b"sid2", b"hello"));
    }

    #[test]
    fn h2c_in_prime_subgroup() {
        // After cofactor clearing, scalar-multiplying by the subgroup order
        // gives identity.
        use crate::curves::Fs;
        let p = hash_to_gin(b"test", b"sub");
        let order_minus_one = -Fs::from(1u64);
        let q = (GinProj::from(p) * order_minus_one + GinProj::from(p)).into_affine();
        assert!(q.is_zero());
    }
}

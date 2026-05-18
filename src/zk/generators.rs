//! Nothing-up-my-sleeve Pedersen generator vectors for Bulletproofs.
//!
//! `g` is fixed to `g_out` so that committing to the pad value `r` with zero
//! blinding gives exactly `R = g_out^r`.  `h, B, B_blinding` and the vectors
//! `G[], H[]` are derived by hashing.  All generators are publicly computable
//! and safe for the verifier to recompute.

use crate::curves::{gout_gen, GoutAffine};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use sha2::{Digest, Sha512};

/// Bulletproofs generator set.  `gens_capacity` is the maximum number of
/// multiplication gates the proof can cover (must be a power of two).
#[derive(Clone, Debug)]
pub struct BpGens {
    pub gens_capacity: usize,
    /// Pedersen base for committed scalar values (`= g_out`, see above).
    pub b: GoutAffine,
    /// Pedersen blinding base.
    pub b_blinding: GoutAffine,
    /// Vector of bases `G[0..n]` for `a_L`.
    pub g_vec: Vec<GoutAffine>,
    /// Vector of bases `H[0..n]` for `a_R`.
    pub h_vec: Vec<GoutAffine>,
}

fn hash_to_gout_h2c(label: &[u8], i: u64) -> GoutAffine {
    // Real hash-to-G1 via the WB map (RFC 9380), so the dlog of the result is
    // unknown.  We use arkworks' built-in.
    use ark_ec::hashing::{
        curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
    };
    use ark_ff::field_hashers::DefaultFieldHasher;
    type Hasher = MapToCurveBasedHasher<
        ark_bls12_381::G1Projective,
        DefaultFieldHasher<sha2::Sha256, 128>,
        WBMap<ark_bls12_381::g1::Config>,
    >;
    let dst = b"golden-nidkg/bp-gens/v1";
    let hasher = Hasher::new(dst).expect("hasher init");
    let mut msg = Vec::with_capacity(label.len() + 8);
    msg.extend_from_slice(label);
    msg.extend_from_slice(&i.to_le_bytes());
    hasher.hash(&msg).expect("hash to curve")
}

impl BpGens {
    /// Create generators supporting up to `gens_capacity` multiplication gates.
    pub fn new(gens_capacity: usize) -> Self {
        assert!(
            gens_capacity.is_power_of_two(),
            "gens_capacity must be a power of two"
        );
        // `B = g_out` (so V-commitments with zero blinding are bare `g_out^v`).
        let b = gout_gen();
        let b_blinding = hash_to_gout_h2c(b"B_blinding", 0);
        let gen = |label: &'static [u8]| -> Vec<GoutAffine> {
            #[cfg(feature = "parallel")]
            {
                use rayon::prelude::*;
                (0..gens_capacity as u64)
                    .into_par_iter()
                    .map(|i| hash_to_gout_h2c(label, i))
                    .collect()
            }
            #[cfg(not(feature = "parallel"))]
            {
                (0..gens_capacity as u64)
                    .map(|i| hash_to_gout_h2c(label, i))
                    .collect()
            }
        };
        let g_vec = gen(b"G");
        let h_vec = gen(b"H");
        Self {
            gens_capacity,
            b,
            b_blinding,
            g_vec,
            h_vec,
        }
    }

    /// Slice the first `n` generators.
    pub fn share(&self, n: usize) -> (&[GoutAffine], &[GoutAffine]) {
        assert!(
            n <= self.gens_capacity,
            "requested {} gens, have {}",
            n,
            self.gens_capacity
        );
        (&self.g_vec[..n], &self.h_vec[..n])
    }
}

/// Pedersen commitment generators used outside Bulletproofs (e.g. for
/// blinded-S commitments in the linking proof).
#[derive(Clone, Debug)]
pub struct PedersenGens {
    pub b: GoutAffine,
    pub b_blinding: GoutAffine,
}

impl PedersenGens {
    pub fn new() -> Self {
        Self {
            b: gout_gen(),
            b_blinding: hash_to_gout_h2c(b"B_blinding", 0),
        }
    }
    pub fn commit(&self, value: &crate::curves::Fp, blinding: &crate::curves::Fp) -> GoutAffine {
        use crate::curves::GoutProj;
        (GoutProj::from(self.b) * value + GoutProj::from(self.b_blinding) * blinding).into_affine()
    }
}

impl Default for PedersenGens {
    fn default() -> Self {
        Self::new()
    }
}

/// Cheaper hash-to-G1 for non-security-critical seeds (known dlog OK).
#[allow(dead_code)]
fn hash_to_gout_known_dlog(label: &[u8], i: u64) -> GoutAffine {
    let mut h = Sha512::new();
    h.update(b"golden-nidkg/bp-gens-fast/v1");
    h.update(label);
    h.update(i.to_le_bytes());
    let s = crate::curves::Fp::from_le_bytes_mod_order(&h.finalize());
    crate::curves::gout_mul(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gens_distinct() {
        let g = BpGens::new(4);
        let mut all: Vec<GoutAffine> = Vec::new();
        all.push(g.b);
        all.push(g.b_blinding);
        all.extend(&g.g_vec);
        all.extend(&g.h_vec);
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "generators {i} and {j} collide");
            }
        }
    }
}

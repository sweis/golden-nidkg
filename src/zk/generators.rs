//! Nothing-up-my-sleeve Pedersen generator vectors for Bulletproofs.
//!
//! `g` is fixed to `g_out` so that committing to the pad value `r` with zero
//! blinding gives exactly `R = g_out^r`.  `h, B, B_blinding` and the vectors
//! `G[], H[]` are derived by hashing.  All generators are publicly computable
//! and safe for the verifier to recompute.

use crate::curves::{gout_gen, GoutAffine};
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
};
use ark_ff::field_hashers::DefaultFieldHasher;

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

/// RFC 9380 hash-to-G1 (WB map) so the discrete log of the result is unknown.
type Hasher = MapToCurveBasedHasher<
    ark_bls12_381::G1Projective,
    DefaultFieldHasher<sha2::Sha256, 128>,
    WBMap<ark_bls12_381::g1::Config>,
>;
const H2C_DST: &[u8] = b"golden-nidkg/bp-gens/v1";

fn hash_to_gout_h2c(hasher: &Hasher, label: &[u8], i: u64) -> GoutAffine {
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
        let hasher = Hasher::new(H2C_DST).expect("hasher init");
        let b_blinding = hash_to_gout_h2c(&hasher, b"B_blinding", 0);
        // Build `G[]`, `H[]`.  `Hasher` is `Send + !Sync`, so the parallel path
        // constructs one hasher per chunk via `map_init` (cheap relative to
        // the hash work).
        let gen = |label: &'static [u8]| -> Vec<GoutAffine> {
            #[cfg(feature = "parallel")]
            {
                use rayon::prelude::*;
                (0..gens_capacity as u64)
                    .into_par_iter()
                    .map_init(
                        || Hasher::new(H2C_DST).expect("hasher init"),
                        |h, i| hash_to_gout_h2c(h, label, i),
                    )
                    .collect()
            }
            #[cfg(not(feature = "parallel"))]
            {
                (0..gens_capacity as u64)
                    .map(|i| hash_to_gout_h2c(&hasher, label, i))
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

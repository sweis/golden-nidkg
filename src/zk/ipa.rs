//! Logarithmic-size inner-product argument (Bulletproofs §3, BCC+16).
//!
//! Proves knowledge of vectors `a, b ∈ F_p^n` such that
//! `P = G^a · H^b · Q^{<a,b>}` for public bases `G, H ∈ G_out^n`, `Q ∈ G_out`,
//! with proof size `2 log₂ n` group elements + 2 scalars.
//!
//! Following the dalek `bulletproofs` notation (we recurse from `a, b` of
//! length `n` to `a', b'` of length `n/2`, sending `L` and `R`).

use crate::curves::{Fp, GoutAffine, GoutProj};
use crate::transcript::TranscriptExt;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{Field, Zero, One};
use merlin::Transcript;

#[derive(Clone, Debug)]
pub struct InnerProductProof {
    pub l_vec: Vec<GoutAffine>,
    pub r_vec: Vec<GoutAffine>,
    pub a: Fp,
    pub b: Fp,
}

/// Multi-scalar multiplication helper.
fn msm(bases: &[GoutAffine], scalars: &[Fp]) -> GoutProj {
    GoutProj::msm(bases, scalars).expect("msm")
}

impl InnerProductProof {
    /// Create an IPA for `<a,b>` with bases `G, H` (each of length a power of
    /// two), Q, and `H_factors` to fold a per-element scaling of `H`
    /// (Bulletproofs uses `y^{-i}` scaling in the R1CS reduction).
    ///
    /// `g_factors` is similarly applied to `G` (used for the `u` deferral in
    /// some optimisations; pass all ones if not needed).
    pub fn create(
        transcript: &mut Transcript,
        q: &GoutAffine,
        g_factors: &[Fp],
        h_factors: &[Fp],
        g_vec: &[GoutAffine],
        h_vec: &[GoutAffine],
        a_vec: &[Fp],
        b_vec: &[Fp],
    ) -> InnerProductProof {
        let n = a_vec.len();
        assert!(n.is_power_of_two() && n >= 1);
        assert_eq!(b_vec.len(), n);
        assert_eq!(g_vec.len(), n);
        assert_eq!(h_vec.len(), n);
        assert_eq!(g_factors.len(), n);
        assert_eq!(h_factors.len(), n);

        // Apply factors to bases up front (this folds `y^{-i}` into `H_i`).
        let mut g: Vec<GoutProj> = g_vec
            .iter()
            .zip(g_factors)
            .map(|(p, s)| GoutProj::from(*p) * s)
            .collect();
        let mut h: Vec<GoutProj> = h_vec
            .iter()
            .zip(h_factors)
            .map(|(p, s)| GoutProj::from(*p) * s)
            .collect();
        let mut a = a_vec.to_vec();
        let mut b = b_vec.to_vec();
        let q_proj = GoutProj::from(*q);

        let lg_n = n.trailing_zeros() as usize;
        let mut l_vec = Vec::with_capacity(lg_n);
        let mut r_vec = Vec::with_capacity(lg_n);

        let mut len = n;
        while len > 1 {
            let half = len / 2;
            let (a_lo, a_hi) = a.split_at(half);
            let (b_lo, b_hi) = b.split_at(half);
            let (g_lo, g_hi) = g.split_at(half);
            let (h_lo, h_hi) = h.split_at(half);

            let c_l = inner_product(a_lo, b_hi);
            let c_r = inner_product(a_hi, b_lo);

            // L = G_hi^{a_lo} · H_lo^{b_hi} · Q^{c_l}
            let g_hi_aff = GoutProj::normalize_batch(g_hi);
            let h_lo_aff = GoutProj::normalize_batch(h_lo);
            let l = (msm(&g_hi_aff, a_lo) + msm(&h_lo_aff, b_hi) + q_proj * c_l).into_affine();
            // R = G_lo^{a_hi} · H_hi^{b_lo} · Q^{c_r}
            let g_lo_aff = GoutProj::normalize_batch(g_lo);
            let h_hi_aff = GoutProj::normalize_batch(h_hi);
            let r = (msm(&g_lo_aff, a_hi) + msm(&h_hi_aff, b_lo) + q_proj * c_r).into_affine();

            transcript.append_gout(b"L", &l);
            transcript.append_gout(b"R", &r);
            l_vec.push(l);
            r_vec.push(r);
            let u = transcript.challenge_fp(b"u");
            let u_inv = u.inverse().unwrap();

            // Fold.
            let mut a_new = Vec::with_capacity(half);
            let mut b_new = Vec::with_capacity(half);
            let mut g_new = Vec::with_capacity(half);
            let mut h_new = Vec::with_capacity(half);
            for i in 0..half {
                a_new.push(a_lo[i] * u + a_hi[i] * u_inv);
                b_new.push(b_lo[i] * u_inv + b_hi[i] * u);
                g_new.push(g_lo[i] * u_inv + g_hi[i] * u);
                h_new.push(h_lo[i] * u + h_hi[i] * u_inv);
            }
            a = a_new;
            b = b_new;
            g = g_new;
            h = h_new;
            len = half;
        }
        InnerProductProof { l_vec, r_vec, a: a[0], b: b[0] }
    }

    /// Compute the verification scalars `(u_i², u_i^{-2}, s_j)` for a proof
    /// with `n = 2^k` length.  `s_j = ∏ u_{b(j,i)}^{±1}` is the product of
    /// challenge factors for index `j`.
    pub fn verification_scalars(
        &self,
        n: usize,
        transcript: &mut Transcript,
    ) -> Result<(Vec<Fp>, Vec<Fp>, Vec<Fp>), String> {
        let lg_n = self.l_vec.len();
        if lg_n >= 64 || n != (1usize << lg_n) {
            return Err(format!("IPA length mismatch: {} L/R vs n={}", lg_n, n));
        }
        let mut u = Vec::with_capacity(lg_n);
        for i in 0..lg_n {
            transcript.append_gout(b"L", &self.l_vec[i]);
            transcript.append_gout(b"R", &self.r_vec[i]);
            u.push(transcript.challenge_fp(b"u"));
        }
        let mut u_inv = u.clone();
        ark_ff::batch_inversion(&mut u_inv);
        let u_sq: Vec<Fp> = u.iter().map(|x| x.square()).collect();
        let u_inv_sq: Vec<Fp> = u_inv.iter().map(|x| x.square()).collect();
        // s_0 = ∏ u_i^{-1}; s_j for j>0 by flipping bits.
        let mut s = Vec::with_capacity(n);
        let s0: Fp = u_inv.iter().product();
        s.push(s0);
        for j in 1..n {
            let lg_i = (32 - 1 - (j as u32).leading_zeros()) as usize;
            let k = 1usize << lg_i;
            // The bit `lg_i` flipped from 0 to 1 ⇒ multiply by u_{lg_n - 1 - lg_i}².
            let u_lg_i_sq = u_sq[(lg_n - 1) - lg_i];
            s.push(s[j - k] * u_lg_i_sq);
        }
        Ok((u_sq, u_inv_sq, s))
    }

    /// Verify `P == G^a · H^b · Q^c` given a folded `P` reconstructed by the
    /// caller (Bulletproofs R1CS does this inline via a single MSM).
    /// Provided for unit testing the IPA in isolation.
    pub fn verify(
        &self,
        n: usize,
        transcript: &mut Transcript,
        g_factors: &[Fp],
        h_factors: &[Fp],
        p: &GoutAffine,
        q: &GoutAffine,
        g_vec: &[GoutAffine],
        h_vec: &[GoutAffine],
    ) -> Result<(), String> {
        let (u_sq, u_inv_sq, s) = self.verification_scalars(n, transcript)?;
        let mut s_inv = s.clone();
        s_inv.reverse(); // s_inv[i] = 1/s[i] — by symmetry of the s vector

        // Expected = ∑ a*s_i*g_factor_i G_i + ∑ b*s_inv_i*h_factor_i H_i + a*b Q
        //            - ∑ u_sq_i L_i - ∑ u_inv_sq_i R_i
        let g_scalars: Vec<Fp> = s
            .iter()
            .zip(g_factors)
            .map(|(si, gf)| self.a * si * gf)
            .collect();
        let h_scalars: Vec<Fp> = s_inv
            .iter()
            .zip(h_factors)
            .map(|(si, hf)| self.b * si * hf)
            .collect();
        let neg_u_sq: Vec<Fp> = u_sq.iter().map(|u| -*u).collect();
        let neg_u_inv_sq: Vec<Fp> = u_inv_sq.iter().map(|u| -*u).collect();

        let mut bases: Vec<GoutAffine> = Vec::with_capacity(2 * n + 2 * self.l_vec.len() + 1);
        let mut scalars: Vec<Fp> = Vec::with_capacity(2 * n + 2 * self.l_vec.len() + 1);
        bases.extend(g_vec);
        scalars.extend(g_scalars);
        bases.extend(h_vec);
        scalars.extend(h_scalars);
        bases.push(*q);
        scalars.push(self.a * self.b);
        bases.extend(&self.l_vec);
        scalars.extend(neg_u_sq);
        bases.extend(&self.r_vec);
        scalars.extend(neg_u_inv_sq);

        let expected = msm(&bases, &scalars).into_affine();
        if expected == *p {
            Ok(())
        } else {
            Err("IPA verification failed".into())
        }
    }
}

pub fn inner_product(a: &[Fp], b: &[Fp]) -> Fp {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(x, y)| *x * y).sum()
}

/// Vandermonde powers `1, x, x², …, x^{n-1}`.
pub fn powers(x: Fp, n: usize) -> Vec<Fp> {
    let mut out = Vec::with_capacity(n);
    let mut acc = Fp::one();
    for _ in 0..n {
        out.push(acc);
        acc *= x;
    }
    out
}

/// `∑_{i=0}^{n-1} x^i = (x^n - 1) / (x - 1)`.
pub fn sum_of_powers(x: Fp, n: usize) -> Fp {
    if x.is_one() {
        return Fp::from(n as u64);
    }
    if n == 0 {
        return Fp::zero();
    }
    (x.pow([n as u64]) - Fp::one()) * (x - Fp::one()).inverse().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::generators::BpGens;
    use ark_std::UniformRand;

    #[test]
    fn ipa_roundtrip() {
        let mut rng = ark_std::test_rng();
        let n = 8;
        let gens = BpGens::new(n);
        let q = gens.b_blinding; // any unrelated generator
        let a: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
        let b: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
        let c = inner_product(&a, &b);
        let ones = vec![Fp::one(); n];
        // P = G^a H^b Q^c
        let mut bases: Vec<GoutAffine> = gens.g_vec.clone();
        bases.extend(&gens.h_vec);
        bases.push(q);
        let mut scalars: Vec<Fp> = a.clone();
        scalars.extend(&b);
        scalars.push(c);
        let p = msm(&bases, &scalars).into_affine();

        let mut t1 = Transcript::new(b"ipa-test");
        let proof = InnerProductProof::create(&mut t1, &q, &ones, &ones, &gens.g_vec, &gens.h_vec, &a, &b);
        let mut t2 = Transcript::new(b"ipa-test");
        proof
            .verify(n, &mut t2, &ones, &ones, &p, &q, &gens.g_vec, &gens.h_vec)
            .unwrap();
        // Tampered P fails.
        let mut t3 = Transcript::new(b"ipa-test");
        let bad_p = (GoutProj::from(p) + GoutProj::from(q)).into_affine();
        assert!(proof.verify(n, &mut t3, &ones, &ones, &bad_p, &q, &gens.g_vec, &gens.h_vec).is_err());
    }

    #[test]
    fn ipa_with_factors() {
        let mut rng = ark_std::test_rng();
        let n = 4;
        let gens = BpGens::new(n);
        let q = gens.b_blinding;
        let a: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
        let b: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
        let h_factors: Vec<Fp> = (0..n).map(|_| Fp::rand(&mut rng)).collect();
        let ones = vec![Fp::one(); n];
        let c = inner_product(&a, &b);
        // P uses H' = H_i^{h_factor_i}
        let h_prime: Vec<GoutAffine> = gens
            .h_vec
            .iter()
            .zip(&h_factors)
            .map(|(p, s)| (GoutProj::from(*p) * s).into_affine())
            .collect();
        let mut bases: Vec<GoutAffine> = gens.g_vec.clone();
        bases.extend(&h_prime);
        bases.push(q);
        let mut scalars: Vec<Fp> = a.clone();
        scalars.extend(&b);
        scalars.push(c);
        let p = msm(&bases, &scalars).into_affine();

        let mut t1 = Transcript::new(b"ipa-test2");
        let proof = InnerProductProof::create(&mut t1, &q, &ones, &h_factors, &gens.g_vec, &gens.h_vec, &a, &b);
        let mut t2 = Transcript::new(b"ipa-test2");
        proof
            .verify(n, &mut t2, &ones, &h_factors, &p, &q, &gens.g_vec, &gens.h_vec)
            .unwrap();
    }
}

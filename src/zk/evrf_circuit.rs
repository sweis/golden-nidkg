//! The `R_eVRF` circuit (Figure 3 of the paper).
//!
//! Proves knowledge of `sk` such that, with `(PK_1, PK_2, H_1, H_2, β, R)`
//! public:
//!
//! ```text
//!   0.  PK_1 = g_in^{sk}
//!   1.  S    = PK_2^{sk}
//!   2-3. k   = int(S.x)
//!   4.  T_1  = H_1^k
//!   5.  T_2  = H_2^k
//!   6-7. r_1 = int(T_1.x), r_2 = int(T_2.x)
//!   8.  r    = β·r_1 + r_2  (mod p)
//!   9.  R    = g_out^r           ← *not* in-circuit; bound via Pedersen V-commit.
//! ```
//!
//! `r` is the only "high-level" committed value `v[0]`, with `V[0] = R = g_out^r`
//! (zero blinding).  All curve work is over Jubjub, native in `F_p`.
//!
//! Step 0 (`PK_1 = g_in^{sk}`) is proven with the *same* bit decomposition of
//! `sk` used for step 1, so a malicious prover cannot use one `sk` for the
//! DH step and another for the PKI key.  Steps 4–5 share the bit decomposition
//! of `k`.

use crate::curves::{gin_gen, Fp, GinAffine};
use crate::evrf::{EvrfPublicInputs, EvrfWitness};
use crate::zk::gadgets::{
    assert_eq_point, bit_decompose_canonical, fs_to_bits_le, scalar_mul_const, ScalarVar,
};
use crate::zk::r1cs::{ConstraintSystem, LinearCombination, Variable};
use ark_ff::Field;

/// Bit width used for `sk` and `k` decompositions.  `255` covers the full
/// `F_p` range; smaller values are used in tests for speed (with reduced
/// soundness against large witnesses).
pub const DEFAULT_LAMBDA: usize = 255;

/// Public inputs for one *recipient* in a batched proof.
#[derive(Clone, Debug)]
pub struct EvrfPeerInputs {
    pub pk2: GinAffine,
    pub r_commit: crate::curves::GoutAffine,
}

/// Build the `R_eVRF` circuit on a `ConstraintSystem`.
///
/// `r_var` is the `Variable` allocated for the committed pad value `r`
/// (returned by `Prover::commit(r, 0)` / `Verifier::commit(R)`).
///
/// `pubs` carries all the public points; `wit` is `Some` for the prover.
pub fn build_circuit<CS: ConstraintSystem>(
    cs: &mut CS,
    pubs: &EvrfPublicInputs,
    r_var: Variable,
    wit: Option<&EvrfWitness>,
    lambda: usize,
) {
    let sk_bits = build_shared_sk(cs, &pubs.pk1, wit.map(|w| &w.sk), lambda);
    build_per_peer(
        cs, &sk_bits, &pubs.pk2, &pubs.h1m, &pubs.h2m, pubs.beta, r_var, wit, lambda,
    );
}

/// Build the *batched* `R_eVRF` circuit (Section 5.3): one proof covering
/// `n-1` recipients.  The dealer's `sk` bit decomposition and `g_in^{sk}`
/// gadget are shared.
///
/// `peers` and `r_vars` and `wits` (if `Some`) must be the same length and
/// in the same order.
pub fn build_batch_circuit<CS: ConstraintSystem>(
    cs: &mut CS,
    pk1: &GinAffine,
    h1m: &GinAffine,
    h2m: &GinAffine,
    beta: Fp,
    peers: &[EvrfPeerInputs],
    r_vars: &[Variable],
    wits: Option<&[EvrfWitness]>,
    lambda: usize,
) {
    debug_assert_eq!(peers.len(), r_vars.len());
    debug_assert!(wits.is_none_or(|w| w.len() == peers.len()));
    let sk_bits = build_shared_sk(cs, pk1, wits.and_then(|w| w.first()).map(|w| &w.sk), lambda);
    for (i, peer) in peers.iter().enumerate() {
        build_per_peer(
            cs,
            &sk_bits,
            &peer.pk2,
            h1m,
            h2m,
            beta,
            r_vars[i],
            wits.map(|w| &w[i]),
            lambda,
        );
    }
}

/// Shared part: allocate `sk`'s bits and constrain `PK_1 = g_in^{sk}`.
fn build_shared_sk<CS: ConstraintSystem>(
    cs: &mut CS,
    pk1: &GinAffine,
    sk_w: Option<&crate::curves::Fs>,
    lambda: usize,
) -> Vec<ScalarVar> {
    let sk_bits = alloc_bits(cs, sk_w.map(|sk| fs_to_bits_le(sk, lambda)), lambda);
    let pk1_circuit = scalar_mul_const(cs, &sk_bits, &gin_gen());
    assert_eq_point(cs, &pk1_circuit, pk1);
    sk_bits
}

/// Per-peer part: `S = PK_2^{sk}`, `k = S.x`, `T_1 = H_1^k`, `T_2 = H_2^k`,
/// `r = β·T_1.x + T_2.x` constrained to the committed `r_var`.
fn build_per_peer<CS: ConstraintSystem>(
    cs: &mut CS,
    sk_bits: &[ScalarVar],
    pk2: &GinAffine,
    h1m: &GinAffine,
    h2m: &GinAffine,
    beta: Fp,
    r_var: Variable,
    wit: Option<&EvrfWitness>,
    lambda: usize,
) {
    // S = PK_2^{sk}.  PK_2 is a public point so this is constant-base.
    let s = scalar_mul_const(cs, sk_bits, pk2);
    debug_assert!(wit.is_none() || s.w.unwrap() == wit.unwrap().s);
    // k = int(S.x) and decompose into bits.  Must be the *canonical*
    // decomposition (sum < p), or a malicious prover can use `k + p` and
    // derive a different pad — see BUGS.md §10.
    let k_bits = bit_decompose_canonical(cs, &s.x, lambda);
    // T_1 = H_1^k, T_2 = H_2^k.
    let t1 = scalar_mul_const(cs, &k_bits, h1m);
    let t2 = scalar_mul_const(cs, &k_bits, h2m);
    debug_assert!(wit.is_none() || t1.w.unwrap() == wit.unwrap().t1);
    debug_assert!(wit.is_none() || t2.w.unwrap() == wit.unwrap().t2);
    // r = β·r_1 + r_2.
    let r_lc = t1.x.lc * beta + t2.x.lc;
    cs.constrain(r_lc - r_var);
}

/// Allocate a vector of boolean witness bits.
fn alloc_bits<CS: ConstraintSystem>(
    cs: &mut CS,
    bits_w: Option<Vec<bool>>,
    n: usize,
) -> Vec<ScalarVar> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let bw = bits_w.as_ref().map(|b| b[i]);
        let assignment = bw.map(|b| {
            let bf = Fp::from(b as u64);
            (bf, Fp::ONE - bf)
        });
        let (vl, vr, vo) = cs.allocate_multiplier(assignment).unwrap();
        cs.constrain(LinearCombination::from(vl) + vr - Fp::ONE);
        cs.constrain(LinearCombination::from(vo));
        out.push(ScalarVar {
            lc: LinearCombination::from(vl),
            w: bw.map(|b| Fp::from(b as u64)),
        });
    }
    out
}

/// Compute the next-power-of-two number of multiplication gates for the
/// `R_eVRF` circuit at a given `lambda`, so callers can size `BpGens`.
pub fn gens_capacity(lambda: usize) -> usize {
    batch_gens_capacity(lambda, 1)
}

/// Compute the gens capacity for a *batched* circuit covering `peers`
/// recipients.
pub fn batch_gens_capacity(lambda: usize, peers: usize) -> usize {
    // Per gadget cost (see gadgets.rs cost summary).  `scalar_mul_const`
    // uses 3-bit windows (≈10 muls per 3-bit chunk + ε).
    let chunks = lambda.div_ceil(crate::zk::gadgets::WINDOW);
    let scalar_mul = 10 * chunks + 4;
    // shared:   alloc_bits(λ) + scalar_mul(g_in^sk)
    // per peer: scalar_mul(S) + bit_decompose_canonical(k, λ) ≈ 2λ + 3×scalar_mul + ε
    let approx = (lambda + scalar_mul) + peers * (3 * scalar_mul + 2 * lambda + 4);
    approx.next_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curves::{gin_mul, Fs};
    use crate::evrf::{eval_pad, public_inputs, Beta, SessionId};
    use crate::zk::bp_r1cs::{Prover, Verifier};
    use crate::zk::generators::BpGens;
    use ark_ec::CurveGroup;
    use ark_ff::Zero;
    use ark_std::UniformRand;
    use merlin::Transcript;
    use rand::SeedableRng;

    /// Tests that the circuit *shape* matches between prover and verifier and
    /// produces a valid proof when the witness is internally consistent.
    /// Run with `cargo test --release -- evrf_circuit_shape` to get the
    /// optimised build (≈4 s on 4 cores).
    #[test]
    fn evrf_circuit_shape_and_proof_lambda_full() {
        let lambda = DEFAULT_LAMBDA;
        let cap = gens_capacity(lambda);
        let gens = BpGens::new(cap);
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);

        let sk1 = Fs::rand(&mut rng);
        let pk1 = gin_mul(&sk1);
        let sk2 = Fs::rand(&mut rng);
        let pk2 = gin_mul(&sk2);
        let sid = SessionId([7u8; 32]);
        let beta = Beta::from_seed(b"test");
        let msg = b"hello world";
        let (out, wit) = eval_pad(&sk1, &pk2, &sid, msg, &beta);
        let pubs = public_inputs(&pk1, &pk2, &sid, msg, &beta, &out.r_commit);

        // Prove.
        let mut prover = Prover::new(&gens, Transcript::new(b"evrf-test"));
        let (r_commit, r_var) = prover.commit(wit.r, Fp::zero());
        assert_eq!(r_commit, out.r_commit);
        build_circuit(&mut prover, &pubs, r_var, Some(&wit), lambda);
        let n_mul = prover.num_multipliers();
        eprintln!(
            "circuit size: {n_mul} mul gates, padded to {}",
            n_mul.next_power_of_two()
        );
        let proof = prover.prove(&mut rng).unwrap();

        // Verify.
        let mut verifier = Verifier::new(&gens, Transcript::new(b"evrf-test"));
        let r_var = verifier.commit(out.r_commit);
        build_circuit(&mut verifier, &pubs, r_var, None, lambda);
        verifier.verify(&proof).unwrap();

        // Tamper with R and ensure verification fails.
        let tampered =
            (crate::curves::GoutProj::from(out.r_commit) + crate::curves::gout_gen()).into_affine();
        let mut verifier = Verifier::new(&gens, Transcript::new(b"evrf-test"));
        let r_var = verifier.commit(tampered);
        build_circuit(&mut verifier, &pubs, r_var, None, lambda);
        assert!(verifier.verify(&proof).is_err());
    }
}

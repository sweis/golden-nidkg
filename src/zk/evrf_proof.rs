//! Public API for the `R_eVRF` zero-knowledge proof.
//!
//! Wraps the Bulletproofs R1CS prover/verifier and the eVRF circuit.  The
//! pad commitment `R = g_out^r` is bound via a high-level Pedersen commitment
//! with zero blinding (the linking trick).
//!
//! ## Soundness mode
//!
//! The full circuit decomposes `sk` and `k` into 255 bits and performs four
//! Jubjub scalar multiplications.  At ~22·255 ≈ 5600 multiplication gates,
//! the prover is on the order of a second on a laptop.  For a quick smoke-test
//! of the *protocol* without exercising the full ZK proof, set
//! `ZkParams::insecure_quick()` which keeps the linking commitment `R = g_out^r`
//! and replaces the rest of the circuit with a Schnorr proof of knowledge of
//! `r` (no eVRF correctness — only that the dealer knows the pad).
//! `insecure_quick()` is **not publicly verifiable** and must never be used
//! outside tests/demos.

use crate::curves::{gout_mul, Fp, GoutAffine, GoutProj};
use crate::errors::{GoldenError, GoldenResult};
use crate::evrf::{EvrfPublicInputs, EvrfWitness, SessionId};
use crate::transcript::TranscriptExt;
use crate::zk::bp_r1cs::{Prover, R1CSProof, Verifier};
use crate::zk::evrf_circuit::{build_circuit, default_lambda, gens_capacity};
use crate::zk::generators::BpGens;
use ark_ec::CurveGroup;
use ark_ff::Zero;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use merlin::Transcript;
use std::sync::Arc;

/// CRS / public parameters for the eVRF proof system.
#[derive(Clone)]
pub struct ZkParams {
    pub mode: ZkMode,
    pub gens: Arc<BpGens>,
    pub lambda: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkMode {
    /// Full Bulletproofs R1CS proof of `R_eVRF`.  Publicly verifiable.
    Full,
    /// Schnorr proof of knowledge of `r` such that `R = g_out^r`, plus an
    /// honest-prover stub for the rest.  **Not publicly verifiable** — only
    /// use for fast iteration in tests/demos.
    InsecureQuick,
}

impl ZkParams {
    /// Set up the full proof system.  The first call hashes ~`16k` curve
    /// points — call once and reuse.
    pub fn full() -> Self {
        let lambda = default_lambda();
        let cap = gens_capacity(lambda);
        Self {
            mode: ZkMode::Full,
            gens: Arc::new(BpGens::new(cap)),
            lambda,
        }
    }
    /// A reduced-`λ` setup for fast tests.  Still a real Bulletproofs proof,
    /// but the bit decompositions are shorter so a malicious prover with a
    /// large `sk` could lie.  Use only when the test fixes `sk` to be small.
    pub fn small_lambda(lambda: usize) -> Self {
        let cap = gens_capacity(lambda);
        Self {
            mode: ZkMode::Full,
            gens: Arc::new(BpGens::new(cap)),
            lambda,
        }
    }
    /// Schnorr-only mode for protocol smoke-tests.
    pub fn insecure_quick() -> Self {
        Self {
            mode: ZkMode::InsecureQuick,
            gens: Arc::new(BpGens::new(1)),
            lambda: 0,
        }
    }
}

/// The proof object carried in a [`crate::dkg::Dealing`].
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)] // `Full` carries ≈40 group elements; the box would only obscure things.
pub enum EvrfProof {
    Full(R1CSProof),
    InsecureQuick(SchnorrR),
}

/// Schnorr PoK of `r` for `R = g_out^r`, used by the `InsecureQuick` stub.
#[derive(Clone, Debug)]
pub struct SchnorrR {
    pub commitment: GoutAffine,
    pub response: Fp,
}

/// Build a fresh transcript bound to all the public inputs.
fn evrf_transcript(sid: &SessionId, pubs: &EvrfPublicInputs) -> Transcript {
    let mut t = Transcript::new(b"golden-nidkg/evrf-proof/v1");
    t.append_bytes(b"sid", &sid.0);
    t.append_gin(b"PK1", &pubs.pk1);
    t.append_gin(b"PK2", &pubs.pk2);
    t.append_gin(b"H1m", &pubs.h1m);
    t.append_gin(b"H2m", &pubs.h2m);
    t.append_fp(b"beta", &pubs.beta);
    t.append_gout(b"R", &pubs.r_commit);
    t
}

/// Generate a proof for the `R_eVRF` relation.
pub fn prove_evrf(
    params: &ZkParams,
    sid: &SessionId,
    pubs: &EvrfPublicInputs,
    wit: &EvrfWitness,
    rng: &mut impl Rng,
) -> GoldenResult<EvrfProof> {
    debug_assert_eq!(
        gout_mul(&wit.r),
        pubs.r_commit,
        "witness/commitment mismatch"
    );
    match params.mode {
        ZkMode::InsecureQuick => {
            let mut t = evrf_transcript(sid, pubs);
            let k = Fp::rand(rng);
            let commitment = gout_mul(&k);
            t.append_gout(b"commit", &commitment);
            let c = t.challenge_fp(b"c");
            let response = k + c * wit.r;
            Ok(EvrfProof::InsecureQuick(SchnorrR {
                commitment,
                response,
            }))
        }
        ZkMode::Full => {
            let t = evrf_transcript(sid, pubs);
            let mut prover = Prover::new(&params.gens, t);
            let (r_commit, r_var) = prover.commit(wit.r, Fp::zero());
            if r_commit != pubs.r_commit {
                return Err(GoldenError::Proof("R commitment mismatch".into()));
            }
            build_circuit(&mut prover, pubs, r_var, Some(wit), params.lambda);
            prover
                .prove(rng)
                .map(EvrfProof::Full)
                .map_err(GoldenError::Proof)
        }
    }
}

/// Verify a proof for the `R_eVRF` relation.
pub fn verify_evrf(
    params: &ZkParams,
    sid: &SessionId,
    pubs: &EvrfPublicInputs,
    proof: &EvrfProof,
) -> GoldenResult<()> {
    match (params.mode, proof) {
        (ZkMode::InsecureQuick, EvrfProof::InsecureQuick(p)) => {
            let mut t = evrf_transcript(sid, pubs);
            t.append_gout(b"commit", &p.commitment);
            let c = t.challenge_fp(b"c");
            // g^response == commit · R^c
            let lhs = gout_mul(&p.response);
            let rhs =
                (GoutProj::from(p.commitment) + GoutProj::from(pubs.r_commit) * c).into_affine();
            if lhs == rhs {
                Ok(())
            } else {
                Err(GoldenError::Proof(
                    "InsecureQuick Schnorr verification failed".into(),
                ))
            }
        }
        (ZkMode::Full, EvrfProof::Full(p)) => {
            let t = evrf_transcript(sid, pubs);
            let mut verifier = Verifier::new(&params.gens, t);
            let r_var = verifier.commit(pubs.r_commit);
            build_circuit(&mut verifier, pubs, r_var, None, params.lambda);
            verifier.verify(p).map_err(GoldenError::Proof)
        }
        _ => Err(GoldenError::Proof("proof/params mode mismatch".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curves::{gin_mul, Fs};
    use crate::evrf::{eval_pad, public_inputs, Beta, SessionId};
    use ark_std::UniformRand;

    fn setup() -> (EvrfPublicInputs, EvrfWitness, SessionId) {
        let mut rng = ark_std::test_rng();
        let sk1 = Fs::rand(&mut rng);
        let pk1 = gin_mul(&sk1);
        let sk2 = Fs::rand(&mut rng);
        let pk2 = gin_mul(&sk2);
        let sid = SessionId([3u8; 32]);
        let beta = Beta::from_seed(b"test");
        let msg = b"msg";
        let (out, wit) = eval_pad(&sk1, &pk2, &sid, msg, &beta);
        (
            public_inputs(&pk1, &pk2, &sid, msg, &beta, &out.r_commit),
            wit,
            sid,
        )
    }

    #[test]
    fn quick_proof_roundtrip() {
        let mut rng = ark_std::test_rng();
        let (pubs, wit, sid) = setup();
        let params = ZkParams::insecure_quick();
        let proof = prove_evrf(&params, &sid, &pubs, &wit, &mut rng).unwrap();
        verify_evrf(&params, &sid, &pubs, &proof).unwrap();
        // Tamper R.
        let mut bad = pubs.clone();
        bad.r_commit = (GoutProj::from(bad.r_commit) + crate::curves::gout_gen()).into_affine();
        assert!(verify_evrf(&params, &sid, &bad, &proof).is_err());
        // Wrong sid.
        assert!(verify_evrf(&params, &SessionId([4u8; 32]), &pubs, &proof).is_err());
    }
}

//! Public API for the `R_eVRF` zero-knowledge proof.
//!
//! Wraps the Bulletproofs R1CS prover/verifier and the eVRF circuit.  The
//! pad commitments `R_j = g_out^{r_j}` are bound via high-level Pedersen
//! commitments with zero blinding (the linking trick).
//!
//! The proof is *batched* (Section 5.3): one Bulletproofs proof per dealer
//! covers all `n-1` recipients, sharing the dealer's `sk` bit decomposition
//! and `g_in^{sk}` gadget.  Verification likewise verifies all `n-1`
//! relations with one MSM.
//!
//! ## Soundness modes
//!
//! * `ZkMode::Full` — the real Bulletproofs proof.  Publicly verifiable.
//! * `ZkMode::InsecureQuick` — replaces the proof with a Schnorr PoK of each
//!   `r_j` for `R_j = g_out^{r_j}`.  Proves only that the dealer *knows* the
//!   pads, not that they were derived from the DH secret.  **Not publicly
//!   verifiable**; only useful for fast tests of the protocol logic.

use crate::curves::{gout_mul, Fp, GinAffine, GoutAffine, GoutProj};
use crate::errors::{GoldenError, GoldenResult};
use crate::evrf::{EvrfWitness, SessionId};
use crate::transcript::TranscriptExt;
use crate::zk::bp_r1cs::{verify_batch, Prover, R1CSProof, VerificationCheck, Verifier};
use crate::zk::evrf_circuit::{
    batch_gens_capacity, build_batch_circuit, EvrfPeerInputs, DEFAULT_LAMBDA,
};
use crate::zk::generators::BpGens;
use ark_ec::CurveGroup;
use ark_ff::Zero;
use ark_std::rand::{CryptoRng, Rng};
use ark_std::UniformRand;
use merlin::Transcript;
use std::sync::Arc;

/// CRS / public parameters for the eVRF proof system.
#[derive(Clone)]
pub struct ZkParams {
    pub mode: ZkMode,
    pub gens: Arc<BpGens>,
    pub lambda: usize,
    /// The maximum number of recipients a single dealer may have to prove for.
    /// `BpGens` are sized for `batch_gens_capacity(lambda, max_peers)`.
    pub max_peers: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkMode {
    /// Full Bulletproofs R1CS proof of `R_eVRF`.  Publicly verifiable.
    Full,
    /// Schnorr proof of knowledge of `r_j`.  **Not publicly verifiable** —
    /// only use for fast iteration in tests/demos.
    InsecureQuick,
}

impl ZkParams {
    /// Set up the full proof system, sized for up to `max_peers` recipients
    /// per dealing (i.e. `n-1`).  The first call hashes
    /// `2·batch_gens_capacity(255, max_peers)` curve points — for `max_peers
    /// = 4` that is ~32k points (~10 s); call once and reuse.
    pub fn full(max_peers: usize) -> Self {
        Self::with_lambda(DEFAULT_LAMBDA, max_peers)
    }
    /// `full()` with a custom `lambda` (bit decomposition width).  Use 255
    /// for production; smaller for tests with bounded witnesses.
    pub fn with_lambda(lambda: usize, max_peers: usize) -> Self {
        let cap = batch_gens_capacity(lambda, max_peers.max(1));
        Self {
            mode: ZkMode::Full,
            gens: Arc::new(BpGens::new(cap)),
            lambda,
            max_peers: max_peers.max(1),
        }
    }
    /// Schnorr-only mode for protocol smoke-tests.
    pub fn insecure_quick() -> Self {
        Self {
            mode: ZkMode::InsecureQuick,
            gens: Arc::new(BpGens::new(1)),
            lambda: 0,
            max_peers: 0,
        }
    }
}

/// The (batched) proof object carried in a [`crate::dkg::Dealing`].
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)] // `Full` carries ≈40 group elements; the box would only obscure things.
pub enum EvrfProof {
    Full(R1CSProof),
    /// Schnorr PoK of each `r_j` (one per recipient, in the same order as
    /// the recipient list).
    InsecureQuick(Vec<SchnorrR>),
}

/// Schnorr PoK of `r` for `R = g_out^r`, used by the `InsecureQuick` stub.
#[derive(Clone, Debug)]
pub struct SchnorrR {
    pub commitment: GoutAffine,
    pub response: Fp,
}

/// Public inputs for one batched proof — the dealer's `PK_1`, the eVRF base
/// points `H_1, H_2`, `β`, and the per-recipient `(PK_j, R_j)`.
#[derive(Clone, Debug)]
pub struct BatchPublicInputs {
    pub pk1: GinAffine,
    pub h1m: GinAffine,
    pub h2m: GinAffine,
    pub beta: Fp,
    pub peers: Vec<EvrfPeerInputs>,
}

/// Build a fresh transcript bound to all the public inputs and the circuit
/// shape parameter `lambda`.  Binding `lambda` makes a prover/verifier
/// parameter mismatch fail cleanly at the first challenge rather than as an
/// MSM mismatch deep in the IPA.
fn batch_transcript(params: &ZkParams, sid: &SessionId, pubs: &BatchPublicInputs) -> Transcript {
    let mut t = Transcript::new(b"golden-nidkg/evrf-batch-proof/v1");
    t.append_bytes(b"sid", &sid.0);
    t.append_u64(b"lambda", params.lambda as u64);
    t.append_gin(b"PK1", &pubs.pk1);
    t.append_gin(b"H1m", &pubs.h1m);
    t.append_gin(b"H2m", &pubs.h2m);
    t.append_fp(b"beta", &pubs.beta);
    t.append_u64(b"n_peers", pubs.peers.len() as u64);
    for p in &pubs.peers {
        t.append_gin(b"PK2", &p.pk2);
        t.append_gout(b"R", &p.r_commit);
    }
    t
}

/// Generate a batched proof for the `R_eVRF` relation, covering all `peers`.
///
/// `wits` must be the same length and order as `pubs.peers`.
pub fn prove_evrf_batch(
    params: &ZkParams,
    sid: &SessionId,
    pubs: &BatchPublicInputs,
    wits: &[EvrfWitness],
    rng: &mut (impl Rng + CryptoRng),
) -> GoldenResult<EvrfProof> {
    if wits.len() != pubs.peers.len() {
        return Err(GoldenError::Internal(
            "peers/witnesses length mismatch".into(),
        ));
    }
    for (p, w) in pubs.peers.iter().zip(wits) {
        debug_assert_eq!(gout_mul(&w.r), p.r_commit, "witness/commitment mismatch");
    }
    match params.mode {
        ZkMode::InsecureQuick => {
            let mut t = batch_transcript(params, sid, pubs);
            let proofs = pubs
                .peers
                .iter()
                .zip(wits)
                .map(|(p, w)| {
                    t.append_gout(b"Rj", &p.r_commit);
                    let k = Fp::rand(rng);
                    let commitment = gout_mul(&k);
                    t.append_gout(b"commit", &commitment);
                    let c = t.challenge_fp(b"c");
                    SchnorrR {
                        commitment,
                        response: k + c * w.r,
                    }
                })
                .collect();
            Ok(EvrfProof::InsecureQuick(proofs))
        }
        ZkMode::Full => {
            if pubs.peers.len() > params.max_peers {
                return Err(GoldenError::TooManyPeers {
                    got: pubs.peers.len(),
                    max: params.max_peers,
                });
            }
            let t = batch_transcript(params, sid, pubs);
            let mut prover = Prover::new(&params.gens, t);
            let mut r_vars = Vec::with_capacity(wits.len());
            for w in wits {
                let (r_commit, r_var) = prover.commit(w.r, Fp::zero());
                debug_assert_eq!(r_commit, gout_mul(&w.r));
                r_vars.push(r_var);
            }
            build_batch_circuit(
                &mut prover,
                &pubs.pk1,
                &pubs.h1m,
                &pubs.h2m,
                pubs.beta,
                &pubs.peers,
                &r_vars,
                Some(wits),
                params.lambda,
            );
            prover
                .prove(rng)
                .map(EvrfProof::Full)
                .map_err(GoldenError::Proof)
        }
    }
}

/// Verify a batched proof for the `R_eVRF` relation.
pub fn verify_evrf_batch(
    params: &ZkParams,
    sid: &SessionId,
    pubs: &BatchPublicInputs,
    proof: &EvrfProof,
) -> GoldenResult<()> {
    match collect_evrf_check(params, sid, pubs, proof)? {
        // A single check needs no random combiner — verify the MSM directly.
        Some(check) => check.verify(&params.gens).map_err(GoldenError::Proof),
        None => Ok(()), // InsecureQuick — already verified inside collect.
    }
}

/// Compute the verification MSM coefficients for one dealing's eVRF proof
/// without running the MSM, so several dealings can be batch-verified with
/// [`verify_evrf_checks`].  Returns `None` for `InsecureQuick` proofs (which
/// are verified inline and have no Bulletproofs MSM to batch).
pub fn collect_evrf_check(
    params: &ZkParams,
    sid: &SessionId,
    pubs: &BatchPublicInputs,
    proof: &EvrfProof,
) -> GoldenResult<Option<VerificationCheck>> {
    match (params.mode, proof) {
        (ZkMode::InsecureQuick, EvrfProof::InsecureQuick(proofs)) => {
            if proofs.len() != pubs.peers.len() {
                return Err(GoldenError::Proof("peer count mismatch".into()));
            }
            let mut t = batch_transcript(params, sid, pubs);
            for (p, sp) in pubs.peers.iter().zip(proofs) {
                t.append_gout(b"Rj", &p.r_commit);
                t.append_gout(b"commit", &sp.commitment);
                let c = t.challenge_fp(b"c");
                let lhs = gout_mul(&sp.response);
                let rhs =
                    (GoutProj::from(sp.commitment) + GoutProj::from(p.r_commit) * c).into_affine();
                if lhs != rhs {
                    return Err(GoldenError::Proof(
                        "InsecureQuick Schnorr verification failed".into(),
                    ));
                }
            }
            Ok(None)
        }
        (ZkMode::Full, EvrfProof::Full(p)) => {
            if pubs.peers.len() > params.max_peers {
                return Err(GoldenError::TooManyPeers {
                    got: pubs.peers.len(),
                    max: params.max_peers,
                });
            }
            let t = batch_transcript(params, sid, pubs);
            let mut verifier = Verifier::new(&params.gens, t);
            let r_vars: Vec<_> = pubs
                .peers
                .iter()
                .map(|p| verifier.commit(p.r_commit))
                .collect();
            build_batch_circuit(
                &mut verifier,
                &pubs.pk1,
                &pubs.h1m,
                &pubs.h2m,
                pubs.beta,
                &pubs.peers,
                &r_vars,
                None,
                params.lambda,
            );
            verifier
                .collect_check(p)
                .map(Some)
                .map_err(GoldenError::Proof)
        }
        _ => Err(GoldenError::Proof("proof/params mode mismatch".into())),
    }
}

/// Batch-verify several dealings' eVRF proofs by random linear combination of
/// their verification MSMs (Section 5.3 of the paper).  Each `check` should
/// come from [`collect_evrf_check`].  Deterministic: the combiners are derived
/// by Fiat-Shamir from the checks' transcript digests.  When the batch fails,
/// this does *not* say which dealing was bad — call [`verify_evrf_batch`] per
/// dealing to localise the fault.
pub fn verify_evrf_checks(params: &ZkParams, checks: &[VerificationCheck]) -> GoldenResult<()> {
    verify_batch(&params.gens, checks).map_err(GoldenError::Proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curves::{gin_mul, Fs};
    use crate::evrf::{eval_pad, Beta, SessionId};
    use crate::hash_to_curve::{h1, h2};
    use ark_std::UniformRand;
    use rand::SeedableRng;

    fn setup(n_peers: usize) -> (BatchPublicInputs, Vec<EvrfWitness>, SessionId) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let sk1 = Fs::rand(&mut rng);
        let pk1 = gin_mul(&sk1);
        let sid = SessionId([3u8; 32]);
        let beta = Beta::from_seed(b"test");
        let msg = b"msg";
        let mut peers = Vec::new();
        let mut wits = Vec::new();
        for _ in 0..n_peers {
            let sk2 = Fs::rand(&mut rng);
            let pk2 = gin_mul(&sk2);
            let (out, wit) = eval_pad(&sk1, &pk2, &sid, msg, &beta);
            peers.push(EvrfPeerInputs {
                pk2,
                r_commit: out.r_commit,
            });
            wits.push(wit);
        }
        let pubs = BatchPublicInputs {
            pk1,
            h1m: h1(&sid.0, msg),
            h2m: h2(&sid.0, msg),
            beta: beta.0,
            peers,
        };
        (pubs, wits, sid)
    }

    #[test]
    fn quick_proof_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let (pubs, wits, sid) = setup(3);
        let params = ZkParams::insecure_quick();
        let proof = prove_evrf_batch(&params, &sid, &pubs, &wits, &mut rng).unwrap();
        verify_evrf_batch(&params, &sid, &pubs, &proof).unwrap();
        // Tamper R.
        let mut bad = pubs.clone();
        bad.peers[1].r_commit =
            (GoutProj::from(bad.peers[1].r_commit) + crate::curves::gout_gen()).into_affine();
        assert!(verify_evrf_batch(&params, &sid, &bad, &proof).is_err());
        // Wrong sid.
        assert!(verify_evrf_batch(&params, &SessionId([4u8; 32]), &pubs, &proof).is_err());
        // Drop a peer.
        let mut bad = pubs.clone();
        bad.peers.pop();
        assert!(verify_evrf_batch(&params, &sid, &bad, &proof).is_err());
    }
}

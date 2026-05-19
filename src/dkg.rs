//! The Golden DKG protocol — Round 0 / publicly-verifiable check / Round 1
//! (Section 5, Figure 4 of the paper).
//!
//! ```text
//! Round 0 (each party i):
//!   ω_i ← Z_p
//!   {x̄_{ij}}, C_i = (A_{i,0}…A_{i,t-1}) ← Shamir.Share(ω_i, n, t)
//!   msg_i ← {0,1}^λ
//!   for j ≠ i:
//!     (r_{ij}, R_{ij}, π_{ij}) ← eVRF.Eval(sk_i, (msg_i, PK_j))
//!     z_{ij} ← r_{ij} + x̄_{ij}
//!   broadcast (msg_i, C_i, {(R_{ij}, z_{ij}, π_{ij})})
//!   keep st_i ← x̄_{ii}
//!
//! Verify (any party / observer, on dealer j's broadcast):
//!   |C_j| = t  else abort
//!   for k ≠ j:
//!     eVRF.Verify(PK_j, (msg_j, PK_k), R_{jk}, π_{jk})
//!     X_{jk} ← ∏_l A_{j,l}^{k^l}
//!     g_out^{z_{jk}} == R_{jk} · X_{jk}        else abort
//!
//! Round 1 (party i, after verifying all dealings):
//!   for j ≠ i:
//!     r_{ji} ← eVRF.Eval(sk_i, (msg_j, PK_j))
//!     x̄_{ji} ← z_{ji} − r_{ji}
//!   sk_i ← ∑_j x̄_{ji}    (incl. own st_i)
//!   PK   ← ∏_j A_{j,0}
//!   PK_l ← ∏_j X_{jl}
//! ```

use crate::curves::{gout_mul, is_in_prime_subgroup, Fp, Fs, GinAffine, GoutAffine, GoutProj};
use crate::errors::{GoldenError, GoldenResult};
use crate::evrf::{eval_pad, Beta, SessionId};
use crate::hash_to_curve::{h1, h2};
use crate::schnorr::RegisteredKey;
use crate::shamir;
use crate::transcript::TranscriptExt;
use crate::vss;
use crate::zk::bp_r1cs::VerificationCheck;
use crate::zk::evrf_circuit::EvrfPeerInputs;
use crate::zk::evrf_proof::{
    collect_evrf_check, prove_evrf_batch, verify_evrf_batch, verify_evrf_checks, BatchPublicInputs,
    EvrfProof,
};
use crate::zk::ZkParams;
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::Zero;
use ark_std::rand::{CryptoRng, Rng};
use ark_std::UniformRand;
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Static configuration for one DKG session.
#[derive(Clone, Debug)]
pub struct DkgConfig {
    pub n: u32,
    pub t: u32,
    pub sid: SessionId,
    pub beta: Beta,
}

impl DkgConfig {
    pub fn new(n: u32, t: u32, sid: SessionId) -> Self {
        assert!(t >= 1 && t <= n, "require 1 ≤ t ≤ n");
        Self {
            n,
            t,
            sid,
            beta: Beta::from_seed(b"golden-nidkg/beta/v1"),
        }
    }
}

/// `(R_{ij}, z_{ij})` — an encrypted share for one recipient.
#[derive(Clone, Debug)]
pub struct ShareCiphertext {
    pub r_commit: GoutAffine,
    pub z: Fp,
}

/// `(msg_i, C_i, {σ_{ij}}, π_i)` — the broadcast message for one dealer.
///
/// The `proof` is a *batched* eVRF proof covering all `n-1` recipients
/// (Section 5.3 of the paper).  Recipients are ordered ascending by
/// participant id (the same order as `ciphertexts` iterates).
#[derive(Clone, Debug)]
pub struct Dealing {
    pub dealer: u32,
    pub sid: SessionId,
    pub msg: [u8; 32],
    pub commitment: Vec<GoutAffine>,
    pub ciphertexts: BTreeMap<u32, ShareCiphertext>,
    pub proof: EvrfProof,
}

/// State the dealer keeps secret — its own Shamir share `f_i(i)`.
/// Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DealingPrivate {
    pub own_share: Fp,
}

/// Joint DKG output.
///
/// `secret_share` is the party's long-term threshold key share.  The struct
/// keeps `Debug`/`PartialEq` for test convenience and is *not* zeroize-on-drop
/// (its lifetime is the application's to manage — wrap it in
/// `zeroize::Zeroizing` if it should be scrubbed when it goes out of scope).
#[derive(Clone, Debug, PartialEq)]
pub struct DkgOutput {
    pub public_key: GoutAffine,
    pub public_key_shares: BTreeMap<u32, GoutAffine>,
    pub secret_share: Fp,
}

/// Round 0 — `Share + Encrypt + Prove` for one dealer.
///
/// `omega` defaults to a fresh random secret; pass `Some(Fp::zero())` for
/// proactive refresh (Section 5.2).  `rng` must be cryptographically secure
/// (it samples the dealer's secret polynomial, the broadcast nonce, and the
/// Bulletproofs blinding factors).
pub fn create_dealing(
    me: &RegisteredKey,
    sk: &Fs,
    cfg: &DkgConfig,
    pki: &BTreeMap<u32, GinAffine>,
    zk: &ZkParams,
    rng: &mut (impl Rng + CryptoRng),
    omega: Option<Fp>,
) -> GoldenResult<(Dealing, DealingPrivate)> {
    if !pki.contains_key(&me.id) {
        return Err(GoldenError::PartyNotInPki { id: me.id });
    }
    let omega = omega.unwrap_or_else(|| Fp::rand(rng));
    // `Polynomial` zeroizes its coefficients on drop; wrap `shares` so the
    // evaluated points are scrubbed too rather than left in freed heap memory.
    let (poly, shares) = shamir::share(omega, cfg.n, cfg.t, rng);
    let shares = Zeroizing::new(shares);
    let commitment = vss::commit(&poly);
    let mut msg = [0u8; 32];
    rng.fill(&mut msg);

    let mut ciphertexts = BTreeMap::new();
    let mut peers = Vec::new();
    let mut wits = Vec::new();
    let mut own_share = None;
    for (j, x_ij) in shares.iter() {
        if *j == me.id {
            own_share = Some(*x_ij);
            continue;
        }
        let pk_j = pki.get(j).ok_or(GoldenError::PartyNotInPki { id: *j })?;
        let (pad, witness) = eval_pad(sk, pk_j, &cfg.sid, &msg, &cfg.beta);
        let z = pad.r + x_ij;
        ciphertexts.insert(
            *j,
            ShareCiphertext {
                r_commit: pad.r_commit,
                z,
            },
        );
        peers.push(EvrfPeerInputs {
            pk2: *pk_j,
            r_commit: pad.r_commit,
        });
        wits.push(witness);
    }
    // Participant ids double as Shamir indices, so they must lie in `1..=n`.
    let own_share = own_share.ok_or_else(|| {
        GoldenError::Internal(format!("dealer id {} must be in 1..={}", me.id, cfg.n))
    })?;
    let pubs = BatchPublicInputs {
        pk1: me.pk,
        h1m: h1(&cfg.sid.0, &msg),
        h2m: h2(&cfg.sid.0, &msg),
        beta: cfg.beta.0,
        peers,
    };
    let proof = prove_evrf_batch(zk, &cfg.sid, &pubs, &wits, rng)?;
    Ok((
        Dealing {
            dealer: me.id,
            sid: cfg.sid,
            msg,
            commitment,
            ciphertexts,
            proof,
        },
        DealingPrivate { own_share },
    ))
}

/// Round 0 for proactive refresh: ω = 0 (Section 5.2).
pub fn refresh_dealing(
    me: &RegisteredKey,
    sk: &Fs,
    cfg: &DkgConfig,
    pki: &BTreeMap<u32, GinAffine>,
    zk: &ZkParams,
    rng: &mut (impl Rng + CryptoRng),
) -> GoldenResult<(Dealing, DealingPrivate)> {
    create_dealing(me, sk, cfg, pki, zk, rng, Some(Fp::zero()))
}

/// Public verification — anyone (even an observer) can run this on a dealing.
///
/// `expect_zero_secret` should be `true` for refresh dealings (ω = 0 ⇒
/// `A_{i,0}` is the identity).
///
/// Verifying many dealings at once?  Use [`verify_dealings`] — it batches the
/// dealings' Bulletproofs verification MSMs into one (Section 5.3) for
/// `~n×` faster verification.
pub fn verify_dealing(
    dealing: &Dealing,
    cfg: &DkgConfig,
    pki: &BTreeMap<u32, GinAffine>,
    zk: &ZkParams,
    expect_zero_secret: bool,
) -> GoldenResult<()> {
    let pubs = check_dealing_structure(dealing, cfg, pki, expect_zero_secret)?;
    verify_evrf_batch(zk, &cfg.sid, &pubs, &dealing.proof).map_err(evrf_err(dealing.dealer))
}

/// Public verification of *all* dealings for one round.
///
/// Performs the cheap per-dealing checks (commitment length, ciphertext
/// consistency, structure) immediately so a misbehaving dealer is identified,
/// then batches all the dealings' Bulletproofs verification MSMs into a single
/// MSM (Section 5.3 of the paper).  If the batch fails, the already-collected
/// per-dealing checks are run individually so the offender can be named —
/// without rebuilding the circuits.
///
/// Deterministic: the batch combiners are derived from the dealings by
/// Fiat-Shamir, so every observer computes the same verdict.  The per-dealing
/// circuit reconstruction (the bulk of the work besides the final MSM) runs in
/// parallel under `--features parallel`.
pub fn verify_dealings(
    dealings: &BTreeMap<u32, Dealing>,
    cfg: &DkgConfig,
    pki: &BTreeMap<u32, GinAffine>,
    zk: &ZkParams,
    expect_zero_secret: bool,
) -> GoldenResult<()> {
    let collect = |d: &Dealing| -> GoldenResult<Option<(u32, VerificationCheck)>> {
        let pubs = check_dealing_structure(d, cfg, pki, expect_zero_secret)?;
        Ok(collect_evrf_check(zk, &cfg.sid, &pubs, &d.proof)
            .map_err(evrf_err(d.dealer))?
            .map(|c| (d.dealer, c)))
    };
    // Run the per-dealing circuit reconstruction (independent across dealings)
    // in parallel.  The collected list is in dealer-id order so the FS-derived
    // batch combiners are deterministic across verifiers.
    #[cfg(feature = "parallel")]
    let collected: Vec<_> = {
        use rayon::prelude::*;
        dealings
            .values()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(collect)
            .collect()
    };
    #[cfg(not(feature = "parallel"))]
    let collected: Vec<_> = dealings.values().map(collect).collect();

    let mut checks = Vec::with_capacity(dealings.len());
    let mut dealer_ids = Vec::with_capacity(dealings.len());
    for r in collected {
        if let Some((dealer, c)) = r? {
            dealer_ids.push(dealer);
            checks.push(c);
        }
    }
    if verify_evrf_checks(zk, &checks).is_ok() {
        return Ok(());
    }
    // Batch failed — re-verify the already-collected checks individually so
    // the offender can be named (no circuit rebuild).
    for (dealer, check) in dealer_ids.iter().zip(&checks) {
        check.verify(&zk.gens).map_err(evrf_err(*dealer))?;
    }
    // Unreachable: the FS-derived combiners are deterministic, so a batch
    // that fails has at least one failing individual check.
    Err(GoldenError::Internal(
        "batch verification failed but every individual check passed".into(),
    ))
}

/// Wrap an eVRF proof error with the offending dealer's id.
fn evrf_err<E: std::fmt::Display>(dealer: u32) -> impl Fn(E) -> GoldenError {
    move |e| GoldenError::EvrfProofFailed {
        dealer,
        reason: e.to_string(),
    }
}

/// Run the cheap structural / Feldman / ciphertext checks on a dealing and
/// return the batched eVRF public inputs.  Shared between [`verify_dealing`]
/// and [`verify_dealings`].
fn check_dealing_structure(
    dealing: &Dealing,
    cfg: &DkgConfig,
    pki: &BTreeMap<u32, GinAffine>,
    expect_zero_secret: bool,
) -> GoldenResult<BatchPublicInputs> {
    let j = dealing.dealer;
    if dealing.sid != cfg.sid {
        return Err(GoldenError::SessionMismatch { dealer: j });
    }
    // BUGS.md §4 — check commitment length explicitly.
    if dealing.commitment.len() != cfg.t as usize {
        return Err(GoldenError::WrongCommitmentLength {
            dealer: j,
            got: dealing.commitment.len(),
            expected: cfg.t as usize,
        });
    }
    if expect_zero_secret && !dealing.commitment[0].is_zero() {
        return Err(GoldenError::NonZeroRefreshSecret { dealer: j });
    }
    // BLS12-381 G1's cofactor has small prime factors (3, 11, …).  An
    // off-subgroup `A_l` or `R_{jk}` lets a malicious dealer publish a dealing
    // whose `g^z = R + X` check and eVRF proof both pass (after grinding the
    // small-order component to cancel) while the recipient's locally
    // re-derived `R' = g_out^r` mismatches — a false complaint.  Reject any
    // off-curve or off-subgroup group element up front (BUGS.md §12).
    for a in &dealing.commitment {
        if !is_in_prime_subgroup(a) {
            return Err(GoldenError::ElementNotInSubgroup { dealer: j });
        }
    }
    let pk_j = pki.get(&j).ok_or(GoldenError::PartyNotInPki { id: j })?;
    // The dealer must send exactly one ciphertext for every party except itself.
    let mut peers = Vec::with_capacity(pki.len().saturating_sub(1));
    for (&k, &pk_k) in pki.iter().filter(|&(&k, _)| k != j) {
        let ct = dealing
            .ciphertexts
            .get(&k)
            .ok_or(GoldenError::MissingCiphertext {
                dealer: j,
                recipient: k,
            })?;
        if !is_in_prime_subgroup(&ct.r_commit) {
            return Err(GoldenError::ElementNotInSubgroup { dealer: j });
        }
        // Ciphertext consistency: g^z == R · X_{jk}.  This is the cheap
        // public check from Figure 4 line 9 — perform it before the eVRF
        // proof so a corrupted ciphertext is rejected without paying for the
        // SNARK verification.  Compare in projective form (`Projective::eq`
        // cross-multiplies) to skip the affine-normalisation inversion.
        let x_jk = vss::share_commitment_proj(&dealing.commitment, k);
        let lhs = GoutProj::generator() * ct.z;
        let rhs = x_jk + ct.r_commit;
        if lhs != rhs {
            return Err(GoldenError::CiphertextCheckFailed {
                dealer: j,
                recipient: k,
            });
        }
        peers.push(EvrfPeerInputs {
            pk2: pk_k,
            r_commit: ct.r_commit,
        });
    }
    // No spurious ciphertexts (e.g. for non-existent parties).
    for &k in dealing.ciphertexts.keys() {
        if k == j || !pki.contains_key(&k) {
            return Err(GoldenError::UnexpectedCiphertext {
                dealer: j,
                recipient: k,
            });
        }
    }
    // Batched eVRF proof: one Bulletproofs proof for all `n-1` recipients.
    Ok(BatchPublicInputs {
        pk1: *pk_j,
        h1m: h1(&cfg.sid.0, &dealing.msg),
        h2m: h2(&cfg.sid.0, &dealing.msg),
        beta: cfg.beta.0,
        peers,
    })
}

/// Round 1 — decrypt + aggregate.  Caller must have verified all dealings
/// (incl. its own) with [`verify_dealing`] first.
pub fn complete(
    me: &RegisteredKey,
    sk: &Fs,
    cfg: &DkgConfig,
    pki: &BTreeMap<u32, GinAffine>,
    own: &DealingPrivate,
    dealings: &BTreeMap<u32, Dealing>,
) -> GoldenResult<DkgOutput> {
    if dealings.len() as u32 != cfg.n || !dealings.contains_key(&me.id) {
        return Err(GoldenError::Internal(format!(
            "expected {} dealings (incl. own), got {}",
            cfg.n,
            dealings.len()
        )));
    }
    let mut secret_share = own.own_share;
    // Aggregate the Feldman commitments coefficient-wise.  Since
    //   PK_l = ∏_j X_{jl} = ∏_j ∏_m A_{j,m}^{l^m} = ∏_m (∏_j A_{j,m})^{l^m},
    // computing `agg[m] = ∏_j A_{j,m}` once and Horner-ing over `agg` turns the
    // per-recipient cost from `O(n·t)` to `O(t)` group ops (`O(n·t)` total
    // rather than `O(n²·t)`).
    let mut agg = vec![GoutProj::zero(); cfg.t as usize];
    for (j, dealing) in dealings {
        if *j != me.id {
            let pk_j = &pki[j];
            // r_{ji} = eVRF.Eval(sk_i, (msg_j, PK_j))
            let (pad, _) = eval_pad(sk, pk_j, &cfg.sid, &dealing.msg, &cfg.beta);
            let ct = dealing
                .ciphertexts
                .get(&me.id)
                .ok_or(GoldenError::MissingCiphertext {
                    dealer: *j,
                    recipient: me.id,
                })?;
            // (Defensive) consistency: the broadcast R should match the locally
            // re-derived pad commitment.  If it doesn't, the dealer lied; the
            // public verification should already have caught this.
            if ct.r_commit != pad.r_commit {
                return Err(GoldenError::CiphertextCheckFailed {
                    dealer: *j,
                    recipient: me.id,
                });
            }
            secret_share += ct.z - pad.r;
        }
        for (m, a) in agg.iter_mut().enumerate() {
            *a += dealing.commitment[m];
        }
    }
    let agg = GoutProj::normalize_batch(&agg);
    let shares_proj: Vec<GoutProj> = pki
        .keys()
        .map(|&l| vss::share_commitment_proj(&agg, l))
        .collect();
    let public_key_shares = pki
        .keys()
        .copied()
        .zip(GoutProj::normalize_batch(&shares_proj))
        .collect();
    Ok(DkgOutput {
        public_key: agg[0],
        public_key_shares,
        secret_share,
    })
}

/// Sanity check: `g_out^{sk_i}` should match the per-party `PK_i` produced by
/// the DKG.
pub fn check_output(out: &DkgOutput, my_id: u32) -> bool {
    out.public_key_shares
        .get(&my_id)
        .is_some_and(|pk_i| gout_mul(&out.secret_share) == *pk_i)
}

/// Build a deterministic `SessionId` for a fresh DKG run from public context.
/// (Convenience helper; in production pull from a beacon.)
pub fn derive_session_id(
    label: &[u8],
    n: u32,
    t: u32,
    pki: &BTreeMap<u32, GinAffine>,
) -> SessionId {
    use merlin::Transcript;
    let mut tr = Transcript::new(b"golden-nidkg/session-id/v1");
    tr.append_bytes(b"label", label);
    tr.append_u64(b"n", n as u64);
    tr.append_u64(b"t", t as u64);
    for (id, pk) in pki {
        tr.append_u64(b"id", *id as u64);
        tr.append_gin(b"pk", pk);
    }
    let mut buf = [0u8; 32];
    tr.challenge_bytes(b"sid", &mut buf);
    SessionId(buf)
}

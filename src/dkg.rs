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

use crate::curves::{gout_mul, Fp, Fs, GinAffine, GoutAffine, GoutProj};
use crate::errors::{GoldenError, GoldenResult};
use crate::evrf::{eval_pad, Beta, SessionId};
use crate::hash_to_curve::{h1, h2};
use crate::schnorr::RegisteredKey;
use crate::shamir;
use crate::transcript::TranscriptExt;
use crate::vss;
use crate::zk::evrf_circuit::EvrfPeerInputs;
use crate::zk::evrf_proof::{
    collect_evrf_check, prove_evrf_batch, verify_evrf_batch, verify_evrf_checks, BatchPublicInputs,
    EvrfProof,
};
use crate::zk::ZkParams;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use std::collections::BTreeMap;

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

/// State the dealer keeps secret — its own share and ω.
#[derive(Clone)]
pub struct DealingPrivate {
    pub own_share: Fp,
}

/// Joint DKG output.
#[derive(Clone, Debug, PartialEq)]
pub struct DkgOutput {
    pub public_key: GoutAffine,
    pub public_key_shares: BTreeMap<u32, GoutAffine>,
    pub secret_share: Fp,
}

/// Round 0 — `Share + Encrypt + Prove` for one dealer.
///
/// `omega` defaults to a fresh random secret; pass `Some(Fp::zero())` for
/// proactive refresh (Section 5.2).
pub fn create_dealing(
    me: &RegisteredKey,
    sk: &Fs,
    cfg: &DkgConfig,
    pki: &BTreeMap<u32, GinAffine>,
    zk: &ZkParams,
    rng: &mut impl Rng,
    omega: Option<Fp>,
) -> GoldenResult<(Dealing, DealingPrivate)> {
    if !pki.contains_key(&me.id) {
        return Err(GoldenError::PartyNotInPki { id: me.id });
    }
    let omega = omega.unwrap_or_else(|| Fp::rand(rng));
    let (poly, shares) = shamir::share(omega, cfg.n, cfg.t, rng);
    let commitment = vss::commit(&poly);
    let mut msg = [0u8; 32];
    rng.fill(&mut msg);

    let mut ciphertexts = BTreeMap::new();
    let mut peers = Vec::new();
    let mut wits = Vec::new();
    let mut own_share = Fp::zero();
    for (j, x_ij) in &shares {
        if *j == me.id {
            own_share = *x_ij;
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
    rng: &mut impl Rng,
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
    verify_evrf_batch(zk, &cfg.sid, &pubs, &dealing.proof).map_err(|e| {
        GoldenError::EvrfProofFailed {
            dealer: dealing.dealer,
            recipient: 0,
            reason: format!("{e}"),
        }
    })
}

/// Public verification of *all* dealings for one round.
///
/// Performs the cheap per-dealing checks (commitment length, ciphertext
/// consistency, structure) immediately so a misbehaving dealer is identified,
/// then batches all the dealings' Bulletproofs verification MSMs into a single
/// MSM (Section 5.3 of the paper).  If the batch fails, falls back to
/// verifying each dealing individually so the offender can be named.
pub fn verify_dealings(
    dealings: &BTreeMap<u32, Dealing>,
    cfg: &DkgConfig,
    pki: &BTreeMap<u32, GinAffine>,
    zk: &ZkParams,
    expect_zero_secret: bool,
    rng: &mut impl Rng,
) -> GoldenResult<()> {
    let mut checks = Vec::with_capacity(dealings.len());
    for d in dealings.values() {
        let pubs = check_dealing_structure(d, cfg, pki, expect_zero_secret)?;
        if let Some(c) = collect_evrf_check(zk, &cfg.sid, &pubs, &d.proof).map_err(|e| {
            GoldenError::EvrfProofFailed {
                dealer: d.dealer,
                recipient: 0,
                reason: format!("{e}"),
            }
        })? {
            checks.push(c);
        }
    }
    if verify_evrf_checks(zk, &checks, rng).is_ok() {
        return Ok(());
    }
    // Batch failed — re-verify each to localise the offender.
    for d in dealings.values() {
        verify_dealing(d, cfg, pki, zk, expect_zero_secret)?;
    }
    Err(GoldenError::Internal(
        "batch verification failed but all individual verifications passed (transient?)".into(),
    ))
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
    let pk_j = pki.get(&j).ok_or(GoldenError::PartyNotInPki { id: j })?;
    // The dealer must send exactly one ciphertext for every party except itself.
    let recipients: Vec<u32> = pki.keys().filter(|&&k| k != j).copied().collect();
    let mut peers = Vec::with_capacity(recipients.len());
    for &k in &recipients {
        let ct = dealing
            .ciphertexts
            .get(&k)
            .ok_or(GoldenError::MissingCiphertext {
                dealer: j,
                recipient: k,
            })?;
        // Ciphertext consistency: g^z == R · X_{jk}.  This is the cheap
        // public check from Figure 4 line 9 — perform it before the eVRF
        // proof so a corrupted ciphertext is rejected without paying for the
        // SNARK verification.
        let x_jk = vss::share_commitment(&dealing.commitment, k);
        let lhs = gout_mul(&ct.z);
        let rhs = (GoutProj::from(ct.r_commit) + GoutProj::from(x_jk)).into_affine();
        if lhs != rhs {
            return Err(GoldenError::CiphertextCheckFailed {
                dealer: j,
                recipient: k,
            });
        }
        let pk_k = pki.get(&k).ok_or(GoldenError::PartyNotInPki { id: k })?;
        peers.push(EvrfPeerInputs {
            pk2: *pk_k,
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
    let mut pk_proj = GoutProj::zero();
    let mut pk_share_acc: BTreeMap<u32, GoutProj> =
        pki.keys().map(|&l| (l, GoutProj::zero())).collect();

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
        pk_proj += GoutProj::from(dealing.commitment[0]);
        for (&l, acc) in pk_share_acc.iter_mut() {
            *acc += GoutProj::from(vss::share_commitment(&dealing.commitment, l));
        }
    }
    let public_key = pk_proj.into_affine();
    let public_key_shares = pk_share_acc
        .into_iter()
        .map(|(l, v)| (l, v.into_affine()))
        .collect();
    Ok(DkgOutput {
        public_key,
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

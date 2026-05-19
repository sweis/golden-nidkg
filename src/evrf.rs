//! Two-party exponent VRF (Section 4 of the paper).
//!
//! `eVRF.Evaluate(sk, (msg, PK')) → (r, R, π)` derives a one-time pad `r ∈ F_p`
//! deterministically from the Diffie-Hellman shared secret `S = PK'^{sk}`:
//!
//! ```text
//!   S  = PK'^{sk}                          (Jubjub point)
//!   k  = int(S.x)                          (cast to integer / F_s scalar)
//!   T1 = H₁(sid, msg)^k                    (Jubjub points)
//!   T2 = H₂(sid, msg)^k
//!   r  = β · int(T1.x) + int(T2.x)  mod p
//!   R  = g_out^r                           (BLS12-381 G1 point)
//! ```
//!
//! Symmetry of `S` gives `r_{ij} = r_{ji}` when both parties evaluate on the
//! same `msg`, so the pad is shared.  `R` is a discrete-log commitment to `r`
//! that the receiver (and any third party) can verify against `PK_1, PK_2,
//! msg, β` via the zero-knowledge proof `π`.
//!
//! `π` is a Bulletproofs R1CS proof of `R_eVRF` (Figure 3) with `R` linked via
//! a Pedersen commitment; see `zk/`.

use crate::curves::{fp_to_fs, gout_mul, x_coord, Fp, Fs, GinAffine, GinProj, GoutAffine};
use crate::hash_to_curve::{h1, h2, hash_to_fp};
use ark_ec::CurveGroup;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A session/CRS identifier.  Mixed into the eVRF hashes and the proof
/// transcript so cross-session replay is impossible (BUGS.md §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionId(pub [u8; 32]);

impl SessionId {
    pub fn random(rng: &mut impl rand::RngCore) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        Self(b)
    }
}

/// Public parameters for the eVRF: the leftover-hash-lemma constant `β`.
///
/// `β` is a public CRS value, derivable from a domain-separated hash.  The
/// LHL requires it be sampled independently of the source distribution, so it
/// must be fixed before any DH keys are generated; deriving it from a public
/// constant string suffices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Beta(pub Fp);

impl Beta {
    /// Derive β from a public string.  This is a CRS operation.
    pub fn from_seed(seed: &[u8]) -> Self {
        Self(hash_to_fp(b"beta", seed))
    }
}

/// All the public points needed by the prover, verifier and circuit.
///
/// The circuit only needs `pk1, pk2, h1m, h2m, beta` plus the (linked)
/// commitment `R`.  We fold `S` and `T1, T2` into the witness.
#[derive(Clone, Debug)]
pub struct EvrfPublicInputs {
    pub pk1: GinAffine, // prover's PKI key
    pub pk2: GinAffine, // peer's PKI key
    pub h1m: GinAffine, // H₁(sid, msg)
    pub h2m: GinAffine, // H₂(sid, msg)
    pub beta: Fp,
    pub r_commit: GoutAffine, // R = g_out^r
}

/// Pad `r` (secret — it decrypts a Shamir share via `z − r`) and its public
/// commitment `R = g_out^r`.  Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PadOutput {
    pub r: Fp,
    pub r_commit: GoutAffine,
}

/// Witness data needed to prove `R_eVRF` (private to the dealer).
///
/// Every field is derived from the dealer's PKI secret key `sk` and the DH
/// shared secret `S`, so the whole struct is secret material.  Zeroized on
/// drop; deliberately not `Debug` so it cannot be accidentally logged.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EvrfWitness {
    pub sk: Fs,
    pub s: GinAffine,
    pub k: Fs,
    pub t1: GinAffine,
    pub t2: GinAffine,
    pub r1: Fp,
    pub r2: Fp,
    pub r: Fp,
}

/// `eVRF.Eval(sk, (msg, PK'))` minus the proof.
///
/// `sid` is mixed into the hash domains for replay protection.  The proof is
/// generated separately (see `zk::prove_evrf`) so that the DKG layer can batch
/// or deduplicate proof work.
pub fn eval_pad(
    sk: &Fs,
    pk_other: &GinAffine,
    sid: &SessionId,
    msg: &[u8],
    beta: &Beta,
) -> (PadOutput, EvrfWitness) {
    // S = PK'^{sk}
    let s = (GinProj::from(*pk_other) * sk).into_affine();
    // The DH shared secret is the identity iff `pk_other` is the identity
    // (which the PKI rejects) or `sk = 0` (which `RegisteredKey::fresh`
    // never produces).  The eVRF is degenerate at the identity (x = 0 ⇒ pad
    // = 0), so we hard-fail rather than silently produce a known pad.
    assert!(
        !ark_ec::AffineRepr::is_zero(&s),
        "DH shared secret is the identity — PKI must reject identity keys"
    );
    // k = int(S.x) reduced mod s
    let k0 = x_coord(&s);
    let k = fp_to_fs(&k0);
    // H₁(sid, msg), H₂(sid, msg) — public points, derived deterministically.
    let h1m = h1(&sid.0, msg);
    let h2m = h2(&sid.0, msg);
    // T1, T2
    let t1 = (GinProj::from(h1m) * k).into_affine();
    let t2 = (GinProj::from(h2m) * k).into_affine();
    let r1 = x_coord(&t1);
    let r2 = x_coord(&t2);
    // r = β·r1 + r2  (mod p)
    let r = beta.0 * r1 + r2;
    // R = g_out^r
    let r_commit = gout_mul(&r);
    (
        PadOutput { r, r_commit },
        EvrfWitness {
            sk: *sk,
            s,
            k,
            t1,
            t2,
            r1,
            r2,
            r,
        },
    )
}

/// Pre-compute the public inputs for a (sender, recipient, msg) triple.
pub fn public_inputs(
    pk1: &GinAffine,
    pk2: &GinAffine,
    sid: &SessionId,
    msg: &[u8],
    beta: &Beta,
    r_commit: &GoutAffine,
) -> EvrfPublicInputs {
    EvrfPublicInputs {
        pk1: *pk1,
        pk2: *pk2,
        h1m: h1(&sid.0, msg),
        h2m: h2(&sid.0, msg),
        beta: beta.0,
        r_commit: *r_commit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curves::gin_mul;
    use ark_std::UniformRand;
    use rand::SeedableRng;

    fn setup() -> (Fs, GinAffine, Fs, GinAffine, SessionId, Beta) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let sk1 = Fs::rand(&mut rng);
        let pk1 = gin_mul(&sk1);
        let sk2 = Fs::rand(&mut rng);
        let pk2 = gin_mul(&sk2);
        let sid = SessionId([7u8; 32]);
        let beta = Beta::from_seed(b"test");
        (sk1, pk1, sk2, pk2, sid, beta)
    }

    #[test]
    fn pad_is_symmetric() {
        let (sk1, pk1, sk2, pk2, sid, beta) = setup();
        let msg = b"hello";
        let (out1, _) = eval_pad(&sk1, &pk2, &sid, msg, &beta);
        let (out2, _) = eval_pad(&sk2, &pk1, &sid, msg, &beta);
        assert_eq!(out1.r, out2.r);
        assert_eq!(out1.r_commit, out2.r_commit);
    }

    #[test]
    fn pad_depends_on_msg_and_sid_and_keys() {
        let (sk1, _pk1, _sk2, pk2, sid, beta) = setup();
        let (a, _) = eval_pad(&sk1, &pk2, &sid, b"a", &beta);
        let (b, _) = eval_pad(&sk1, &pk2, &sid, b"b", &beta);
        assert_ne!(a.r, b.r);
        let sid2 = SessionId([8u8; 32]);
        let (c, _) = eval_pad(&sk1, &pk2, &sid2, b"a", &beta);
        assert_ne!(a.r, c.r);
        // Different peer.
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let pk3 = gin_mul(&Fs::rand(&mut rng));
        let (d, _) = eval_pad(&sk1, &pk3, &sid, b"a", &beta);
        assert_ne!(a.r, d.r);
        // Different β.
        let beta2 = Beta::from_seed(b"other");
        let (e, _) = eval_pad(&sk1, &pk2, &sid, b"a", &beta2);
        assert_ne!(a.r, e.r);
    }

    #[test]
    fn r_commit_consistent() {
        let (sk1, _pk1, _sk2, pk2, sid, beta) = setup();
        let (out, _) = eval_pad(&sk1, &pk2, &sid, b"x", &beta);
        assert_eq!(out.r_commit, gout_mul(&out.r));
    }

    #[test]
    fn witness_consistent() {
        let (sk1, pk1, _sk2, pk2, sid, beta) = setup();
        let (out, w) = eval_pad(&sk1, &pk2, &sid, b"x", &beta);
        // S = pk2^{sk1}
        assert_eq!(w.s, (GinProj::from(pk2) * sk1).into_affine());
        // pk1 = g_in^{sk1}
        assert_eq!(pk1, gin_mul(&w.sk));
        // r consistent with the formula
        assert_eq!(w.r, beta.0 * w.r1 + w.r2);
        assert_eq!(w.r, out.r);
    }
}

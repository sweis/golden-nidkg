//! Schnorr proof of knowledge of `sk` such that `PK = g_in^sk`, used for PKI
//! registration (Section 5.1, Appendix F).
//!
//! The proof binds the registrant identity into the Fiat-Shamir transcript.
//! See BUGS.md §1: an unbound Schnorr PoK is replayable, which lets an
//! adversary register an honest party's `PK` as its own and recover that
//! party's secret contribution from the broadcast transcript.

use crate::curves::{gin_gen, GinAffine, GinProj, Fs};
use crate::errors::{GoldenError, GoldenResult};
use crate::transcript::TranscriptExt;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::rand::Rng;
use ark_std::UniformRand;
use merlin::Transcript;

/// `(R = g_in^k, s = k + c·sk)` with `c = H(ctx ‖ id ‖ PK ‖ R)`.
#[derive(Clone, Debug)]
pub struct SchnorrPoK {
    pub commitment: GinAffine,
    pub response: Fs,
}

const DOMAIN: &[u8] = b"golden-nidkg/schnorr-pok/v1";

fn challenge(id: u32, pk: &GinAffine, commitment: &GinAffine) -> Fs {
    let mut t = Transcript::new(DOMAIN);
    t.append_u64(b"id", id as u64);
    t.append_gin(b"pk", pk);
    t.append_gin(b"R", commitment);
    t.challenge_fs(b"c")
}

impl SchnorrPoK {
    /// Prove knowledge of `sk` for `PK = g_in^sk`, bound to `id`.
    pub fn prove(id: u32, sk: &Fs, pk: &GinAffine, rng: &mut impl Rng) -> Self {
        let k = Fs::rand(rng);
        let commitment = (GinProj::generator() * k).into_affine();
        let c = challenge(id, pk, &commitment);
        let response = k + c * sk;
        Self { commitment, response }
    }

    /// Verify against the (id, PK) the registrant claims.
    pub fn verify(&self, id: u32, pk: &GinAffine) -> GoldenResult<()> {
        if pk.is_zero() {
            return Err(GoldenError::IdentityPublicKey { party: id });
        }
        let c = challenge(id, pk, &self.commitment);
        // g^s == R · PK^c
        let lhs = GinProj::generator() * self.response;
        let rhs = GinProj::from(self.commitment) + GinProj::from(*pk) * c;
        if lhs.into_affine() == rhs.into_affine() {
            Ok(())
        } else {
            Err(GoldenError::SchnorrPoKFailed { party: id })
        }
    }
}

/// A registered participant's PKI material.
#[derive(Clone, Debug)]
pub struct RegisteredKey {
    pub id: u32,
    pub pk: GinAffine,
    pub pok: SchnorrPoK,
}

impl RegisteredKey {
    pub fn new(id: u32, sk: &Fs, rng: &mut impl Rng) -> (Self, Fs) {
        let pk = (GinProj::generator() * sk).into_affine();
        let pok = SchnorrPoK::prove(id, sk, &pk, rng);
        (Self { id, pk, pok }, *sk)
    }

    pub fn fresh(id: u32, rng: &mut impl Rng) -> (Self, Fs) {
        let sk = Fs::rand(rng);
        Self::new(id, &sk, rng)
    }

    pub fn verify(&self) -> GoldenResult<()> {
        self.pok.verify(self.id, &self.pk)
    }
}

/// Verify an entire PKI snapshot: each PoK + no duplicate / negated keys.
/// See BUGS.md §1 (key-duplication share-recovery attack) and §2 (the negate
/// case, which doesn't apply on Jubjub-with-x but is kept defensively).
pub fn verify_pki(registry: &[RegisteredKey]) -> GoldenResult<()> {
    for r in registry {
        r.verify()?;
    }
    for i in 0..registry.len() {
        for j in (i + 1)..registry.len() {
            let (a, b) = (&registry[i], &registry[j]);
            if a.pk == b.pk || a.pk == -b.pk {
                return Err(GoldenError::PkiKeyCollision { a: a.id, b: b.id });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pok_roundtrip() {
        let mut rng = ark_std::test_rng();
        let (rk, _) = RegisteredKey::fresh(1, &mut rng);
        assert!(rk.verify().is_ok());
    }

    #[test]
    fn pok_replay_to_other_id_fails() {
        // An adversary replaying honest party 1's registration to register
        // themselves as party 2 must fail (BUGS.md §1).
        let mut rng = ark_std::test_rng();
        let (rk1, _) = RegisteredKey::fresh(1, &mut rng);
        let stolen = RegisteredKey { id: 2, pk: rk1.pk, pok: rk1.pok.clone() };
        assert!(stolen.verify().is_err());
    }

    #[test]
    fn identity_key_rejected() {
        let mut rng = ark_std::test_rng();
        let pk = GinAffine::zero();
        let pok = SchnorrPoK::prove(1, &Fs::from(0u64), &pk, &mut rng);
        assert!(pok.verify(1, &pk).is_err());
    }

    #[test]
    fn pki_collision_rejected() {
        // Two registrations with the same PK (e.g. a fully malicious PKI).
        let mut rng = ark_std::test_rng();
        let (rk1, sk1) = RegisteredKey::fresh(1, &mut rng);
        // Adversary "knows" sk1 (e.g. malicious PKI / key reuse) and re-registers it.
        let (rk2, _) = RegisteredKey::new(2, &sk1, &mut rng);
        let registry = vec![rk1.clone(), rk2];
        assert!(verify_pki(&registry).is_err());

        // Negated key.
        let (rk3, _) = RegisteredKey::new(3, &(-sk1), &mut rng);
        let registry = vec![rk1, rk3];
        assert!(verify_pki(&registry).is_err());
    }
}

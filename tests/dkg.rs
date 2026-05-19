//! End-to-end and adversarial tests for the Golden DKG protocol.
//!
//! These run with `ZkParams::insecure_quick()` so they cover the protocol
//! logic (Shamir, VSS, eVRF pad, aggregation) without the multi-second
//! Bulletproofs overhead.  Full-ZK round-trips live in `tests/zk_full.rs` and
//! the lib tests in `src/zk/evrf_circuit.rs`.

use ark_ec::CurveGroup;
use golden_nidkg::curves::{gout_mul, Fp, Fs, GinAffine, GoutProj};
use golden_nidkg::dkg::{
    check_output, complete, create_dealing, derive_session_id, refresh_dealing, verify_dealing,
    verify_dealings, Dealing, DkgConfig,
};
use golden_nidkg::errors::GoldenError;
use golden_nidkg::schnorr::{verify_pki, RegisteredKey};
use golden_nidkg::shamir;
use golden_nidkg::zk::ZkParams;
use rand::{rngs::StdRng, SeedableRng};
use std::collections::BTreeMap;

struct TestNet {
    cfg: DkgConfig,
    pki: BTreeMap<u32, GinAffine>,
    registry: Vec<RegisteredKey>,
    sks: BTreeMap<u32, Fs>,
    zk: ZkParams,
    rng: StdRng,
}

impl TestNet {
    fn new(n: u32, t: u32) -> Self {
        let mut rng = StdRng::seed_from_u64(42);
        let mut sks = BTreeMap::new();
        let mut registry = Vec::new();
        let mut pki = BTreeMap::new();
        for id in 1..=n {
            let (rk, sk) = RegisteredKey::fresh(id, &mut rng);
            sks.insert(id, sk);
            pki.insert(id, rk.pk);
            registry.push(rk);
        }
        verify_pki(&registry).unwrap();
        let sid = derive_session_id(b"test", n, t, &pki);
        let cfg = DkgConfig::new(n, t, sid);
        Self {
            cfg,
            pki,
            registry,
            sks,
            zk: ZkParams::insecure_quick(),
            rng,
        }
    }

    fn round0_all(
        &mut self,
    ) -> (
        BTreeMap<u32, Dealing>,
        BTreeMap<u32, golden_nidkg::DealingPrivate>,
    ) {
        let mut dealings = BTreeMap::new();
        let mut privates = BTreeMap::new();
        for rk in self.registry.clone() {
            let (d, p) = create_dealing(
                &rk,
                &self.sks[&rk.id],
                &self.cfg,
                &self.pki,
                &self.zk,
                &mut self.rng,
                None,
            )
            .unwrap();
            dealings.insert(rk.id, d);
            privates.insert(rk.id, p);
        }
        (dealings, privates)
    }

    fn refresh_all(
        &mut self,
        cfg: &DkgConfig,
    ) -> (
        BTreeMap<u32, Dealing>,
        BTreeMap<u32, golden_nidkg::DealingPrivate>,
    ) {
        let mut dealings = BTreeMap::new();
        let mut privates = BTreeMap::new();
        for rk in self.registry.clone() {
            let (d, p) = refresh_dealing(
                &rk,
                &self.sks[&rk.id],
                cfg,
                &self.pki,
                &self.zk,
                &mut self.rng,
            )
            .unwrap();
            dealings.insert(rk.id, d);
            privates.insert(rk.id, p);
        }
        (dealings, privates)
    }
}

#[test]
fn dkg_end_to_end() {
    for (n, t) in [(2, 2), (3, 2), (5, 3), (7, 5)] {
        let mut net = TestNet::new(n, t);
        let (dealings, privates) = net.round0_all();
        // Per-dealing and batched verification must agree.
        for d in dealings.values() {
            verify_dealing(d, &net.cfg, &net.pki, &net.zk, false).unwrap();
        }
        verify_dealings(&dealings, &net.cfg, &net.pki, &net.zk, false).unwrap();
        let mut outs = BTreeMap::new();
        for rk in net.registry.clone() {
            let out = complete(
                &rk,
                &net.sks[&rk.id],
                &net.cfg,
                &net.pki,
                &privates[&rk.id],
                &dealings,
            )
            .unwrap();
            assert!(check_output(&out, rk.id));
            outs.insert(rk.id, out);
        }
        // All parties agree.
        let pk = outs[&1].public_key;
        for o in outs.values() {
            assert_eq!(o.public_key, pk);
            assert_eq!(o.public_key_shares, outs[&1].public_key_shares);
        }
        // t shares reconstruct.
        let shares: Vec<(u32, Fp)> = (1..=t).map(|i| (i, outs[&i].secret_share)).collect();
        let sk = shamir::recover(t, &shares).unwrap();
        assert_eq!(gout_mul(&sk), pk);
        // Any t shares (not just the first t).
        if n > t {
            let shares: Vec<(u32, Fp)> = (n - t + 1..=n)
                .map(|i| (i, outs[&i].secret_share))
                .collect();
            let sk2 = shamir::recover(t, &shares).unwrap();
            assert_eq!(sk, sk2);
        }
    }
}

#[test]
fn t_minus_one_does_not_reconstruct() {
    let (n, t) = (5, 3);
    let mut net = TestNet::new(n, t);
    let (dealings, privates) = net.round0_all();
    let mut outs = BTreeMap::new();
    for rk in net.registry.clone() {
        let out = complete(
            &rk,
            &net.sks[&rk.id],
            &net.cfg,
            &net.pki,
            &privates[&rk.id],
            &dealings,
        )
        .unwrap();
        outs.insert(rk.id, out);
    }
    let pk = outs[&1].public_key;
    let shares_tm1: Vec<(u32, Fp)> = (1..t).map(|i| (i, outs[&i].secret_share)).collect();
    let bad = shamir::recover(t - 1, &shares_tm1).unwrap();
    assert_ne!(gout_mul(&bad), pk);
}

#[test]
fn refresh_preserves_sk_and_rotates_shares() {
    let (n, t) = (5, 3);
    let mut net = TestNet::new(n, t);
    let (dealings, privates) = net.round0_all();
    for d in dealings.values() {
        verify_dealing(d, &net.cfg, &net.pki, &net.zk, false).unwrap();
    }
    let mut outs = BTreeMap::new();
    for rk in net.registry.clone() {
        outs.insert(
            rk.id,
            complete(
                &rk,
                &net.sks[&rk.id],
                &net.cfg,
                &net.pki,
                &privates[&rk.id],
                &dealings,
            )
            .unwrap(),
        );
    }
    let shares: Vec<(u32, Fp)> = (1..=t).map(|i| (i, outs[&i].secret_share)).collect();
    let sk = shamir::recover(t, &shares).unwrap();

    let sid2 = derive_session_id(b"refresh", n, t, &net.pki);
    let cfg2 = DkgConfig::new(n, t, sid2);
    let (rd, rp) = net.refresh_all(&cfg2);
    for d in rd.values() {
        verify_dealing(d, &cfg2, &net.pki, &net.zk, true).unwrap();
    }
    let mut new_shares = BTreeMap::new();
    let mut changed = false;
    for rk in net.registry.clone() {
        let delta = complete(&rk, &net.sks[&rk.id], &cfg2, &net.pki, &rp[&rk.id], &rd).unwrap();
        let s = outs[&rk.id].secret_share + delta.secret_share;
        if s != outs[&rk.id].secret_share {
            changed = true;
        }
        new_shares.insert(rk.id, s);
    }
    let nshares: Vec<(u32, Fp)> = (1..=t).map(|i| (i, new_shares[&i])).collect();
    assert_eq!(shamir::recover(t, &nshares).unwrap(), sk);
    assert!(changed, "refresh must rotate at least one share");
}

#[test]
fn refresh_dealing_with_nonzero_omega_rejected() {
    let (n, t) = (3, 2);
    let mut net = TestNet::new(n, t);
    // Malicious dealer 1 uses a regular dealing (ω ≠ 0) in a refresh session.
    let rk1 = net.registry[0].clone();
    let (bad, _) = create_dealing(
        &rk1,
        &net.sks[&1],
        &net.cfg,
        &net.pki,
        &net.zk,
        &mut net.rng,
        None,
    )
    .unwrap();
    assert!(matches!(
        verify_dealing(&bad, &net.cfg, &net.pki, &net.zk, true),
        Err(GoldenError::NonZeroRefreshSecret { dealer: 1 })
    ));
}

// ────────────────────────── tampering detection ──────────────────────────

#[test]
fn tampered_ciphertext_detected() {
    let (n, t) = (3, 2);
    let mut net = TestNet::new(n, t);
    let (mut dealings, _) = net.round0_all();
    // Corrupt z_{1,2}.
    if let Some(ct) = dealings.get_mut(&1).unwrap().ciphertexts.get_mut(&2) {
        ct.z += Fp::from(1u64);
    }
    assert!(matches!(
        verify_dealing(&dealings[&1], &net.cfg, &net.pki, &net.zk, false),
        Err(GoldenError::CiphertextCheckFailed {
            dealer: 1,
            recipient: 2
        })
    ));
}

#[test]
fn tampered_r_commitment_detected() {
    let (n, t) = (3, 2);
    let mut net = TestNet::new(n, t);
    let (mut dealings, _) = net.round0_all();
    if let Some(ct) = dealings.get_mut(&1).unwrap().ciphertexts.get_mut(&2) {
        ct.r_commit = (GoutProj::from(ct.r_commit)
            + GoutProj::from(golden_nidkg::curves::gout_gen()))
        .into_affine();
    }
    assert!(verify_dealing(&dealings[&1], &net.cfg, &net.pki, &net.zk, false).is_err());
}

#[test]
fn tampered_vss_commitment_detected() {
    let (n, t) = (3, 2);
    let mut net = TestNet::new(n, t);
    let (mut dealings, _) = net.round0_all();
    let d = dealings.get_mut(&1).unwrap();
    d.commitment[1] = (GoutProj::from(d.commitment[1])
        + GoutProj::from(golden_nidkg::curves::gout_gen()))
    .into_affine();
    assert!(matches!(
        verify_dealing(&dealings[&1], &net.cfg, &net.pki, &net.zk, false),
        Err(GoldenError::CiphertextCheckFailed { dealer: 1, .. })
    ));
}

#[test]
fn wrong_degree_commitment_rejected() {
    // BUGS.md §4: commitment vector with wrong length.
    let (n, t) = (3, 2);
    let mut net = TestNet::new(n, t);
    let (mut dealings, _) = net.round0_all();
    dealings
        .get_mut(&1)
        .unwrap()
        .commitment
        .push(golden_nidkg::curves::gout_gen());
    assert!(matches!(
        verify_dealing(&dealings[&1], &net.cfg, &net.pki, &net.zk, false),
        Err(GoldenError::WrongCommitmentLength { dealer: 1, .. })
    ));
    dealings.get_mut(&1).unwrap().commitment.truncate(1);
    assert!(matches!(
        verify_dealing(&dealings[&1], &net.cfg, &net.pki, &net.zk, false),
        Err(GoldenError::WrongCommitmentLength { dealer: 1, .. })
    ));
}

#[test]
fn off_subgroup_commitment_rejected() {
    // BLS12-381 G1's cofactor has small prime factors (3, 11, …).  A dealing
    // whose `A_l` or `R_{jk}` carry a small-order component can pass the
    // `g^z = R · X` check (the dealer crafts the components to cancel) and the
    // eVRF proof (after grinding the FS challenges) — yet the recipient's
    // re-derived `R'` is in `G_1`, so `complete()` raises a false complaint.
    // Public verification must reject any off-subgroup element up front.
    use ark_bls12_381::Fq;
    use ark_ff::Field;
    let off_subgroup = {
        // The full curve has order `cofactor · p`, so a random on-curve point
        // is in the prime-order subgroup with prob. 1/cofactor ≈ 2^{-126}.
        let mut x = Fq::from(2u64);
        loop {
            if let Some(p) = golden_nidkg::GoutAffine::get_point_from_x_unchecked(x, false) {
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    break p;
                }
            }
            x += Fq::ONE;
        }
    };

    let (n, t) = (3, 2);
    let mut net = TestNet::new(n, t);
    let (dealings, _) = net.round0_all();

    // Off-subgroup VSS commitment.
    let mut d1 = dealings.clone();
    d1.get_mut(&1).unwrap().commitment[1] = off_subgroup;
    assert!(matches!(
        verify_dealing(&d1[&1], &net.cfg, &net.pki, &net.zk, false),
        Err(GoldenError::ElementNotInSubgroup { dealer: 1 })
    ));

    // Off-subgroup pad commitment R.
    let mut d2 = dealings.clone();
    d2.get_mut(&1)
        .unwrap()
        .ciphertexts
        .get_mut(&2)
        .unwrap()
        .r_commit = off_subgroup;
    assert!(matches!(
        verify_dealing(&d2[&1], &net.cfg, &net.pki, &net.zk, false),
        Err(GoldenError::ElementNotInSubgroup { dealer: 1 })
    ));
}

#[test]
fn missing_ciphertext_detected() {
    let (n, t) = (3, 2);
    let mut net = TestNet::new(n, t);
    let (mut dealings, _) = net.round0_all();
    dealings.get_mut(&1).unwrap().ciphertexts.remove(&2);
    assert!(matches!(
        verify_dealing(&dealings[&1], &net.cfg, &net.pki, &net.zk, false),
        Err(GoldenError::MissingCiphertext {
            dealer: 1,
            recipient: 2
        })
    ));
}

#[test]
fn cross_session_replay_rejected() {
    // BUGS.md §5: dealing from one session must be rejected in another.
    let (n, t) = (3, 2);
    let mut net = TestNet::new(n, t);
    let (dealings, _) = net.round0_all();
    let other_sid = derive_session_id(b"other", n, t, &net.pki);
    let other_cfg = DkgConfig::new(n, t, other_sid);
    assert!(matches!(
        verify_dealing(&dealings[&1], &other_cfg, &net.pki, &net.zk, false),
        Err(GoldenError::SessionMismatch { dealer: 1 })
    ));
}

#[test]
fn unexpected_extra_ciphertext_rejected() {
    let (n, t) = (3, 2);
    let mut net = TestNet::new(n, t);
    let (mut dealings, _) = net.round0_all();
    // Insert a ciphertext for a non-existent party 99.
    let ct = dealings[&1].ciphertexts[&2].clone();
    dealings.get_mut(&1).unwrap().ciphertexts.insert(99, ct);
    assert!(matches!(
        verify_dealing(&dealings[&1], &net.cfg, &net.pki, &net.zk, false),
        Err(GoldenError::UnexpectedCiphertext {
            dealer: 1,
            recipient: 99
        })
    ));
}

#[test]
fn rogue_key_pki_detected() {
    // BUGS.md §1: an adversary who copies an honest party's registration
    // (same PK, replayed proof) must be rejected.
    let mut rng = StdRng::seed_from_u64(7);
    let (rk1, _) = RegisteredKey::fresh(1, &mut rng);
    let stolen = RegisteredKey {
        id: 2,
        pk: rk1.pk,
        pok: rk1.pok.clone(),
    };
    assert!(verify_pki(&[rk1.clone(), stolen]).is_err());
}

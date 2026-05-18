//! Full-ZK round-trip — runs the real Bulletproofs `R_eVRF` proof in the DKG.
//!
//! This is `#[ignore]`d by default because the prover takes O(seconds) per
//! dealing.  Run with:
//!
//! ```sh
//! cargo test --release --test zk_full -- --ignored --nocapture
//! ```

use golden_nidkg::curves::{gout_mul, Fp};
use golden_nidkg::dkg::{
    check_output, complete, create_dealing, derive_session_id, verify_dealing, DkgConfig,
};
use golden_nidkg::errors::GoldenError;
use golden_nidkg::schnorr::{verify_pki, RegisteredKey};
use golden_nidkg::shamir;
use golden_nidkg::zk::ZkParams;
use rand::{rngs::StdRng, SeedableRng};
use std::collections::BTreeMap;
use std::time::Instant;

#[test]
#[ignore = "slow (~60s release): full Bulletproofs proof per dealing"]
fn full_zk_round_trip() {
    let (n, t) = (3, 2);
    let mut rng = StdRng::seed_from_u64(0xdeadbeef);
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
    let sid = derive_session_id(b"zk-full", n, t, &pki);
    let cfg = DkgConfig::new(n, t, sid);

    let zk_setup = Instant::now();
    let zk = ZkParams::full();
    eprintln!("ZK setup: {:?}", zk_setup.elapsed());

    let r0_start = Instant::now();
    let mut dealings = BTreeMap::new();
    let mut privates = BTreeMap::new();
    for rk in &registry {
        let t0 = Instant::now();
        let (d, p) = create_dealing(rk, &sks[&rk.id], &cfg, &pki, &zk, &mut rng, None).unwrap();
        eprintln!("party {}: dealing in {:?}", rk.id, t0.elapsed());
        dealings.insert(rk.id, d);
        privates.insert(rk.id, p);
    }
    eprintln!("Round 0: {:?}", r0_start.elapsed());

    let v_start = Instant::now();
    for d in dealings.values() {
        verify_dealing(d, &cfg, &pki, &zk, false).unwrap();
    }
    eprintln!("Verification: {:?}", v_start.elapsed());

    let mut outs = BTreeMap::new();
    for rk in &registry {
        let out = complete(rk, &sks[&rk.id], &cfg, &pki, &privates[&rk.id], &dealings).unwrap();
        assert!(check_output(&out, rk.id));
        outs.insert(rk.id, out);
    }
    let pk = outs[&1].public_key;
    let shares: Vec<(u32, Fp)> = (1..=t).map(|i| (i, outs[&i].secret_share)).collect();
    let sk = shamir::recover(t, &shares).unwrap();
    assert_eq!(gout_mul(&sk), pk);
    eprintln!("Round 1 + recovery OK; PK = g^sk verified");

    // Tamper one ciphertext and re-verify: must fail at the VSS check
    // (it would also fail at the eVRF proof if the VSS check were absent,
    // but we order VSS first for a cheap early-out).
    let mut bad = dealings.clone();
    bad.get_mut(&1).unwrap().ciphertexts.get_mut(&2).unwrap().z += Fp::from(1u64);
    assert!(matches!(
        verify_dealing(&bad[&1], &cfg, &pki, &zk, false),
        Err(GoldenError::CiphertextCheckFailed {
            dealer: 1,
            recipient: 2
        })
    ));
    eprintln!("Tampered ciphertext rejected");
}

/// Soundness test: replay a valid eVRF proof against a different `R`.
/// Since the eVRF proof binds `R` via the linked Pedersen commitment, this
/// must be detected.
#[test]
#[ignore = "slow (~30s release): full Bulletproofs proof"]
fn full_zk_proof_binds_r() {
    use ark_ec::CurveGroup;
    use golden_nidkg::curves::{gin_mul, Fs, GoutProj};
    use golden_nidkg::evrf::{eval_pad, public_inputs, Beta, SessionId};
    use golden_nidkg::zk::evrf_proof::{prove_evrf, verify_evrf};

    let mut rng = StdRng::seed_from_u64(1);
    let zk = ZkParams::full();
    use ark_ff::UniformRand;
    let sk1 = Fs::rand(&mut rng);
    let pk1 = gin_mul(&sk1);
    let sk2 = Fs::rand(&mut rng);
    let pk2 = gin_mul(&sk2);
    let sid = SessionId([1u8; 32]);
    let beta = Beta::from_seed(b"test");
    let (out, wit) = eval_pad(&sk1, &pk2, &sid, b"msg", &beta);
    let pubs = public_inputs(&pk1, &pk2, &sid, b"msg", &beta, &out.r_commit);
    let proof = prove_evrf(&zk, &sid, &pubs, &wit, &mut rng).unwrap();
    verify_evrf(&zk, &sid, &pubs, &proof).unwrap();
    // Tamper `R`.
    let mut bad = pubs.clone();
    bad.r_commit = (GoutProj::from(bad.r_commit)
        + GoutProj::from(golden_nidkg::curves::gout_gen()))
    .into_affine();
    assert!(verify_evrf(&zk, &sid, &bad, &proof).is_err());
    // Wrong sender PK.
    let mut bad = pubs.clone();
    bad.pk1 = gin_mul(&Fs::rand(&mut rng));
    assert!(verify_evrf(&zk, &sid, &bad, &proof).is_err());
    // Wrong recipient PK.
    let mut bad = pubs.clone();
    bad.pk2 = gin_mul(&Fs::rand(&mut rng));
    assert!(verify_evrf(&zk, &sid, &bad, &proof).is_err());
    // Wrong sid.
    assert!(verify_evrf(&zk, &SessionId([2u8; 32]), &pubs, &proof).is_err());
}

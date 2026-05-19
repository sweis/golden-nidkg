//! Micro-benchmark comparable to `fy/golden/bench_test.go::TestPerf`.
//!
//! Reports wall-clock for the major DKG operations so the BLS12-381+Bulletproofs
//! implementation can be put side-by-side with fy's BN254+PLONK one.
//!
//! ```sh
//! cargo run --release --example bench
//! ```

use std::collections::BTreeMap;
use std::time::Instant;

use golden_nidkg::curves::{gin_mul, Fs};
use golden_nidkg::dkg::{
    create_dealing, derive_session_id, verify_dealing, verify_dealings, DkgConfig,
};
use golden_nidkg::evrf::{eval_pad, Beta, SessionId};
use golden_nidkg::hash_to_curve::{h1, h2};
use golden_nidkg::schnorr::{verify_pki, RegisteredKey};
use golden_nidkg::zk::evrf_circuit::EvrfPeerInputs;
use golden_nidkg::zk::evrf_proof::{prove_evrf_batch, verify_evrf_batch, BatchPublicInputs};
use golden_nidkg::zk::ZkParams;
use rand::{rngs::StdRng, SeedableRng};

fn main() {
    let mut rng = StdRng::seed_from_u64(42);
    println!("# golden-nidkg micro-benchmarks (BLS12-381 G1 + Jubjub, Bulletproofs)\n");

    // ── eVRF pad derivation ──
    let sk_a = ark_ff::UniformRand::rand(&mut rng);
    let sk_b: Fs = ark_ff::UniformRand::rand(&mut rng);
    let pk_a = gin_mul(&sk_a);
    let pk_b = gin_mul(&sk_b);
    let sid = SessionId([1u8; 32]);
    let beta = Beta::from_seed(b"bench");
    let msg = b"msg";
    let iters = 100;
    let t0 = Instant::now();
    let mut last = None;
    for _ in 0..iters {
        last = Some(eval_pad(&sk_a, &pk_b, &sid, msg, &beta));
    }
    let pad_time = t0.elapsed() / iters;
    println!("eVRF pad derivation:      {pad_time:?}");
    let (out, wit) = last.unwrap();

    // ── ZK setup (one-time CRS hashing) ──
    let t0 = Instant::now();
    let zk = ZkParams::full(1);
    println!(
        "ZK setup (CRS, {} gens):  {:?}",
        zk.gens.gens_capacity,
        t0.elapsed()
    );

    // ── single-peer eVRF prove/verify ──
    let pubs = BatchPublicInputs {
        pk1: pk_a,
        h1m: h1(&sid.0, msg),
        h2m: h2(&sid.0, msg),
        beta: beta.0,
        peers: vec![EvrfPeerInputs {
            pk2: pk_b,
            r_commit: out.r_commit,
        }],
    };
    let t0 = Instant::now();
    let proof = prove_evrf_batch(&zk, &sid, &pubs, std::slice::from_ref(&wit), &mut rng).unwrap();
    println!("eVRF prove (1 peer):      {:?}", t0.elapsed());
    let proof_bytes = match &proof {
        golden_nidkg::zk::evrf_proof::EvrfProof::Full(p) => {
            (3 + 5 + 2 * p.ipp.l_vec.len()) * 48 + 5 * 32
        }
        _ => 0,
    };
    println!("eVRF proof size:          ~{proof_bytes} bytes");
    let t0 = Instant::now();
    for _ in 0..5 {
        verify_evrf_batch(&zk, &sid, &pubs, &proof).unwrap();
    }
    println!("eVRF verify (1 peer):     {:?}", t0.elapsed() / 5);

    // ── full DKG round 0 + verification, n=3 t=2 ──
    let (n, t) = (3u32, 2u32);
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
    let sid = derive_session_id(b"bench", n, t, &pki);
    let cfg = DkgConfig::new(n, t, sid);
    let t0 = Instant::now();
    let zk_n = ZkParams::full((n - 1) as usize);
    println!(
        "\n# DKG n={n}, t={t}\nZK setup ({} gens):    {:?}",
        zk_n.gens.gens_capacity,
        t0.elapsed()
    );

    let t0 = Instant::now();
    let mut dealings = BTreeMap::new();
    for rk in &registry {
        let (d, _) = create_dealing(rk, &sks[&rk.id], &cfg, &pki, &zk_n, &mut rng, None).unwrap();
        dealings.insert(rk.id, d);
    }
    let r0 = t0.elapsed();
    println!(
        "Round 0 ({n} dealings):     {r0:?}   (≈{:?} per dealing)",
        r0 / n
    );

    let t0 = Instant::now();
    for d in dealings.values() {
        verify_dealing(d, &cfg, &pki, &zk_n, false).unwrap();
    }
    let v = t0.elapsed();
    println!(
        "Verify {n} dealings (one-by-one): {v:?}   (≈{:?} per dealing)",
        v / n
    );

    let t0 = Instant::now();
    verify_dealings(&dealings, &cfg, &pki, &zk_n, false, &mut rng).unwrap();
    let v = t0.elapsed();
    println!(
        "Verify {n} dealings (batched):    {v:?}   (≈{:?} per dealing)",
        v / n
    );
}

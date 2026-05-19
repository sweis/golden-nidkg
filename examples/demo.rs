//! End-to-end demo of the Golden NIDKG protocol.
//!
//! Runs an `n`-party `t`-threshold DKG, including PKI registration,
//! per-party Round 0 dealings, public verification of every dealing by every
//! party, Round 1 decryption + aggregation, threshold reconstruction of the
//! group secret key, and a key refresh.
//!
//! Usage:
//! ```sh
//! cargo run --release --example demo                 # n=5, t=3, full ZK
//! cargo run --release --example demo -- 7 4          # n=7, t=4, full ZK
//! cargo run --release --example demo -- 5 3 quick    # n=5, t=3, quick mode (no real ZK)
//! ```

use ark_ec::AffineRepr;
use golden_nidkg::curves::{gout_mul, Fp};
use golden_nidkg::dkg::{
    check_output, complete, create_dealing, derive_session_id, refresh_dealing, verify_dealing,
    DkgConfig,
};
use golden_nidkg::schnorr::{verify_pki, RegisteredKey};
use golden_nidkg::shamir;
use golden_nidkg::zk::ZkParams;
use rand::thread_rng;
use std::collections::BTreeMap;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let t: u32 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or((n + 1) / 2 + 1);
    let quick = args.get(3).map(|s| s == "quick").unwrap_or(false);
    assert!(t >= 1 && t <= n, "require 1 ≤ t ≤ n");

    println!(
        "══ Golden NIDKG demo: n={n}, t={t}, mode={} ══",
        if quick { "quick (insecure)" } else { "full" }
    );

    let mut rng = thread_rng();

    // ── PKI registration ──
    println!("\n[1] PKI registration: {n} parties register Jubjub keypairs with Schnorr PoKs");
    let mut sks = BTreeMap::new();
    let mut registry = Vec::new();
    let mut pki = BTreeMap::new();
    for id in 1..=n {
        let (rk, sk) = RegisteredKey::fresh(id, &mut rng);
        sks.insert(id, sk);
        pki.insert(id, rk.pk);
        registry.push(rk);
    }
    verify_pki(&registry).expect("PKI verification");
    println!("    all PoKs verified, no key collisions");

    // ── ZK setup ──
    println!(
        "\n[2] Setting up ZK proof system (one-time CRS, sized for {n}-1 = {} recipients)…",
        n - 1
    );
    let setup_start = Instant::now();
    let zk = if quick {
        ZkParams::insecure_quick()
    } else {
        ZkParams::full((n - 1) as usize)
    };
    println!(
        "    {} mode, {} generator pairs, {:?}",
        if quick { "quick" } else { "full" },
        zk.gens.gens_capacity,
        setup_start.elapsed()
    );

    // ── Round 0: each party creates a dealing ──
    let sid = derive_session_id(b"demo", n, t, &pki);
    let cfg = DkgConfig::new(n, t, sid);
    println!("\n[3] Round 0: each party broadcasts an encrypted, publicly-verifiable dealing");
    let r0_start = Instant::now();
    let mut dealings = BTreeMap::new();
    let mut privates = BTreeMap::new();
    for rk in &registry {
        let t0 = Instant::now();
        let (d, p) =
            create_dealing(rk, &sks[&rk.id], &cfg, &pki, &zk, &mut rng, None).expect("dealing");
        let bytes = approx_dealing_size(&d);
        println!(
            "    party {} created dealing ({} ciphertexts, ≈{} kb, {:?})",
            rk.id,
            d.ciphertexts.len(),
            bytes / 1024,
            t0.elapsed()
        );
        dealings.insert(rk.id, d);
        privates.insert(rk.id, p);
    }
    println!("    Round 0 total: {:?}", r0_start.elapsed());

    // ── Public verification (any observer can do this) ──
    println!("\n[4] Public verification: any observer checks every dealing (batched MSM)");
    let v_start = Instant::now();
    verify_dealings(&dealings, &cfg, &pki, &zk, false, &mut rng).expect("verify");
    println!("    all {n} dealings verified in {:?}", v_start.elapsed());

    // ── Round 1: each party decrypts + aggregates ──
    println!("\n[5] Round 1: each party decrypts its shares and aggregates");
    let mut outputs = BTreeMap::new();
    for rk in &registry {
        let out =
            complete(rk, &sks[&rk.id], &cfg, &pki, &privates[&rk.id], &dealings).expect("round 1");
        assert!(
            check_output(&out, rk.id),
            "PK_i ≠ g^sk_i for party {}",
            rk.id
        );
        outputs.insert(rk.id, out);
    }
    let pk = outputs[&1].public_key;
    println!("    public key PK = {}", short_point(&pk));
    for rk in &registry {
        assert_eq!(
            outputs[&rk.id].public_key, pk,
            "party {} disagrees on PK",
            rk.id
        );
        for &l in pki.keys() {
            assert_eq!(
                outputs[&rk.id].public_key_shares[&l],
                outputs[&1].public_key_shares[&l]
            );
        }
    }
    println!("    all {n} parties agree on PK and the per-party PK shares");

    // ── Threshold reconstruction ──
    println!(
        "\n[6] Threshold reconstruction: {t} parties recover sk; {} parties cannot",
        t - 1
    );
    let shares_t: Vec<(u32, Fp)> = (1..=t).map(|i| (i, outputs[&i].secret_share)).collect();
    let sk = shamir::recover(t, &shares_t).expect("reconstruction");
    assert_eq!(gout_mul(&sk), pk, "reconstructed secret does not match PK");
    println!("    reconstructed sk; g_out^sk = PK ✓");
    if t > 1 {
        let shares_tm1: Vec<(u32, Fp)> = (1..t).map(|i| (i, outputs[&i].secret_share)).collect();
        // Lying about the threshold to force interpolation with t-1 points yields garbage.
        let bad = shamir::recover(t - 1, &shares_tm1).expect("forced");
        assert_ne!(gout_mul(&bad), pk);
        println!(
            "    {t}-1 = {} parties produce a wrong key (as expected)",
            t - 1
        );
    }

    // ── Key refresh (Section 5.2) ──
    println!("\n[7] Proactive refresh: re-share with ω_i = 0; PK is unchanged but shares rotate");
    let sid2 = derive_session_id(b"demo-refresh", n, t, &pki);
    let cfg2 = DkgConfig::new(n, t, sid2);
    let mut refresh_dealings = BTreeMap::new();
    let mut refresh_privates = BTreeMap::new();
    for rk in &registry {
        let (d, p) =
            refresh_dealing(rk, &sks[&rk.id], &cfg2, &pki, &zk, &mut rng).expect("refresh dealing");
        refresh_dealings.insert(rk.id, d);
        refresh_privates.insert(rk.id, p);
    }
    for d in refresh_dealings.values() {
        verify_dealing(d, &cfg2, &pki, &zk, true).expect("refresh verify");
    }
    let mut new_outputs = BTreeMap::new();
    for rk in &registry {
        let delta = complete(
            rk,
            &sks[&rk.id],
            &cfg2,
            &pki,
            &refresh_privates[&rk.id],
            &refresh_dealings,
        )
        .expect("refresh round 1");
        // The refresh delta has PK = g^0 = identity; the new share is the old + delta.
        assert!(delta.public_key.is_zero());
        new_outputs.insert(rk.id, outputs[&rk.id].secret_share + delta.secret_share);
    }
    let new_shares: Vec<(u32, Fp)> = (1..=t).map(|i| (i, new_outputs[&i])).collect();
    let sk_new = shamir::recover(t, &new_shares).expect("refresh reconstruction");
    assert_eq!(sk_new, sk, "refresh changed the group secret!");
    let mut changed = false;
    for id in 1..=n {
        if new_outputs[&id] != outputs[&id].secret_share {
            changed = true;
        }
    }
    assert!(changed, "refresh did not rotate any shares");
    println!("    new shares interpolate to the same sk; shares are rotated ✓");

    println!("\n══ done ══");
    println!("    PK             = {}", short_point(&pk));
    println!("    sk (recovered) = {}", short_fp(&sk));
    println!("    party PKs:");
    for id in 1..=n {
        println!(
            "      PK_{} = {} (g^sk_{} = {})",
            id,
            short_point(&outputs[&id].public_key_shares[&id]),
            id,
            short_point(&gout_mul(&outputs[&id].secret_share))
        );
    }
}

fn short_point(p: &golden_nidkg::GoutAffine) -> String {
    use ark_serialize::CanonicalSerialize;
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).unwrap();
    format!("0x{}…", hex_prefix(&buf, 8))
}
fn short_fp(p: &Fp) -> String {
    use ark_serialize::CanonicalSerialize;
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).unwrap();
    format!("0x{}…", hex_prefix(&buf, 8))
}
fn hex_prefix(b: &[u8], n: usize) -> String {
    b.iter().take(n).map(|x| format!("{x:02x}")).collect()
}

/// Rough serialized size (compressed points + scalars) for the demo printout.
fn approx_dealing_size(d: &golden_nidkg::Dealing) -> usize {
    let pt = 48; // compressed BLS12-381 G1
    let sc = 32; // Fp scalar
    let proof_sz = match &d.proof {
        golden_nidkg::zk::evrf_proof::EvrfProof::Full(p) => {
            // A_I, A_O, S, T_1..T_6 + IPA L/R + 3 scalars
            (3 + 5 + 2 * p.ipp.l_vec.len()) * pt + 3 * sc
        }
        golden_nidkg::zk::evrf_proof::EvrfProof::InsecureQuick(v) => v.len() * (pt + sc),
    };
    32 + d.commitment.len() * pt + d.ciphertexts.len() * (pt + sc) + proof_sz
}

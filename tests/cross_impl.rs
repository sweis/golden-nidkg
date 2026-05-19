//! Cross-implementation comparison against `f3rmion/fy/golden` (Go, BN254 G1 +
//! Baby Jubjub + gnark/PLONK).
//!
//! The two implementations use **different curve pairs** (BLS12-381/Jubjub vs
//! BN254/Baby-Jubjub) and the underlying Baby-Jubjub parameterisations differ
//! between `gnark-crypto` (`a = -1`) and `arkworks` (`a = 1`), so most
//! intermediate values cannot be compared byte-for-byte.  What *can* be
//! compared:
//!
//! * **Shamir polynomial evaluation** with small-integer coefficients and
//!   indices is field-independent (the values fit in any prime field large
//!   enough), so the share values must match numerically.
//! * **Structural** behaviours (pad symmetry, identity rejection,
//!   commitment-length checks).
//!
//! Test vectors are in `tests/fy_test_vectors.txt`, regenerated with
//! `go run ./cmd/testvectors/` against the fy `golden` package.
use rand::SeedableRng;

use golden_nidkg::curves::Fp;
use golden_nidkg::shamir::{recover, share, Polynomial};
use golden_nidkg::vss;

/// Shamir share evaluation for `f(Z) = 42 + 3Z + 7Z²` at `Z = 1..5`.
/// fy emits:
///   share[1] = 0x34 = 52
///   share[2] = 0x4c = 76
///   share[3] = 0x72 = 114
///   share[4] = 0xa6 = 166
///   share[5] = 0xe8 = 232
#[test]
fn shamir_small_integer_eval_matches_fy() {
    let coeffs = [Fp::from(42u64), Fp::from(3u64), Fp::from(7u64)];
    let poly = Polynomial::from_coeffs(coeffs.to_vec());
    let expected = [52u64, 76, 114, 166, 232];
    for (i, &e) in expected.iter().enumerate() {
        let z = Fp::from((i + 1) as u64);
        assert_eq!(
            poly.evaluate(z),
            Fp::from(e),
            "f({}) should be {}",
            i + 1,
            e
        );
    }
    // Recovering from t = 3 shares must yield the secret.
    let shares: Vec<(u32, Fp)> = (1u32..=3)
        .map(|i| (i, poly.evaluate(Fp::from(i))))
        .collect();
    assert_eq!(recover(3, &shares).unwrap(), Fp::from(42u64));
}

/// Feldman VSS commitments for the same polynomial: `A[i] = g_out^{a_i}`.
/// (We can't compare the *bytes* against fy's BN254 output, but we can
/// confirm that the share-commitment derivation matches the polynomial.)
#[test]
fn feldman_vss_consistent_with_shamir() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    let secret = Fp::from(42u64);
    let (poly, shares) = share(secret, 5, 3, &mut rng);
    let c = vss::commit(&poly);
    assert_eq!(c.len(), 3);
    for (j, s) in shares {
        assert!(vss::verify_share(&c, j, s));
    }
}

/// Verify that the pad-derivation symmetry property holds (Sec. 4.3 of the
/// paper).  Both implementations rely on `S = sk_a · PK_b = sk_b · PK_a`.
#[test]
fn pad_symmetry_invariant() {
    use golden_nidkg::curves::{gin_mul, Fs};
    use golden_nidkg::evrf::{eval_pad, Beta, SessionId};
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    use ark_ff::UniformRand;
    let sk_a = Fs::rand(&mut rng);
    let sk_b = Fs::rand(&mut rng);
    let pk_a = gin_mul(&sk_a);
    let pk_b = gin_mul(&sk_b);
    let sid = SessionId([3u8; 32]);
    let beta = Beta::from_seed(b"x");
    let (out_ab, _) = eval_pad(&sk_a, &pk_b, &sid, b"m", &beta);
    let (out_ba, _) = eval_pad(&sk_b, &pk_a, &sid, b"m", &beta);
    assert_eq!(out_ab.r, out_ba.r);
    assert_eq!(out_ab.r_commit, out_ba.r_commit);
}

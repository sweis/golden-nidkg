# golden-nidkg

A reference implementation of **Golden: Lightweight Non-Interactive Distributed
Key Generation** (Bünz, Choi, Komlo — [ePrint 2025/1924](https://eprint.iacr.org/2025/1924)).

Golden is a one-round (broadcast) DKG that outputs Shamir secret shares of a
field element `sk ∈ Z_p` and a public key `PK = g^sk` to `n` participants with
threshold `t`.  Public verifiability is achieved without ElGamal/Paillier/class-
group encryption — each pairwise Shamir share is encrypted with a one-time pad
derived from a Diffie-Hellman shared secret via a *two-party exponent VRF*, and
a Bulletproofs proof binds the pad to its commitment so any third party can
verify every dealing.

> ⚠️ **Reference implementation only.**  Side-channel resistance, constant-time
> hash-to-curve, and a third-party audit are out of scope.  Do not deploy.

## Quick start

```sh
cargo run --release --example demo                 # 5-of-3 with full ZK proofs
cargo run --release --example demo -- 7 4          # custom n, t
cargo run --release --example demo -- 5 3 quick    # protocol-only, no real ZK
cargo test --release                               # all tests except slow ZK
cargo test --release -- --ignored                  # full-ZK round-trips (~60s)
```

## What the demo does

1. **PKI registration** — each party generates a Jubjub keypair `(sk_i^I, PK_i^I)`
   and registers it with a Schnorr proof of knowledge bound to its identity.
2. **Round 0** — each party builds a degree-`(t-1)` Shamir polynomial,
   Feldman-commits it, encrypts every peer's share with an eVRF pad, and
   broadcasts `(msg_i, C_i, {(R_{ij}, z_{ij}, π_{ij})})`.
3. **Public verification** — anyone re-derives each `X_{jk} = g^{f_j(k)}` from
   the Feldman commitment and checks `g^{z_{jk}} = R_{jk} · X_{jk}` and the
   Bulletproofs proof that `R_{jk}` is the right pad commitment.
4. **Round 1** — each party re-derives its own pads, decrypts and aggregates
   `sk_i = Σ_j x_{ji}`, derives `PK = ∏_j A_{j,0}` and `PK_l = ∏_j X_{jl}`.
5. **Threshold reconstruction** — the demo recovers `sk` from `t` shares,
   checks `g^sk = PK`, and that `t-1` shares cannot.
6. **Proactive refresh** — re-runs with `ω_i = 0`; shares rotate, `sk` and `PK`
   are preserved.

## Layout

| Path                       | Contents |
|----------------------------|----------|
| `src/curves.rs`            | Jubjub (`G_in`) over BLS12-381 G1 (`G_out`) type aliases. |
| `src/shamir.rs`            | Shamir share/recover, Lagrange interpolation. |
| `src/vss.rs`               | Feldman VSS commit + share-commitment derivation. |
| `src/schnorr.rs`           | Schnorr PoK over `G_in` for PKI registration (rogue-key safe). |
| `src/hash_to_curve.rs`     | Try-and-increment hash-to-Jubjub. |
| `src/evrf.rs`              | Two-party exponent VRF (DH pad derivation + LHL). |
| `src/zk/`                  | Bulletproofs R1CS over BLS12-381 G1 + the `R_eVRF` circuit. |
| `src/dkg.rs`               | Round 0 / verify / Round 1. |
| `examples/demo.rs`         | End-to-end demo (above). |
| `tests/dkg.rs`             | Protocol & adversarial integration tests. |
| `tests/zk_full.rs`         | Full-ZK round-trips (`--ignored`). |
| `BUGS.md`                  | Issues found in the paper. |
| `CLAUDE.md`                | Project notes for future sessions. |

## Why a hand-rolled Bulletproofs R1CS?

Golden's `R_eVRF` circuit lives over `F_p` = the BLS12-381 scalar field
(= Jubjub's base field), so the Bulletproofs proof must commit over BLS12-381
`G1`.  No published Rust Bulletproofs library does this:

* `bulletproofs` (dalek) — Ristretto only; the 5.x R1CS module is also broken.
* `bulletproofs-bls` (zkcrypto) — targets BLS12-381, but its `yoloproofs`
  (R1CS) feature does not compile against any `blstrs_plus`/`bls12_381_plus`
  version.
* `ark-bulletproofs` — secq256k1/Zorro.

`src/zk/{ipa,r1cs,bp_r1cs}.rs` is a ~600-line port of the dalek `yoloproofs`
design (Bulletproofs §5 / BCC+16) to arkworks.  It is unit-tested against
tampered witnesses, and the `R_eVRF` circuit test verifies a full 255-bit proof
round-trip and rejects a tampered `R`.

## Performance (4-core x86-64, `--release` with `parallel`, `λ = 255`)

| Operation              | n=3, t=2 | n=5, t=4 | Notes |
|------------------------|----------|----------|-------|
| ZK CRS setup           | ~1.3 s   | ~3 s     | Hash-to-G1 for `2·gens` generators; one-time per `n`. |
| Dealing (Round 0)      | ~3.1 s   | ~8.4 s   | One batched eVRF proof per dealer. |
| Verify one dealing     | ~145 ms  | ~250 ms  | Circuit reconstruction + single MSM. |
| Verify all `n` (batch) | ~45 ms/d | ~56 ms/d | `verify_dealings` — parallel circuit builds + one MSM, §5.3. |
| Round 1                | <1 ms    | <1 ms    | |

The implementation uses the *batched* protocol from §5.3 of the paper:

* **batched proving** — one Bulletproofs proof per dealer covers all `n-1`
  evaluations, sharing the dealer's `sk` bit decomposition and `g_in^{sk}`
  gadget.  For `n=5` this is ≈13.4 k mul gates (16 384 generator pairs); each
  additional recipient adds ~3.1 k gates.
* **batched verification** — `verify_dealings()` reconstructs each dealing's
  verification circuit in parallel, then combines the resulting MSM
  coefficients with Fiat–Shamir-derived weights into a single MSM over the
  shared `G[]/H[]` Bulletproofs generators.  The combiners are deterministic
  so every observer accepts the same set, and a colluding pair of dealers
  cannot pre-compute proofs whose residues cancel (`BUGS.md §13`).

The `R_eVRF` circuit uses 3-bit-window scalar multiplication (≈3.4 mul gates
per scalar bit) and a chained `< p` comparison to make the `int(S.x)`
decomposition canonical (see `BUGS.md §10`).

A side-by-side comparison with `f3rmion/fy/golden` (a Go implementation of
Golden over BN254 + Baby Jubjub + gnark/PLONK) is in `COMPARISON.md`.

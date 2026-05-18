# CLAUDE.md — Notes for working on golden-nidkg

## What this project is

A reference implementation of **Golden: Lightweight Non-Interactive Distributed Key
Generation** (Bünz, Choi, Komlo — IACR ePrint 2025/1924,
https://eprint.iacr.org/2025/1924.pdf).

Golden is a one-round (broadcast) DKG that outputs Shamir secret shares of a
field element `sk ∈ Z_p` and a public key `PK = g^sk`.  Public verifiability is
achieved without ElGamal/Paillier/class-group encryption.  Instead, a *two-party
exponent VRF (eVRF)* built on Diffie-Hellman + a ZK proof produces a one-time
pad to encrypt each pairwise Shamir share.

This repo contains:
* `src/` — the Rust library (workspace below)
* `BUGS.md` — analysis of issues found in the paper
* `CLAUDE.md` — this file (notes for future sessions)

## Big picture of the protocol

Two curves:
* `G_in`  ⊆ E(F_p), prime order `s` — the **embedded curve** (we use Jubjub,
  `ark-ed-on-bls12-381`).  PKI keys `(sk_i^I, PK_i^I = g_in^{sk_i^I})` live
  here.  Diffie-Hellman secrets `S = PK_j^{sk_i}` live here.
* `G_out`, order `p` — the **outer curve** (we use BLS12-381 `G1`).  The DKG
  output `PK ∈ G_out`, the Feldman VSS commitments `A_l = g_out^{a_l}`, and the
  pad commitments `R = g_out^r` live here.  `p` equals `F_r` (the BLS12-381
  scalar field), which is also the base field of Jubjub.  This is the
  arrangement that makes the ZK circuit native.

eVRF: the pad shared between parties `i` and `j` (sender `i`) is derived
deterministically from the Diffie-Hellman shared secret and `i`'s nonce:

```
S    = PK_j^{sk_i}                 (Jubjub point, same as PK_i^{sk_j})
k    = int(S.x)                    (an integer in [0, p))
T1   = H1(msg_i)^k                 (Jubjub point; H1 hashes to G_in)
T2   = H2(msg_i)^k
r1   = int(T1.x), r2 = int(T2.x)
r    = beta * r1 + r2  (mod p)     (the pad)
R    = g_out^r                     (commitment to the pad, in G_out)
```

`beta ∈ F_p` is a public CRS constant.  Symmetry of `S` ⇒ recipient `j` can
re-derive the same `r`.

Round 0 (each party `i`):
1. `omega_i ← Z_p`; build degree-`(t-1)` polynomial `f_i` with `f_i(0)=omega_i`.
2. Feldman commitment `C_i = (A_{i,0}, …, A_{i,t-1})` with `A_{i,l} = g_out^{a_l}`.
3. Pick random nonce `msg_i ∈ {0,1}^λ`.
4. For each `j ≠ i`: derive pad `(r_{ij}, R_{ij}, π_{ij}) ← eVRF.Eval(sk_i^I, (msg_i, PK_j^I))`.
5. Encrypt: `z_{ij} ← r_{ij} + f_i(j)`.
6. Keep `f_i(i)` as own share.
7. Broadcast `(msg_i, C_i, {(R_{ij}, z_{ij}, π_{ij})}_{j≠i})`.

Round 1 (each party `i`):
1. For all `j ≠ i`, all `k ≠ j`:
   * Verify `eVRF.Verify(PK_j, (msg_j, PK_k), R_{jk}, π_{jk})`.
   * Compute Feldman share commitment `X_{jk} = ∏_l A_{j,l}^{k^l} = g_out^{f_j(k)}`.
   * Check `g_out^{z_{jk}} == R_{jk} · X_{jk}`.  (this is the *public*
     verification — anyone, including non-participants, can do it)
2. For all `j ≠ i`: re-derive pad `r_{ji} ← eVRF.Eval(sk_i^I, (msg_j, PK_j^I))`,
   recover share `x_{ji} ← z_{ji} - r_{ji}`.
3. Aggregate: `sk_i ← ∑_j x_{ji}`.
4. `PK ← ∏_j A_{j,0}`; `PK_l ← ∏_j X_{jl}` for each `l`.

## Key implementation decisions

* **Curves**: Jubjub (embedded, `G_in`) over BLS12-381 G1 (outer, `G_out`).
  `ark-ed-on-bls12-381` for Jubjub, `ark-bls12-381` for the outer curve.
* **ZK proof for `R_eVRF`**: Bulletproofs R1CS over BLS12-381 G1 with the
  Pedersen-commitment-linking trick (see below).  The pad `r` is bound to
  `R = g_out^r` by making `R` a "high-level" V-commitment with zero blinding.
  The circuit (over `F_p`) proves the rest of the eVRF computation natively
  (Jubjub scalar mults are over `F_p`).
* **Why a hand-rolled Bulletproofs R1CS?** No published Rust Bulletproofs
  library can produce R1CS proofs over BLS12-381 G1 (which is required because
  Jubjub's base field is the BLS12-381 scalar field).  See `src/zk/mod.rs` for
  the survey: `bulletproofs` (dalek) is Ristretto-only and its R1CS module is
  broken in 5.x; `bulletproofs-bls` (zkcrypto) targets BLS12-381 but its
  `yoloproofs` (R1CS) feature does not compile against any `blstrs_plus` /
  `bls12_381_plus` version; `ark-bulletproofs` is secq256k1/Zorro.  The
  ~600-line `bp_r1cs.rs` is a careful port of the dalek `yoloproofs` design.
* **PKI registration**: Schnorr proof of knowledge of `sk_i^I` over Jubjub,
  with the prover identity bound into the Fiat-Shamir transcript (rogue-key
  & key-replay protection).
* **Hashing**: domain-separated SHA-256 via Merlin transcripts; hash-to-curve
  on Jubjub via try-and-increment or RFC 9380 SSWU (Jubjub is twisted Edwards
  with no published RFC SSWU; we use Elligator2 / try-and-increment).
* **Indices**: participant indices are **1-based** so that `f(0)` is the secret.

## Layout

```
src/
  lib.rs              public API surface, re-exports
  curves.rs           type aliases and helpers for Jubjub + BLS12-381
  shamir.rs           Shamir Share/Recover, Lagrange interpolation
  vss.rs              Feldman VSS commit + share-commitment derivation
  schnorr.rs          Schnorr PoK over G_in for PKI registration
  hash_to_curve.rs    deterministic hash-to-Jubjub
  evrf.rs             two-party eVRF: pad derivation + (proof types)
  transcript.rs       Merlin-based Fiat-Shamir transcript helpers
  errors.rs           error types
  zk/
    mod.rs            survey of why a hand-rolled BP is needed; re-exports
    generators.rs     Pedersen generator vectors for Bulletproofs (CRS)
    r1cs.rs           constraint system + linear combinations
    ipa.rs            inner-product argument
    bp_r1cs.rs        Bulletproofs R1CS prover/verifier
    gadgets.rs        bit decomposition, embedded-curve scalar mult (3-bit window)
    evrf_circuit.rs   the R_eVRF circuit (single + batched)
    evrf_proof.rs     ZkParams, prove/verify_evrf_batch, EvrfProof
  dkg.rs              Round0/Round1, dealing/verify/complete, refresh
examples/
  demo.rs             end-to-end demo: n-party DKG, verification, recovery, refresh
tests/
  dkg.rs              protocol & adversarial integration tests (quick mode)
  zk_full.rs          full-ZK round-trips (`#[ignore]`d, run with `--ignored`)
```

## Building & testing

```
cargo build
cargo test                                # quick protocol + circuit tests
cargo test --release -- --ignored         # full-ZK round-trips (~30s)
cargo run --release --example demo                  # default n=5, t=4
cargo run --release --example demo -- 3 2           # custom n, t
cargo run --release --example demo -- 5 3 quick     # protocol-only, no real ZK
```

## Status / TODO

- [x] Project skeleton, CLAUDE.md, BUGS.md
- [x] Curve types, Shamir, Feldman VSS, Lagrange
- [x] Schnorr PoK for PKI (identity-bound, replay/rogue-key safe)
- [x] Hash-to-curve (Jubjub)
- [x] eVRF pad derivation + symmetry test
- [x] DKG Round0 / verify / Round1
- [x] Bulletproofs R1CS infrastructure (transcript, IPA, prover/verifier)
- [x] Embedded-curve gadgets + R_eVRF circuit
- [x] Wire ZK proof into eVRF / DKG
- [x] End-to-end demo binary
- [x] Negative tests (tampered share, tampered VSS commitment, tampered proof,
      tampered R, replay)
- [x] Threshold reconstruction test (`t` parties recover `sk`, `t-1` cannot)
- [x] Key refresh (`omega_i = 0`)
- [x] Batched eVRF proof (Section 5.3): one proof per dealer, shared `sk` gadget
- [x] 3-bit window scalar mult gadget + Karatsuba `add_var` (~3.4 muls/bit)
- [x] Parallel IPA fold + parallel CRS setup (`--features parallel`, default on)
- [ ] Key resharing / membership change (Section 5.2 mentions this is supported
      via the same machinery as refresh; not implemented here)
- [ ] Constant-time hash-to-curve (current impl is try-and-increment)
- [ ] Serialization (`ark-serialize` / `borsh`) for `Dealing`, `EvrfProof`, etc.
- [ ] Aggregate the cheap `g^z = R · X` check into one MSM
- [ ] Batch-verification of multiple dealings' Bulletproofs (random linear
      combination across proofs — Section 5.3 mentions ~30% verifier savings)

## Notes & gotchas (see BUGS.md for paper-level findings)

* Could not retrieve the actual PDF from eprint.iacr.org in this sandbox
  (network policy).  Protocol details were reconstructed from:
  - the IACR abstract & web search snippets,
  - the author's blog post summary,
  - a third-party implementer's notes which quote Figure 4 verbatim
    (`https://github.com/farazshaikh/golden-rs/blob/main/papers/golden_dkg.md`),
  - the antecedent eVRF paper (Boneh–Haitner–Lindell–Segev, 2024/397).
  Where the implementation depends on a paper detail I could not verify
  directly, there is a `// PAPER:` comment.  If you can fetch the PDF,
  reconcile against Figure 3 (R_eVRF) and Figure 4 (Π_Golden).
* The eVRF circuit's `R = g_out^r` constraint is **not** done in-circuit —
  `R` is bound via a high-level Pedersen commitment in Bulletproofs R1CS
  (zero blinding).  This is the trick from the eVRF paper that keeps the
  circuit at ~14λ constraints instead of doing non-native G_out arithmetic.
* The Schnorr PoK *must* bind the registrant identity (and ideally a session
  string) in the FS challenge — see BUGS.md §1 on key-duplication / replay.
* Jubjub is a twisted Edwards curve.  Negation is `−(x,y) = (−x,y)`, so `.x`
  is **injective on the prime-order subgroup**: `(x, y)` and `(x, −y)` differ
  by the 2-torsion `(0, −1)`, which is not in the odd-order subgroup.  This is
  *better* than short-Weierstrass where `.x` is 2-to-1 — see BUGS.md §2.
* The `k = int(S.x)` bit decomposition must be **canonical** (`Σ b_i 2^i < p`).
  A naive `≡ mod p` constraint admits `k + p`, which derives a *different*
  pad from `k` and lets a malicious dealer pass public verification while the
  recipient gets an undecryptable share.  This implementation adds a chained
  `< p` comparison (`bit_decompose_canonical`).  See BUGS.md §10.  The `sk`
  decomposition does *not* need it (any of its valid integer representatives
  produce identical embedded-curve exponentiations).

## Reproducing the analysis / sources

Web search confirmed authors, abstract, performance numbers.  The protocol
listing was cross-checked against the third-party `golden-rs` repo, which
quotes the paper's Figure 4 line-by-line.  The eVRF construction was further
cross-checked against the abstract of "Exponent-VRFs and Their Applications"
(Boneh, Haitner, Lindell, Segev — ePrint 2024/397, EUROCRYPT 2025), which
introduced eVRFs and the linking technique.

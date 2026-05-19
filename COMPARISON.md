# Comparison with `f3rmion/fy/golden` (Go)

`f3rmion/fy/golden` is an independent Go implementation of the Golden NIDKG
protocol (https://github.com/f3rmion/fy/tree/main/golden).  It targets a
different curve pair and ZK proof system, so the two implementations cannot be
test-vector-compatible end-to-end, but they implement the same protocol and the
abstract behaviours can be cross-checked.  This document records the comparison.

## At a glance

| Dimension                | golden-nidkg (this repo)     | f3rmion/fy/golden               |
|--------------------------|------------------------------|----------------------------------|
| Language                 | Rust                         | Go                               |
| `G_in` (DH curve)        | Jubjub (`a=−1` twisted Ed.)  | Baby Jubjub (`a=−1`, gnark form) |
| `G_out` (commitment)     | BLS12-381 G1                 | BN254 G1                         |
| ZK proof system          | Bulletproofs R1CS (transparent) | PLONK + KZG (Aztec Ignition trusted SRS) |
| `R = g_out^r` in circuit | No — Pedersen-linking (zero-blind V-commitment) | Yes — emulated BN254 G1 (`sw_emulated`) |
| Proof batching (§5.3)    | Yes — one proof / dealer     | No — one proof / (dealer, recipient) |
| Constraint count (1 peer)| ≈ 4 200 R1CS muls            | ≈ 238 200 PLONK constraints      |
| Proof size (1 peer)      | ≈ 1.8 kB (`O(log n)`)        | ≈ 0.6 kB (constant)              |
| Setup                    | hash-to-curve CRS, transparent | gnark compile + trusted SRS    |
| Schnorr PoK binding      | `(id ‖ PK ‖ R)`              | `(sid ‖ PK ‖ R)` — *not* `id`   |
| Duplicate-PK rejection   | Yes (`schnorr::verify_pki`)  | Not in package; caller's job     |
| LHL coefficient          | CRS constant `β`             | per-session `α = H(sid)`         |
| LHL formula              | `r = β·T₁.x + T₂.x`          | `pad = P₁.x + α·P₂.x`            |

## Test vectors

Cross-checking test vectors requires both implementations to run on the same
curve pair.  They don't:

* fy uses BN254 Fr as `F_p`; golden-nidkg uses BLS12-381 Fr.
* Even over BN254, the Baby Jubjub parameterisation differs between
  `gnark-crypto` (`a = −1`, generator `(9671717…, 16950150…)`) and
  `arkworks ark-ed-on-bn254` (`a = 1`, generator `(19698561…, 19298250…)`).
  The curves are isomorphic but the coordinate systems differ.

What *can* be cross-checked numerically is captured in `tests/cross_impl.rs`:

* **Shamir polynomial evaluation** with small-integer coefficients — the
  shares of `f(Z) = 42 + 3Z + 7Z²` at `Z = 1..5` are `52, 76, 114, 166, 232`
  in *any* large-enough prime field.  fy emits the same values
  (`tests/fy_test_vectors.txt`).
* **Pad symmetry** — `eval_pad(sk_a, PK_b) == eval_pad(sk_b, PK_a)`.  Both
  implementations rely on the DH symmetry; both pass.
* **Identity rejection** — both reject a degenerate (identity) DH secret.

The rest of `tests/fy_test_vectors.txt` (eVRF intermediates, hash-to-curve
outputs, VSS commitments) is BN254/Baby-Jubjub-specific and is recorded for
reference only.  Regenerate with `go run ./cmd/testvectors/` against the fy
checkout.

## Performance (4-core x86-64, both builds with default optimisations)

`golden-nidkg`: `cargo run --release --example bench`
`fy`: `go test ./golden/ -run TestPerf` with `unsafekzg` SRS (so the SRS
download cost is excluded).

| Operation                        | golden-nidkg | fy (Go)      | ratio     |
|----------------------------------|--------------|--------------|-----------|
| eVRF pad derivation              | 0.65 ms      | 0.80 ms      | 1.2× faster |
| ZK setup (one-time)              | 1.5 s        | 11.4 s       | 7.6× faster |
| eVRF prove (1 peer)              | 3.3 s        | 7.9 s        | 2.4× faster |
| eVRF verify (1 peer)             | 147 ms       | 3.0 ms       | **49× slower** |
| Round 0 (n=3, 3 dealers)         | 10.3 s       | 49.8 s       | 4.8× faster |
| Verify 3 dealings (one-by-one)   | 463 ms       | 18 ms        | **26× slower** |
| Verify 3 dealings (batched MSM)  | 249 ms       | —            | **14× slower** |
| Proof size (1 peer)              | ≈ 1.8 kB     | 584 B        | 3.1× larger |

Take-aways:

* **golden-nidkg is faster at proving** despite the heavier curve, because the
  circuit is ~60× smaller (no in-circuit `R = g^r`) and proofs are batched.
* **fy is much faster at verifying** because PLONK verification is `O(1)` MSM
  + a few pairings, while Bulletproofs verification is `O(N)` MSM (`N` ≈ 8 k–32 k
  group elements).  This is the **structural cost** of choosing a transparent
  SNARK over a trusted-setup one.
* fy's setup is dominated by gnark circuit compilation (~10 s for 238 k
  constraints).  golden-nidkg's setup is hash-to-curve for the Bulletproofs
  generator vectors.

The verification gap is the area that warrants optimisation in golden-nidkg.
Mitigations applied:

1. *Batch verification of multiple dealings' proofs* (§5.3 of the paper) —
   `verify_dealings()` collects each dealing's verification coefficients,
   takes a random linear combination, and runs **one** MSM over the shared
   `G[0..n]/H[0..n]` generators plus a small per-proof tail.  Implemented
   (`bp_r1cs::verify_batch`); ~1.9× faster at `n=3` and the savings grow
   with `n` because the shared-generator MSM is amortised across dealers.
2. *Parallel MSM and IPA fold* — on by default under `--features parallel`.
3. *Pre-allocated MSM buffers, batched curve normalisation, cached offset
   point* (`OnceLock`).

Remaining gap is structural — closing it would require switching to a
constant-size SNARK (and accepting a trusted setup, which the paper considered
and rejected; Section 3.4).

## Discrepancies / observations about `fy/golden`

### F1. Schnorr PoK does not bind the registrant's identity
`pki.go::ProveIdentity` computes the Fiat–Shamir challenge as
`c = H("golden-pki-pok" ‖ sid ‖ PK ‖ R)`.  The dealer's `NodeID` is **not** in
the transcript.  Consequently a proof for `PK` can be replayed under a
different `NodeID` *within the same session*.  Combined with the lack of a
duplicate-PK check anywhere in the `golden` package, an adversary who can
register an arbitrary `(NodeID, PK)` mapping into the application's PKI can
mount the share-recovery attack described in `BUGS.md §1` (two recipients with
the same `PK` get the same eVRF pad from every dealer; the public broadcast
then leaks `f_j(k₁) − f_j(k₂)`).  The session-ID binding only blocks
*cross-session* replay.  This implementation binds the registrant `id` into
the Schnorr challenge (`schnorr.rs`) and additionally rejects PKI snapshots
with duplicate or negated keys (`schnorr::verify_pki`).

Severity: depends on the surrounding application.  Worth flagging upstream.

### F2. LHL coefficient is per-session, not a CRS constant
fy derives `α = HashToScalar("golden-lhl-alpha" ‖ sid)`.  The paper presents
`β` as a public CRS constant.  In the random-oracle model both work (the seed
is statistically independent of the DH source either way), but a CRS constant
makes the leftover-hash-lemma argument cleaner because the seed is fixed
*before any party samples a key*.  Not a bug, but a deviation from the paper.

### F3. LHL combination has the coefficient on the second term
fy: `pad = x₁ + α·x₂`.  Paper / golden-nidkg: `r = β·r₁ + r₂` (the coefficient
is on `T₁.x`).  Both are valid universal-hash extractors, but they produce
*different* pads, so the formulas are not interchangeable.  Note this in case
anyone tries to make the implementations interoperate.

### F4. `R = g_out^r` proven in-circuit via emulated BN254 G1
fy implements the *alternative construction* (the paper's Appendix E): the
`R = pad · G` constraint is enforced inside the SNARK using
`gnark/std/algebra/emulated/sw_emulated` non-native arithmetic.  This is what
inflates the circuit from the paper's `≈14λ ≈ 3.6 k` to `≈238 k` constraints.
The paper's main construction (and golden-nidkg) avoids this with the
Pedersen-commitment linking trick.  Not a soundness issue, but it makes
proving ≈10× slower per pad than necessary.

### F5. No batched eVRF proof
fy generates one ~238 k-constraint PLONK proof per `(dealer, recipient)` pair.
The paper's §5.3 batching (and golden-nidkg) shares the `sk` decomposition and
`g_in^{sk}` gadget across all `n−1` recipients, reducing both proof count and
prover work.  Not a soundness issue.

### F6. Canonical bit decomposition for `int(S.x)` not visibly enforced
`evrf_circuit.go` uses gnark's `twistededwards.ScalarMul(h₁, s)` with
`s = S.X` as a native `Fr` variable, with the comment that "the gnark
twistededwards ScalarMul gadget correctly handles" the `mod l` reduction.  The
algebra is fine for *honest* `s`, but BUGS.md §10 explains that a 254-bit
decomposition (`gnark.api.ToBinary`) of an `F_r` value over BN254 admits two
valid integer pre-images for ≈30 % of `s` values — `s` and `s + r`.  Whether
gnark's `ToBinary`/`twistededwards.ScalarMul` adds a strict `< r` range check
is not visible from the fy code.  If it does not, fy has the same soundness
gap as the one fixed in this repo's `bit_decompose_canonical`.

Severity: needs verification against gnark internals; flagged as a question.

### Where golden-nidkg is weaker
* **Verification time** — Bulletproofs is structurally `O(N)`-verifier;
  PLONK is `O(1)`.  Mitigated by batch-verification of dealings (TODO).
* **Proof size** — `O(log N)` (~1.8 kB) vs constant (~0.6 kB).
* **Trusted setup** is *not needed* in golden-nidkg, which is the Bulletproofs
  trade-off the paper made deliberately (Section 3.4).

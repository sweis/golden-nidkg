# BUGS.md — Errors, flaws, and concerns in *Golden: Lightweight Non-Interactive Distributed Key Generation* (ePrint 2025/1924)

> **Caveat about sourcing.** The eprint.iacr.org PDF could not be fetched from
> this sandbox (outbound network policy).  The analysis below is reconstructed
> from the public abstract, the authors' blog post, a third-party implementer's
> line-by-line notes that quote Figure 3 (`R_eVRF`) and Figure 4 (`Π_Golden`)
> verbatim, and the antecedent eVRF paper (ePrint 2024/397).  Item severity is
> hedged accordingly: where I cannot see the exact wording, I describe the
> *class* of issue and what to check in the PDF.  Items 1–4 are protocol-level
> and are reproduced as failing/passing tests in this repo.

---

## 1. Identity binding in the PKI registration / key-uniqueness — **likely underspecified, leads to a concrete share-recovery attack**

Section 5.1 (per the third-party notes) requires that each party "prove
knowledge of `sk_i^I` when registering" `PK_i^I` with the PKI.  That is the
right defense against rogue-key attacks.  However, **the proof of knowledge
must be (a) non-replayable across registrations and (b) the PKI must reject
duplicate keys, or the following attack recovers an honest dealer's secret
contribution `omega_j`**:

* The eVRF pad between sender `j` and recipient `k` is derived from the
  *Diffie-Hellman shared secret* `S_{jk} = g_in^{sk_j · sk_k}`.  Two
  recipients `k`, `k'` with `PK_k = PK_{k'}` (or equivalently `sk_k = sk_{k'}`)
  receive the *same pad* from any sender `j` — because the eVRF input
  `(msg_j, PK_k)` is identical (the recipient's index `k` is *not* part of the
  eVRF input).
* Both ciphertexts `z_{jk} = r_{jk} + f_j(k)` and `z_{jk'} = r_{jk'} + f_j(k')`
  are *broadcast*.  If `r_{jk} = r_{jk'}` then the **public quantity**
  `z_{jk} - z_{jk'} = f_j(k) - f_j(k')` leaks a fresh linear constraint on the
  honest dealer's polynomial.
* An adversary controlling `t-1` corrupt parties already knows `t-1`
  evaluations of `f_j`.  One extra independent linear constraint determines the
  degree-`(t-1)` polynomial `f_j` completely — recovering `omega_j = f_j(0)`.
* The adversary mounts this by **registering one of the honest parties' public
  keys as its own**.  If the PoK is a vanilla Schnorr proof
  `(g_in^a, c = H(PK, g_in^a), a + c·sk)`, an adversary can simply replay the
  honest party's `(PK_l, π_l)` registration message verbatim and have it
  accepted (the proof verifies).  No knowledge of `sk_l` is required.

**What the paper should say (and an implementer must do regardless):** bind the
registrant's identity (and ideally a fresh per-registration nonce / session
string) into the Fiat-Shamir transcript of the PoK, *and/or* have the PKI
ideal functionality reject a registration whose `PK` duplicates a
previously-registered one.  In the UC model, `F_pki` should be defined to
disallow two parties registering the same key; the standard `F_ca` from
Canetti's framework does *not* enforce this.

This implementation binds the registrant identity into the PoK transcript
(`schnorr.rs`).  See `tests/dkg.rs::rogue_key_pki_detected`,
`schnorr::tests::pok_replay_to_other_id_fails`, and
`schnorr::tests::pki_collision_rejected` for regression tests.

> If the PDF in fact specifies an identity-bound PoK, downgrade this to
> "implementation guidance the paper should make explicit."  If it does not
> mention either fix, this is a real bug in the protocol description.

---

## 2. x-coordinate symmetry in the eVRF / "negate-the-key" pad collision — **curve-dependent — none on Jubjub-with-x, real on short Weierstrass**

`R_eVRF` (Figure 3) computes `k = int(S.x)` where `S = PK_2^{sk_1}`.  Whether
`P ↦ P.x` is injective on the prime-order subgroup of `E(F_p)` depends on the
curve form:

* **Short Weierstrass.**  `−P = (P.x, −P.y)`, so `.x` is a 2-to-1 map even
  inside the prime-order subgroup.  Then `(sk_j, −PK_k)` derives *the same*
  pad as `(sk_j, PK_k)` (because `(−PK_k)^{sk_j} = −(PK_k^{sk_j})` shares an
  x-coordinate).  A recipient who registers `−PK_k` for an honest party `k`
  would learn `f_j(idx) − f_j(k)` from the broadcast difference, the same
  share-recovery as item 1.  Registering `−PK_k` requires knowing `−sk_k`, so
  a sound PoK prevents the attack — but the *semantic* gap remains: the eVRF
  output is unique only per unordered pair of `±PK`, not per public-key pair,
  which the eVRF uniqueness definition and the simulation bookkeeping must
  account for.
* **Twisted Edwards** (this implementation uses Jubjub, `−P = (−P.x, P.y)`).
  Here `(P.x, P.y)` and `(P.x, −P.y)` differ by the 2-torsion point `(0, −1)`,
  which is *not* in the odd-order prime subgroup.  So **`.x` *is* injective on
  the prime-order subgroup** — there is no negate-the-key symmetry.  Verified
  in `curves::tests::jubjub_x_is_injective_on_prime_subgroup`.

The paper's Figure 3 uses unspecified curve notation `E(F_p)`.  If the
intended curve is short-Weierstrass, the negate symmetry should be addressed
in the eVRF definitions and the simulator.  If the intended curve is
Edwards/twisted Edwards (likely, since the embedded-curve trick implies a
circuit-friendly curve), this is a non-issue but should be stated.

**Mitigation for implementers regardless of curve:** check `PK ≠ −PK'` for
all distinct registered keys before running the DKG (this implementation
does so in `schnorr::verify_pki`), or hash the *full* point `S` (compressed
serialization) instead of `S.x` when deriving `k` — at the cost of a few
more bits in the in-circuit decomposition.

---

## 3. Min-entropy accounting for the leftover-hash-lemma extraction — **needs DDH (not just CDH/"unrecoverability") for the second hop**

The eVRF pad is `r = beta · int(T1.x) + int(T2.x)  (mod p)` where
`T1 = H1(msg)^k`, `T2 = H2(msg)^k`, `k = int(S.x)`.

Once the adversary's view is fixed, `(T1, T2)` is a **deterministic function
of `k`** — its joint min-entropy is the min-entropy of `k`, which is at most
`log s ≈ log p`.  The leftover hash lemma applied directly to a source with
`≈ log p` bits of min-entropy producing `log p` output bits gives statistical
distance `≈ 1/√(2^{H∞ - m})` ≈ 1, i.e. *no security*.

The correct argument is two hops:

1. Replace `S` (and hence `k`) with a fresh random point — costs the NIKE
   "session-key unrecoverability" or DDH advantage.
2. Replace `T2 = H2(msg)^k` with an *independent* random group element — this
   is a **DDH** instance `(H1(msg), H2(msg), T1, T2)` (in the random-oracle
   model, with programmable `H1, H2`).  After this hop, `(T1.x, T2.x)` has
   joint min-entropy `≈ 2(log s - 1)` and the leftover hash lemma gives
   `O(1/√p)` distance.

If the paper's Appendix D advantage bound is stated as
`Adv ≤ Adv_DH^unrec + O(1/√p)` (which is what the third-party summary says),
that is **missing a DDH term** unless "unrecoverability" is being used as a
misnomer for DDH or the proof argues hop 2 differently.  Either the bound
should be `Adv ≤ Adv_NIKE + Adv_DDH + O(1/√p)`, or the proof needs an
explanation of why a single x-coordinate's `≈ (log s - 1)` bits of min-entropy
suffice — which they do not, on their own, for a `log p`-bit output.

> If the PDF actually states a DDH term, this is fine and the third-party
> summary I worked from elided it.  Check Appendix D / the eVRF security proof.

---

## 4. Missing "degree of the broadcast commitment" check in Round 1 — **likely an editorial gap in Figure 4**

Round 1 line 8 computes `X_{jk} = ∏_{l=0}^{t-1} A_{j,l}^{k^l}`.  The implicit
assumption is `|C_j| = t`.  If a malicious dealer broadcasts a commitment
vector of length `t' ≠ t`:

* `t' < t`: the dealer's polynomial has degree `< t-1`, so *fewer than `t`*
  parties can reconstruct that dealer's contribution.  Combined with the other
  honest contributions of degree `t-1` this is mostly self-defeating, but it
  silently changes the reconstruction threshold for the *aggregate* secret if
  several dealers do it.
* `t' > t`: ambiguous — a verifier that truncates to `t` coefficients will
  compute a *different* `X_{jk}` than one that uses all `t'`.  Two honest
  verifiers can then disagree about whether the dealing is valid, breaking the
  agreement guarantee.

Figure 4 (per the available notes) parses `C_j → (A_{j,0}, …, A_{j,t-1})`
without an explicit `|C_j| = t` abort.  A reference implementation must check
the length before computing `X_{jk}`.  This implementation does so
(`dkg::verify_dealing` returns `WrongCommitmentLength`) and there is a
regression test (`tests/dkg.rs::wrong_degree_commitment_rejected`).

---

## 5. eVRF inputs do not include a session identifier — **a concern for refresh/reshare reuse, not the one-shot DKG**

`eVRF.Evaluate(sk, (msg, PK'))` is keyed on `(msg, PK')`.  `msg` is a `λ`-bit
nonce sampled by the *sender*.  There is no session id in the eVRF input.

For a one-shot DKG, this is fine: a malicious sender who replays an old
`(msg, R, z, π)` tuple just commits to a different (already-known) `omega`.
But Section 5.2's key refresh re-runs the protocol with `omega_i = 0`.  A
malicious dealer who *re-broadcasts the same `msg_j` and `R_{jk}` from a prior
session* but a different `z_{jk}` causes recipient `k` to derive
`x_{jk} = z_{jk} - r_{jk}` with the *old* `r_{jk}` — which now leaks
`x_{jk}^{new} - x_{jk}^{old} = z^{new} - z^{old}` via cross-session arithmetic
to anyone who recorded both sessions and has *one* of the two cleartexts (e.g.
party `k` if it was honest in one session and corrupt in the other).

**Fix:** bind a session identifier into the eVRF message, e.g.
`x = (sid ‖ msg, PK')`, and bind `sid` into the broadcast and the FS transcript
of `π`.  This implementation does this (`SessionId` is mixed into the eVRF
hash domain and into the proof transcript).

> If the PDF explicitly threads `sid` through the eVRF input, this is fine.
> If not, it should.

---

## 6. `Recover` is defined for an arbitrary set `C` but the DKG never re-runs the consistency check on `|C| = t` — **minor / editorial**

Section 3.3's `Recover(t, {(i, x̄_i)})` interpolates with whichever set `C` of
shares it is handed.  Given `> t` shares, it should either (a) take an
arbitrary `t`-subset, or (b) check pairwise consistency.  As written (per the
available notes) it sums `Σ_{i∈C} x̄_i · L_i(0)` over the *entire* `C`, which
is only correct if `|C| ≤ t` (Lagrange coefficients are computed on the subset
`C`).  For `|C| = t` it is exact; for `|C| > t` it is *also* exact because the
larger Lagrange basis still interpolates the degree-`(t-1)` polynomial; for
`|C| < t` it is incorrect but produces a value silently.  The reference
algorithm should at least assert `|C| ≥ t`.

---

## 7. The `R = g_out^r` step is *outside* the in-circuit relation — make this explicit when porting

Figure 3 step 9 says `R = g_out^r`, but the constraint count
`14λ + 14 ≈ 3598` (for `λ=256`) does **not** budget a non-native G_out scalar
multiplication.  The intent (per ePrint 2024/397) is that `R` is bound via a
Pedersen commitment in the Bulletproofs R1CS protocol with zero blinding, not
proven inside the constraint system.  Anyone porting to Groth16/Plonk/etc. must
implement the commitment-linking separately (e.g. via cc-Groth16 / LegoSNARK)
or budget ≈100k extra constraints for non-native `G_out` arithmetic.

This is not a bug per se, but the protocol listing reads as if step 9 is part
of the constraint system, which is a foot-gun.

---

## 8. `int(·)` casts and modular reduction biases — **negligible but should be stated**

`k = int(S.x)` interprets a base-field element of `F_p` as an integer in
`[0, p)`.  The exponentiations `H_i(msg)^k` live in `G_in` of order `s < p`,
so `k` is implicitly reduced `mod s`.  Similarly, `int(T_i.x)` is in `[0, p)`
and the linear combination `β·r1 + r2` is computed `mod p`.  These reductions
introduce small statistical biases (≈`(p-s)/p` and ≈`1/p`) that should be
explicitly absorbed into the LHL bound; for Jubjub-over-BLS12-381 they are
≈`2^{-126}` and `2^{-255}` respectively, comfortably negligible.

---

## 10. `int(·)` casts inside `R_eVRF` need *canonical* bit decomposition — **a soundness pitfall the paper should flag explicitly**

`R_eVRF` step 3 (`k = int(S.x)`) and steps 4–5 (`T_i = H_i(msg)^k`) require
the prover to decompose `k` into bits and run a bit-controlled scalar
multiplication.  The naive bit-decomposition gadget enforces only

```text
  Σ_{i<λ} b_i 2^i ≡ k  (mod p)        with   b_i (1 − b_i) = 0.
```

For `λ ≥ ⌈log₂ p⌉`, this is satisfied by both the *integer* `k` **and**
`k + p` whenever `k + p < 2^λ` — i.e. whenever `k < 2^λ − p`.  For
`λ = 255` and `p` the BLS12-381 scalar-field prime, this is `k < 2^{251.6}`
— roughly `1/8` of all `k` values.

The two integers `k` and `k + p` reduce *differently* modulo `s` (the embedded
curve's prime order, since `p ≢ 0 (mod s)`), so `H_i(msg)^k ≠ H_i(msg)^{k+p}`
and the derived pads `r ≠ r'` differ.  A malicious dealer can therefore:

1. Find a recipient with `S.x < 2^λ − p` (1-in-8; or grind `sk^I` against a
   target recipient's already-published key, ≈8 keygen attempts).
2. Use the non-canonical bits in the proof and compute the *wrong* pad `r'`.
3. Commit `R = g_out^{r'}` and broadcast `z = r' + share`.
4. Both checks pass: `g^{z} = R · X` and the eVRF proof.

The recipient re-derives the *canonical* `r` and decrypts to a wrong share.
**Public verification accepts a dealing that the recipient cannot decrypt
correctly** — exactly what public verifiability is supposed to prevent.

The paper's Section 4.5 cost table lists "bit-decomposition gadget: `λ + 2`
constraints per decomposition".  If `+2` is just the recombination + sum
constraint, the canonicity check is missing and this is a genuine bug.  If
`+2` is shorthand for a strict-comparison gadget, that should be stated and
the constraint count is too low (a chained `MSB→LSB < p` comparison costs
`≈ λ` extra).

This implementation adds [`bit_decompose_canonical`] which constrains the
*integer* sum to be `< p` (≈`λ` extra mul gates).  It is applied to the
`k = S.x` decomposition.  The dealer's `sk` decomposition does *not* need it:
that decomposition's sum is constrained only via `g_in^{Σ b_i 2^i} = PK_1`,
and any of the ≈8 valid integer representatives `{log PK_1 + j·s}` produce
identical group elements for every embedded-curve exponentiation in the
circuit.

There is a defence-in-depth check in `dkg::complete` that detects a wrong
`R_jk` locally (recipient re-derives the pad commitment), so the recipient
can blame the dealer — but this is a *complaint*, not the public verification
the paper is selling.

---

## 9. Performance table — initially looked off, now understood (resolved)

The summary's Table 2 (Section 5.3) lists "comm. (unopt.) 3.7 MB" for `n=50`
and "comm. (opt.) 223 kb", a ~17× ratio.  At first read this looked
inconsistent with the per-proof size in Section 4.6 (≈1.5 kb).  After
implementing both, this is *not* an inconsistency: the unoptimised variant
ships `n-1` separate eVRF proofs per dealing, so each participant *downloads*
`(n-1) × (n-1) × 1.5 kb ≈ 49² × 1.5 kb ≈ 3.6 MB` — quadratic in `n`.  The
batched variant ships one logarithmic-size proof per dealing (`≈ 2 kb`), so
the download is `(n-1) × (2 kb + share material) ≈ 220 kb` — linear.  The
~17× ratio at `n=50` is the proof-count savings, not a unit error.

This implementation defaults to the batched proof.

---

## 11. Cross-implementation observations from `f3rmion/fy/golden`

`f3rmion/fy/golden` (Go, BN254/Baby-Jubjub + gnark/PLONK) is a second
independent Golden NIDKG implementation.  Cross-checking the two surfaces a
few protocol-level observations and confirms that some of the issues above
are not specific to one implementation; see `COMPARISON.md` for the full
side-by-side and performance comparison.

* **fy's Schnorr PoK (`pki.go`) does not bind the registrant `NodeID`.**  The
  Fiat–Shamir challenge is `H("golden-pki-pok" ‖ sid ‖ PK ‖ R)` — no `id` —
  and the package does not reject duplicate public keys.  This makes it
  vulnerable to the *same-session* key-duplication share-recovery attack from
  §1 unless the caller's PKI rejects duplicate keys independently.  This
  reinforces that §1 deserves an explicit fix in the paper.
* **fy proves `R = g_out^r` in-circuit** with emulated BN254 G1 arithmetic
  (`sw_emulated`) — i.e. the paper's Appendix E alternative, not the main
  construction's commitment-linking trick — and the circuit balloons from
  the paper's `≈14λ ≈ 3.6 k` to `≈238 k` constraints.  This is what §7 above
  warns implementers about.
* **fy uses `pad = x₁ + α·x₂`** with `α` derived from the session ID, while
  the paper (and this implementation) use `r = β·r₁ + r₂` with `β` a CRS
  constant.  Both are valid universal-hash extractors, but they are not
  interchangeable.  See `COMPARISON.md` §F2/§F3.
* **Whether fy's gnark circuit constrains a canonical `int(S.x)`
  decomposition is not visible** from the `golden` package.  If gnark's
  `twistededwards.ScalarMul` decomposes its scalar with `api.ToBinary(s, 254)`
  and no `< r` check, fy has the same gap fixed here in §10.

---

## 12. Subgroup membership of broadcast group elements — **implementation pitfall, not a paper bug**

Figure 4 publishes group elements (`A_{j,l} ∈ G_out`, `R_{jk} ∈ G_out`,
`PK_i^I ∈ G_in`) without specifying that the verifier must reject elements
outside the prime-order subgroup.  This is invisible if the implementation
deserialises group elements with a subgroup check (arkworks'
`CanonicalDeserialize` does), but a foot-gun if it constructs them in place.

* **`G_in` (Jubjub, cofactor 8).**  An adversary can grind the Schnorr
  challenge `c` of the PKI PoK to a multiple of the small order so a key
  `PK + L` (with `L ∈ E[8] \ G_in`) passes verification.  The DH shared
  secret then differs between the two parties, so the recipient cannot
  decrypt — a self-DOS rather than a forgery, but the public verification
  cannot catch it.
* **`G_out` (BLS12-381 G1, cofactor `3 · 11² · 10177² · 859267² · 52437899²`).**
  The smallest prime factor is **3**.  A malicious dealer can publish
  `A_{j,l} = G_l + L_l` and `R_{jk} = G + L'` with order-3 components chosen
  so `g^z = R + X` still holds, and grind the eVRF Bulletproofs proof (≈3
  re-runs) so the residual small-order term in the verification MSM
  vanishes.  Public verification then accepts the dealing.  The recipient's
  re-derived `R' = g_out^r` is in the prime-order subgroup, so `R ≠ R'` and
  the recipient raises a *complaint that public verification considers
  unfounded* — exactly the failure mode "publicly verifiable" is supposed to
  exclude.  The aggregated `PK_l` (Round 1 step 11) also inherits the
  small-order component, leaking outside the subgroup.

**Mitigation:** subgroup-check every broadcast group element before
verification.  This implementation does so for the PKI keys
(`schnorr::SchnorrPoK::verify`) and for each dealing's Feldman commitment
and pad commitments (`dkg::check_dealing_structure`).  See
`tests/dkg.rs::off_subgroup_commitment_rejected` and
`schnorr::tests::small_order_component_rejected`.

The Bulletproofs proof's *internal* group elements (`A_I, A_O, S, T_*, IPA
L/R`) do **not** need subgroup checks: a small-order component in those bases
adds an *extra* constraint to the verification MSM that the prover must
cancel; it cannot relax the soundness condition.

---

## 13. Batch-verification combiners must be unpredictable to the prover — **implementation pitfall**

Section 5.3 batches per-dealing Bulletproofs verifications into one MSM
`Σ_i r_i · check_i = 0` with random combiners `r_i`.  If two colluding
dealers `i`, `j` can predict `r_i, r_j`, they can craft forged residues
`check_i = -r_j/r_i · check_j` and pass the batch.  Drawing `r_i` from an
honest verifier coin works but makes acceptance non-deterministic across
verifiers (one observer's batch may fail while another's passes); drawing
them from a poorly-seeded RNG is unsafe.

This implementation derives the combiners by Fiat–Shamir from a transcript
that absorbs every check's verification-transcript digest (which itself
binds `(sid, pubs, proof)`), so the combiners are deterministic, every
observer agrees, and the proofs must be fixed before the combiners are
known (`bp_r1cs::verify_batch`).  The fy implementation uses one proof per
`(dealer, recipient)` and does not batch, so it does not face this.

---

## Open questions (could not resolve without the PDF)

* Exactly how `β` is sampled (CRS? hashed? per-session?).  This implementation
  derives it deterministically from a domain-separated hash of the parameter
  string, treating it as a CRS constant.
* Whether the Bulletproofs commitment generators for the R1CS are nothing-up-
  my-sleeve or also CRS.  This implementation hashes them.
* Whether Round 1 aborts on the *first* failed verification or collects a
  blame set.  This implementation aborts and reports the offending `(j, k)`.
* Whether the eVRF `Evaluate` and `Verify` interfaces include `sid` (see §5).

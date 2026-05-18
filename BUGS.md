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

## 1. Identity binding in the PKI registration / key-uniqueness — **likely
   underspecified, leads to a concrete share-recovery attack**

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
(`schnorr.rs`).  See `tests/rogue_key.rs` for a regression test.

> If the PDF in fact specifies an identity-bound PoK, downgrade this to
> "implementation guidance the paper should make explicit."  If it does not
> mention either fix, this is a real bug in the protocol description.

---

## 2. x-coordinate symmetry in the eVRF / "negate-the-key" pad collision —
   **likely a real but bounded gap in `R_eVRF`**

`R_eVRF` (Figure 3) computes `k = int(S.x)` where `S = PK_2^{sk_1}`.  Taking
the x-coordinate (or u-coordinate, for an Edwards curve) is a 2-to-1 map:
`S.x = (-S).x`.  Therefore the pad derived from `(sk_j, PK_k)` equals the pad
derived from `(sk_j, -PK_k)` — because `PK_k^{sk_j}` and `(-PK_k)^{sk_j} =
-(PK_k^{sk_j})` share an x-coordinate.

This means a recipient with key `PK_k' = -PK_k` (i.e. `sk_k' = -sk_k`) gets
*the same* pad as recipient `k` from every sender, leading to the same
share-difference leak as item 1.

In contrast to item 1, this *is* prevented by a sound PoK: registering
`-PK_k` requires knowing `-sk_k`.  But it is worth flagging because:

* It is *not* prevented by a "no duplicate keys" rule alone (`PK_k` and
  `-PK_k` are distinct group elements).
* It means **the eVRF output is not unique per (sender, recipient) public-key
  pair** — it is unique only per *unordered pair of `±PK`*.  Definitions of
  VRF/eVRF uniqueness should be examined for whether this matters formally.
* In the simulation argument, the simulator's bookkeeping of pads keyed on
  `(PK_1, PK_2, msg)` must therefore either also key on the sign of `S`, or
  the proof must explicitly argue this never matters.

**Mitigation for implementers:** check `PK ≠ -PK'` for all distinct `(P, P')`
in the PKI snapshot before running the DKG (this implementation does so in
`dkg::verify_pki`).  Better: hash the *full* point `S` (e.g. its compressed
serialization) instead of only `S.x` when deriving `k`, which removes the
symmetry entirely at the cost of one extra bit-decomposition in the circuit.

---

## 3. Min-entropy accounting for the leftover-hash-lemma extraction —
   **needs DDH (not just CDH/"unrecoverability") for the second hop**

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

## 4. Missing "degree of the broadcast commitment" check in Round 1 — **likely
   an editorial gap in Figure 4**

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
the length before computing `X_{jk}`.  This implementation does so and there
is a regression test (`tests/dkg_negative.rs::wrong_degree_commitment`).

---

## 5. eVRF inputs do not include a session identifier — **a concern for
   refresh/reshare reuse, not the one-shot DKG**

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

## 6. `Recover` is defined for an arbitrary set `C` but the DKG never re-runs
   the consistency check on `|C| = t` — **minor / editorial**

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

## 7. The `R = g_out^r` step is *outside* the in-circuit relation — make this
   explicit when porting

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

## 8. `int(·)` casts and modular reduction biases — **negligible but should be
   stated**

`k = int(S.x)` interprets a base-field element of `F_p` as an integer in
`[0, p)`.  The exponentiations `H_i(msg)^k` live in `G_in` of order `s < p`,
so `k` is implicitly reduced `mod s`.  Similarly, `int(T_i.x)` is in `[0, p)`
and the linear combination `β·r1 + r2` is computed `mod p`.  These reductions
introduce small statistical biases (≈`(p-s)/p` and ≈`1/p`) that should be
explicitly absorbed into the LHL bound; for Jubjub-over-BLS12-381 they are
≈`2^{-126}` and `2^{-255}` respectively, comfortably negligible.

---

## 9. Performance table — minor inconsistency / typo to verify

The summary's Table 2 (Section 5.3) lists "comm. (unopt.) 3.7 MB" for `n=50`
and "comm. (opt.) 223 kb", a ~17× ratio.  The proof-size table (Section 4.6)
gives single-statement proof size ≈1.5 kb and 49-statement batch ≈2.1 kb.
Unoptimised communication for 49 dealings ≈ 49 × (1.5 kb + ε) ≈ 75 kb, not
3.7 MB.  The 3.7 MB figure is more consistent with a *quadratic* (n²)
unbatched communication count (everyone forwarding everyone's dealings), or
with byte/bit confusion.  Worth double-checking the units and what's being
counted.

> This may be a misreading of the paper's tables on my part — the inconsistency
> is between two tables in a third-party summary.  Verify against the PDF.

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

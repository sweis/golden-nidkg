//! Zero-knowledge proof of `R_eVRF` (Figure 3 of the paper) via Bulletproofs
//! over R1CS.
//!
//! ## Why a hand-rolled Bulletproofs R1CS?
//!
//! Golden's `R_eVRF` circuit is over `F_p` = the BLS12-381 scalar field
//! (= the Jubjub base field, so the Jubjub arithmetic is native).  The proof
//! must therefore commit over a group of order `p`, i.e. BLS12-381 `G1`.
//!
//! As of writing, **no published Rust Bulletproofs library can produce R1CS
//! proofs over BLS12-381 G1**:
//!
//! * `bulletproofs` (dalek, 4.x/5.x) — Ristretto only; wrong curve for Jubjub.
//!   The 5.0 `yoloproofs` (R1CS) feature also fails to build (dependency rot
//!   against `subtle::CtOption`).
//! * `bulletproofs-bls` (zkcrypto, 4.0) — *does* target BLS12-381 G1 (via
//!   `blstrs_plus` / `bls12_381_plus`), but the `yoloproofs` (R1CS) feature
//!   does not compile against any version of those crates (≈40 type errors —
//!   the R1CS module was never updated for the trait reshuffle).  Only range
//!   proofs build.
//! * `ark-bulletproofs` — secq256k1/Zorro; wrong curve.
//! * `ark-spartan-golden` — a one-off fork of Microsoft Spartan published by
//!   another Golden implementer (`farazshaikh`); not a maintained standard
//!   library, and the witness-binding interface differs.
//!
//! The R1CS protocol below is a small (~600-line) port of the dalek
//! `bulletproofs` R1CS protocol (the `yoloproofs` design, BCC+16 / Bulletproofs
//! §5) to arkworks BLS12-381.  It is intentionally *not* a general-purpose
//! library — only what `R_eVRF` needs is implemented (single-phase, no
//! randomized constraints).  The IPA and toy R1CS round-trips are unit-tested
//! against tampered inputs.  If a maintained arkworks-compatible Bulletproofs
//! R1CS library appears, the `evrf_proof` module is the only thing that needs
//! to change.
//!
//! ## Layout
//!
//! * [`generators`]   — the Pedersen generator vectors (`G`, `H`, `B`, `B_b`).
//! * [`r1cs`]         — constraint system (multiplication gates + linear
//!   constraints on `a_L, a_R, a_O, v`).
//! * [`ipa`]          — log-size inner-product argument.
//! * [`bp_r1cs`]      — Bulletproofs R1CS prover/verifier.
//! * [`gadgets`]      — bit decomposition + Jubjub fixed/variable-base MSM.
//! * [`evrf_circuit`] — the actual `R_eVRF` circuit.
//! * [`evrf_proof`]   — public API tying the circuit to the prover/verifier.
//!
//! The pad commitment `R = g_out^r` is bound to the proof as a *high-level
//! Pedersen commitment with zero blinding* (`V = R, γ = 0`).  The Pedersen
//! base `B` is `g_out` (BLS12-381 G1's standard generator) so `commit(r, 0) =
//! g_out^r = R`.  This is the linking trick from the eVRF paper (ePrint
//! 2024/397) that avoids non-native `G_out` arithmetic inside the circuit.

pub mod bp_r1cs;
pub mod evrf_circuit;
pub mod evrf_proof;
pub mod gadgets;
pub mod generators;
pub mod ipa;
pub mod r1cs;

pub use evrf_proof::{
    prove_evrf_batch, verify_evrf_batch, BatchPublicInputs, EvrfProof, ZkMode, ZkParams,
};

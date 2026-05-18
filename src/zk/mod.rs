//! Zero-knowledge proof of `R_eVRF` (Figure 3 of the paper) via Bulletproofs
//! over R1CS.
//!
//! Layout:
//! * [`generators`]   — the Pedersen generator vectors (`G`, `H`, `B`, `B_b`).
//! * [`r1cs`]         — constraint system (multiplication gates + linear
//!                       constraints on `a_L, a_R, a_O, v`).
//! * [`ipa`]          — log-size inner-product argument.
//! * [`bp_r1cs`]      — Bulletproofs R1CS prover/verifier.
//! * [`gadgets`]      — bit decomposition + Jubjub fixed/variable-base MSM.
//! * [`evrf_circuit`] — the actual `R_eVRF` circuit.
//! * [`evrf_proof`]   — public API tying the circuit to the prover/verifier.
//!
//! The pad commitment `R = g_out^r` is bound to the proof as a *high-level
//! Pedersen commitment with zero blinding* (`V = R, γ = 0`).  This is the
//! linking trick from the eVRF paper that avoids non-native `G_out` arithmetic
//! inside the circuit.

pub mod bp_r1cs;
pub mod evrf_circuit;
pub mod evrf_proof;
pub mod gadgets;
pub mod generators;
pub mod ipa;
pub mod r1cs;

pub use evrf_proof::{prove_evrf, verify_evrf, EvrfProof, ZkParams};

//! Reference implementation of **Golden: Lightweight Non-Interactive
//! Distributed Key Generation** (Bünz, Choi, Komlo — ePrint 2025/1924).
//!
//! See [`CLAUDE.md`] for a protocol overview, [`BUGS.md`] for a list of
//! issues found while reading the paper, and `examples/demo.rs` for a
//! runnable end-to-end DKG.
//!
//! The crate is organised as:
//!
//! * [`curves`]         — the (`G_in`=Jubjub, `G_out`=BLS12-381 G1) pair.
//! * [`shamir`], [`vss`]— Shamir SS + Feldman commitment.
//! * [`schnorr`]        — Schnorr PoK for PKI registration (rogue-key safe).
//! * [`hash_to_curve`]  — try-and-increment `H : {0,1}* → G_in`.
//! * [`evrf`]           — two-party exponent VRF (pad derivation).
//! * [`zk`]             — Bulletproofs R1CS proof of `R_eVRF`.
//! * [`dkg`]            — Round 0 / verify / Round 1.

#![allow(clippy::needless_range_loop, clippy::too_many_arguments)]

pub mod curves;
pub mod dkg;
pub mod errors;
pub mod evrf;
pub mod hash_to_curve;
pub mod schnorr;
pub mod shamir;
pub mod transcript;
pub mod vss;
pub mod zk;

pub use curves::{Fp, Fs, GinAffine, GoutAffine};
pub use dkg::{
    complete, create_dealing, refresh_dealing, verify_dealing, Dealing, DealingPrivate, DkgConfig,
    DkgOutput,
};
pub use errors::{GoldenError, GoldenResult};
pub use evrf::{Beta, SessionId};
pub use schnorr::{verify_pki, RegisteredKey, SchnorrPoK};

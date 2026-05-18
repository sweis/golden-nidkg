//! Error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GoldenError {
    #[error("not enough shares: have {have}, need {need}")]
    NotEnoughShares { have: u32, need: u32 },

    #[error("duplicate share index")]
    DuplicateShareIndex,

    #[error("invalid share index (0 is reserved for the secret)")]
    InvalidShareIndex,

    #[error("VSS commitment from dealer {dealer} has wrong length: got {got}, expected {expected}")]
    WrongCommitmentLength { dealer: u32, got: usize, expected: usize },

    #[error("Schnorr PoK verification failed for party {party}")]
    SchnorrPoKFailed { party: u32 },

    #[error("session id mismatch from dealer {dealer}")]
    SessionMismatch { dealer: u32 },

    #[error("ciphertext consistency check failed: dealer {dealer} → recipient {recipient}")]
    CiphertextCheckFailed { dealer: u32, recipient: u32 },

    #[error("eVRF proof failed: dealer {dealer} → recipient {recipient}: {reason}")]
    EvrfProofFailed { dealer: u32, recipient: u32, reason: String },

    #[error("dealer {dealer} did not send a ciphertext for recipient {recipient}")]
    MissingCiphertext { dealer: u32, recipient: u32 },

    #[error("dealer {dealer} sent an unexpected ciphertext for recipient {recipient}")]
    UnexpectedCiphertext { dealer: u32, recipient: u32 },

    #[error("PKI public key for party {party} is the identity")]
    IdentityPublicKey { party: u32 },

    #[error("PKI keys for parties {a} and {b} are equal or negations — see BUGS.md §1/§2")]
    PkiKeyCollision { a: u32, b: u32 },

    #[error("refresh dealing from dealer {dealer} commits to a non-zero secret")]
    NonZeroRefreshSecret { dealer: u32 },

    #[error("Bulletproofs proof error: {0}")]
    Proof(String),

    #[error("internal: {0}")]
    Internal(String),
}

pub type GoldenResult<T> = Result<T, GoldenError>;

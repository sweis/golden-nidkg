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

    #[error(
        "VSS commitment from dealer {dealer} has wrong length: got {got}, expected {expected}"
    )]
    WrongCommitmentLength {
        dealer: u32,
        got: usize,
        expected: usize,
    },

    #[error("Schnorr PoK verification failed for party {party}")]
    SchnorrPoKFailed { party: u32 },

    #[error("session id mismatch from dealer {dealer}")]
    SessionMismatch { dealer: u32 },

    #[error("ciphertext consistency check failed: dealer {dealer} → recipient {recipient}")]
    CiphertextCheckFailed { dealer: u32, recipient: u32 },

    #[error("eVRF proof failed for dealer {dealer}: {reason}")]
    EvrfProofFailed { dealer: u32, reason: String },

    #[error("dealer {dealer} did not send a ciphertext for recipient {recipient}")]
    MissingCiphertext { dealer: u32, recipient: u32 },

    #[error("dealer {dealer} sent an unexpected ciphertext for recipient {recipient}")]
    UnexpectedCiphertext { dealer: u32, recipient: u32 },

    #[error("PKI public key for party {party} is the identity")]
    IdentityPublicKey { party: u32 },

    #[error("PKI public key for party {party} is not in the prime-order subgroup")]
    PublicKeyNotInSubgroup { party: u32 },

    #[error(
        "dealing from dealer {dealer} contains a group element not in the prime-order subgroup"
    )]
    ElementNotInSubgroup { dealer: u32 },

    #[error("PKI keys for parties {a} and {b} are equal or negations — see BUGS.md §1/§2")]
    PkiKeyCollision { a: u32, b: u32 },

    #[error("refresh dealing from dealer {dealer} commits to a non-zero secret")]
    NonZeroRefreshSecret { dealer: u32 },

    #[error("party {id} is not registered in the PKI snapshot")]
    PartyNotInPki { id: u32 },

    #[error("dealing has {got} recipients but the ZK CRS supports at most {max}")]
    TooManyPeers { got: usize, max: usize },

    #[error("Bulletproofs proof error: {0}")]
    Proof(String),

    #[error("internal: {0}")]
    Internal(String),
}

pub type GoldenResult<T> = Result<T, GoldenError>;

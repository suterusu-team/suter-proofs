use bincode::Error as BCError;
use bulletproofs::ProofError as BPProofError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("Bulletproofs ProofError: {0}")]
    BulletProofs(BPProofError),
    #[error("No transactions")]
    EmptyTransfers,
    #[error("Too many transactions to do in a batch, given {given}, max {max}")]
    TooManyTransfers { given: usize, max: usize },
    #[error("Commitments and transfers number not match")]
    NumNotMatch,
    #[error("Error while trying to decrypt balance")]
    Decryption,
    #[error("Overflow while doing arithmetic operations")]
    Overflow,
    #[error("Attempt to send balance to oneself")]
    SelfTransfer,
}

#[derive(Error, Debug)]
pub enum TransactionSerdeError {
    #[error("Underlying serde Error: {0}")]
    Underlying(BCError),
    #[error("Unknown transaction version: {0}")]
    Version(u8),
    #[error("Invalid format")]
    Format,
    #[error("Transaction malformed")]
    Malformed,
}

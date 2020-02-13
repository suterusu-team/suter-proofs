use bulletproofs::ProofError as BPProofError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("Bulletproofs ProofError: {0}")]
    BulletProofs(BPProofError),
    #[error("No transactions")]
    EmptyTransfers,
    #[error("Commitments and transfers number not match")]
    NumNotMatch,
    #[error("Error while trying to decrypt balance")]
    Decryption,
    #[error("Overflow while doing arithmetic operations")]
    Overflow,
}

use bulletproofs::ProofError as BPProofError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("Error while trying to decrypt balance")]
    Decryption,
    #[error("Overflow while doing arithmetic operations")]
    Overflow,
    #[error("Bulletproofs ProofError: {0}")]
    BulletProofs(BPProofError),
}

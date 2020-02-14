use bulletproofs::ProofError as BPProofError;
use thiserror::Error;

use crate::constants::MAX_PARTIES;

#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("Bulletproofs ProofError: {0}")]
    BulletProofs(BPProofError),
    #[error("No transactions")]
    EmptyTransfers,
    #[error("Too many transactions to do in a batch {}", MAX_PARTIES)]
    TooManyTransfers,
    #[error("Commitments and transfers number not match")]
    NumNotMatch,
    #[error("Error while trying to decrypt balance")]
    Decryption,
    #[error("Overflow while doing arithmetic operations")]
    Overflow,
}

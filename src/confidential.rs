use bulletproofs::{BulletproofGens, PedersenGens, ZetherProof};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
#[cfg(feature = "std")]
use rand::thread_rng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::amount::Amount;
use super::constants::MERLIN_CONFIDENTIAL_TRANSACTION_LABEL;
use super::TransactionError;
use crate::{Ciphertext, PublicKey, SecretKey};

lazy_static! {
    static ref PC_GENS: PedersenGens = PedersenGens::default();
    static ref BP_GENS: BulletproofGens = BulletproofGens::new(64, 1);
}

pub type EncryptedBalance = Ciphertext;
pub type IndividualTransaction = Ciphertext;

fn new_individual_transaction(
    pk: &PublicKey,
    value: &u64,
    blinding: &Scalar,
) -> IndividualTransaction {
    let base_point: RistrettoPoint = (*PC_GENS).B;
    Ciphertext {
        pk: *pk,
        points: (
            Scalar::from(*value) * base_point + blinding * pk.get_point(),
            blinding * base_point,
        ),
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    sender: PublicKey,
    original_balance: EncryptedBalance,
    sender_transaction: IndividualTransaction,
    receiver_transaction: IndividualTransaction,
    comitments: Vec<RistrettoPoint>,
    proof: ZetherProof,
}

impl Transaction {
    fn new(
        sender: PublicKey,
        original_balance: EncryptedBalance,
        sender_transaction: IndividualTransaction,
        receiver_transaction: IndividualTransaction,
        commitments: Vec<RistrettoPoint>,
        proof: ZetherProof,
    ) -> Self {
        Transaction {
            sender: sender,
            original_balance: original_balance,
            sender_transaction: sender_transaction,
            receiver_transaction: receiver_transaction,
            comitments: commitments,
            proof: proof,
        }
    }
}

pub trait ConfidentialTransaction {
    type Amount: Amount;
    fn create_transaction(
        original_balance: &EncryptedBalance,
        values: &<Self::Amount as Amount>::Target,
        pk_sender: &PublicKey,
        pk_receiver: &PublicKey,
        sk_sender: &Scalar,
    ) -> Result<Transaction, TransactionError>;
}

impl ConfidentialTransaction for Transaction {
    type Amount = u32;
    fn create_transaction(
        original_balance: &EncryptedBalance,
        value: &u32,
        pk_sender: &PublicKey,
        pk_receiver: &PublicKey,
        sk_sender: &Scalar,
    ) -> Result<Transaction, TransactionError> {
        create_transaction_with_rng(
            original_balance,
            value,
            pk_sender,
            pk_receiver,
            sk_sender,
            &mut thread_rng(),
        )
    }
}

pub fn create_transaction_with_rng<T: RngCore + CryptoRng>(
    original_balance: &EncryptedBalance,
    value: &u32,
    pk_sender: &PublicKey,
    pk_receiver: &PublicKey,
    sk_sender: &Scalar,
    rng: &mut T,
) -> Result<Transaction, TransactionError> {
    let blinding1 = Scalar::random(rng);
    let blinding2 = Scalar::random(rng);
    let comm_rnd = Scalar::random(rng);
    do_create_transaction(
        original_balance,
        value,
        &[blinding1, blinding2],
        pk_sender,
        pk_receiver,
        sk_sender,
        &comm_rnd,
    )
}

fn do_create_transaction(
    original_balance: &EncryptedBalance,
    value: &u32,
    blindings: &[Scalar],
    pk_sender: &PublicKey,
    pk_receiver: &PublicKey,
    sk_sender: &Scalar,
    comm_rnd: &Scalar,
) -> Result<Transaction, TransactionError> {
    let sk = SecretKey::from(*sk_sender);
    let decrypted_balance: u32 =
        u32::try_decrypt_from(sk, *original_balance).ok_or(TransactionError::Decryption)?;
    let new_balance: u32 = decrypted_balance
        .checked_sub(*value)
        .ok_or(TransactionError::Overflow)?;
    let b_sent = *value as u64;
    let b_remaining = new_balance as u64;
    let sender_transaction = new_individual_transaction(pk_sender, &b_sent, &blindings[0]);
    let receiver_transaction = new_individual_transaction(pk_receiver, &b_sent, &blindings[1]);
    let remaining_balance = original_balance - sender_transaction;
    let mut prover_transcript = Transcript::new(MERLIN_CONFIDENTIAL_TRANSACTION_LABEL);
    let (proof, commitments) = ZetherProof::prove_multiple(
        &BP_GENS,
        &PC_GENS,
        &mut prover_transcript,
        &vec![b_sent, b_remaining],
        blindings,
        32,
        &pk_sender.get_point(),
        &pk_receiver.get_point(),
        &remaining_balance.get_points(),
        &sender_transaction.get_points(),
        sk_sender,
        comm_rnd,
    )
    .map_err(TransactionError::BulletProofs)?;
    let commitments = commitments
        .iter()
        .map(|p| {
            p.decompress()
                .expect("commitments in zether proof should be able to be decompressed")
        })
        .collect();
    Ok(Transaction::new(
        *pk_sender,
        *original_balance,
        sender_transaction,
        receiver_transaction,
        commitments,
        proof,
    ))
}

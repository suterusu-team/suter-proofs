use bulletproofs::ZetherProof;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
#[cfg(feature = "std")]
use rand::thread_rng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::amount::Amount;
use super::constants::MERLIN_CONFIDENTIAL_TRANSACTION_LABEL;
use super::TransactionError;
use crate::constants::{BASE_POINT, BP_GENS, PC_GENS};
use crate::{Ciphertext, PublicKey, SecretKey};

pub type EncryptedBalance = Ciphertext;
pub type IndividualTransaction = Ciphertext;

fn new_individual_transaction(
    pk: &PublicKey,
    value: &u64,
    blinding: &Scalar,
) -> IndividualTransaction {
    Ciphertext {
        pk: *pk,
        points: (
            blinding * *BASE_POINT,
            Scalar::from(*value) * *BASE_POINT + blinding * pk.get_point(),
        ),
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction {
    sender: PublicKey,
    original_balance: EncryptedBalance,
    sender_transaction: IndividualTransaction,
    receiver_transaction: IndividualTransaction,
    commitments: Vec<CompressedRistretto>,
    proof: ZetherProof,
}

impl Transaction {
    fn new(
        sender: PublicKey,
        original_balance: EncryptedBalance,
        sender_transaction: IndividualTransaction,
        receiver_transaction: IndividualTransaction,
        commitments: Vec<CompressedRistretto>,
        proof: ZetherProof,
    ) -> Self {
        Transaction {
            sender: sender,
            original_balance: original_balance,
            sender_transaction: sender_transaction,
            receiver_transaction: receiver_transaction,
            commitments: commitments,
            proof: proof,
        }
    }

    pub fn get_sender_final_balance(&self) -> EncryptedBalance {
        self.original_balance - self.sender_transaction
    }

    pub fn get_receiver_final_balance(
        &self,
        receiver_original_balance: &EncryptedBalance,
    ) -> EncryptedBalance {
        receiver_original_balance + self.receiver_transaction
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
    assert!(blindings.len() == 2);
    let sk = SecretKey::from(*sk_sender);
    let decrypted_balance: u32 =
        u32::try_decrypt_from(&sk, original_balance).ok_or(TransactionError::Decryption)?;
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
    Ok(Transaction::new(
        *pk_sender,
        *original_balance,
        sender_transaction,
        receiver_transaction,
        commitments,
        proof,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::TestResult;
    use rand_core::OsRng;

    #[quickcheck]
    fn transacation_balance_should_be_corrent(
        sent_balance: u32,
        sender_initial_balance: u32,
        receiver_initial_balance: u32,
    ) -> TestResult {
        if sent_balance > sender_initial_balance {
            return TestResult::discard();
        };

        let sender_final_balance = &sender_initial_balance - &sent_balance;
        let receiver_final_balance = &receiver_initial_balance + &sent_balance;

        let mut csprng = OsRng;
        let sk_scalar = Scalar::random(&mut csprng);
        let sk_sender = SecretKey::from(sk_scalar);
        let pk_sender = PublicKey::from(&sk_sender);
        let sk_receiver = SecretKey::new(&mut csprng);
        let pk_receiver = PublicKey::from(&sk_receiver);
        let sender_initial_encrypted_balance = sender_initial_balance.encrypt_with(&pk_sender);
        let receiver_initial_encrypted_balance =
            receiver_initial_balance.encrypt_with(&pk_receiver);

        let transaction = Transaction::create_transaction(
            &sender_initial_encrypted_balance,
            &sent_balance,
            &pk_sender,
            &pk_receiver,
            &sk_scalar,
        )
        .expect("Should be able to create transaction");

        assert!(
            u32::try_decrypt_from(&sk_sender, &transaction.sender_transaction).unwrap()
                == sent_balance
        );
        assert!(
            u32::try_decrypt_from(&sk_receiver, &transaction.receiver_transaction).unwrap()
                == sent_balance
        );
        assert!(
            u32::try_decrypt_from(&sk_sender, &transaction.get_sender_final_balance()).unwrap()
                == sender_final_balance
        );
        assert!(
            u32::try_decrypt_from(
                &sk_receiver,
                &transaction.get_receiver_final_balance(&receiver_initial_encrypted_balance)
            )
            .unwrap()
                == receiver_final_balance
        );
        TestResult::passed()
    }
}

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
use super::utils::{ciphertext_points_random_term_last, RistrettoPointTuple};
use super::TransactionError;
use crate::constants::{BASE_POINT, BP_GENS, PC_GENS};
use crate::{Ciphertext, PublicKey, SecretKey};

pub type EncryptedBalance = Ciphertext;
pub type IndividualTransaction = Ciphertext;

/// Create a ciphertext with the specified plain value and random scalar.
pub fn new_ciphertext(pk: &PublicKey, value: u64, blinding: &Scalar) -> Ciphertext {
    let tuple = RistrettoPointTuple {
        random_term: blinding * BASE_POINT,
        payload_term: Scalar::from(value) * BASE_POINT + blinding * pk.get_point(),
    };
    tuple.ciphertext_for(pk)
}

/// One to one confidential transaction.
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
    pub fn new(
        sender: PublicKey,
        original_balance: EncryptedBalance,
        sender_transaction: IndividualTransaction,
        receiver_transaction: IndividualTransaction,
        commitments: Vec<CompressedRistretto>,
        proof: ZetherProof,
    ) -> Self {
        Transaction {
            sender,
            original_balance,
            sender_transaction,
            receiver_transaction,
            commitments,
            proof,
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

    /// Create a new transaction from pk_sender which transfers transaction_value to pk_receiver.
    /// Returned Transaction can be used to calculate the final balance of the sender and receiver.
    /// The caller must provide original_balance so as to generate a valid proof.
    /// The caller must not allow race condition of transactions with the same sender.
    fn create_transaction(
        original_balance: &EncryptedBalance,
        transaction_value: <Self::Amount as Amount>::Target,
        pk_sender: &PublicKey,
        pk_receiver: &PublicKey,
        sk_sender: &Scalar,
    ) -> Result<Transaction, TransactionError> {
        Self::create_transaction_with_rng(
            original_balance,
            transaction_value,
            pk_sender,
            pk_receiver,
            sk_sender,
            &mut thread_rng(),
        )
    }

    /// Create a new transaction with blindings generated from the given rng.
    fn create_transaction_with_rng<T: RngCore + CryptoRng>(
        original_balance: &EncryptedBalance,
        transaction_value: <Self::Amount as Amount>::Target,
        pk_sender: &PublicKey,
        pk_receiver: &PublicKey,
        sk_sender: &Scalar,
        rng: &mut T,
    ) -> Result<Transaction, TransactionError>;

    /// Verify if a transaction is valid.
    fn verify_transaction(&self) -> Result<(), TransactionError>;
}

impl ConfidentialTransaction for Transaction {
    type Amount = u32;

    fn create_transaction_with_rng<T: RngCore + CryptoRng>(
        original_balance: &EncryptedBalance,
        transaction_value: u32,
        pk_sender: &PublicKey,
        pk_receiver: &PublicKey,
        sk_sender: &Scalar,
        rng: &mut T,
    ) -> Result<Transaction, TransactionError> {
        let (blindings, blinding_for_transaction_value) =
            generate_transaction_random_parameters(rng);
        my_debug!(&blindings, &blinding_for_transaction_value);
        do_create_transaction(
            original_balance,
            transaction_value,
            &blindings,
            &blinding_for_transaction_value,
            pk_sender,
            pk_receiver,
            sk_sender,
        )
    }

    fn verify_transaction(&self) -> Result<(), TransactionError> {
        let mut verifier_transcript = Transcript::new(MERLIN_CONFIDENTIAL_TRANSACTION_LABEL);
        self.proof
            .verify_multiple(
                &BP_GENS,
                &PC_GENS,
                &mut verifier_transcript,
                &self.commitments,
                32,
                &self.sender.get_point(),
                &self.receiver_transaction.pk.get_point(),
                &ciphertext_points_random_term_last(&self.get_sender_final_balance()),
                &ciphertext_points_random_term_last(&self.sender_transaction),
                &ciphertext_points_random_term_last(&self.receiver_transaction),
            )
            .map_err(TransactionError::BulletProofs)?;
        Ok(())
    }
}

fn generate_transaction_random_parameters<T: RngCore + CryptoRng>(
    rng: &mut T,
) -> ((Scalar, Scalar), Scalar) {
    let blindings = (Scalar::random(rng), Scalar::random(rng));
    let blinding_for_transaction_value = Scalar::random(rng);
    (blindings, blinding_for_transaction_value)
}

fn do_create_transaction(
    original_balance: &EncryptedBalance,
    transaction_value: u32,
    blindings: &(Scalar, Scalar),
    blinding_for_transaction_value: &Scalar,
    pk_sender: &PublicKey,
    pk_receiver: &PublicKey,
    sk_sender: &Scalar,
) -> Result<Transaction, TransactionError> {
    let sent_balance = transaction_value as u64;
    let sk = SecretKey::from(*sk_sender);
    let sender_initial_balance: u32 =
        u32::try_decrypt_from(&sk, original_balance).ok_or(TransactionError::Decryption)?;
    let sender_final_balance = sender_initial_balance
        .checked_sub(transaction_value)
        .ok_or(TransactionError::Overflow)? as u64;
    let sender_transaction =
        new_ciphertext(pk_sender, sent_balance, blinding_for_transaction_value);
    let receiver_transaction =
        new_ciphertext(pk_receiver, sent_balance, blinding_for_transaction_value);
    let sender_final_encrypted_balance = original_balance - sender_transaction;
    let mut prover_transcript = Transcript::new(MERLIN_CONFIDENTIAL_TRANSACTION_LABEL);
    let (proof, commitments) = ZetherProof::prove_multiple(
        &BP_GENS,
        &PC_GENS,
        &mut prover_transcript,
        &[sent_balance, sender_final_balance],
        &[blindings.0, blindings.1],
        32,
        &pk_sender.get_point(),
        &pk_receiver.get_point(),
        &ciphertext_points_random_term_last(&sender_final_encrypted_balance),
        &ciphertext_points_random_term_last(&sender_transaction),
        sk_sender,
        blinding_for_transaction_value,
    )
    .map_err(TransactionError::BulletProofs)?;
    my_debug!(&proof, &commitments);
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
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};

    #[quickcheck]
    fn new_ciphertext_should_work(seed: u64) {
        let mut csprng: ChaCha20Rng = SeedableRng::seed_from_u64(seed);
        let sk_scalar = Scalar::random(&mut csprng);
        let sk = SecretKey::from(sk_scalar);
        let pk = PublicKey::from(&sk);
        // TODO: u32 takes too long to finish.
        let value = csprng.next_u32() as u16;
        let blinding = Scalar::random(&mut csprng);
        let ciphertext = new_ciphertext(&pk, value as u64, &blinding);
        assert!(u32::try_decrypt_from(&sk, &ciphertext).unwrap() == value as u32)
    }

    // Deterministically generate transacation parameters
    fn setup_from_seed(
        seed: u64,
    ) -> (
        ChaCha20Rng,
        (Scalar, SecretKey, PublicKey, SecretKey, PublicKey),
        (u32, Scalar, EncryptedBalance, u32, u32),
        (u32, Scalar, EncryptedBalance),
    ) {
        let mut csprng: ChaCha20Rng = SeedableRng::seed_from_u64(seed);
        let sk_scalar = Scalar::random(&mut csprng);
        let sk_sender = SecretKey::from(sk_scalar);
        let pk_sender = PublicKey::from(&sk_sender);
        let sk_receiver = SecretKey::new(&mut csprng);
        let pk_receiver = PublicKey::from(&sk_receiver);
        // TODO: u32 takes too long to finish.
        let sender_final_balance = (csprng.next_u32() as u16) as u32;
        let sent_balance = (csprng.next_u32() as u16) as u32;
        let sender_initial_balance = sender_final_balance + sent_balance;
        let sender_initial_balance_blinding = Scalar::random(&mut csprng);
        let sender_initial_encrypted_balance = new_ciphertext(
            &pk_sender,
            sender_initial_balance as u64,
            &sender_initial_balance_blinding,
        );
        let receiver_initial_balance = csprng.next_u32();
        let receiver_initial_balance_blinding = Scalar::random(&mut csprng);
        let receiver_initial_encrypted_balance = new_ciphertext(
            &pk_receiver,
            receiver_initial_balance as u64,
            &receiver_initial_balance_blinding,
        );

        (
            csprng,
            (sk_scalar, sk_sender, pk_sender, sk_receiver, pk_receiver),
            (
                sender_initial_balance,
                sender_initial_balance_blinding,
                sender_initial_encrypted_balance,
                sender_final_balance,
                sent_balance,
            ),
            (
                receiver_initial_balance,
                receiver_initial_balance_blinding,
                receiver_initial_encrypted_balance,
            ),
        )
    }

    #[quickcheck]
    fn create_and_verify_transaction(seed: u64) {
        let (
            mut csprng,
            (sk_scalar, _sk_sender, pk_sender, _sk_receiver, pk_receiver),
            (
                _sender_initial_balance,
                _sender_initial_balance_blinding,
                sender_initial_encrypted_balance,
                _sender_final_balance,
                sent_balance,
            ),
            (
                _receiver_initial_balance,
                _receiver_initial_balance_blinding,
                _receiver_initial_encrypted_balance,
            ),
        ) = setup_from_seed(seed);

        let transaction = Transaction::create_transaction_with_rng(
            &sender_initial_encrypted_balance,
            sent_balance,
            &pk_sender,
            &pk_receiver,
            &sk_scalar,
            &mut csprng,
        )
        .expect("Should be able to create transaction");

        assert!(transaction.verify_transaction().is_ok());
    }

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
            sent_balance,
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

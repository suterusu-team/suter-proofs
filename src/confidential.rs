use std::marker::PhantomData;

use bulletproofs::{BatchZetherProof, ZetherProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use num::CheckedSub;
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
pub enum Proof {
    Zether(ZetherProof),
    BatchZether(BatchZetherProof),
}

/// One to one confidential transaction.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transaction<A: Amount> {
    sender: PublicKey,
    original_balance: EncryptedBalance,
    transfers: Vec<(EncryptedBalance, EncryptedBalance)>,
    commitments: Vec<CompressedRistretto>,
    proof: Proof,
    _phantom: PhantomData<A>,
}

impl<A: Amount> Transaction<A> {
    fn new(
        sender: PublicKey,
        original_balance: EncryptedBalance,
        transfers: Vec<(EncryptedBalance, EncryptedBalance)>,
        commitments: Vec<CompressedRistretto>,
        proof: Proof,
    ) -> Self {
        Transaction {
            sender,
            original_balance,
            transfers,
            commitments,
            proof,
            _phantom: PhantomData,
        }
    }

    pub fn num_of_transfers(&self) -> usize {
        self.transfers.len()
    }

    pub fn sender_transactions(&self) -> Vec<&EncryptedBalance> {
        self.transfers.iter().map(|(s, _r)| s).collect()
    }

    pub fn pk_sender(&self) -> PublicKey {
        self.original_balance.pk
    }

    fn pk_sender_point(&self) -> RistrettoPoint {
        self.original_balance.pk.get_point()
    }

    pub fn receiver_transactions(&self) -> Vec<&EncryptedBalance> {
        self.transfers.iter().map(|(_s, r)| r).collect()
    }

    pub fn pk_receivers(&self) -> Vec<PublicKey> {
        self.transfers.iter().map(|(_s, r)| r.pk).collect()
    }

    fn pk_receivers_points(&self) -> Vec<RistrettoPoint> {
        self.transfers
            .iter()
            .map(|(_s, r)| r.pk.get_point())
            .collect()
    }

    pub fn get_sender_final_balance(&self) -> EncryptedBalance {
        self.sender_transactions()
            .iter()
            .fold(self.original_balance, |sum, i| sum - *i)
    }

    pub fn get_receiver_final_balance(
        &self,
        receiver_original_balance: &[EncryptedBalance],
    ) -> Option<Vec<EncryptedBalance>> {
        if receiver_original_balance.len() != self.num_of_transfers() {
            return None;
        }
        Some(
            receiver_original_balance
                .iter()
                .zip(self.receiver_transactions())
                .map(|(original, transaction)| original + transaction)
                .collect(),
        )
    }
}

pub trait ConfidentialTransaction {
    type Amount: Amount;

    /// Create a new transaction from pk_sender which transfers transfers.1 to transfers.0.
    /// Returned Transaction can be used to calculate the final balance of the sender and receiver.
    /// The caller must provide original_balance so as to generate a valid proof.
    /// The caller must not allow race condition of transactions with the same sender.
    fn create_transaction(
        original_balance: &EncryptedBalance,
        transfers: &[(PublicKey, <Self::Amount as Amount>::Target)],
        pk_sender: &PublicKey,
        sk_sender: &Scalar,
    ) -> Result<Transaction<Self::Amount>, TransactionError> {
        Self::create_transaction_with_rng(
            original_balance,
            transfers,
            pk_sender,
            sk_sender,
            &mut thread_rng(),
        )
    }

    /// Create a new transaction with blindings generated from the given rng.
    fn create_transaction_with_rng<T: RngCore + CryptoRng>(
        original_balance: &EncryptedBalance,
        transfers: &[(PublicKey, <Self::Amount as Amount>::Target)],
        pk_sender: &PublicKey,
        sk_sender: &Scalar,
        rng: &mut T,
    ) -> Result<Transaction<Self::Amount>, TransactionError>;

    /// Verify if a transaction is valid.
    fn verify_transaction(&self) -> Result<(), TransactionError>;
}

impl<A: Amount> ConfidentialTransaction for Transaction<A> {
    type Amount = A;

    fn create_transaction_with_rng<T: RngCore + CryptoRng>(
        original_balance: &EncryptedBalance,
        transfers: &[(PublicKey, <Self::Amount as Amount>::Target)],
        pk_sender: &PublicKey,
        sk_sender: &Scalar,
        rng: &mut T,
    ) -> Result<Transaction<A>, TransactionError> {
        let num_of_transfers = transfers.len();
        if num_of_transfers == 0 {
            return Err(TransactionError::EmptyTransfers);
        }
        let (blindings, blinding_for_transaction_value) =
            generate_transaction_random_parameters(rng, num_of_transfers + 1);
        my_debug!(&blindings, &blinding_for_transaction_value);
        do_create_transaction::<Self::Amount>(
            original_balance,
            transfers,
            &blindings,
            &blinding_for_transaction_value,
            pk_sender,
            sk_sender,
        )
    }

    fn verify_transaction(&self) -> Result<(), TransactionError> {
        if self.num_of_transfers() == 0 {
            return Err(TransactionError::EmptyTransfers);
        }
        if self.num_of_transfers() + 1 != self.commitments.len() {
            return Err(TransactionError::NumNotMatch);
        }
        let mut verifier_transcript = Transcript::new(MERLIN_CONFIDENTIAL_TRANSACTION_LABEL);
        match &self.proof {
            Proof::Zether(proof) => {
                if self.num_of_transfers() != 1 {
                    return Err(TransactionError::NumNotMatch);
                }
                proof
                    .verify_multiple(
                        &BP_GENS,
                        &PC_GENS,
                        &mut verifier_transcript,
                        &self.commitments,
                        32,
                        &self.pk_sender_point(),
                        &self
                            .pk_receivers_points()
                            .first()
                            .expect("Checked nonempty earlier"),
                        &ciphertext_points_random_term_last(&self.get_sender_final_balance()),
                        &self
                            .sender_transactions()
                            .first()
                            .map(|t| ciphertext_points_random_term_last(t))
                            .expect("Checked nonempty earlier"),
                        &self
                            .receiver_transactions()
                            .first()
                            .map(|t| ciphertext_points_random_term_last(t))
                            .expect("Checked nonempty earlier"),
                    )
                    .map_err(TransactionError::BulletProofs)?
            }
            Proof::BatchZether(proof) => {
                // TODO: verify the number of transfers not too large
                proof
                    .verify_multiple(
                        &BP_GENS,
                        &PC_GENS,
                        &mut verifier_transcript,
                        &self.commitments,
                        32,
                        &self.pk_sender_point(),
                        &self.pk_receivers_points(),
                        &ciphertext_points_random_term_last(&self.get_sender_final_balance()),
                        self.sender_transactions()
                            .into_iter()
                            .map(|t| ciphertext_points_random_term_last(t))
                            .collect(),
                        self.receiver_transactions()
                            .into_iter()
                            .map(|t| ciphertext_points_random_term_last(t))
                            .collect(),
                    )
                    .map_err(TransactionError::BulletProofs)?
            }
        };
        Ok(())
    }
}

fn generate_transaction_random_parameters<T: RngCore + CryptoRng>(
    rng: &mut T,
    num_of_blindings: usize,
) -> (Vec<Scalar>, Scalar) {
    (
        (1..=num_of_blindings)
            .map(|_| Scalar::random(rng))
            .collect(),
        Scalar::random(rng),
    )
}

fn do_create_transaction<A: Amount>(
    original_balance: &EncryptedBalance,
    transfers: &[(PublicKey, <A as Amount>::Target)],
    blindings: &[Scalar],
    blinding_for_transaction_value: &Scalar,
    pk_sender: &PublicKey,
    sk_sender: &Scalar,
) -> Result<Transaction<A>, TransactionError> {
    // Must have transfers
    assert!(!transfers.is_empty());
    // Blindings includes blindings for transfer value, and blinding for final value.
    assert_eq!(transfers.len() + 1, blindings.len());

    let sk = SecretKey::from(*sk_sender);
    let mut values_to_commit: Vec<u64> = transfers
        .iter()
        .map(|(_pk, v)| (Into::<u64>::into(*v)))
        .collect();
    let sender_initial_balance: A::Target =
        A::try_decrypt_from(&sk, original_balance).ok_or(TransactionError::Decryption)?;
    let sender_final_balance: <A as Amount>::Target = transfers
        .iter()
        .try_fold(sender_initial_balance, |acc, &(_pk, v)| acc.checked_sub(&v))
        .ok_or(TransactionError::Overflow)?;
    values_to_commit.push(sender_final_balance.into());
    let pk_receivers: Vec<PublicKey> = transfers.iter().map(|(pk, _v)| *pk).collect();
    let sender_transactions: Vec<Ciphertext> = transfers
        .iter()
        .map(|(_, v)| {
            new_ciphertext(
                pk_sender,
                Into::<u64>::into(*v),
                blinding_for_transaction_value,
            )
        })
        .collect();
    let receiver_transactions: Vec<Ciphertext> = transfers
        .iter()
        .map(|(pk, v)| new_ciphertext(pk, Into::<u64>::into(*v), blinding_for_transaction_value))
        .collect();
    let sender_final_encrypted_balance = sender_transactions
        .iter()
        .fold(*original_balance, |acc, i| acc - *i);
    let mut prover_transcript = Transcript::new(MERLIN_CONFIDENTIAL_TRANSACTION_LABEL);
    let (proof, commitments) = if transfers.len() == 1 {
        let (p, c) = ZetherProof::prove_multiple(
            &BP_GENS,
            &PC_GENS,
            &mut prover_transcript,
            &values_to_commit,
            &blindings,
            32,
            &pk_sender.get_point(),
            &pk_receivers
                .first()
                .expect("Checked nonempty earlier")
                .get_point(),
            &ciphertext_points_random_term_last(&sender_final_encrypted_balance),
            &sender_transactions
                .first()
                .map(|t| ciphertext_points_random_term_last(t))
                .expect("Checked nonempty earlier"),
            sk_sender,
            blinding_for_transaction_value,
        )
        .map_err(TransactionError::BulletProofs)?;
        (Proof::Zether(p), c)
    } else {
        let (p, c) = BatchZetherProof::prove_multiple(
            &BP_GENS,
            &PC_GENS,
            &mut prover_transcript,
            &values_to_commit,
            &blindings,
            32,
            &pk_sender.get_point(),
            &pk_receivers.iter().map(|pk| pk.get_point()).collect(),
            &ciphertext_points_random_term_last(&sender_final_encrypted_balance),
            sender_transactions
                .iter()
                .map(|t| ciphertext_points_random_term_last(t))
                .collect(),
            sk_sender,
            &blinding_for_transaction_value,
        )
        .map_err(TransactionError::BulletProofs)?;
        (Proof::BatchZether(p), c)
    };

    my_debug!(&proof, &commitments);
    Ok(Transaction::new(
        *pk_sender,
        *original_balance,
        sender_transactions
            .into_iter()
            .zip(receiver_transactions)
            .collect(),
        commitments,
        proof,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::TestResult;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, RngCore, SeedableRng};

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
        let transaction_value = (csprng.next_u32() as u16) as u32;
        let sender_initial_balance = sender_final_balance + transaction_value;
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
                transaction_value,
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
                transaction_value,
            ),
            (
                _receiver_initial_balance,
                _receiver_initial_balance_blinding,
                _receiver_initial_encrypted_balance,
            ),
        ) = setup_from_seed(seed);

        let transaction = Transaction::<u32>::create_transaction_with_rng(
            &sender_initial_encrypted_balance,
            &[(pk_receiver, transaction_value)],
            &pk_sender,
            &sk_scalar,
            &mut csprng,
        )
        .expect("Should be able to create transaction");

        assert!(transaction.verify_transaction().is_ok());
    }

    #[quickcheck]
    fn transacation_balance_should_be_corrent(
        transaction_value: u32,
        sender_initial_balance: u32,
        receiver_initial_balance: u32,
    ) -> TestResult {
        if transaction_value > sender_initial_balance {
            return TestResult::discard();
        };

        let sender_final_balance = &sender_initial_balance - &transaction_value;
        let receiver_final_balance = &receiver_initial_balance + &transaction_value;

        let mut csprng = OsRng;
        let sk_scalar = Scalar::random(&mut csprng);
        let sk_sender = SecretKey::from(sk_scalar);
        let pk_sender = PublicKey::from(&sk_sender);
        let sk_receiver = SecretKey::new(&mut csprng);
        let pk_receiver = PublicKey::from(&sk_receiver);
        let sender_initial_encrypted_balance = sender_initial_balance.encrypt_with(&pk_sender);
        let receiver_initial_encrypted_balance =
            receiver_initial_balance.encrypt_with(&pk_receiver);

        let transaction = Transaction::<u32>::create_transaction(
            &sender_initial_encrypted_balance,
            &[(pk_receiver, transaction_value)],
            &pk_sender,
            &sk_scalar,
        )
        .expect("Should be able to create transaction");

        assert_eq!(
            u32::try_decrypt_from(
                &sk_sender,
                &transaction.sender_transactions().first().unwrap()
            )
            .unwrap(),
            transaction_value
        );
        assert_eq!(
            u32::try_decrypt_from(
                &sk_receiver,
                &transaction.receiver_transactions().first().unwrap()
            )
            .unwrap(),
            transaction_value
        );
        assert_eq!(
            u32::try_decrypt_from(&sk_sender, &transaction.get_sender_final_balance()).unwrap(),
            sender_final_balance
        );
        assert_eq!(
            u32::try_decrypt_from(
                &sk_receiver,
                &transaction
                    .get_receiver_final_balance(&[receiver_initial_encrypted_balance])
                    .unwrap()
                    .first()
                    .unwrap()
            )
            .unwrap(),
            receiver_final_balance
        );
        TestResult::passed()
    }
}

use crate::constants::FEE_KEYPAIR;
use std::{iter, marker::PhantomData};

use bulletproofs::{BatchZetherProof, ZetherProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use num::CheckedSub;
#[cfg(feature = "std")]
use rand::thread_rng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::constants::{
    BP_GENS, MAX_NUM_OF_TRANSFERS, MERLIN_CONFIDENTIAL_TRANSACTION_LABEL, PC_GENS,
    RANDOM_PK_TO_PAD_TRANSACTIONS,
};
use crate::crypto::{from_elgamal_ristretto_public_key, to_elgamal_ristretto_secret_key};
use crate::utils::{ciphertext_points_random_term_last, new_ciphertext};
use crate::{
    Amount, EncryptedBalance, PublicKey, SecretKey, TransactionError, TransactionSerdeError,
};

// TODO: Evaluate the trade-off of using BatchZetherProof for all transactions.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Proof {
    Zether(ZetherProof),
    BatchZether(BatchZetherProof),
}

/// One to n confidential transaction.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound(
    serialize = "A::Target: Serialize",
    deserialize = "A::Target: Deserialize<'de>",
))]
pub struct Transaction<A: Amount> {
    sender: PublicKey,
    original_balance: EncryptedBalance,
    transfers: Vec<(EncryptedBalance, EncryptedBalance)>,
    transfer_fee: Option<(<A as Amount>::Target, Scalar)>,
    commitments: Vec<CompressedRistretto>,
    proof: Proof,
    _phantom: PhantomData<A>,
}

impl<A: Amount> Transaction<A> {
    fn new(
        sender: PublicKey,
        original_balance: EncryptedBalance,
        transfers: Vec<(EncryptedBalance, EncryptedBalance)>,
        transfer_fee: Option<(<A as Amount>::Target, Scalar)>,
        commitments: Vec<CompressedRistretto>,
        proof: Proof,
    ) -> Self {
        Transaction {
            sender,
            original_balance,
            transfers,
            transfer_fee,
            commitments,
            proof,
            _phantom: PhantomData,
        }
    }

    // Number of transfers contained in this transaction
    fn num_of_transfers_for_verification(&self) -> usize {
        if self.transfer_fee.is_some() {
            self.transfers.len() + 1
        } else {
            self.transfers.len()
        }
    }

    // Transactions for sender to apply
    fn sender_transactions(&self) -> Vec<EncryptedBalance> {
        self.transfers.iter().map(|(s, _r)| *s).collect()
    }

    fn sender_fee_transaction(&self) -> Option<EncryptedBalance> {
        self.transfer_fee
            .map(|(fee, blinding_for_transaction_value)| {
                new_ciphertext(
                    &self.sender_pk(),
                    fee.into(),
                    &blinding_for_transaction_value,
                )
            })
    }

    fn sender_transactions_for_verification(&self) -> Vec<EncryptedBalance> {
        match self.sender_fee_transaction() {
            Some(fee_transaction) => iter::once(fee_transaction)
                .chain(self.sender_transactions())
                .collect(),
            None => self.sender_transactions(),
        }
    }

    /// Get the public key of sender
    pub fn sender_pk(&self) -> PublicKey {
        from_elgamal_ristretto_public_key(&self.original_balance.pk)
    }

    fn sender_pk_point(&self) -> RistrettoPoint {
        self.original_balance.pk.get_point()
    }

    // Transactions for receiver to apply
    fn receiver_transactions(&self) -> Vec<EncryptedBalance> {
        self.transfers.iter().map(|(_s, r)| *r).collect()
    }

    fn receiver_fee_transaction(&self, receiver_pk: &PublicKey) -> Option<EncryptedBalance> {
        self.transfer_fee
            .map(|(fee, blinding_for_transaction_value)| {
                new_ciphertext(&receiver_pk, fee.into(), &blinding_for_transaction_value)
            })
    }

    fn receiver_transactions_for_verification(&self) -> Vec<EncryptedBalance> {
        match self.receiver_fee_transaction(&FEE_KEYPAIR.1) {
            Some(fee_transaction) => iter::once(fee_transaction)
                .chain(self.receiver_transactions())
                .collect(),
            None => self.receiver_transactions(),
        }
    }

    /// Get the public keys of receivers
    pub fn receiver_pks(&self) -> Vec<PublicKey> {
        self.transfers
            .iter()
            .map(|(_s, r)| from_elgamal_ristretto_public_key(&r.pk))
            .collect()
    }

    fn receiver_pks_points(&self) -> Vec<RistrettoPoint> {
        self.receiver_pks().iter().map(|x| *x.as_point()).collect()
    }

    /// Get the final encrypted balance of sender after transaction is applied
    pub fn get_sender_final_encrypted_balance(&self) -> EncryptedBalance {
        self.sender_transactions_for_verification()
            .iter()
            .fold(self.original_balance, |acc, i| acc - *i)
    }

    /// Get the final balance of sender after transaction is applied
    pub fn try_get_sender_final_balance(&self, sk: &SecretKey) -> Option<<A as Amount>::Target> {
        A::try_decrypt_from(sk, &self.get_sender_final_encrypted_balance())
    }

    /// Get the final balance of sender after transaction is applied
    pub fn try_get_sender_final_balance_with_guess(
        &self,
        sk: &SecretKey,
        guess: <A as Amount>::Target,
    ) -> Option<<A as Amount>::Target> {
        A::try_decrypt_from_with_hint(sk, &self.get_sender_final_encrypted_balance(), guess)
    }

    /// Get the final balance of receivers after transaction is applied to receiver_original_balance.
    /// Panics on encrypted balances and receiver transactions are not encrypted with the same public keys.
    pub fn get_receiver_final_encrypted_balance(
        &self,
        receiver_original_balance: &[EncryptedBalance],
    ) -> Vec<EncryptedBalance> {
        receiver_original_balance
            .iter()
            .zip(self.receiver_transactions())
            .map(|(original, transaction)| original + transaction)
            .collect()
    }

    /// Get a compact binary representation of the transaction.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TransactionSerdeError> {
        let version = 0u8;
        let encoded = bincode::serialize(self).map_err(TransactionSerdeError::Underlying)?;
        let mut buf = Vec::with_capacity(encoded.len() + 1);
        buf.extend(&version.to_ne_bytes());
        buf.extend_from_slice(&encoded);
        Ok(buf)
    }

    /// Convert binary representations into transactions.
    pub fn from_bytes(slice: &[u8]) -> Result<Self, TransactionSerdeError> {
        if slice.is_empty() {
            return Err(TransactionSerdeError::Format);
        }
        let version = u8::from_ne_bytes([slice[0]]);
        if version != 0u8 {
            return Err(TransactionSerdeError::Version(version));
        }
        let transaction: Self =
            bincode::deserialize(&slice[1..]).map_err(TransactionSerdeError::Underlying)?;
        if transaction.transfers.is_empty()
            || transaction.commitments.len() != transaction.transfers.len() + 1
        {
            return Err(TransactionSerdeError::Malformed);
        }
        Ok(transaction)
    }
}

struct ProofBuilder<A: Amount> {
    public_key: PublicKey,
    secret_key: SecretKey,
    original_balance: EncryptedBalance,
    transfers: Vec<(PublicKey, <A as Amount>::Target)>,
    blindings: Vec<Scalar>,
    fee: Option<<A as Amount>::Target>,
}

fn identity_pk() -> PublicKey {
    use curve25519_dalek::traits::Identity;
    PublicKey::from_point(Identity::identity())
}

impl<A: Amount> ProofBuilder<A> {
    fn new(
        public_key: PublicKey,
        secret_key: SecretKey,
        original_balance: EncryptedBalance,
        transfers: Vec<(PublicKey, <A as Amount>::Target)>,
        fee: Option<<A as Amount>::Target>,
    ) -> Self {
        let mut builder = Self {
            public_key,
            secret_key,
            original_balance,
            transfers,
            blindings: vec![],
            fee: None,
        };
        if let Some(fee) = fee {
            builder.add_fee(fee);
        }
        builder
    }

    fn add_fee(&mut self, fee: <A as Amount>::Target) {
        if self.fee.is_some() {
            return;
        }
        self.transfers.insert(0, (identity_pk(), fee));
        self.fee = Some(fee);
    }

    // Padding transfers with transferred value 0, so that we can use aggregate zether proofs.
    // This is necessary as BatchZetherProof only supports 2^n value commitments.
    // For some unfathomable reason, verification of transaction padded with transfers from the sender to the sender failed.
    // TODO: fix this.
    fn pad_transfers(&mut self) {
        let n = self.transfers.len();
        self.transfers.extend(
            std::iter::repeat((*RANDOM_PK_TO_PAD_TRANSACTIONS, A::zero()))
                .take((n + 1).next_power_of_two() - n - 1),
        );
    }

    fn get_transfer_values(&self) -> Vec<u64> {
        self.transfers.iter().map(|x| x.1.into()).collect()
    }

    fn generate_transaction_random_parameters<T: RngCore + CryptoRng>(&mut self, rng: &mut T) {
        my_debug!(&self.blindings);
        self.blindings = (0..=self.transfers.len() + 1)
            .map(|_| Scalar::random(rng))
            .collect();
        my_debug!(&self.blindings);
    }

    fn get_blindings(&self) -> (&Scalar, &[Scalar]) {
        let (left, right) = self.blindings.split_at(1);
        my_debug!(left, right);
        (left.first().unwrap(), right)
    }

    fn create_proof_from_rng<T: RngCore + CryptoRng>(
        &mut self,
        rng: &mut T,
    ) -> Result<Transaction<A>, TransactionError> {
        self.pad_transfers();
        self.generate_transaction_random_parameters(rng);

        let (blinding_for_transaction_value, blindings) = self.get_blindings();
        // Must have transfers.
        assert!(!self.transfers.is_empty());
        // Blindings includes blindings for transfer value, and blinding for final value.
        assert_eq!(self.transfers.len() + 1, blindings.len());

        if self.transfers.len() > MAX_NUM_OF_TRANSFERS {
            return Err(TransactionError::TooManyTransfers {
                given: self.transfers.len(),
                max: MAX_NUM_OF_TRANSFERS,
            });
        }

        if self.transfers.iter().any(|(pk, _)| *pk == self.public_key) {
            return Err(TransactionError::SelfTransfer);
        }

        let mut values_to_commit: Vec<u64> = self.get_transfer_values();

        let sender_initial_balance: A::Target =
            A::try_decrypt_from(&self.secret_key, &self.original_balance)
                .ok_or(TransactionError::Decryption)?;
        let sender_final_balance: <A as Amount>::Target = self
            .transfers
            .iter()
            .try_fold(sender_initial_balance, |acc, &(_pk, v)| acc.checked_sub(&v))
            .ok_or(TransactionError::Overflow)?;
        my_debug!(
            sender_initial_balance,
            sender_final_balance,
            &values_to_commit
        );
        values_to_commit.push(sender_final_balance.into());
        let receiver_pks: Vec<PublicKey> = self.transfers.iter().map(|(pk, _v)| *pk).collect();
        let sender_transactions: Vec<EncryptedBalance> = self
            .transfers
            .iter()
            .map(|(_, v)| {
                new_ciphertext(
                    &self.public_key,
                    Into::<u64>::into(*v),
                    blinding_for_transaction_value,
                )
            })
            .collect();
        let receiver_transactions: Vec<EncryptedBalance> = self
            .transfers
            .iter()
            .map(|(pk, v)| {
                new_ciphertext(pk, Into::<u64>::into(*v), blinding_for_transaction_value)
            })
            .collect();
        let sender_final_encrypted_balance = sender_transactions
            .iter()
            .fold(self.original_balance, |acc, i| acc - *i);
        let mut prover_transcript = Transcript::new(MERLIN_CONFIDENTIAL_TRANSACTION_LABEL);
        let (proof, commitments) = if self.transfers.len() == 1 {
            let (p, c) = ZetherProof::prove_multiple(
                &BP_GENS,
                &PC_GENS,
                &mut prover_transcript,
                &values_to_commit,
                &blindings,
                A::bit_size(),
                self.public_key.as_point(),
                receiver_pks
                    .first()
                    .expect("Checked nonempty earlier")
                    .as_point(),
                &ciphertext_points_random_term_last(&sender_final_encrypted_balance),
                &sender_transactions
                    .first()
                    .map(|t| ciphertext_points_random_term_last(t))
                    .expect("Checked nonempty earlier"),
                &to_elgamal_ristretto_secret_key(&self.secret_key).get_scalar(),
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
                A::bit_size(),
                self.public_key.as_point(),
                &receiver_pks.iter().map(|pk| pk.into_point()).collect(),
                &ciphertext_points_random_term_last(&sender_final_encrypted_balance),
                sender_transactions
                    .iter()
                    .map(|t| ciphertext_points_random_term_last(t))
                    .collect(),
                &to_elgamal_ristretto_secret_key(&self.secret_key).get_scalar(),
                &blinding_for_transaction_value,
            )
            .map_err(TransactionError::BulletProofs)?;
            (Proof::BatchZether(p), c)
        };

        my_debug!(&proof, &commitments);
        Ok(Transaction::new(
            self.public_key,
            self.original_balance,
            sender_transactions
                .into_iter()
                .zip(receiver_transactions)
                .collect(),
            None,
            commitments,
            proof,
        ))
    }
}

pub trait ConfidentialTransaction {
    type Amount: Amount;

    /// Create a new transaction from sender_pk which transfers transfers.1 to transfers.0.
    /// Returned Transaction can be used to calculate the final balance of the sender and receiver.
    /// The caller must provide original_balance so as to generate a valid proof.
    /// The caller must not allow race condition of transactions with the same sender.
    fn create_transaction(
        original_balance: &EncryptedBalance,
        transfers: &[(PublicKey, <Self::Amount as Amount>::Target)],
        sender_pk: &PublicKey,
        sender_sk: &SecretKey,
    ) -> Result<Transaction<Self::Amount>, TransactionError> {
        Self::create_transaction_with_rng(
            original_balance,
            transfers,
            sender_pk,
            sender_sk,
            &mut thread_rng(),
        )
    }

    /// Create a new transaction with blindings generated from the given rng.
    fn create_transaction_with_rng<T: RngCore + CryptoRng>(
        original_balance: &EncryptedBalance,
        transfers: &[(PublicKey, <Self::Amount as Amount>::Target)],
        sender_pk: &PublicKey,
        sender_sk: &SecretKey,
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
        sender_pk: &PublicKey,
        sender_sk: &SecretKey,
        rng: &mut T,
    ) -> Result<Transaction<A>, TransactionError> {
        let mut builder = ProofBuilder::<A>::new(
            sender_pk.clone(),
            sender_sk.clone(),
            original_balance.clone(),
            transfers.iter().map(Clone::clone).collect(),
            None,
        );
        builder.create_proof_from_rng(rng)
    }

    fn verify_transaction(&self) -> Result<(), TransactionError> {
        let num_of_transfers = self.num_of_transfers_for_verification();
        if num_of_transfers == 0 {
            return Err(TransactionError::EmptyTransfers);
        }
        if num_of_transfers + 1 != self.commitments.len() {
            return Err(TransactionError::NumNotMatch);
        }
        if num_of_transfers > MAX_NUM_OF_TRANSFERS {
            return Err(TransactionError::TooManyTransfers {
                given: num_of_transfers,
                max: MAX_NUM_OF_TRANSFERS,
            });
        }
        let mut verifier_transcript = Transcript::new(MERLIN_CONFIDENTIAL_TRANSACTION_LABEL);
        match &self.proof {
            Proof::Zether(proof) => {
                if num_of_transfers != 1 {
                    return Err(TransactionError::NumNotMatch);
                }
                proof
                    .verify_multiple(
                        &BP_GENS,
                        &PC_GENS,
                        &mut verifier_transcript,
                        &self.commitments,
                        A::bit_size(),
                        &self.sender_pk_point(),
                        &self
                            .receiver_pks_points()
                            .first()
                            .expect("Checked nonempty earlier"),
                        &ciphertext_points_random_term_last(
                            &self.get_sender_final_encrypted_balance(),
                        ),
                        &self
                            .sender_transactions_for_verification()
                            .first()
                            .map(|t| ciphertext_points_random_term_last(&t))
                            .expect("Checked nonempty earlier"),
                        &self
                            .receiver_transactions_for_verification()
                            .first()
                            .map(|t| ciphertext_points_random_term_last(&t))
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
                        A::bit_size(),
                        &self.sender_pk_point(),
                        &self.receiver_pks_points(),
                        &ciphertext_points_random_term_last(
                            &self.get_sender_final_encrypted_balance(),
                        ),
                        self.sender_transactions_for_verification()
                            .into_iter()
                            .map(|t| ciphertext_points_random_term_last(&t))
                            .collect(),
                        self.receiver_transactions_for_verification()
                            .into_iter()
                            .map(|t| ciphertext_points_random_term_last(&t))
                            .collect(),
                    )
                    .map_err(TransactionError::BulletProofs)?
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::TestResult;
    use rand::distributions::{Distribution, Standard};
    use rand::Rng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};

    fn new_ciphertext_should_work<T>(seed: u64)
    where
        T: Amount,
        Standard: Distribution<T>,
    {
        let mut csprng: ChaCha20Rng = SeedableRng::seed_from_u64(seed);
        let sk = SecretKey::generate_with(&mut csprng);
        let pk = sk.to_public();
        let value = Rng::gen::<T>(&mut csprng);
        let blinding = Scalar::random(&mut csprng);
        let ciphertext = new_ciphertext(&pk, value.to_u64(), &blinding);
        assert!(
            T::try_decrypt_from_with_hint(&sk, &ciphertext, value.inner()).unwrap()
                == value.inner()
        )
    }

    #[quickcheck]
    fn new_ciphertext_should_work_u8(seed: u64) {
        new_ciphertext_should_work::<u8>(seed)
    }

    #[quickcheck]
    fn new_ciphertext_should_work_u16(seed: u64) {
        new_ciphertext_should_work::<u16>(seed)
    }

    #[quickcheck]
    fn new_ciphertext_should_work_u32(seed: u64) {
        new_ciphertext_should_work::<u32>(seed)
    }

    #[quickcheck]
    fn new_ciphertext_should_work_u64(seed: u64) {
        new_ciphertext_should_work::<u64>(seed)
    }

    // Deterministically generate transacation parameters
    fn setup_from_seed_and_num_of_transfers<T>(
        seed: u64,
        num_of_transfers: u8,
    ) -> Option<(
        ChaCha20Rng,
        // sender_sk, sender_pk
        (SecretKey, PublicKey),
        // sender_initial_balance, sender_final_balance, sender_initial_balance_blinding, sender_initial_encrypted_balance
        (T, T, Scalar, EncryptedBalance),
        // receiver_sk, receiver_pk, receiver_initial_balance, receiver_initial_balance_blinding, receiver_initial_encrypted_balance, transaction_value, transaction_blinding, sender_transaction, receiver_transaction
        Vec<(
            SecretKey,
            PublicKey,
            T,
            Scalar,
            EncryptedBalance,
            T,
            Scalar,
            EncryptedBalance,
            EncryptedBalance,
        )>,
    )>
    where
        T: Copy
            + std::fmt::Debug
            + From<u16>
            + Amount
            + num::Integer
            + num::CheckedAdd
            + std::iter::Sum,
        Standard: Distribution<T>,
    {
        // It's fucking tedious. I can haz a good combinator?
        let n = num_of_transfers.rem_euclid(MAX_NUM_OF_TRANSFERS as u8);
        let num_of_transfers = if n == 0 {
            MAX_NUM_OF_TRANSFERS as u8
        } else {
            n
        };
        let mut csprng: ChaCha20Rng = SeedableRng::seed_from_u64(seed);
        let sender_sk = SecretKey::generate_with(&mut csprng);
        let sender_pk = sender_sk.to_public();
        // TODO: u16 takes reasonable time to finish.
        // let sender_final_balance = Rng::gen::<T>(&mut csprng);
        let sender_final_balance = T::from(Rng::gen::<u16>(&mut csprng));
        let info: Vec<_> = (1..=num_of_transfers)
            .map(|_i| {
                let receiver_sk = SecretKey::generate_with(&mut csprng);
                let receiver_pk = receiver_sk.to_public();
                // Don't use large transaction value to avoid overflow
                let transaction_value = T::from(Rng::gen::<u8>(&mut csprng) as u16);
                let transaction_blinding = Scalar::random(&mut csprng);
                let receiver_initial_balance = T::from(Rng::gen::<u16>(&mut csprng));
                let receiver_initial_balance_blinding = Scalar::random(&mut csprng);
                let receiver_initial_encrypted_balance = new_ciphertext(
                    &receiver_pk,
                    receiver_initial_balance.to_u64(),
                    &receiver_initial_balance_blinding,
                );
                let sender_transaction = new_ciphertext(
                    &sender_pk,
                    transaction_value.to_u64(),
                    &transaction_blinding,
                );
                let receiver_transaction = new_ciphertext(
                    &receiver_pk,
                    transaction_value.to_u64(),
                    &transaction_blinding,
                );
                (
                    receiver_sk,
                    receiver_pk,
                    receiver_initial_balance,
                    receiver_initial_balance_blinding,
                    receiver_initial_encrypted_balance,
                    transaction_value,
                    transaction_blinding,
                    sender_transaction,
                    receiver_transaction,
                )
            })
            .collect();
        let transaction_values = info.iter().map(|x| x.5).collect::<Vec<_>>();
        let sender_initial_balance = transaction_values
            .iter()
            .try_fold(sender_final_balance, |acc, v| acc.checked_add(&v))?;
        let sender_initial_balance_blinding = Scalar::random(&mut csprng);
        let sender_initial_encrypted_balance = new_ciphertext(
            &sender_pk,
            sender_initial_balance.to_u64(),
            &sender_initial_balance_blinding,
        );
        return Some((
            csprng,
            (sender_sk, sender_pk),
            (
                sender_initial_balance,
                sender_final_balance,
                sender_initial_balance_blinding,
                sender_initial_encrypted_balance,
            ),
            info,
        ));
    }

    fn setup_from_seed<T>(
        seed: u64,
    ) -> Option<(
        ChaCha20Rng,
        // sender_sk, sender_pk
        (SecretKey, PublicKey),
        // sender_initial_balance, sender_final_balance, sender_initial_balance_blinding, sender_initial_encrypted_balance
        (T, T, Scalar, EncryptedBalance),
        // receiver_sk, receiver_pk, receiver_initial_balance, receiver_initial_balance_blinding, receiver_initial_encrypted_balance, transaction_value, transaction_blinding, sender_transaction, receiver_transaction
        (
            SecretKey,
            PublicKey,
            T,
            Scalar,
            EncryptedBalance,
            T,
            Scalar,
            EncryptedBalance,
            EncryptedBalance,
        ),
    )>
    where
        T: Copy
            + std::fmt::Debug
            + From<u16>
            + Amount
            + num::Integer
            + num::CheckedAdd
            + std::iter::Sum,
        Standard: Distribution<T>,
    {
        setup_from_seed_and_num_of_transfers(seed, 1)
            .map(|(a, b, c, d)| (a, b, c, d.into_iter().next().unwrap()))
    }

    fn create_one_to_one_transaction<T>(seed: u64) -> Option<Transaction<T>>
    where
        T: Copy
            + std::fmt::Debug
            + From<u16>
            + Amount
            + num::Integer
            + num::CheckedAdd
            + std::iter::Sum,
        Standard: Distribution<T>,
    {
        setup_from_seed::<T>(seed).map(
            |(
                mut csprng,
                (sender_sk, sender_pk),
                (
                    _sender_initial_balance,
                    _sender_final_balance,
                    _sender_initial_balance_blinding,
                    sender_initial_encrypted_balance,
                ),
                (
                    _receiver_sk,
                    receiver_pk,
                    _receiver_initial_balance,
                    _receiver_initial_balance_blinding,
                    _receiver_initial_encrypted_balance,
                    transaction_value,
                    _transaction_blinding,
                    _sender_transaction,
                    _receiver_transaction,
                ),
            )| {
                Transaction::<T>::create_transaction_with_rng(
                    &sender_initial_encrypted_balance,
                    &[(receiver_pk, transaction_value.inner())],
                    &sender_pk,
                    &sender_sk,
                    &mut csprng,
                )
                .expect("Should be able to create transaction")
            },
        )
    }

    #[quickcheck]
    fn serde_one_to_one_transaction_u32(seed: u64) -> TestResult {
        match create_one_to_one_transaction::<u32>(seed) {
            None => {
                return TestResult::discard();
            }
            Some(transaction) => {
                assert_eq!(
                    transaction.to_bytes().unwrap(),
                    Transaction::<u32>::from_bytes(&transaction.to_bytes().unwrap())
                        .unwrap()
                        .to_bytes()
                        .unwrap(),
                );
                TestResult::passed()
            }
        }
    }

    fn create_and_verify_one_to_one_transaction<T>(seed: u64) -> TestResult
    where
        T: Copy
            + std::fmt::Debug
            + From<u16>
            + Amount
            + num::Integer
            + num::CheckedAdd
            + std::iter::Sum,
        Standard: Distribution<T>,
    {
        match create_one_to_one_transaction::<T>(seed) {
            None => {
                return TestResult::discard();
            }
            Some(transaction) => {
                assert!(transaction.verify_transaction().is_ok());
                TestResult::passed()
            }
        }
    }

    #[quickcheck]
    fn create_and_verify_one_to_one_transaction_u16(seed: u64) -> TestResult {
        create_and_verify_one_to_one_transaction::<u16>(seed)
    }

    #[quickcheck]
    fn create_and_verify_one_to_one_transaction_u32(seed: u64) -> TestResult {
        create_and_verify_one_to_one_transaction::<u32>(seed)
    }

    #[quickcheck]
    fn create_and_verify_one_to_one_transaction_u64(seed: u64) -> TestResult {
        create_and_verify_one_to_one_transaction::<u64>(seed)
    }

    fn create_one_to_n_transaction<T>(seed: u64, n: u8) -> Option<Transaction<T>>
    where
        T: Copy
            + std::fmt::Debug
            + From<u16>
            + Amount
            + num::Integer
            + num::CheckedAdd
            + std::iter::Sum,
        Standard: Distribution<T>,
    {
        setup_from_seed_and_num_of_transfers::<T>(seed, n).map(
            |(
                mut csprng,
                (sender_sk, sender_pk),
                (
                    _sender_initial_balance,
                    _sender_final_balance,
                    _sender_initial_balance_blinding,
                    sender_initial_encrypted_balance,
                ),
                info,
            )| {
                let transfers: Vec<(PublicKey, <T as Amount>::Target)> =
                    info.iter().map(|x| (x.1, x.5.inner())).collect();
                Transaction::<T>::create_transaction_with_rng(
                    &sender_initial_encrypted_balance,
                    &transfers,
                    &sender_pk,
                    &sender_sk,
                    &mut csprng,
                )
                .expect("Should be able to create transaction")
            },
        )
    }

    #[quickcheck]
    fn serde_one_to_n_transaction_u32(seed: u64, n: u8) -> TestResult {
        match create_one_to_n_transaction::<u32>(seed, n) {
            None => {
                return TestResult::discard();
            }
            Some(transaction) => {
                let bytes = transaction.to_bytes().unwrap();
                let new_transaction = Transaction::<u32>::from_bytes(&bytes).unwrap();
                assert_eq!(
                    transaction.to_bytes().unwrap(),
                    new_transaction.to_bytes().unwrap(),
                );
                TestResult::passed()
            }
        }
    }

    fn create_and_verify_one_to_n_transaction<T>(seed: u64, n: u8) -> TestResult
    where
        T: Copy
            + std::fmt::Debug
            + From<u16>
            + Amount
            + num::Integer
            + num::CheckedAdd
            + std::iter::Sum,
        Standard: Distribution<T>,
    {
        match create_one_to_n_transaction::<T>(seed, n) {
            None => {
                return TestResult::discard();
            }
            Some(transaction) => {
                assert!(transaction.verify_transaction().is_ok());
                TestResult::passed()
            }
        }
    }

    #[quickcheck]
    fn create_and_verify_one_to_n_transaction_u16(seed: u64, n: u8) -> TestResult {
        create_and_verify_one_to_n_transaction::<u16>(seed, n)
    }

    #[quickcheck]
    fn create_and_verify_one_to_n_transaction_u32(seed: u64, n: u8) -> TestResult {
        create_and_verify_one_to_n_transaction::<u32>(seed, n)
    }

    #[quickcheck]
    fn create_and_verify_one_to_n_transaction_u64(seed: u64, n: u8) -> TestResult {
        create_and_verify_one_to_n_transaction::<u64>(seed, n)
    }

    #[quickcheck]
    fn one_to_one_transacation_balance_should_be_correct(
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
        let sender_sk = SecretKey::generate_with(&mut csprng);
        let sender_pk = sender_sk.to_public();
        let receiver_sk = SecretKey::generate_with(&mut csprng);
        let receiver_pk = receiver_sk.to_public();
        let sender_initial_encrypted_balance = sender_initial_balance.encrypt_with(&sender_pk);
        let receiver_initial_encrypted_balance =
            receiver_initial_balance.encrypt_with(&receiver_pk);

        let transaction = Transaction::<u32>::create_transaction(
            &sender_initial_encrypted_balance,
            &[(receiver_pk, transaction_value)],
            &sender_pk,
            &sender_sk,
        )
        .expect("Should be able to create transaction");

        assert_eq!(
            u32::try_decrypt_from_with_hint(
                &sender_sk,
                &transaction.sender_transactions().first().unwrap(),
                transaction_value
            )
            .unwrap(),
            transaction_value
        );
        assert_eq!(
            u32::try_decrypt_from_with_hint(
                &receiver_sk,
                &transaction.receiver_transactions().first().unwrap(),
                transaction_value
            )
            .unwrap(),
            transaction_value
        );
        assert_eq!(
            transaction
                .try_get_sender_final_balance_with_guess(&sender_sk, sender_final_balance)
                .unwrap(),
            sender_final_balance
        );
        assert_eq!(
            u32::try_decrypt_from_with_hint(
                &receiver_sk,
                &transaction
                    .get_receiver_final_encrypted_balance(&[receiver_initial_encrypted_balance])
                    .first()
                    .unwrap(),
                receiver_final_balance
            )
            .unwrap(),
            receiver_final_balance
        );
        TestResult::passed()
    }

    fn one_to_n_transacation_balance_should_be_correct<T>(seed: u64, n: u8) -> TestResult
    where
        T: Copy
            + std::fmt::Debug
            + From<u16>
            + Amount
            + num::Integer
            + num::CheckedAdd
            + std::iter::Sum,
        Standard: Distribution<T>,
    {
        match setup_from_seed_and_num_of_transfers::<T>(seed, n) {
            None => {
                return TestResult::discard();
            }
            Some((
                mut csprng,
                (sender_sk, sender_pk),
                (
                    _sender_initial_balance,
                    sender_final_balance,
                    _sender_initial_balance_blinding,
                    sender_initial_encrypted_balance,
                ),
                info,
            )) => {
                let transfers: Vec<(PublicKey, <T as Amount>::Target)> =
                    info.iter().map(|x| (x.1, x.5.inner())).collect();
                let transaction = Transaction::<T>::create_transaction_with_rng(
                    &sender_initial_encrypted_balance,
                    &transfers[..],
                    &sender_pk,
                    &sender_sk,
                    &mut csprng,
                )
                .expect("Should be able to create transaction");
                assert_eq!(
                    transaction
                        .try_get_sender_final_balance_with_guess(
                            &sender_sk,
                            sender_final_balance.inner()
                        )
                        .unwrap(),
                    sender_final_balance.inner()
                );

                let receivers_original_balance: Vec<EncryptedBalance> =
                    info.iter().map(|x| x.4).collect();
                let receivers_final_balance =
                    transaction.get_receiver_final_encrypted_balance(&receivers_original_balance);
                for (
                    (
                        receiver_sk,
                        _receiver_pk,
                        receiver_initial_balance,
                        _receiver_initial_balance_blinding,
                        _receiver_initial_encrypted_balance,
                        transaction_value,
                        _transaction_blinding,
                        _sender_transaction,
                        _receiver_transaction,
                    ),
                    receiver_final_encrypted_balance,
                ) in info.iter().zip(receivers_final_balance)
                {
                    match transaction_value.checked_add(receiver_initial_balance) {
                        None => return TestResult::discard(),
                        Some(b) => assert_eq!(
                            T::try_decrypt_from_with_hint(
                                &receiver_sk,
                                &receiver_final_encrypted_balance,
                                b.inner()
                            )
                            .unwrap(),
                            b.inner()
                        ),
                    }
                }
            }
        }
        TestResult::passed()
    }

    #[quickcheck]
    fn one_to_n_transacation_balance_should_be_correct_u16(seed: u64, n: u8) -> TestResult {
        one_to_n_transacation_balance_should_be_correct::<u16>(seed, n)
    }

    #[quickcheck]
    fn one_to_n_transacation_balance_should_be_correct_u32(seed: u64, n: u8) -> TestResult {
        one_to_n_transacation_balance_should_be_correct::<u32>(seed, n)
    }

    #[quickcheck]
    fn one_to_n_transacation_balance_should_be_correct_u64(seed: u64, n: u8) -> TestResult {
        one_to_n_transacation_balance_should_be_correct::<u64>(seed, n)
    }
}

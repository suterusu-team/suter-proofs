use std::iter;

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
    BP_GENS, FEE_KEYPAIR, MAX_NUM_OF_TRANSFERS, MERLIN_CONFIDENTIAL_TRANSACTION_LABEL, PC_GENS,
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

    fn verify_num_of_transfers(&self) -> Result<(), TransactionError> {
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
        Ok(())
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
        match self.receiver_fee_transaction(&pk_for_fee()) {
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

    /// Get the public keys of receivers
    pub fn receiver_pks_for_verification(&self) -> Vec<PublicKey> {
        match self.transfer_fee {
            Some(_) => iter::once(pk_for_fee())
                .chain(self.receiver_pks())
                .collect(),
            None => self.receiver_pks(),
        }
    }

    fn receiver_pks_for_verification_points(&self) -> Vec<RistrettoPoint> {
        self.receiver_pks_for_verification()
            .iter()
            .map(|x| *x.as_point())
            .collect()
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

    pub fn get_transfer_fee_receiver_final_encrypted_balance(
        &self,
        receiver_original_balance: &EncryptedBalance,
    ) -> EncryptedBalance {
        match self.transfer_fee {
            Some((x, blinding)) => {
                receiver_original_balance
                    + new_ciphertext(
                        &from_elgamal_ristretto_public_key(&receiver_original_balance.pk),
                        x.into(),
                        &blinding,
                    )
            }
            None => *receiver_original_balance,
        }
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
        transaction
            .verify_num_of_transfers()
            .map_err(|_| TransactionSerdeError::Malformed)?;
        Ok(transaction)
    }
}

fn pk_for_fee() -> PublicKey {
    FEE_KEYPAIR.1
}

#[derive(Clone, Debug)]
struct ProofBuilder<A: Amount> {
    public_key: PublicKey,
    secret_key: SecretKey,
    original_balance: EncryptedBalance,
    transfers: Vec<(PublicKey, <A as Amount>::Target)>,
    blindings: Vec<Scalar>,
    fee: Option<<A as Amount>::Target>,
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
        my_debug!(&builder);
        if let Some(fee) = fee {
            builder.add_fee(fee);
        }
        my_debug!(&builder);
        builder
    }

    fn add_fee(&mut self, fee: <A as Amount>::Target) {
        if self.fee.is_some() {
            return;
        }
        self.transfers.insert(0, (pk_for_fee(), fee));
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
        // Generate enough blindings for the fee, transaction value,
        // sender final balance and transferred values and padded transfers
        self.blindings = (0..=(self.transfers.len() + 2).next_power_of_two())
            .map(|_| Scalar::random(rng))
            .collect();
    }

    fn get_blindings(&self) -> (&Scalar, &[Scalar]) {
        let (left, right) = self.blindings.split_at(1);
        (left.first().unwrap(), right)
    }

    fn create_proof_from_rng<T: RngCore + CryptoRng>(
        &mut self,
        rng: &mut T,
    ) -> Result<Transaction<A>, TransactionError> {
        self.pad_transfers();
        self.generate_transaction_random_parameters(rng);

        if self.transfers.is_empty() {
            return Err(TransactionError::EmptyTransfers);
        }

        if self.transfers.iter().any(|(pk, _)| *pk == self.public_key) {
            return Err(TransactionError::SelfTransfer);
        }

        if self.transfers.len() > MAX_NUM_OF_TRANSFERS {
            return Err(TransactionError::TooManyTransfers {
                given: self.transfers.len(),
                max: MAX_NUM_OF_TRANSFERS,
            });
        }

        let (blinding_for_transaction_value, blindings) = self.get_blindings();
        // Blindings includes blindings for transfer value, and blinding for final value.
        assert!(self.transfers.len() + 1 < blindings.len());
        let mut blindings = blindings.to_vec();
        blindings.truncate(self.transfers.len() + 1);

        let mut values_to_commit: Vec<u64> = self.get_transfer_values();
        let sender_initial_balance: A::Target =
            A::try_decrypt_from(&self.secret_key, &self.original_balance)
                .ok_or(TransactionError::Decryption)?;
        let sender_final_balance: <A as Amount>::Target = self
            .transfers
            .iter()
            .try_fold(sender_initial_balance, |acc, &(_pk, v)| acc.checked_sub(&v))
            .ok_or(TransactionError::Overflow)?;
        values_to_commit.push(sender_final_balance.into());
        my_debug!(
            sender_initial_balance,
            sender_final_balance,
            &values_to_commit
        );
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
        match self.fee {
            Some(fee) => Ok(Transaction::new(
                self.public_key,
                self.original_balance,
                sender_transactions
                    .into_iter()
                    .zip(receiver_transactions)
                    .skip(1)
                    .collect(),
                Some((fee, *blinding_for_transaction_value)),
                commitments,
                proof,
            )),
            None => Ok(Transaction::new(
                self.public_key,
                self.original_balance,
                sender_transactions
                    .into_iter()
                    .zip(receiver_transactions)
                    .collect(),
                None,
                commitments,
                proof,
            )),
        }
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
        transfer_fee: Option<<Self::Amount as Amount>::Target>,
        sender_pk: &PublicKey,
        sender_sk: &SecretKey,
    ) -> Result<Self, TransactionError>
    where
        Self: std::marker::Sized,
    {
        Self::create_transaction_with_rng(
            original_balance,
            transfers,
            transfer_fee,
            sender_pk,
            sender_sk,
            &mut thread_rng(),
        )
    }

    /// Create a new transaction with blindings generated from the given rng.
    fn create_transaction_with_rng<T: RngCore + CryptoRng>(
        original_balance: &EncryptedBalance,
        transfers: &[(PublicKey, <Self::Amount as Amount>::Target)],
        transfer_fee: Option<<Self::Amount as Amount>::Target>,
        sender_pk: &PublicKey,
        sender_sk: &SecretKey,
        rng: &mut T,
    ) -> Result<Self, TransactionError>
    where
        Self: std::marker::Sized;

    // TODO: Like the verification of transfer fee, currently we only verify
    // the transaction is valid, the amount is not verified yet. That is, adversary may
    // fabricate the amount of money transferred. This is a hole to be filled.
    // We can unify logic of burning balance and creating transfer fee, as they are identical.
    /// Create a new transaction which burns balance of `amount` with `rng`.
    fn burn_balance_with_rng<T: RngCore + CryptoRng>(
        original_balance: &EncryptedBalance,
        amount: &<Self::Amount as Amount>::Target,
        transfer_fee: Option<<Self::Amount as Amount>::Target>,
        sender_pk: &PublicKey,
        sender_sk: &SecretKey,
        rng: &mut T,
    ) -> Result<Self, TransactionError>
    where
        Self: std::marker::Sized,
    {
        Self::create_transaction_with_rng(
            original_balance,
            &[(*RANDOM_PK_TO_PAD_TRANSACTIONS, *amount)],
            transfer_fee,
            sender_pk,
            sender_sk,
            rng,
        )
    }

    /// Create a new transaction which burns balance of `amount`.
    fn burn_balance(
        original_balance: &EncryptedBalance,
        amount: &<Self::Amount as Amount>::Target,
        transfer_fee: Option<<Self::Amount as Amount>::Target>,
        sender_pk: &PublicKey,
        sender_sk: &SecretKey,
    ) -> Result<Self, TransactionError>
    where
        Self: std::marker::Sized,
    {
        Self::create_transaction_with_rng(
            original_balance,
            &[(*RANDOM_PK_TO_PAD_TRANSACTIONS, *amount)],
            transfer_fee,
            sender_pk,
            sender_sk,
            &mut thread_rng(),
        )
    }

    /// Verify if a transaction is valid.
    fn verify_transaction(&self) -> Result<(), TransactionError>;
}

impl<A: Amount> ConfidentialTransaction for Transaction<A> {
    type Amount = A;

    fn create_transaction_with_rng<T: RngCore + CryptoRng>(
        original_balance: &EncryptedBalance,
        transfers: &[(PublicKey, <Self::Amount as Amount>::Target)],
        transfer_fee: Option<<Self::Amount as Amount>::Target>,
        sender_pk: &PublicKey,
        sender_sk: &SecretKey,
        rng: &mut T,
    ) -> Result<Transaction<A>, TransactionError> {
        let mut builder = ProofBuilder::<A>::new(
            *sender_pk,
            sender_sk.clone(),
            *original_balance,
            transfers.iter().map(Clone::clone).collect(),
            transfer_fee,
        );
        builder.create_proof_from_rng(rng)
    }

    fn verify_transaction(&self) -> Result<(), TransactionError> {
        self.verify_num_of_transfers()?;

        let mut verifier_transcript = Transcript::new(MERLIN_CONFIDENTIAL_TRANSACTION_LABEL);
        match &self.proof {
            Proof::Zether(proof) => {
                if self.num_of_transfers_for_verification() != 1 {
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
                            .receiver_pks_for_verification_points()
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
                // TODO: Verify the commitment for transfer fee is correct.
                // We need to create a Zether burn proof in bulletproofs.
                // See https://eprint.iacr.org/2019/191.pdf p41.
                proof
                    .verify_multiple(
                        &BP_GENS,
                        &PC_GENS,
                        &mut verifier_transcript,
                        &self.commitments,
                        A::bit_size(),
                        &self.sender_pk_point(),
                        &self.receiver_pks_for_verification_points(),
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

mod tests;

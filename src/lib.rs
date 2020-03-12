//! This library currently implemented only the confidential transaction scheme.
//! The support for anonymous transaction is planned.
//! For an example usage of this library, see `example/main.rs`.
//!
//! A confidential transaction scheme should implement the trait [confidential::ConfidentialTransaction](confidential::ConfidentialTransaction).
//! We implemented `confidential::ConfidentialTransaction` with [confidential::Transaction<T>](confidential::Transaction).
//! `confidential::Transaction<T>` requires a generic parameter `T`.
//! `T` should implement the trait [Amount](Amount).
//!
//! The trait `Amount` is used to encrypt
//! and decrypt balances. `Amount` is not implementable outside this library, as it is not intended for
//! types other than `u8`, `u16`, `u32` and `u64`, which have implemented `Amount` in this library.
//! To encrypt an amount, use the method [Amount::encrypt_with](Amount::encrypt_with).
//! This requires a parameter pk of type [schnorrkel::PublicKey](schnorrkel::PublicKey).
//! To decrypt an amount, use the method [Amount::try_decrypt_from](Amount::try_decrypt_from).
//! This requires the ciphertext obtained from early encryption and a private key of type
//! [schnorrkel::SecretKey](schnorrkel::SecretKey). In theory, the decryption may fail,
//! as we encrypt the amount with additional homomorphic property. This process may be irreversible.
//! In practice, the decryption should be fast. To accelerate the decryption,
//! a hint of the amount can be given with [Amount::try_decrypt_from_with_hint](Amount::try_decrypt_from_with_hint).
//!
//! To create a verifiable confidential transaction, we can use the method [create_transaction](confidential::ConfidentialTransaction::create_transaction),
//! the resulting transaction can be verified with [verify_transaction](confidential::ConfidentialTransaction::verify_transaction) method.
//! We have implemented support for one to n confidential transaction, i.e. one sender to multiple receivers confidential transaction.
//! To create a 1-to-n transaction, simply feed `create_transaction` with multiple receivers.
//! Currently the transaction number should be less or equal to `constants::MAX_NUM_OF_TRANSFERS`.
//! After the verification, we can obtain the final decrypted balance of the sender with
//! [try_get_sender_final_balance](confidential::Transaction::try_get_sender_final_balance),
//! obtain the final encrypted balances of the receivers
//! with [get_receiver_final_encrypted_balance](confidential::Transaction::get_receiver_final_encrypted_balance).
//! The transaction data can be serialized and deserialized with [serde::Deserialize](serde::Deserialize) and [serde::Serialize](serde::Serialize).
//! To get a compact binary representation of `confidential::Transaction`, use [to_bytes](confidential::Transaction::to_bytes),
//! which can then be converted back to `confidential::Transaction` with [from_bytes](confidential::Transaction::from_bytes).

#[macro_use]
extern crate lazy_static;

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[macro_use]
mod macros;
mod amount;
pub use amount::Amount;
pub mod confidential;
pub mod constants;
mod errors;
pub use errors::{TransactionError, TransactionSerdeError};
pub mod crypto;
pub use crypto::{Ciphertext, EncryptedBalance, PublicKey, Scalar, SecretKey};
pub(crate) mod utils;

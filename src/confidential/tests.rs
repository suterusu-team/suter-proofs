#![cfg(test)]

use super::*;
use quickcheck::TestResult;
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, SeedableRng};

// TODO: Create tests for abnormal inputs.

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
    let ciphertext = new_ciphertext(pk, value.to_u64(), blinding);
    assert!(T::try_decrypt_from_with_hint(&sk, ciphertext, value.inner()).unwrap() == value.inner())
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
    let sender_initial_encrypted_balance = sender_initial_balance.encrypt_with(sender_pk);
    let receiver_initial_encrypted_balance = receiver_initial_balance.encrypt_with(receiver_pk);

    let transaction = Transaction::<u32>::create_transaction(
        &sender_initial_encrypted_balance,
        &[(receiver_pk, transaction_value)],
        None,
        sender_pk,
        &sender_sk,
    )
    .expect("Should be able to create transaction");

    assert_eq!(
        u32::try_decrypt_from_with_hint(
            &sender_sk,
            *transaction.sender_transactions().first().unwrap(),
            transaction_value
        )
        .unwrap(),
        transaction_value
    );
    assert_eq!(
        u32::try_decrypt_from_with_hint(
            &receiver_sk,
            *transaction.receiver_transactions().first().unwrap(),
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
            *transaction
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

#[quickcheck]
fn burn_balance_with_incorrect_amount_should_not_work(
    seed: u64,
    initial_balance: u32,
) -> TestResult {
    let mut csprng: ChaCha20Rng = SeedableRng::seed_from_u64(seed);
    let sender_sk = SecretKey::generate_with(&mut csprng);
    let sender_pk = sender_sk.to_public();
    let initial_balance_plus_1 = match initial_balance.checked_add(1) {
        Some(b) => b,
        None => return TestResult::discard(),
    };
    let initial_encrypted_balance = initial_balance.encrypt_with(sender_pk);

    Transaction::<u32>::burn_balance(
        &initial_encrypted_balance,
        &initial_balance_plus_1,
        None,
        sender_pk,
        &sender_sk,
    )
    .expect_err("Should not be able to burn this much balance");
    TestResult::passed()
}

#[quickcheck]
fn burn_balance_with_correct_amount_should_work(seed: u64, initial_balance: u32) -> TestResult {
    let mut csprng: ChaCha20Rng = SeedableRng::seed_from_u64(seed);
    let sender_sk = SecretKey::generate_with(&mut csprng);
    let sender_pk = sender_sk.to_public();
    let initial_balance_minus_1 = match initial_balance.checked_sub(1) {
        Some(b) => b,
        None => return TestResult::discard(),
    };
    let initial_encrypted_balance = initial_balance.encrypt_with(sender_pk);

    let transaction = Transaction::<u32>::burn_balance(
        &initial_encrypted_balance,
        &initial_balance_minus_1,
        None,
        sender_pk,
        &sender_sk,
    )
    .expect("Should be able to burn balance");

    assert!(transaction.verify_transaction().is_ok());
    assert_eq!(
        transaction
            .try_get_sender_final_balance(&sender_sk)
            .unwrap(),
        1
    );
    TestResult::passed()
}

// Deterministically generate transacation parameters
fn do_setup_from_seed_and_num_of_transfers<T>(
    seed: u64,
    num_of_transfers: u8,
    include_fee: bool,
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
    Option<T>,
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
    let transfer_fee = T::from(Rng::gen::<u16>(&mut csprng));
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
                receiver_pk,
                receiver_initial_balance.to_u64(),
                receiver_initial_balance_blinding,
            );
            let sender_transaction =
                new_ciphertext(sender_pk, transaction_value.to_u64(), transaction_blinding);
            let receiver_transaction = new_ciphertext(
                receiver_pk,
                transaction_value.to_u64(),
                transaction_blinding,
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
    let sender_initial_balance = if include_fee {
        iter::once(transfer_fee)
            .chain(transaction_values)
            .try_fold(sender_final_balance, |acc, v| acc.checked_add(&v))?
    } else {
        transaction_values
            .iter()
            .try_fold(sender_final_balance, |acc, v| acc.checked_add(&v))?
    };
    let sender_initial_balance_blinding = Scalar::random(&mut csprng);
    let sender_initial_encrypted_balance = new_ciphertext(
        sender_pk,
        sender_initial_balance.to_u64(),
        sender_initial_balance_blinding,
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
        if include_fee {
            Some(transfer_fee)
        } else {
            None
        },
    ));
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
    do_setup_from_seed_and_num_of_transfers(seed, num_of_transfers, false)
        .map(|(a, b, c, d, _)| (a, b, c, d))
}

fn setup_from_seed_and_num_of_transfers_with_fee<T>(
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
    T,
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
    do_setup_from_seed_and_num_of_transfers(seed, num_of_transfers, true)
        .map(|(a, b, c, d, e)| (a, b, c, d, e.unwrap()))
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

fn setup_from_seed_with_fee<T>(
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
    T,
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
    setup_from_seed_and_num_of_transfers_with_fee(seed, 1)
        .map(|(a, b, c, d, e)| (a, b, c, d.into_iter().next().unwrap(), e))
}

fn create_fee_only_transaction<T>(seed: u64) -> Option<Transaction<T>>
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
                _receiver_pk,
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
                &[],
                Some(transaction_value.inner()),
                sender_pk,
                &sender_sk,
                &mut csprng,
            )
            .expect("Should be able to create transaction")
        },
    )
}

#[quickcheck]
fn create_and_verify_fee_only_transaction_u16(seed: u64) -> TestResult {
    create_and_verify_fee_only_transaction::<u16>(seed)
}

#[quickcheck]
fn create_and_verify_fee_only_transaction_u32(seed: u64) -> TestResult {
    create_and_verify_fee_only_transaction::<u32>(seed)
}

#[quickcheck]
fn create_and_verify_fee_only_transaction_u64(seed: u64) -> TestResult {
    create_and_verify_fee_only_transaction::<u64>(seed)
}

fn create_and_verify_fee_only_transaction<T>(seed: u64) -> TestResult
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
    match create_fee_only_transaction::<T>(seed) {
        None => {
            return TestResult::discard();
        }
        Some(transaction) => {
            assert!(transaction.verify_transaction().is_ok());
            TestResult::passed()
        }
    }
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
                None,
                sender_pk,
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

fn create_one_to_one_transaction_with_fee<T>(seed: u64) -> Option<Transaction<T>>
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
    setup_from_seed_with_fee::<T>(seed).map(
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
            transfer_fee,
        )| {
            Transaction::<T>::create_transaction_with_rng(
                &sender_initial_encrypted_balance,
                &[(receiver_pk, transaction_value.inner())],
                Some(transfer_fee.inner()),
                sender_pk,
                &sender_sk,
                &mut csprng,
            )
            .expect("Should be able to create transaction")
        },
    )
}

#[quickcheck]
fn serde_one_to_one_transaction_with_fee_u32(seed: u64) -> TestResult {
    match create_one_to_one_transaction_with_fee::<u32>(seed) {
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

fn create_and_verify_one_to_one_transaction_with_fee<T>(seed: u64) -> TestResult
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
    match create_one_to_one_transaction_with_fee::<T>(seed) {
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
fn create_and_verify_one_to_one_transaction_with_fee_u16(seed: u64) -> TestResult {
    create_and_verify_one_to_one_transaction_with_fee::<u16>(seed)
}

#[quickcheck]
fn create_and_verify_one_to_one_transaction_with_fee_u32(seed: u64) -> TestResult {
    create_and_verify_one_to_one_transaction_with_fee::<u32>(seed)
}

#[quickcheck]
fn create_and_verify_one_to_one_transaction_with_fee_u64(seed: u64) -> TestResult {
    create_and_verify_one_to_one_transaction_with_fee::<u64>(seed)
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
                None,
                sender_pk,
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

fn create_one_to_n_transaction_with_fee<T>(seed: u64, n: u8) -> Option<Transaction<T>>
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
                None,
                sender_pk,
                &sender_sk,
                &mut csprng,
            )
            .expect("Should be able to create transaction")
        },
    )
}

#[quickcheck]
fn serde_one_to_n_transaction_with_fee_u32(seed: u64, n: u8) -> TestResult {
    match create_one_to_n_transaction_with_fee::<u32>(seed, n) {
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

fn create_and_verify_one_to_n_transaction_with_fee<T>(seed: u64, n: u8) -> TestResult
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
    match create_one_to_n_transaction_with_fee::<T>(seed, n) {
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
fn create_and_verify_one_to_n_transaction_with_fee_u16(seed: u64, n: u8) -> TestResult {
    create_and_verify_one_to_n_transaction_with_fee::<u16>(seed, n)
}

#[quickcheck]
fn create_and_verify_one_to_n_transaction_with_fee_u32(seed: u64, n: u8) -> TestResult {
    create_and_verify_one_to_n_transaction_with_fee::<u32>(seed, n)
}

#[quickcheck]
fn create_and_verify_one_to_n_transaction_with_fee_u64(seed: u64, n: u8) -> TestResult {
    create_and_verify_one_to_n_transaction_with_fee::<u64>(seed, n)
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
                None,
                sender_pk,
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
                            receiver_final_encrypted_balance,
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

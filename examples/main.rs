use rand_core::OsRng;

use suter_proofs::confidential::ConfidentialTransaction;
use suter_proofs::confidential::Transaction;
use suter_proofs::{Amount, PublicKey, SecretKey};

fn main() {
    let mut csprng = OsRng;
    let sender_sk = SecretKey::generate_with(&mut csprng);
    let sender_pk = sender_sk.to_public();
    let receiver_initial_balances: Vec<u64> = vec![1, 10, 100];
    let transaction_values: Vec<u64> = vec![8, 88, 888];
    let receivers_info: Vec<_> = receiver_initial_balances
        .iter()
        .map(|receiver_initial_balance| {
            let receiver_sk = SecretKey::generate_with(&mut csprng);
            let receiver_pk = receiver_sk.to_public();
            let receiver_initial_encrypted_balance =
                receiver_initial_balance.encrypt_with(&receiver_pk);
            (
                receiver_sk,
                receiver_pk,
                *receiver_initial_balance,
                receiver_initial_encrypted_balance,
            )
        })
        .collect();
    let sender_final_balance = 10000u64;
    let transferred: u64 = transaction_values.iter().sum();
    let sender_initial_balance: u64 = sender_final_balance + transferred;
    let sender_initial_encrypted_balance = sender_initial_balance.encrypt_with(&sender_pk);
    let transfers: Vec<(PublicKey, u64)> = receivers_info
        .iter()
        .map(|x| (x.1))
        .zip(transaction_values.clone())
        .collect();
    let transaction = Transaction::<u64>::create_transaction(
        &sender_initial_encrypted_balance,
        &transfers,
        &sender_pk,
        &sender_sk,
    )
    .expect("Should be able to create transaction");
    assert!(transaction.verify_transaction().is_ok());
    assert_eq!(
        transaction
            .try_get_sender_final_balance(&sender_sk)
            .unwrap(),
        sender_final_balance
    );
    let receiver_final_encrypted_balances = transaction.get_receiver_final_encrypted_balance(
        &receivers_info.iter().map(|x| (x.3)).collect::<Vec<_>>(),
    );
    for (i, sk) in receivers_info.iter().map(|x| (&x.0)).enumerate() {
        assert_eq!(
            receivers_info[i].2 + &transaction_values[i],
            u64::try_decrypt_from(sk, &receiver_final_encrypted_balances[i]).unwrap()
        )
    }
}

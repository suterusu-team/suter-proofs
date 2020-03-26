# Introduction

This library currently has implemented the confidential transaction scheme.
The support for anonymous transaction is planned.

We have written [an expository article](https://github.com/suterusu-team/suter_proofs/blob/master/docs/sigma-bullets.org)
about how the confidential transaction scheme works and how to implement it.

In summary, a confidential transaction scheme
is a transaction scheme with which the transaction value and the balance
of the sender and receiver are encrypted. The zero-knowledge part means
that outsider can effectively learn nothing about the values, although
he can verify the transaction is not fabricated. The main references are
[Bulletproofs](https://eprint.iacr.org/2017/1066) and
[Zether](https://eprint.iacr.org/2019/191). We use Zether to
homomorphically encrypt the transaction value so that the we can
directly add/subtract ciphertext of the encrypted balance which can then
be decrypted into the correct balance after the transaction. We use
bulletproofs to check the transaction value is valid, i.e. it is a
non-negative number within the range $[0, 2^n)$, and after the
transaction the sender must still have a non-negative balance. The
vanilla bulletproofs do not apply to the scenario of zether as Elgamal
commitments are not fully homomorphic. We need to tweak bulletproofs to
support $\Sigma$-protocols, i.e. interactive proof of the values
commited in Bulletproofs are truly the values involved in zether, whence
we obtain a complete and sound proof of a confidential transaction.

# Library Usage

A confidential transaction scheme should implement the trait `confidential::ConfidentialTransaction`.
We implemented `confidential::ConfidentialTransaction` with `confidential::Transaction`.
`confidential::Transaction` requires a generic parameter `T`.
`T` should implement the trait `Amount`.

The trait `Amount` is used to encrypt
and decrypt balances. `Amount` is not implementable outside this library, as it is not intended for
types other than `u8`, `u16`, `u32` and `u64`, which have implemented `Amount` in this library.
To encrypt an amount, use the method `Amount::encrypt_with`.
This requires a parameter pk of type `schnorrkel::PublicKey`.
To decrypt an amount, use the method `Amount::try_decrypt_from`.
This requires the ciphertext obtained from early encryption and a private key of type
`schnorrkel::SecretKey`. In theory, the decryption may fail,
as we encrypt the amount with additional homomorphic property. This process may be irreversible.
In practice, the decryption should be fast. To accelerate the decryption,
a hint of the amount can be given with `Amount::try_decrypt_from_with_hint`.

To create a verifiable confidential transaction, we can use the method `confidential::ConfidentialTransaction::create_transaction`,
the resulting transaction can be verified with `confidential::ConfidentialTransaction::verify_transaction` method.
We have implemented support for one to n confidential transaction, i.e. one sender to multiple receivers confidential transaction.
To create a 1-to-n transaction, simply feed `create_transaction` with multiple receivers.
Currently the transaction number should be less or equal to `constants::MAX_NUM_OF_TRANSFERS`.
After the verification, we can obtain the final decrypted balance of the sender with
`confidential::Transaction::try_get_sender_final_balance`,
obtain the final encrypted balances of the receivers
with `confidential::Transaction::get_receiver_final_encrypted_balance`.
The transaction data can be serialized and deserialized with `serde::Deserialize` and `serde::Serialize`.
To get a compact binary representation of `confidential::Transaction`, use `confidential::Transaction::to_bytes`,
which can then be converted back to `confidential::Transaction` with `confidential::Transaction::from_bytes`.

# Examples

For an example usage of this library, see [examples/main.rs](https://github.com/suterusu-team/suter_proofs/blob/master/examples/main.rs).

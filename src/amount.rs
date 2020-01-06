use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use elgamal_ristretto::{Ciphertext, PublicKey, SecretKey};

pub trait Amount {
    type Target;
    fn encrypt(self, pk: PublicKey) -> Ciphertext;
    fn decrypt(sk: SecretKey, ciphertext: Ciphertext) -> Option<Self::Target>;
}

impl Amount for u32 {
    type Target = u32;

    // Elgamal encryption with balances raised from base point.
    // This makes ElGamal encryption additively homomorphic.
    // See also zether paper https://crypto.stanford.edu/~buenz/papers/zether.pdf
    fn encrypt(self, pk: PublicKey) -> Ciphertext {
        let message = &self.into() * &RISTRETTO_BASEPOINT_POINT;
        pk.encrypt(message)
    }

    // TODO: Brute force currently is the only viable way. Quickcheck shows that this is too slow.
    // Let $g$ be the base point, $y$ the public key of the reciever, $m$ the amount of money ransferred,
    // maybe we should store $(m*y^r, g^m*y^r, g^r)$ as ciphertext.
    // This way the reciever is able to recover plaintext with his secret key.
    // But this tuple is only additively homomorphic in the second and the last componnect.
    // And we need to store the entire transaction history.
    // This seems to be not worthwhile.
    fn decrypt(sk: SecretKey, ciphertext: Ciphertext) -> Option<Self::Target> {
        let point = sk.decrypt(ciphertext);
        let mut acc = RISTRETTO_BASEPOINT_POINT;
        for i in 0..std::u32::MAX {
            if acc == point {
                return Some(i);
            }
            acc = acc + RISTRETTO_BASEPOINT_POINT;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use elgamal_ristretto::{PublicKey, SecretKey};
    use rand_core::OsRng;

    fn randomly_encrypt_and_decrypt(x: u32) -> Option<u32> {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);
        let res = u32::decrypt(sk, x.encrypt(pk));
        println!("The amount decrypted is {:?}", res);
        res
    }

    #[quickcheck]
    fn encrypt_and_decrypt_should_be_identity(xs: Vec<u32>) -> bool {
        xs.into_iter()
            .all(|x| x == randomly_encrypt_and_decrypt(x).unwrap())
    }
}

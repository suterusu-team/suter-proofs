use std::marker::Sized;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use num::{CheckedAdd, CheckedSub, Integer, Zero};

use crate::constants::BASE_POINT;
use crate::crypto::{to_elgamal_ristretto_public_key, to_elgamal_ristretto_secret_key};
use crate::{Ciphertext, PublicKey, SecretKey};

/// Represents some amount of type {u8,u16,u32,u64} which can be encrypted and decrypted.
/// This trait is essentially a wrapper to target types.
/// Only {u8,u16,u32,u64} have implemented Amount, and only they can implement Amount.
pub trait Amount: Sized + private::Sealed {
    type Target: Copy + std::fmt::Debug + Integer + Zero + CheckedAdd + CheckedSub + Into<u64>;

    /// Create a new Amount from the target type.
    fn new(target: <Self as Amount>::Target) -> Self;

    /// Get the inner data of this wrapper.
    fn inner(&self) -> <Self as Amount>::Target;

    fn zero() -> <Self as Amount>::Target {
        <Self as Amount>::Target::zero()
    }

    /// The bit size of the wrapped type.
    fn bit_size() -> usize;

    /// Convert the wrapped data to u64.
    fn to_u64(&self) -> u64 {
        self.inner().into()
    }

    /// Convert the amount to a point of the Ristretto group.
    fn to_point(&self) -> RistrettoPoint {
        Scalar::from(self.to_u64()) * BASE_POINT
    }

    // Elgamal encryption with balances raised from base point.
    // This makes ElGamal encryption additively homomorphic.
    // See also zether paper https://eprint.iacr.org/2019/191.pdf
    /// Encrypt the amount with the provide public key.
    fn encrypt_with(&self, pk: &PublicKey) -> Ciphertext {
        let pk = to_elgamal_ristretto_public_key(pk);
        pk.encrypt(&self.to_point())
    }

    /// Get the decrypted point in the Ristretto group.
    fn get_decrypted_point(sk: &SecretKey, ciphertext: &Ciphertext) -> RistrettoPoint {
        let sk = to_elgamal_ristretto_secret_key(sk);
        sk.decrypt(&ciphertext)
    }

    // TODO: Currently we obtain decrypted amount with brute force. We may also use lookup table.
    /// Decrypt the ciphertext with sk, and then try to convert Ristretto point to an amount.
    /// Converting Ristretto point to an amount may fail.
    fn try_decrypt_from(
        sk: &SecretKey,
        ciphertext: &Ciphertext,
    ) -> Option<<Self as Amount>::Target>;

    /// Accelerate try_decrypt_from with a guess. If the guessed amount is the amount
    /// corresponding to the decrypted Ristretto point. Then the decryption will be faster.
    /// This function is otherwise the same as try_decrypt_from.
    fn try_decrypt_from_with_guess(
        sk: &SecretKey,
        ciphertext: &Ciphertext,
        guess: <Self as Amount>::Target,
    ) -> Option<<Self as Amount>::Target> {
        if Self::new(guess).to_point() == Self::get_decrypted_point(sk, ciphertext) {
            return Some(guess);
        }
        Self::try_decrypt_from(sk, ciphertext)
    }
}

mod private {
    // private::Sealed is used to prevent any other types from implementing Amount.
    // See https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
    pub trait Sealed {}
    impl Sealed for u8 {}
    impl Sealed for u16 {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
}

macro_rules! impl_amount {
    ( $t:ty, $bit_size:expr, $max:expr ) => {
        impl Amount for $t {
            type Target = $t;

            #[inline]
            fn new(target: <Self as Amount>::Target) -> Self {
                target
            }

            #[inline]
            fn inner(&self) -> <Self as Amount>::Target {
                *self
            }

            #[inline]
            fn bit_size() -> usize {
                $bit_size
            }

            fn try_decrypt_from(
                sk: &SecretKey,
                ciphertext: &Ciphertext,
            ) -> Option<<Self as Amount>::Target> {
                let point = Self::get_decrypted_point(sk, ciphertext);
                let mut acc: RistrettoPoint = Identity::identity();
                for i in 0..=$max {
                    if acc == point {
                        return Some(i);
                    }
                    acc += BASE_POINT;
                }
                None
            }
        }
    };
}

impl_amount!(u8, 8, std::u8::MAX);
impl_amount!(u16, 16, std::u16::MAX);
impl_amount!(u32, 32, std::u32::MAX);
impl_amount!(u64, 64, std::u64::MAX);

#[cfg(test)]
mod tests {
    use super::*;

    use rand_core::OsRng;

    fn randomly_encrypt_and_decrypt(x: u32) -> Option<u32> {
        let mut csprng = OsRng;
        let sk = SecretKey::generate_with(&mut csprng);
        let pk = sk.to_public();
        u32::try_decrypt_from(&sk, &x.encrypt_with(&pk))
    }

    #[quickcheck]
    fn encrypt_and_decrypt_should_be_identity(xs: Vec<u32>) -> bool {
        xs.into_iter()
            .all(|x| x == randomly_encrypt_and_decrypt(x).unwrap())
    }
}

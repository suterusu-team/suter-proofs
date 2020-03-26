use curve25519_dalek::ristretto::RistrettoPoint;
pub use curve25519_dalek::scalar::Scalar;
pub use elgamal_ristretto::ciphertext::Ciphertext;
pub(crate) use elgamal_ristretto::{
    private::SecretKey as ERSecretKey, public::PublicKey as ERPublicKey,
};
pub use schnorrkel::{PublicKey, SecretKey};
pub type EncryptedBalance = Ciphertext;
use crate::constants::BASE_POINT;

// Due to orphan rules, we can not implement Into<SecretKey> for ERSecretKey
pub(crate) fn to_elgamal_ristretto_secret_key(sk: &SecretKey) -> ERSecretKey {
    let bytes = sk.to_bytes();
    let mut key: [u8; 32] = [0u8; 32];
    key.copy_from_slice(&bytes[00..32]);
    Scalar::from_canonical_bytes(key)
        .expect("Secret key in schnorrkel must be in canonical bytes; qed")
        .into()
}

pub(crate) fn to_elgamal_ristretto_public_key(pk: PublicKey) -> ERPublicKey {
    ERPublicKey::from(*pk.as_point())
}

pub(crate) fn from_elgamal_ristretto_public_key(pk: ERPublicKey) -> PublicKey {
    PublicKey::from_point(pk.get_point())
}

/// Represents two Ristretto points of the form $(m + r * y, r * g)$
/// where y is a public key, g is the base point, r is a random scalar
/// the first is called payload term, while the last is called random term
/// This is used to avoid inconsistency in the order of points in the tuple.
pub(crate) struct RistrettoPointTuple {
    pub(crate) random_term: RistrettoPoint,
    pub(crate) payload_term: RistrettoPoint,
}

impl RistrettoPointTuple {
    pub(crate) fn random_term_first(&self) -> (RistrettoPoint, RistrettoPoint) {
        ((*self).random_term, (*self).payload_term)
    }
    pub(crate) fn random_term_last(&self) -> (RistrettoPoint, RistrettoPoint) {
        ((*self).payload_term, (*self).random_term)
    }
    pub(crate) fn ciphertext_for(&self, pk: ERPublicKey) -> EncryptedBalance {
        EncryptedBalance {
            pk,
            points: self.random_term_first(),
        }
    }
}

impl<'a> From<&'a EncryptedBalance> for RistrettoPointTuple {
    fn from(ciphertext: &'a EncryptedBalance) -> RistrettoPointTuple {
        let pts = (*ciphertext).get_points();
        RistrettoPointTuple {
            random_term: pts.0,
            payload_term: pts.1,
        }
    }
}

#[allow(dead_code)]
pub(crate) fn ciphertext_points_random_term_first(
    ciphertext: EncryptedBalance,
) -> (RistrettoPoint, RistrettoPoint) {
    RistrettoPointTuple::from(&ciphertext).random_term_first()
}

pub(crate) fn ciphertext_points_random_term_last(
    ciphertext: EncryptedBalance,
) -> (RistrettoPoint, RistrettoPoint) {
    RistrettoPointTuple::from(&ciphertext).random_term_last()
}

// Create a ciphertext with the specified plain value and random scalar.
pub(crate) fn new_ciphertext(pk: PublicKey, value: u64, blinding: Scalar) -> EncryptedBalance {
    let pk = to_elgamal_ristretto_public_key(pk);
    let tuple = RistrettoPointTuple {
        random_term: blinding * BASE_POINT,
        payload_term: Scalar::from(value) * BASE_POINT + blinding * pk.get_point(),
    };
    tuple.ciphertext_for(pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[quickcheck]
    fn to_elgamal_ristretto_secret_key_should_work() {
        let mut csprng = OsRng;
        let sk = SecretKey::generate_with(&mut csprng);
        let sk2 = to_elgamal_ristretto_secret_key(&sk);
        assert!(sk2
            .to_bytes()
            .iter()
            .zip(&sk.to_bytes()[..])
            .all(|(b1, b2)| b1 == b2))
    }
}

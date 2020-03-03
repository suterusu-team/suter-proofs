pub use curve25519_dalek::scalar::Scalar;
pub use elgamal_ristretto::ciphertext::Ciphertext;
pub(crate) use elgamal_ristretto::{
    private::SecretKey as ERSecretKey, public::PublicKey as ERPublicKey,
};
pub use schnorrkel::{PublicKey, SecretKey};

// Due to orphan rules, we can not implement Into<SecretKey> for ERSecretKey
pub(crate) fn to_elgamal_ristretto_secret_key(sk: &SecretKey) -> ERSecretKey {
    let bytes = sk.to_bytes();
    let mut key: [u8; 32] = [0u8; 32];
    key.copy_from_slice(&bytes[00..32]);
    Scalar::from_canonical_bytes(key)
        .expect("Secret key in schnorrkel must be in canonical bytes; qed")
        .into()
}

pub(crate) fn to_elgamal_ristretto_public_key(pk: &PublicKey) -> ERPublicKey {
    ERPublicKey::from(*pk.as_point())
}

pub(crate) fn from_elgamal_ristretto_public_key(pk: &ERPublicKey) -> PublicKey {
    PublicKey::from_point(pk.get_point())
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

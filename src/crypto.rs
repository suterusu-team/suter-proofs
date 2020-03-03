pub use curve25519_dalek::scalar::Scalar;
pub use elgamal_ristretto::ciphertext::Ciphertext;
pub(crate) use elgamal_ristretto::{
    private::SecretKey as ERSecretKey, public::PublicKey as ERPublicKey,
};
pub use schnorrkel::{PublicKey, SecretKey};

pub fn to_elgamal_ristretto_secret_key(sk: &SecretKey) -> ERSecretKey {
    let bytes = sk.to_bytes();
    let mut key: [u8; 32] = [0u8; 32];
    key.copy_from_slice(&bytes[00..32]);
    Scalar::from_canonical_bytes(key)
        .expect("Secret key in schnorrkel must be in canonical bytes; qed")
        .into()
}

pub fn to_elgamal_ristretto_public_key(pk: &PublicKey) -> ERPublicKey {
    ERPublicKey::from(*pk.as_point())
}

pub fn from_elgamal_ristretto_public_key(pk: &ERPublicKey) -> PublicKey {
    PublicKey::from_point(pk.get_point())
}

use super::constants::MERLIN_RANGE_PROOF_LABEL;
use bulletproofs::{BulletproofGens, PedersenGens, ProofError, RangeProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use elgamal_ristretto::{ciphertext::Ciphertext, private::SecretKey, public::PublicKey};
use merlin::Transcript;

lazy_static! {
    static ref PC_GENS: PedersenGens = PedersenGens::default();
    static ref BP_GENS: BulletproofGens = BulletproofGens::new(64, 1);
}

pub trait Amount {
    type Target;
    fn to_point(self) -> RistrettoPoint;
    fn encrypt_with(self, pk: PublicKey) -> Ciphertext;
    fn try_decrypt_from(sk: SecretKey, ciphertext: Ciphertext) -> Option<Self::Target>;
    fn create_range_proof(
        &self,
        blinding_value: Scalar,
    ) -> Result<(RangeProof, CompressedRistretto), ProofError>;
    fn verify_range_proof(
        proof: &RangeProof,
        committed_value: &CompressedRistretto,
    ) -> Result<(), ProofError>;
}

impl Amount for u32 {
    type Target = u32;

    #[inline]
    fn to_point(self) -> RistrettoPoint {
        Scalar::from(self) * RISTRETTO_BASEPOINT_POINT
    }

    // Elgamal encryption with balances raised from base point.
    // This makes ElGamal encryption additively homomorphic.
    // See also zether paper https://eprint.iacr.org/2019/191.pdf
    fn encrypt_with(self, pk: PublicKey) -> Ciphertext {
        pk.encrypt(&self.to_point())
    }

    // TODO: Brute force currently is the only viable way.
    // Let $g$ be the base point, $y$ be the public key of the reciever,
    // $f$ be a mapping from scalar to the group, $m$ be the amount of money ransferred,
    // maybe we should store $(f(m)*y^r, g^m*y^r, g^r)$ as ciphertext.
    // This way the reciever is able to recover plaintext with his secret key.
    // But this tuple is only additively homomorphic in the second and the last componnect.
    // And we need to store the entire transaction history.
    // This seems to be not worthwhile.
    fn try_decrypt_from(sk: SecretKey, ciphertext: Ciphertext) -> Option<Self::Target> {
        let point = sk.decrypt(&ciphertext);
        let mut acc: RistrettoPoint = Identity::identity();
        for i in 0..std::u32::MAX {
            if acc == point {
                return Some(i);
            }
            acc += RISTRETTO_BASEPOINT_POINT;
        }
        None
    }

    fn create_range_proof(
        &self,
        blinding_value: Scalar,
    ) -> Result<(RangeProof, CompressedRistretto), ProofError> {
        let secret_value = *self as u64;
        let mut prover_transcript = Transcript::new(MERLIN_RANGE_PROOF_LABEL);
        RangeProof::prove_single(
            &BP_GENS,
            &PC_GENS,
            &mut prover_transcript,
            secret_value,
            &blinding_value,
            32,
        )
    }

    fn verify_range_proof(
        proof: &RangeProof,
        committed_value: &CompressedRistretto,
    ) -> Result<(), ProofError> {
        let mut verifier_transcript = Transcript::new(MERLIN_RANGE_PROOF_LABEL);
        proof.verify_single(
            &BP_GENS,
            &PC_GENS,
            &mut verifier_transcript,
            committed_value,
            32,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use elgamal_ristretto::{private::SecretKey, public::PublicKey};
    use rand_core::OsRng;

    fn randomly_encrypt_and_decrypt(x: u32) -> Option<u32> {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);
        u32::try_decrypt_from(sk, x.encrypt_with(pk))
    }

    #[quickcheck]
    fn encrypt_and_decrypt_should_be_identity(xs: Vec<u32>) -> bool {
        xs.into_iter()
            .all(|x| x == randomly_encrypt_and_decrypt(x).unwrap())
    }

    fn fake_encrypt_and_decrypt(x: u32) -> Option<u32> {
        let sk = SecretKey::from(Scalar::from(0 as u32));
        let pk = PublicKey::from(&sk);
        u32::try_decrypt_from(sk, x.encrypt_with(pk))
    }

    #[quickcheck]
    fn fake_encrypt_and_decrypt_should_be_identity(xs: Vec<u32>) -> bool {
        xs.into_iter()
            .all(|x| x == fake_encrypt_and_decrypt(x).unwrap())
    }

    fn create_range_proof_and_verify(x: u32) -> Result<(), ProofError> {
        let mut csprng = OsRng;
        let blinding_value = Scalar::random(&mut csprng);
        x.create_range_proof(blinding_value)
            .and_then(|(proof, committed_value)| u32::verify_range_proof(&proof, &committed_value))
    }

    #[quickcheck]
    fn create_range_proof_and_verify_should_pass(x: u32) -> Result<(), ProofError> {
        create_range_proof_and_verify(x)
    }

    // TODO: This took too long to finish.
    // #[quickcheck]
    #[allow(dead_code)]
    fn create_range_proof_and_verify_should_pass2(xs: Vec<u32>) -> bool {
        xs.into_iter()
            .all(|x| create_range_proof_and_verify(x).is_ok())
    }
}

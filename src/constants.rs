use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha512, Sha512Trunc256};

use crate::{PublicKey, SecretKey};

pub(crate) static MERLIN_CONFIDENTIAL_TRANSACTION_LABEL: &[u8] =
    b"suter_confidential_transaction_proof";

static RANDOM_RISTRETTO_POINT_HASH_INPUT: &[u8] = b"random_ristretto_point_hash_input";

static RANDOM_SK_HASH_INPUT: &[u8] = b"random_sk_hash_input";

pub const BASE_POINT: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

pub static MAX_BITS: usize = 64;
pub static MAX_PARTIES: usize = 8;
pub static MAX_NUM_OF_TRANSFERS: usize = MAX_PARTIES - 1;

lazy_static! {
    pub static ref PC_GENS: PedersenGens = PedersenGens::default();
    pub static ref BP_GENS: BulletproofGens = BulletproofGens::new(MAX_BITS, MAX_PARTIES);
    pub static ref RANDOM_PK_TO_PAD_TRANSACTIONS: PublicKey = PublicKey::from_point(
        RistrettoPoint::hash_from_bytes::<Sha512>(RANDOM_RISTRETTO_POINT_HASH_INPUT)
    );
    pub(crate) static ref FEE_KEYPAIR: (SecretKey, PublicKey) = {
        let mut hasher = Sha512Trunc256::new();
        hasher.input(RANDOM_SK_HASH_INPUT);
        let result = hasher.result();
        let mut csprng: ChaCha20Rng = SeedableRng::from_seed(result.into());
        let sk = SecretKey::generate_with(&mut csprng);
        let pk = sk.to_public();
        (sk, pk)
    };
}

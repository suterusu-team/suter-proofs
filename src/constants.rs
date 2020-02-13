use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;

pub(crate) static MERLIN_CONFIDENTIAL_TRANSACTION_LABEL: &[u8] =
    b"suter_confidential_transaction_proof";

pub const BASE_POINT: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

lazy_static! {
    pub static ref PC_GENS: PedersenGens = PedersenGens::default();
    pub static ref BP_GENS: BulletproofGens = BulletproofGens::new(64, 8);
}

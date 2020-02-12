use crate::{Ciphertext, PublicKey};
use curve25519_dalek::ristretto::RistrettoPoint;

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
    pub(crate) fn ciphertext_for(&self, pk: &PublicKey) -> Ciphertext {
        Ciphertext {
            pk: *pk,
            points: self.random_term_first(),
        }
    }
}

impl<'a> From<&'a Ciphertext> for RistrettoPointTuple {
    fn from(ciphertext: &'a Ciphertext) -> RistrettoPointTuple {
        let pts = (*ciphertext).get_points();
        RistrettoPointTuple {
            random_term: pts.0,
            payload_term: pts.1,
        }
    }
}

#[allow(dead_code)]
pub(crate) fn ciphertext_points_random_term_first(
    ciphertext: &Ciphertext,
) -> (RistrettoPoint, RistrettoPoint) {
    RistrettoPointTuple::from(ciphertext).random_term_first()
}

pub(crate) fn ciphertext_points_random_term_last(
    ciphertext: &Ciphertext,
) -> (RistrettoPoint, RistrettoPoint) {
    RistrettoPointTuple::from(ciphertext).random_term_last()
}

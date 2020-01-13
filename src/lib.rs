#[macro_use]
extern crate zkp;
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[macro_use]
pub mod macros;
pub mod amount;
pub mod constants;
pub mod elgamal;

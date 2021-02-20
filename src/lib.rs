#![feature(hash_raw_entry)]
#![feature(test)]
#![feature(map_into_keys_values)]

extern crate bincode;
extern crate flate2;
extern crate fnv;
extern crate gmp_mpfr_sys;
extern crate rand;
extern crate rayon;
extern crate sapling_crypto;
extern crate test;
#[macro_use]
extern crate derivative;
extern crate rug;
extern crate sha2;
#[macro_use]
extern crate lazy_static;
extern crate serde; // serialization deserialization
extern crate regex;
extern crate serde_json;

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;
extern crate core;

#[macro_use]
pub mod util;
pub mod group;
pub mod hash;
pub mod mp;
pub mod rollup;
pub mod set;
pub mod wesolowski;


use serde::{Deserialize, Serialize};

use sapling_crypto::bellman::SynthesisError;

type CResult<T> = Result<T, SynthesisError>;

trait OptionExt<T> {
    fn grab(&self) -> Result<&T, SynthesisError>;
    fn grab_mut(&mut self) -> Result<&mut T, SynthesisError>;
}

impl<T> OptionExt<T> for Option<T> {
    fn grab(&self) -> Result<&T, SynthesisError> {
        self.as_ref().ok_or(SynthesisError::AssignmentMissing)
    }
    fn grab_mut(&mut self) -> Result<&mut T, SynthesisError> {
        self.as_mut().ok_or(SynthesisError::AssignmentMissing)
    }
}

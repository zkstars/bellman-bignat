extern crate bellman_bignat;
extern crate docopt;
extern crate rand;
extern crate sapling_crypto;
extern crate serde;
use std::sync::Arc;

use bellman_bignat::hash::hashes::{Poseidon, Pedersen};
use bellman_bignat::rollup::{merkle, rsa};
use bellman_bignat::util::bench::{ConstraintCounter, ConstraintProfiler};
use docopt::Docopt;
use sapling_crypto::bellman::pairing::Engine;
use sapling_crypto::bellman::pairing::bn256::Bn256;
use sapling_crypto::alt_babyjubjub::{AltJubjubBn256, FixedGenerators};
use serde::Deserialize;
use sapling_crypto::bellman::groth16::{
    generate_random_parameters, prepare_prover, prepare_verifying_key, verify_proof,create_random_proof,
    ParameterSource, Parameters, Proof,
};

use sapling_crypto::bellman::{Circuit, SynthesisError};
use rand::{thread_rng, Rng};
use std::time::{Duration, Instant};

use bellman_bignat::rollup::merkle::{RollupBenchParams, MerkleParams, RollupBench,RollupBenchInputs};


fn merkle_bench(t: usize, c: usize) {
    let rng = &mut thread_rng();
    let circuit =

        merkle::RollupBench::<Bn256, _>::from_counts(c, t, AltJubjubBn256::new(), Poseidon::default());

    let empty_circuit = {
        let jj_params = Arc::new(AltJubjubBn256::new());
        let params = RollupBenchParams {
            jj_params: jj_params.clone(),
            sig_hasher: Pedersen {
                params: jj_params.clone(),
            },
            gen: FixedGenerators::SpendingKeyGenerator,
            n_tx: t,
            set_params: MerkleParams {
                depth: c,
                hasher: Poseidon::default(),
            },
        };
        merkle::RollupBench::<Bn256, _> {
            input: None,
            params: params
        }
    };


    let params = generate_random_parameters(empty_circuit,rng).unwrap();
    println!("{:?}",params.vk.delta_g1);
    let pvk = prepare_verifying_key(&params.vk);

    let proof = create_random_proof(circuit, &params, rng);
    if (proof.is_ok()){
        println!("{}",proof.unwrap().a);
    }
    else{
        println!("{:?}", proof.err());
    }



    // println!("generate proof");
    // // println!("proof is {}",verify_proof(&pvk, &proof,&[]).unwrap());
    // println!("{},{},{}",proof.a,proof.b, proof.c);

}


const USAGE: &str = "
Rollup Benchmarker

Usage:
  rust-example  <transactions> <capacity>
  rust-example (-h | --help)
  rollup_bench --version
";


#[derive(Debug, Deserialize)]
struct Args {
    arg_transactions: usize,
    arg_capacity: usize,
}
fn main() {
    color_backtrace::install();
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    merkle_bench(args.arg_transactions, args.arg_capacity);



}
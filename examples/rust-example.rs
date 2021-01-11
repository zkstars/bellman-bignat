extern crate bellman_bignat;
extern crate docopt;
extern crate rand;
extern crate sapling_crypto;
extern crate serde;

use bellman_bignat::hash::hashes::Poseidon;
use bellman_bignat::rollup::{merkle, rsa};
use bellman_bignat::util::bench::{ConstraintCounter, ConstraintProfiler};
use docopt::Docopt;
use sapling_crypto::bellman::pairing::Engine;
use sapling_crypto::bellman::pairing::bn256::Bn256;
use sapling_crypto::alt_babyjubjub::AltJubjubBn256;
use serde::Deserialize;
use sapling_crypto::bellman::groth16::{
    generate_random_parameters, prepare_prover, prepare_verifying_key, verify_proof,
    ParameterSource, Parameters, Proof,
};

use sapling_crypto::bellman::{Circuit, SynthesisError};
use rand::{thread_rng, Rng};
use std::time::{Duration, Instant};



fn merkle_bench(t: usize, c: usize)  {
    let circuit =
        merkle::RollupBench::<Bn256, _>::from_counts(c, t, AltJubjubBn256::new(), Poseidon::default());
    let empty_circuit =
        merkle::RollupBench::<Bn256, _>::from_counts(c, t, AltJubjubBn256::new(), Poseidon::default());
    println!("{:?}",circuit.input.unwrap());
    println!("{:?}", circuit.input.unwrap().accounts);
    println!("{:?}",circuit.input.unwrap().transactions);

    let param_start = Instant::now();
    let params = {
        let p = generate_random_parameters(empty_circuit,rng);
        println!("Params gen is okey:{:#?}", p.is_ok());
        p.unwrap()
    };
    let pvk = prepare_verifying_key(&params.vk);
    let param_end = Instant::now();

    println!("generating proof");
    let (proof, prover_synth_time, prover_crypto_time) =
        create_random_proof(circuit, &params, rng).unwrap();
    println!("Proof generation successful? true");

    let verifier_start = Instant::now();
    let result = verify_proof(&pvk, &proof, &inputs);
    let verifier_end = Instant::now();
    println!("Verified? {:?}", result.is_ok(),);
    TimeReport {
        param_gen: param_end - param_start,
        prover_synth: prover_synth_time,
        prover_crypto: prover_crypto_time,
        verifier: verifier_end - verifier_start,
    }

}


fn create_random_proof<E, C, R, P: ParameterSource<E>>(
    circuit: C,
    params: P,
    rng: &mut R,
) -> Result<(Proof<E>, Duration, Duration), SynthesisError>
    where
        E: Engine,
        C: Circuit<E>,
        R: Rng,
{
    let synth_start = Instant::now();
    let r = rng.gen();
    let s = rng.gen();
    let prover = prepare_prover(circuit)?;
    let synth_end = Instant::now();

    let crypto_start = Instant::now();
    let proof = prover.create_proof(params, r, s)?;
    let crypto_end = Instant::now();

    Ok((proof, synth_end - synth_start, crypto_end - crypto_start))
}
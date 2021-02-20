extern crate bellman_bignat;
extern crate docopt;
extern crate rand;
extern crate sapling_crypto;
extern crate serde;

use std::fs::File;
use rand::{thread_rng, Rng};
use sapling_crypto::bellman::pairing::ff::to_hex;

use bellman_bignat::hash::hashes::Poseidon;
use bellman_bignat::rollup::{merkle, rsa};
use bellman_bignat::util::bench::{ConstraintCounter, ConstraintProfiler, Engine};
use docopt::Docopt;

use sapling_crypto::bellman::pairing::bn256::Bn256;
use sapling_crypto::bellman::Circuit;
use sapling_crypto::alt_babyjubjub::{AltJubjubBn256, JubjubEngine};
use serde::Deserialize;


use sapling_crypto::bellman::groth16::{
    generate_random_parameters, prepare_prover, prepare_verifying_key, verify_proof,create_random_proof,
    ParameterSource, Parameters, Proof,
};
use bellman_bignat::rollup::merkle::{RollupBenchInputs, RollupBench, Accounts};
use bellman_bignat::hash::Hasher;
use std::ptr::null;
use bellman_bignat::set::GenSet;
use bellman_bignat::hash::circuit::MaybeHashed;
use bellman_bignat::rollup::tx::Account;

use bellman_bignat::util::parse_bellman::{parse_vk, parse_g1, parse_g2, VerificationKey, ProofPoints, parse_proof, write_vk, parse_fr, AProof, parse_input, write_proof};
use bellman_bignat::util::solidity::{export_solidity_verifier,write_sol};
use std::io::{Write, Error};
use std::path::Path;


const USAGE: &str = "
Rollup Benchmarker

Usage:
  rollup_bench [options] rsa <transactions> <capacity>
  rollup_bench [options] merkle <transactions> <capacity>
  rollup_bench (-h | --help)
  rollup_bench --version

Options:
  -p --profile  Profile constraints, instead of just counting them
                Emits JSON to stdout
  -h --help     Show this screen.
  --version     Show version.
";

#[derive(Debug, Deserialize)]
struct Args {
    arg_transactions: usize,
    arg_capacity: usize,
    flag_profile: bool,
    cmd_rsa: bool,
    cmd_merkle: bool,
}

fn main() {
    color_backtrace::install();
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
    let (set, constraints) = if args.cmd_rsa {
        (
            "rsa",
            rsa_bench(args.arg_transactions, args.arg_capacity, args.flag_profile),
        )
    } else if args.cmd_merkle {
        (
            "merkle",
            merkle_bench(args.arg_transactions, args.arg_capacity, args.flag_profile),
        )
    } else {
        panic!("Unknown command")
    };
    if !args.flag_profile {
        println!(
            "{},{},{},{}",
            set, args.arg_transactions, args.arg_capacity, constraints
        );
    }
}

fn rsa_bench(t: usize, _c: usize, profile: bool) -> usize {
    let circuit = rsa::RollupBench::<Bn256, Poseidon<Bn256>>::from_counts(
        t, // Use `t` in place of `c` for sparse-ness.
        t,
        AltJubjubBn256::new(),
        Poseidon::default(),
    );

    if profile {
        let mut cs = ConstraintProfiler::new();
        circuit.synthesize(&mut cs).expect("synthesis failed");
        cs.emit_as_json(&mut std::io::stdout()).unwrap();
        cs.num_constraints()
    } else {
        let mut cs = ConstraintCounter::new();
        circuit.synthesize(&mut cs).expect("synthesis failed");
        cs.num_constraints()
    }
}


// fn printStatus(inputs:RollupBenchInputs<E, H>)
// where
//     E:JubjubEngine,
//     H:Hasher,
// {
//     println!("accounts:{}",inputs.unwrap().accounts);
// }



fn merkle_bench(t: usize, c: usize, profile: bool) ->  usize
{

    let rng = &mut thread_rng();
    let circuit:RollupBench<Bn256,Poseidon<Bn256>> =
        merkle::RollupBench::<Bn256, _>::from_counts(c, t, AltJubjubBn256::new(), Poseidon::default());
    // 这里进行了第一次synethix
    let params = generate_random_parameters(circuit.clone(),rng).unwrap();


    let mut set_init = circuit.clone().input.unwrap().accounts.set;
    let init_digest = set_init.digest();

    // calculate final digest.
    let final_digest = {
        let input_account = circuit.clone().input.unwrap().accounts;
        let input_tx = circuit.clone().input.unwrap().transactions;
        let mut accounts :Accounts<Bn256,Poseidon<Bn256>>= input_account.clone();
        for t in &input_tx {
            accounts.apply_tx(&t.tx);
        }
        accounts.set.digest()
    };

    println!("===================");
    // println!("{}",circuit.clone().input.unwrap().accounts);
    let pvk = prepare_verifying_key(&params.vk);

    println!("init hash :{}",to_hex(&init_digest));
    println!("last hash :{}",to_hex(&final_digest));

    // save vk
    let vk = parse_vk(&params);
    println!("{}",&vk.to_string());
    write_vk(&vk);

    // geterate verifier contract
    let verifier = export_solidity_verifier(vk);
    write_sol(verifier);


    //Generate proof
    let proof = create_random_proof(circuit, &params, rng).unwrap();
    let ProofPoints = parse_proof(&proof);

    let inputs = parse_input::<Bn256>(&[init_digest, final_digest].to_vec());

    //write proof.json. ready to onchain verify.
    let a_proof = AProof::new(ProofPoints,inputs);
    write_proof(a_proof);

    //
    //
    // let success =
    //     verify_proof(&pvk, &proof, &[init_digest,final_digest]).expect("cannot verify proof");
    // assert!(success);
    // println!("do we prove it? {}",success);


    1
}





// fn write_proof(vk:)->Result<bool,String>{
//     const VERIFICATION_KEY_DEFAULT_PATH: &str = "verification.key";
//     let output_path = Path::new(VERIFICATION_KEY_DEFAULT_PATH);
//     let mut vk_file = File::create(output_path)
//         .map_err(|why| format!("couldn't create {}: {}", output_path.display(), why))?;
//     vk_file
//         .write(
//             serde_json::to_string_pretty(vk)
//                 .unwrap()
//                 .as_bytes(),
//         )
//         .map_err(|why| format!("couldn't write to {}: {}", output_path.display(), why))?;
//     Ok(true)
// }
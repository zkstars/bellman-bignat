use std::fs::File;
use lazy_static::lazy_static;
use regex::Regex;
use sapling_crypto::bellman::pairing::Engine;
use sapling_crypto::bellman::pairing::ff::ScalarEngine;

use serde::{Deserialize, Serialize};
//define base type for vk,
use sapling_crypto::bellman::groth16::{Parameters,Proof};
use std::path::Path;
use serde_json::{from_reader, to_writer_pretty, Value};
use std::io::Write;
use serde::de::DeserializeOwned;

pub type Fr = String;
pub type Fq = String;
pub type Fq2 = (String, String);

#[derive(Serialize, Deserialize)]
pub struct G1Affine(Fq, Fq);

// When G2 is defined on Fq2 field
#[derive(Serialize, Deserialize)]
pub struct G2Affine(Fq2, Fq2);

// When G2 is defined on a Fq field (BW6_761 curve)
#[derive(Serialize, Deserialize)]
pub struct G2AffineFq(Fq, Fq);

impl ToString for G1Affine {
    fn to_string(&self) -> String {
        format!("{}, {}", self.0, self.1)
    }
}

impl ToString for G2AffineFq {
    fn to_string(&self) -> String {
        format!("{}, {}", self.0, self.1)
    }
}
impl ToString for G2Affine {
    fn to_string(&self) -> String {
        format!(
            "[{}, {}], [{}, {}]",
            (self.0).0,
            (self.0).1,
            (self.1).0,
            (self.1).1
        )
    }
}



// define our type for vk
#[derive(Serialize, Deserialize)]
pub struct VerificationKey {
    pub alpha: G1Affine,
    pub beta: G2Affine,
    pub gamma: G2Affine,
    pub delta: G2Affine,
    pub gamma_abc: Vec<G1Affine>,
}


impl ToString for VerificationKey{
    fn to_string(&self) -> String {
        format!(
            "alpha:{}\n beta:{}\n gamma:{}\n delta:{}\n ",
            self.alpha.to_string(),
            self.beta.to_string(),
            self.gamma.to_string(),
            self.delta.to_string(),
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProofPoints {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}


#[derive(Serialize, Deserialize)]
pub struct AProof {
    pub proof: ProofPoints,
    pub inputs: Vec<String>,
}

impl AProof {
    pub fn new(proof: ProofPoints, inputs: Vec<String>) -> Self {
        AProof { proof, inputs }
    }
}


/// paser tool

lazy_static! {
        static ref G2_REGEX: Regex = Regex::new(r"G2\(x=Fq2\(Fq\((?P<x0>0[xX][0-9a-fA-F]*)\) \+ Fq\((?P<x1>0[xX][0-9a-fA-F]*)\) \* u\), y=Fq2\(Fq\((?P<y0>0[xX][0-9a-fA-F]*)\) \+ Fq\((?P<y1>0[xX][0-9a-fA-F]*)\) \* u\)\)").unwrap();
    }

lazy_static! {
        static ref G1_REGEX: Regex =
            Regex::new(r"G1\(x=Fq\((?P<x>0[xX][0-9a-fA-F]*)\), y=Fq\((?P<y>0[xX][0-9a-fA-F]*)\)\)")
                .unwrap();
    }

lazy_static! {
        static ref FR_REGEX: Regex = Regex::new(r"Fr\((?P<x>0[xX][0-9a-fA-F]*)\)").unwrap();
    }


//
pub fn parse_g1<T: Engine>(
    e: &<T>::G1Affine,
) -> G1Affine {
    let raw_e = e.to_string();
    let captures = G1_REGEX.captures(&raw_e).unwrap();
    G1Affine(
        captures.name(&"x").unwrap().as_str().to_string(),
        captures.name(&"y").unwrap().as_str().to_string(),
    )
}

pub fn parse_g2<T: Engine>(
    e: &<T>::G2Affine,
) -> G2Affine {
    let raw_e = e.to_string();
    let captures = G2_REGEX.captures(&raw_e).unwrap();
    G2Affine(
        (
            captures.name(&"x0").unwrap().as_str().to_string(),
            captures.name(&"x1").unwrap().as_str().to_string(),
        ),
        (
            captures.name(&"y0").unwrap().as_str().to_string(),
            captures.name(&"y1").unwrap().as_str().to_string(),
        ),
    )
}
//
pub fn parse_fr<E: ScalarEngine>(
    e: &<E>::Fr) -> Fr {
    let raw_e = e.to_string();
    let captures = FR_REGEX.captures(&raw_e).unwrap();
    captures.name(&"x").unwrap().as_str().to_string()
}
//
//
//
//
// // function trasfer vk to string's vk
//
//
pub fn parse_vk<T:Engine>(param:&Parameters<T>)->VerificationKey {
    VerificationKey {
        alpha: parse_g1::<T>(&param.vk.alpha_g1),
        beta: parse_g2::<T>(&param.vk.beta_g2),
        gamma: parse_g2::<T>(&param.vk.gamma_g2),
        delta: parse_g2::<T>(&param.vk.delta_g2),
        gamma_abc: param
            .vk
            .ic
            .iter()
            .map(|g1| parse_g1::<T>(g1))
            .collect(),
    }
}
// pub fn parse_vk(){}

pub fn parse_proof<E:Engine>(proof:&Proof<E>) ->ProofPoints{
    ProofPoints {
        a: parse_g1::<E>(&proof.a),
        b: parse_g2::<E>(&proof.b),
        c: parse_g1::<E>(&proof.c),
    }
}

pub fn parse_input<E:ScalarEngine>(input :& Vec<E::Fr>)->Vec<String>{
    input.iter().map(parse_fr::<E>).collect()
}


pub fn write_vk(vk:&VerificationKey)->Result<(),String>{
    const VERIFICATION_KEY_DEFAULT_PATH: &str = "verification.key";
    let output_path = Path::new(VERIFICATION_KEY_DEFAULT_PATH);
    let mut vk_file = File::create(output_path)
        .map_err(|why| format!("couldn't create {}: {}", output_path.display(), why))?;
    vk_file
        .write(
            serde_json::to_string_pretty(vk)
                .unwrap()
                .as_bytes(),
        )
        .map_err(|why| format!("couldn't write to {}: {}", output_path.display(), why))?;
    Ok(())
}

pub fn write_proof(aproof:AProof)->Result<(),String>{
    const JSON_PROOF_PATH: &str = "proof.json";
    let output_path = Path::new(JSON_PROOF_PATH);
    let mut proof_file = File::create(output_path).unwrap();
    let proof = serde_json::to_string_pretty(&aproof).unwrap();
    proof_file
        .write(proof.as_bytes())
        .map_err(|why| format!("Couldn't write to {}: {}", output_path.display(), why))?;

    println!("Proof:\n{}", format!("{}", proof));

    Ok(())
}
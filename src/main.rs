mod block;
mod cli;
mod io;
mod blowfish;
mod packer;
mod decryptor;
mod encryptor;
mod modes;
mod feistel;
mod mode_of_operation;


use decryptor::Decryptor;
use packer::Packer;
use clap::Parser;
use cli::Args;
use encryptor::Encryptor;
use blowfish::Blowfish;
use mode_of_operation::ModeOfOperation;
use feistel::FeistelNetwork;
use modes::{CBC, ECB};


use rand::rngs::OsRng;
use rand::rngs::adapter::ReseedingRng;
use rand::prelude::*;
use rand_chacha::ChaCha20Core;

fn main() {
    // if true {
    //     let prng = ChaCha20Core::from_entropy();
    //     let mut reseeding_rng = ReseedingRng::new(prng, 0, OsRng); //Reseeding
    //     println!("Random number: {}", reseeding_rng.gen::<u64>());
    //     return
    // }

    let args = Args::parse();

    let (path, encrypt_msg) = match (args.encrypt, args.decrypt) {
        (Some(p), None) => (p, true), 
        (None, Some(p)) => (p, false),
        (Some(_), Some(_)) => panic!("Encrypt and Decrypt are mutually exclusive"),
        (None, None) => panic!("Must either encrypt or decrypt"),
    };

    let prng = ChaCha20Core::from_entropy();
    let mut reseeding_rng = ReseedingRng::new(prng, 0, OsRng);
    let iv = reseeding_rng.gen::<u64>(); // PLACEHOLDER IV

    let key = args.key.as_bytes().to_vec();
    let (ecb, cbc) = (ECB{}, CBC { init_vec: iv });
    match (args.mode, encrypt_msg) {
        (0, true) => enc(Encryptor::<ECB, Blowfish>(ecb, Blowfish::initialize::<Packer>(key)), &path),
        (1, true) => enc(Encryptor::<CBC, Blowfish>(cbc, Blowfish::initialize::<Packer>(key)), &path),
        (0, false) => dec(Decryptor::<ECB, Blowfish>(ecb, Blowfish::initialize::<Packer>(key)), &path),
        (1, false) => dec(Decryptor::<CBC, Blowfish>(cbc, Blowfish::initialize::<Packer>(key)), &path),
        _ => panic!("Not Implemented"),
    }
}


fn enc(encryptor: Encryptor<impl ModeOfOperation, impl FeistelNetwork>, path: &str) {
    let msg = encryptor.parse::<Packer>(path);
    encryptor.encrypt(msg);
}

fn dec(decryptor: Decryptor<impl ModeOfOperation, impl FeistelNetwork>, path: &str) {
    let msg = decryptor.parse::<Packer>(path);
    decryptor.decrypt(msg);
}
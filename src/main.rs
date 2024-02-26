mod block;
mod cli;
mod io;
mod blowfish;
mod packer;
mod cipher;
mod modes;
mod feistel;
mod mode_of_operation;
mod errors;


use errors::CipherError;
use io::output_to_file;
use packer::Packer;
use clap::Parser;
use cli::Args;
use cipher::Cipher;
use blowfish::Blowfish;
use mode_of_operation::ModeOfOperation;
use feistel::FeistelNetwork;
use modes::{CBC, ECB};


use rand::rngs::OsRng;
use rand::rngs::adapter::ReseedingRng;
use rand::prelude::*;
use rand_chacha::ChaCha20Core;

use crate::errors::rgb_string;

fn main() {
    let args = Args::parse();

    let (path, encrypt_msg) = match (args.encrypt, args.decrypt) {
        (Some(p), None) => (p, true), 
        (None, Some(p)) => (p, false),
        (Some(_), Some(_)) => {eprintln!("{}Encrypt and Decrypt are mutually exclusive.\x1b[0m", rgb_string(200, 200, 0)); std::process::exit(1)},
        (None, None) => {eprintln!("{}No Encryption or Decryption selected. See --help.\x1b[0m", rgb_string(200, 200, 0)); std::process::exit(1)},
    };

    let prng = ChaCha20Core::from_entropy();
    let mut reseeding_rng = ReseedingRng::new(prng, 0, OsRng);
    let iv = reseeding_rng.gen::<u64>();

    let key = args.key.as_bytes().to_vec();
    let (ecb, cbc) = (ECB{}, CBC { init_vec: iv });
    let blowfish = match Blowfish::initialize::<Packer>(key) {
        Ok(bf) => bf,
        Err(e) => {
            eprintln!("Failed: {e}");
            return;
        }
    };
    match (args.mode, encrypt_msg) {
        (0, true) => encode_file(Cipher::<ECB, Blowfish>(ecb, blowfish), &path),
        (1, true) => encode_file(Cipher::<CBC, Blowfish>(cbc, blowfish), &path),
        (0, false) => decode_file(Cipher::<ECB, Blowfish>(ecb, blowfish), &path),
        (1, false) => decode_file(Cipher::<CBC, Blowfish>(cbc, blowfish), &path),
        _ => {eprintln!("{}Bad Mode Selection. See --help.\x1b[0m", rgb_string(200, 200, 0)); std::process::exit(1)},
    }
}

fn encode_file(cipher: Cipher<impl ModeOfOperation, impl FeistelNetwork>, path: &str) {
    let msg = cipher.parse::<Packer>(path);
    output_to_file(enc(cipher, msg), "encrypted_file");
}

fn enc(cipher: Cipher<impl ModeOfOperation, impl FeistelNetwork>, data: Vec<u8>) ->  Vec<u8>  {
    cipher.encrypt::<Packer>(data)
}

fn decode_file(cipher: Cipher<impl ModeOfOperation, impl FeistelNetwork>, path: &str) {
    let msg = cipher.parse::<Packer>(path);
    match dec(cipher, msg) {
        Ok(data) => {
            output_to_file(data, path)
        },
        Err(e) => {
            eprintln!("Failed to decrypt: {e}");
        }
    }
}

fn dec(cipher: Cipher<impl ModeOfOperation, impl FeistelNetwork>, data: Vec<u8>) -> Result<Vec<u8>, CipherError> {
    cipher.decrypt::<Packer>(data)
}
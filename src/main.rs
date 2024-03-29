mod block;
mod blowfish;
mod cipher;
mod cli;
mod errors;
mod feistel;
mod io;
mod mode_of_operation;
mod modes;
mod packer;

use blowfish::Blowfish;
use cipher::Cipher;
use clap::Parser;
use cli::Args;
use errors::CipherError;
use feistel::FeistelNetwork;
use io::output_to_file;
use mode_of_operation::ModeOfOperation;
use modes::{CBC, ECB};
use packer::Packer;

use rand::prelude::*;
use rand::rngs::adapter::ReseedingRng;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Core;

use crate::errors::rgb_string;

fn main() -> Result<(), CipherError> {
    let args = Args::parse();

    let (path, encrypt_msg) = match (args.encrypt, args.decrypt) {
        (Some(p), None) => (p, true),
        (None, Some(p)) => (p, false),
        (Some(_), Some(_)) => {
            eprintln!(
                "{}Encrypt and Decrypt are mutually exclusive.\x1b[0m",
                rgb_string(200, 200, 0)
            );
            std::process::exit(1)
        }
        (None, None) => {
            eprintln!(
                "{}No Encryption or Decryption selected. See --help.\x1b[0m",
                rgb_string(200, 200, 0)
            );
            std::process::exit(1)
        }
    };

    let prng = ChaCha20Core::from_entropy();
    let mut reseeding_rng = ReseedingRng::new(prng, 0, OsRng);
    let iv = reseeding_rng.gen::<u64>();

    let key = args.key.as_bytes().to_vec();
    let (ecb, cbc) = (ECB {}, CBC { init_vec: Some(iv) });
    let blowfish = Blowfish::initialize::<Packer>(key)?;
    match (args.mode, encrypt_msg) {
        (0, true) => encode_file(Cipher::<ECB, Blowfish>(ecb, blowfish), &path),
        (1, true) => encode_file(Cipher::<CBC, Blowfish>(cbc, blowfish), &path),
        (0, false) => decode_file(Cipher::<ECB, Blowfish>(ecb, blowfish), &path),
        (1, false) => decode_file(Cipher::<CBC, Blowfish>(cbc, blowfish), &path),
        _ => {
            eprintln!(
                "{}Bad Mode Selection. See --help.\x1b[0m",
                rgb_string(200, 200, 0)
            );
            std::process::exit(1)
        }
    }
}

fn encode_file(
    cipher: Cipher<impl ModeOfOperation, impl FeistelNetwork>,
    path: &str,
) -> Result<(), CipherError> {
    let msg = cipher.parse::<Packer>(path);
    let encoded = enc(cipher, msg)?;
    output_to_file(encoded, "encrypted_file");
    Ok(())
}

fn enc(
    cipher: Cipher<impl ModeOfOperation, impl FeistelNetwork>,
    data: Vec<u8>,
) -> Result<Vec<u8>, CipherError> {
    cipher.encrypt::<Packer>(data)
}

fn decode_file(
    cipher: Cipher<impl ModeOfOperation, impl FeistelNetwork>,
    path: &str,
) -> Result<(), CipherError> {
    let msg = cipher.parse::<Packer>(path);
    let decoded = dec(cipher, msg)?;
    output_to_file(decoded, path);
    Ok(())
}

fn dec(
    cipher: Cipher<impl ModeOfOperation, impl FeistelNetwork>,
    data: Vec<u8>,
) -> Result<Vec<u8>, CipherError> {
    cipher.decrypt::<Packer>(data)
}
